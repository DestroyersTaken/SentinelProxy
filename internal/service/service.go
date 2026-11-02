// Package service is the API the UI talks to. Every exported method of API
// is callable from the frontend (Wails binding in the desktop app, the same
// binding over HTTP in server mode).
package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/elevate"
	"github.com/DestroyersTaken/SentinelProxy/internal/engine"
	"github.com/DestroyersTaken/SentinelProxy/internal/importexport"
	"github.com/DestroyersTaken/SentinelProxy/internal/inbound"
	"github.com/DestroyersTaken/SentinelProxy/internal/intercept"
	"github.com/DestroyersTaken/SentinelProxy/internal/logx"
	"github.com/DestroyersTaken/SentinelProxy/internal/match"
	"github.com/DestroyersTaken/SentinelProxy/internal/procinfo"
	"github.com/DestroyersTaken/SentinelProxy/internal/proxy"
	"github.com/DestroyersTaken/SentinelProxy/internal/rules"
	"github.com/DestroyersTaken/SentinelProxy/internal/sysproxy"
)

// Version is set by main.
var Version = "dev"

// AppSettings are machine-wide preferences (not part of a profile).
type AppSettings struct {
	StartEnabled   bool   `json:"startEnabled"`   // turn proxying on at launch
	StartMinimized bool   `json:"startMinimized"` // start hidden in the tray
	CloseToTray    bool   `json:"closeToTray"`
	Theme          string `json:"theme"` // system, dark, light
	Notifications  bool   `json:"notifications"`
}

// API is the frontend-facing service.
type API struct {
	mu       sync.Mutex
	store    *config.Store
	eng      *engine.Engine
	log      *logx.Log
	profile  *config.Profile
	app      AppSettings
	running  bool
	ic       intercept.Interceptor
	icErr    string
	local    *inbound.Server
	localErr string
	sysOn    bool
	sysErr   string

	pendingMu sync.Mutex
	pending   map[string]*importexport.Result

	// Emit pushes an event to the UI (set by main; may be nil).
	Emit func(name string, data any)
	// SaveDialog asks the user for a save path (GUI only; nil in server mode).
	SaveDialog func(defaultName string) (string, error)
	// OnStateChange lets the tray refresh its menu.
	OnStateChange func(running bool)
	// Quit ends the application (set by main).
	Quit func()

	stop chan struct{}
}

// New loads the active profile and creates the engine.
func New(dataDir string) (*API, error) {
	store, err := config.NewStore(dataDir)
	if err != nil {
		return nil, err
	}
	lg := logx.New(5000)
	_ = lg.OpenFile(filepath.Join(dataDir, "logs", "sentinelproxy.log"))
	p, err := store.LoadActive()
	if err != nil {
		return nil, err
	}
	a := &API{store: store, log: lg, profile: p, eng: engine.New(lg), pending: map[string]*importexport.Result{}, stop: make(chan struct{})}
	a.app = a.loadAppSettings()
	if err := a.eng.Apply(p); err != nil {
		lg.Errorf("Profile %q has problems and was not applied: %v", p.Name, err)
	}
	lg.Infof("SentinelProxy %s started (%s/%s), profile %q", Version, runtime.GOOS, runtime.GOARCH, p.Name)
	go a.ticker()
	return a, nil
}

// Engine exposes the engine (for main and tests).
func (a *API) Engine() *engine.Engine { return a.eng }

// AppPrefs returns the machine-wide preferences.
func (a *API) AppPrefs() AppSettings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.app
}

// Shutdown stops everything and restores system settings.
func (a *API) Shutdown() {
	a.mu.Lock()
	a.stopLocked()
	a.mu.Unlock()
	close(a.stop)
	a.eng.Close()
	a.log.Close()
}

func (a *API) emit(name string, data any) {
	if a.Emit != nil {
		a.Emit(name, data)
	}
}

func (a *API) ticker() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-t.C:
			a.emit("tick", a.GetSummary())
		}
	}
}

// ---------------------------------------------------------------- state

// Component reports the status of one subsystem.
type Component struct {
	Enabled bool   `json:"enabled"` // wanted by settings
	Active  bool   `json:"active"`  // actually running
	Detail  string `json:"detail"`
	Error   string `json:"error,omitempty"`
}

// State is the overall app status.
type State struct {
	Running      bool        `json:"running"`
	Version      string      `json:"version"`
	OS           string      `json:"os"`
	Profile      string      `json:"profile"`
	Profiles     []string    `json:"profiles"`
	Capture      Component   `json:"capture"`
	CaptureReady bool        `json:"captureReady"`
	CaptureHint  string      `json:"captureHint,omitempty"`
	LocalProxy   Component   `json:"localProxy"`
	SystemProxy  Component   `json:"systemProxy"`
	SysProxyOK   bool        `json:"sysProxySupported"`
	Elevated     bool        `json:"elevated"`
	CanElevate   bool        `json:"canElevate"`
	DataDir      string      `json:"dataDir"`
	App          AppSettings `json:"app"`
}

// GetState returns the overall status.
func (a *API) GetState() State {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stateLocked()
}

func (a *API) stateLocked() State {
	s := a.profile.Settings
	names, _ := a.store.List()
	ready, hint := intercept.Available()
	st := State{Running: a.running, Version: Version, OS: runtime.GOOS, Profile: a.profile.Name, Profiles: names,
		CaptureReady: ready, CaptureHint: hint, SysProxyOK: sysproxy.Supported(), DataDir: a.store.Dir(), App: a.app,
		Elevated: elevate.IsElevated(), CanElevate: elevate.Supported() && !elevate.IsElevated()}
	st.Capture = Component{Enabled: s.Intercept, Active: a.ic != nil, Error: a.icErr}
	if a.ic != nil {
		st.Capture.Detail = a.ic.Name()
	}
	st.LocalProxy = Component{Enabled: s.LocalProxy, Active: a.local != nil, Error: a.localErr}
	if a.local != nil {
		st.LocalProxy.Detail = a.local.Addr()
	}
	st.SystemProxy = Component{Enabled: s.SystemProxy, Active: a.sysOn, Error: a.sysErr}
	return st
}

func (a *API) changed() {
	st := a.stateLocked()
	go func() {
		a.emit("state", st)
		if a.OnStateChange != nil {
			a.OnStateChange(st.Running)
		}
	}()
}

// SetRunning turns proxying on or off (capture, local proxy, system proxy).
func (a *API) SetRunning(on bool) State {
	a.mu.Lock()
	defer a.mu.Unlock()
	if on {
		a.startLocked()
	} else {
		a.stopLocked()
		a.log.Infof("Proxying turned off")
	}
	a.changed()
	return a.stateLocked()
}

// Toggle flips the running state.
func (a *API) Toggle() State { return a.SetRunning(!a.GetState().Running) }

func (a *API) startLocked() {
	a.stopLocked()
	a.running = true
	s := a.profile.Settings
	if s.LocalProxy {
		srv, err := inbound.Listen(a.eng, s.LocalProxyListen, s.LocalProxyUser, s.LocalProxyPassword)
		if err != nil {
			a.localErr = err.Error()
			a.log.Errorf("Local proxy on %s: %v", s.LocalProxyListen, err)
		} else {
			a.local = srv
			a.localErr = ""
			a.log.Infof("Local proxy (SOCKS5/SOCKS4/HTTP) listening on %s", srv.Addr())
		}
	}
	if s.SystemProxy && a.local != nil {
		if err := sysproxy.Enable(a.local.Addr()); err != nil {
			a.sysErr = err.Error()
			a.log.Errorf("System proxy: %v", err)
		} else {
			a.sysOn, a.sysErr = true, ""
			a.log.Infof("System proxy set to %s", a.local.Addr())
		}
	}
	if s.Intercept {
		ic, err := intercept.Start(a.eng, s)
		if err != nil {
			a.icErr = err.Error()
			a.log.Errorf("System-wide capture unavailable: %v", err)
		} else {
			a.ic, a.icErr = ic, ""
		}
	}
	a.log.Infof("Proxying turned on (profile %q)", a.profile.Name)
}

func (a *API) stopLocked() {
	if a.ic != nil {
		_ = a.ic.Close()
		a.ic = nil
	}
	if a.sysOn {
		_ = sysproxy.Disable()
		a.sysOn = false
	}
	if a.local != nil {
		_ = a.local.Close()
		a.local = nil
	}
	a.icErr, a.localErr, a.sysErr = "", "", ""
	a.running = false
}

// ---------------------------------------------------------------- profile

// GetProfile returns the active profile.
func (a *API) GetProfile() *config.Profile {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.profile.Clone()
}

// SaveResult reports a save.
type SaveResult struct {
	OK       bool             `json:"ok"`
	Problems []config.Problem `json:"problems"`
	Error    string           `json:"error,omitempty"`
	State    State            `json:"state"`
}

// SaveProfile validates, stores and applies a profile. Listeners restart
// when their settings changed.
func (a *API) SaveProfile(p *config.Profile) SaveResult {
	if p == nil {
		return SaveResult{Error: "no profile"}
	}
	p.Normalize()
	res := SaveResult{Problems: p.Validate()}
	for _, r := range p.Rules {
		if _, err := rules.CompileRule(r); err != nil {
			res.Problems = append(res.Problems, config.Problem{Kind: "rule", ID: r.ID, Message: fmt.Sprintf("%q: %v", r.Name, err)})
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(res.Problems) > 0 {
		res.State = a.stateLocked()
		return res
	}
	if p.Name != a.profile.Name {
		// Renames go through RenameProfile; keep the stored name.
		p.Name = a.profile.Name
	}
	if err := a.eng.Apply(p); err != nil {
		res.Error = err.Error()
		res.State = a.stateLocked()
		return res
	}
	if err := a.store.Save(p); err != nil {
		res.Error = err.Error()
		res.State = a.stateLocked()
		return res
	}
	old := a.profile.Settings
	a.profile = p.Clone()
	if a.running && listenerSettingsChanged(old, p.Settings) {
		a.log.Infof("Capture settings changed; restarting")
		a.startLocked()
	}
	res.OK = true
	a.changed()
	res.State = a.stateLocked()
	return res
}

func listenerSettingsChanged(a, b config.Settings) bool {
	return a.Intercept != b.Intercept || a.InterceptUDP != b.InterceptUDP || a.InterceptIPv6 != b.InterceptIPv6 ||
		a.LocalProxy != b.LocalProxy || a.LocalProxyListen != b.LocalProxyListen || a.LocalProxyUser != b.LocalProxyUser ||
		a.LocalProxyPassword != b.LocalProxyPassword || a.SystemProxy != b.SystemProxy || a.DNS.Mode != b.DNS.Mode
}

// ValidatePattern checks one rule condition as the user types it. kind is
// "app", "host" or "port". It returns "" when valid, otherwise the error;
// for hosts the description of the pattern is returned with an "ok:" prefix.
func (a *API) ValidatePattern(kind, value string) string {
	switch kind {
	case "host":
		d, err := match.ParseHostPattern(value)
		if err != nil {
			return err.Error()
		}
		return "ok:" + d
	case "port":
		if _, err := match.NewPortMatcher([]string{value}); err != nil {
			return err.Error()
		}
	}
	return ""
}

// ---------------------------------------------------------------- profiles

// SwitchProfile activates another stored profile.
func (a *API) SwitchProfile(name string) (State, error) {
	p, err := a.store.Load(name)
	if err != nil {
		return a.GetState(), err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.eng.Apply(p); err != nil {
		return a.stateLocked(), err
	}
	_ = a.store.SetActive(p.Name)
	a.profile = p
	if a.running {
		a.startLocked()
	}
	a.log.Infof("Switched to profile %q", p.Name)
	a.changed()
	return a.stateLocked(), nil
}

// CreateProfile makes a new profile, empty or copied from the active one.
func (a *API) CreateProfile(name string, copyCurrent bool) (State, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return a.GetState(), errors.New("enter a name")
	}
	names, _ := a.store.List()
	for _, n := range names {
		if strings.EqualFold(config.FileName(n), config.FileName(name)) {
			return a.GetState(), fmt.Errorf("a profile named %q already exists", n)
		}
	}
	var p *config.Profile
	if copyCurrent {
		p = a.GetProfile()
		p.Name = name
	} else {
		p = config.NewProfile(name)
	}
	if err := a.store.Save(p); err != nil {
		return a.GetState(), err
	}
	return a.SwitchProfile(name)
}

// RenameProfile renames the active profile.
func (a *API) RenameProfile(newName string) (State, error) {
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return a.GetState(), errors.New("enter a name")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.store.Rename(a.profile.Name, newName); err != nil {
		return a.stateLocked(), err
	}
	a.profile.Name = newName
	_ = a.store.SetActive(newName)
	a.changed()
	return a.stateLocked(), nil
}

// DeleteProfile removes a profile that is not active.
func (a *API) DeleteProfile(name string) (State, error) {
	a.mu.Lock()
	active := a.profile.Name
	a.mu.Unlock()
	if name == active {
		return a.GetState(), errors.New("switch to another profile before deleting this one")
	}
	if err := a.store.Delete(name); err != nil {
		return a.GetState(), err
	}
	a.mu.Lock()
	a.changed()
	a.mu.Unlock()
	return a.GetState(), nil
}

// RestartAsAdmin relaunches SentinelProxy elevated (UAC prompt) so
// system-wide capture can start, then quits this instance.
func (a *API) RestartAsAdmin() error {
	args := []string{}
	if a.GetState().Running {
		args = append(args, "--start")
	}
	if err := elevate.Relaunch(args); err != nil {
		return err
	}
	if a.Quit != nil {
		go func() { time.Sleep(300 * time.Millisecond); a.Quit() }()
	}
	return nil
}

// ---------------------------------------------------------------- app settings

func (a *API) appSettingsPath() string { return filepath.Join(a.store.Dir(), "app.json") }

func (a *API) loadAppSettings() AppSettings {
	s := AppSettings{CloseToTray: true, Theme: "system", Notifications: true}
	if b, err := os.ReadFile(a.appSettingsPath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

// SaveAppSettings stores machine-wide preferences.
func (a *API) SaveAppSettings(s AppSettings) (State, error) {
	b, _ := json.MarshalIndent(s, "", "  ")
	if err := os.WriteFile(a.appSettingsPath(), b, 0o600); err != nil {
		return a.GetState(), err
	}
	a.mu.Lock()
	a.app = s
	a.changed()
	a.mu.Unlock()
	return a.GetState(), nil
}

// ---------------------------------------------------------------- traffic

// Summary is the dashboard payload.
type Summary struct {
	engine.Summary
	Capture  *intercept.Stats `json:"capture,omitempty"`
	Running  bool             `json:"running"`
	DNSCache int              `json:"dnsCache"`
	UDP      int              `json:"udpSessions"`
}

// GetSummary returns live totals and the speed history.
func (a *API) GetSummary() Summary {
	s := Summary{Summary: a.eng.Tracker.Summary(), DNSCache: a.eng.DNSCache.Len(), UDP: a.eng.UDPSessions()}
	a.mu.Lock()
	s.Running = a.running
	if a.ic != nil {
		st := a.ic.Stats()
		s.Capture = &st
	}
	a.mu.Unlock()
	return s
}

// GetConnections lists active (and optionally recently closed) connections.
func (a *API) GetConnections(includeClosed bool) []engine.ConnView {
	return a.eng.Tracker.Connections(includeClosed)
}

// KillConnection closes one connection.
func (a *API) KillConnection(id uint64) bool { return a.eng.Tracker.Kill(id) }

// KillApp closes every connection of an application.
func (a *API) KillApp(app string) int {
	return a.eng.Tracker.KillWhere(func(v engine.ConnView) bool { return strings.EqualFold(v.App, app) })
}

// ClearClosed forgets closed connections.
func (a *API) ClearClosed() { a.eng.Tracker.ClearClosed() }

// GetApps returns per-application traffic.
func (a *API) GetApps() []engine.AppStat { return a.eng.Tracker.Apps() }

// GetRoutes returns per-proxy traffic.
func (a *API) GetRoutes() []engine.RouteStat { return a.eng.Tracker.Routes() }

// GetTopHosts returns the busiest destinations.
func (a *API) GetTopHosts(n int) []engine.HostStat { return a.eng.Tracker.TopHosts(n) }

// ResetStats zeroes traffic statistics.
func (a *API) ResetStats() { a.eng.Tracker.ResetStats() }

// GetRuleHits returns how often each rule matched ("" = default rule).
func (a *API) GetRuleHits() map[string]uint64 { return a.eng.Rules().Hits() }

// ListProcesses returns running programs for the app picker, merged with
// apps that already made connections.
func (a *API) ListProcesses() []procinfo.Process {
	ps := procinfo.List()
	seen := map[string]bool{}
	for _, p := range ps {
		seen[strings.ToLower(p.Name)] = true
	}
	for _, s := range a.eng.Tracker.Apps() {
		if s.Name != "Unknown" && !seen[strings.ToLower(s.Name)] {
			ps = append(ps, procinfo.Process{Name: s.Name, Path: s.Path})
			seen[strings.ToLower(s.Name)] = true
		}
	}
	sort.Slice(ps, func(i, j int) bool { return strings.ToLower(ps[i].Name) < strings.ToLower(ps[j].Name) })
	return ps
}

// ---------------------------------------------------------------- logs

// GetLogs returns log entries newer than after.
func (a *API) GetLogs(after uint64, limit int) []logx.Entry { return a.log.Since(after, limit) }

// ClearLogs empties the in-memory log.
func (a *API) ClearLogs() { a.log.Clear() }

// ---------------------------------------------------------------- checks & testing

// CheckProxy runs the full checker against a proxy or chain.
func (a *API) CheckProxy(id string) (proxy.CheckResult, error) {
	rt := a.eng.Router().Route(id)
	if rt == nil {
		return proxy.CheckResult{}, fmt.Errorf("proxy or chain %q not found (save first)", id)
	}
	res := a.eng.CheckRoute(rt, true)
	a.log.Infof("Check %s: %s", rt.Label(), checkText(res))
	return res, nil
}

func checkText(r proxy.CheckResult) string {
	if r.OK {
		s := fmt.Sprintf("OK, %d ms", r.LatencyMs)
		if r.ExitIP != "" {
			s += ", exit IP " + r.ExitIP
		}
		return s
	}
	return "failed: " + r.Error
}

// CheckAll checks every proxy (quick mode) in parallel.
func (a *API) CheckAll() map[string]proxy.CheckResult {
	p := a.GetProfile()
	out := map[string]proxy.CheckResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, px := range p.Proxies {
		rt := a.eng.Router().Route(px.ID)
		if rt == nil {
			continue
		}
		wg.Add(1)
		go func(rt proxy.Route) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := a.eng.CheckRoute(rt, false)
			mu.Lock()
			out[rt.ID()] = r
			mu.Unlock()
		}(rt)
	}
	wg.Wait()
	return out
}

// GetHealth returns the health table.
func (a *API) GetHealth() map[string]proxy.Status { return a.eng.Health.Snapshot() }

// TestInput describes a hypothetical connection for the rule tester.
type TestInput struct {
	App      string `json:"app"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// TestResult is what the rule tester shows.
type TestResult struct {
	Decision rules.Decision `json:"decision"`
	Label    string         `json:"label"`
	Steps    []rules.Step   `json:"steps"`
}

// TestRule explains which rule a connection would hit (using the given
// profile, so unsaved edits can be tested; nil means the active profile).
func (a *API) TestRule(in TestInput, p *config.Profile) TestResult {
	if p == nil {
		p = a.GetProfile()
	}
	m := rules.Meta{Network: config.Protocol(strings.ToLower(in.Protocol))}
	app := strings.TrimSpace(in.App)
	if strings.ContainsAny(app, `/\`) {
		m.App = match.AppInfo{Path: app}
	} else {
		m.App = match.AppInfo{Name: app}
	}
	host := strings.TrimSpace(in.Host)
	if h, port, err := splitHostPortLoose(host); err == nil {
		host = h
		if in.Port == 0 {
			in.Port = port
		}
	}
	m.Target = match.Target{Port: uint16(in.Port)}
	if ip, err := parseIP(host); err == nil {
		m.Target.IP = ip
	} else {
		m.Target.Domain = host
	}
	d, steps := rules.Explain(p, m)
	return TestResult{Decision: d, Label: p.ActionLabel(d.Action), Steps: steps}
}

// ---------------------------------------------------------------- quick rules

// QuickRuleInput creates a rule from the Connections view.
type QuickRuleInput struct {
	App    string        `json:"app"`
	Host   string        `json:"host"`
	Scope  string        `json:"scope"` // "app", "host", "app+host", "domain" (host and subdomains)
	Action config.Action `json:"action"`
}

// AddQuickRule inserts a rule at the top of the list and applies it.
func (a *API) AddQuickRule(in QuickRuleInput) SaveResult {
	p := a.GetProfile()
	r := config.Rule{ID: config.NewID(), Enabled: true, Action: in.Action}
	host := strings.ToLower(strings.TrimSpace(in.Host))
	switch in.Scope {
	case "app":
		r.Apps = []string{in.App}
		r.Name = in.App
	case "host":
		r.Hosts = []string{host}
		r.Name = host
	case "domain":
		r.Hosts = []string{"." + registrable(host)}
		r.Name = "*." + registrable(host)
	default:
		r.Apps = []string{in.App}
		r.Hosts = []string{host}
		r.Name = in.App + " → " + host
	}
	r.Name = fmt.Sprintf("%s: %s", p.ActionLabel(in.Action), r.Name)
	p.Rules = append([]config.Rule{r}, p.Rules...)
	res := a.SaveProfile(p)
	if res.OK {
		a.log.Infof("Added rule %q", r.Name)
	}
	return res
}

// registrable trims a hostname to its last two labels (three for common
// second-level country domains like co.uk).
func registrable(h string) string {
	parts := strings.Split(strings.Trim(h, "."), ".")
	if len(parts) <= 2 {
		return strings.Join(parts, ".")
	}
	n := 2
	sl := parts[len(parts)-2]
	if len(parts[len(parts)-1]) == 2 && (sl == "co" || sl == "com" || sl == "net" || sl == "org" || sl == "ac" || sl == "gov") {
		n = 3
	}
	return strings.Join(parts[len(parts)-n:], ".")
}

// ---------------------------------------------------------------- import / export

// GetFormats lists import/export formats.
func (a *API) GetFormats() []importexport.Format { return importexport.Formats }

// ImportPreview is shown before an import is applied.
type ImportPreview struct {
	Token       string          `json:"token"`
	Format      string          `json:"format"`
	FormatName  string          `json:"formatName"`
	Warnings    []string        `json:"warnings"`
	Profile     *config.Profile `json:"profile"`
	HasSettings bool            `json:"hasSettings"`
	HasDefault  bool            `json:"hasDefault"`
	DefaultText string          `json:"defaultText"`
}

// PreviewImport parses a file. content is base64 when isBase64 is true
// (binary-safe upload from the browser), otherwise plain text.
func (a *API) PreviewImport(fileName, content string, isBase64 bool, format string) (*ImportPreview, error) {
	data := []byte(content)
	if isBase64 {
		var err error
		if data, err = base64.StdEncoding.DecodeString(content); err != nil {
			return nil, fmt.Errorf("could not read the file: %w", err)
		}
	}
	if len(data) > 32<<20 {
		return nil, errors.New("file is too large")
	}
	r, err := importexport.Import(fileName, data, format)
	if err != nil {
		return nil, err
	}
	tok := config.NewID()
	a.pendingMu.Lock()
	a.pending[tok] = r
	a.pendingMu.Unlock()
	return &ImportPreview{Token: tok, Format: r.Format, FormatName: importexport.FormatByID(r.Format).Name, Warnings: r.Warnings,
		Profile: r.Profile, HasSettings: r.HasSettings, HasDefault: r.HasDefault, DefaultText: r.Profile.ActionLabel(r.Profile.DefaultAction)}, nil
}

// ApplyImportResult reports an applied import.
type ApplyImportResult struct {
	Summary importexport.MergeSummary `json:"summary"`
	Save    SaveResult                `json:"save"`
}

// ApplyImport merges a previewed import into the active profile, or into a
// brand-new profile when newProfile is non-empty.
func (a *API) ApplyImport(token string, opts importexport.MergeOptions, newProfile string) (*ApplyImportResult, error) {
	a.pendingMu.Lock()
	r := a.pending[token]
	delete(a.pending, token)
	a.pendingMu.Unlock()
	if r == nil {
		return nil, errors.New("this import expired; open the file again")
	}
	if newProfile = strings.TrimSpace(newProfile); newProfile != "" {
		if _, err := a.CreateProfile(newProfile, false); err != nil {
			return nil, err
		}
	}
	merged, sum := importexport.Merge(a.GetProfile(), r.Profile, opts)
	res := a.SaveProfile(merged)
	if res.OK {
		a.log.Infof("Imported %s: %d proxies, %d chains, %d rules", importexport.FormatByID(r.Format).Name, sum.ProxiesAdded, sum.ChainsAdded, sum.RulesAdded)
	}
	return &ApplyImportResult{Summary: sum, Save: res}, nil
}

// ExportResult carries an exported file.
type ExportResult struct {
	FileName string   `json:"fileName"`
	Content  string   `json:"content"`
	Warnings []string `json:"warnings"`
	SavedTo  string   `json:"savedTo,omitempty"`
}

// Export renders the active profile in format. When a native save dialog
// is available the file is written there; otherwise the content is
// returned for a browser download.
func (a *API) Export(format string, useDialog bool) (*ExportResult, error) {
	b, name, warn, err := importexport.Export(a.GetProfile(), format)
	if err != nil {
		return nil, err
	}
	res := &ExportResult{FileName: name, Content: string(b), Warnings: warn}
	if useDialog && a.SaveDialog != nil {
		path, err := a.SaveDialog(name)
		if err != nil {
			return nil, err
		}
		if path == "" {
			return nil, errors.New("cancelled")
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, err
		}
		res.SavedTo = path
		res.Content = ""
		a.log.Infof("Exported profile to %s", path)
	}
	return res, nil
}

// HasSaveDialog reports whether Export can show a native dialog.
func (a *API) HasSaveDialog() bool { return a.SaveDialog != nil }

// ---------------------------------------------------------------- helpers

func splitHostPortLoose(s string) (string, int, error) {
	i := strings.LastIndex(s, ":")
	if i <= 0 || strings.Count(s, ":") > 1 && !strings.HasPrefix(s, "[") {
		return "", 0, errors.New("no port")
	}
	var port int
	if _, err := fmt.Sscan(s[i+1:], &port); err != nil {
		return "", 0, err
	}
	return strings.Trim(s[:i], "[]"), port, nil
}
