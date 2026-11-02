// Package config holds the SentinelProxy profile model: proxies, chains,
// rules and settings, plus validation and persistence helpers.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
)

// SchemaVersion is bumped whenever the on-disk profile format changes in a way
// that needs migration.
const SchemaVersion = 1

// ProxyType is a supported upstream proxy protocol.
type ProxyType string

const (
	SOCKS5  ProxyType = "socks5"
	SOCKS4  ProxyType = "socks4"
	SOCKS4A ProxyType = "socks4a"
	HTTP    ProxyType = "http"  // plain HTTP proxy using CONNECT
	HTTPS   ProxyType = "https" // HTTP CONNECT over a TLS connection to the proxy
)

// ProxyTypes lists every type in display order.
var ProxyTypes = []ProxyType{SOCKS5, HTTP, HTTPS, SOCKS4A, SOCKS4}

// Valid reports whether t is a known proxy type.
func (t ProxyType) Valid() bool {
	for _, k := range ProxyTypes {
		if k == t {
			return true
		}
	}
	return false
}

// SupportsUDP reports whether the protocol can carry UDP datagrams.
func (t ProxyType) SupportsUDP() bool { return t == SOCKS5 }

// SupportsAuth reports whether the protocol carries username/password.
func (t ProxyType) SupportsAuth() bool { return t != SOCKS4 && t != SOCKS4A }

// DefaultPort returns the conventional port for the protocol.
func (t ProxyType) DefaultPort() int {
	switch t {
	case HTTP:
		return 8080
	case HTTPS:
		return 443
	default:
		return 1080
	}
}

// Proxy is one upstream proxy server.
type Proxy struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Type     ProxyType `json:"type"`
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	Username string    `json:"username,omitempty"`
	Password string    `json:"password,omitempty"`
	// TLSServerName overrides the SNI/verification name for HTTPS proxies.
	TLSServerName string `json:"tlsServerName,omitempty"`
	// TLSInsecure skips certificate verification for HTTPS proxies.
	TLSInsecure bool `json:"tlsInsecure,omitempty"`
	// LocalDNS forces SentinelProxy to resolve hostnames itself and hand the
	// proxy an IP address. By default hostnames are sent to the proxy
	// (remote resolution) whenever the protocol allows it.
	LocalDNS bool     `json:"localDns,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

// Address returns host:port.
func (p *Proxy) Address() string { return net.JoinHostPort(p.Host, fmt.Sprint(p.Port)) }

// Label is a human readable name for logs and UI.
func (p *Proxy) Label() string {
	if strings.TrimSpace(p.Name) != "" {
		return p.Name
	}
	return p.Address()
}

// ChainMode controls how a chain uses its members.
type ChainMode string

const (
	// ModeChain connects through every member in order (A -> B -> C -> target).
	ModeChain ChainMode = "chain"
	// ModeFailover uses the first healthy member and falls over to the next on error.
	ModeFailover ChainMode = "failover"
	// ModeRoundRobin rotates between healthy members per connection.
	ModeRoundRobin ChainMode = "roundrobin"
	// ModeFastest uses the healthy member with the lowest measured latency.
	ModeFastest ChainMode = "fastest"
	// ModeRandom picks a random healthy member per connection.
	ModeRandom ChainMode = "random"
)

// ChainModes lists every mode in display order.
var ChainModes = []ChainMode{ModeChain, ModeFailover, ModeFastest, ModeRoundRobin, ModeRandom}

// Valid reports whether m is a known mode.
func (m ChainMode) Valid() bool {
	for _, k := range ChainModes {
		if k == m {
			return true
		}
	}
	return false
}

// Chain is a proxy chain or a proxy group. Members reference proxy IDs or,
// for group modes, other chain IDs (a failover group of two chains is legal).
type Chain struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Mode    ChainMode `json:"mode"`
	Members []string  `json:"members"`
	Notes   string    `json:"notes,omitempty"`
}

// ActionType is what a rule does with a matching connection.
type ActionType string

const (
	ActionDirect ActionType = "direct"
	ActionProxy  ActionType = "proxy" // Target is a proxy ID or chain ID
	ActionBlock  ActionType = "block"
)

// Action is the outcome of a rule.
type Action struct {
	Type   ActionType `json:"type"`
	Target string     `json:"target,omitempty"`
}

// Protocol restricts a rule to TCP or UDP.
type Protocol string

const (
	ProtoAny Protocol = ""
	ProtoTCP Protocol = "tcp"
	ProtoUDP Protocol = "udp"
)

// Rule routes connections that match all of its non-empty conditions.
// Each list is OR-ed internally; the lists are AND-ed together.
type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Apps are executable names or paths with * and ? wildcards
	// ("chrome.exe", "steam*", "C:\Games\*"). Empty matches any app.
	Apps []string `json:"apps,omitempty"`
	// Hosts are hostnames, wildcard hostnames, IPs, CIDRs or IP ranges.
	// Empty matches any destination.
	Hosts []string `json:"hosts,omitempty"`
	// Ports are single ports or ranges ("443", "8000-9000"). Empty matches any port.
	Ports    []string `json:"ports,omitempty"`
	Protocol Protocol `json:"protocol,omitempty"`
	Action   Action   `json:"action"`
	Notes    string   `json:"notes,omitempty"`
}

// DNSMode controls how hostnames are resolved for proxied traffic.
type DNSMode string

const (
	// DNSAuto keeps the system resolver and learns hostnames from DNS
	// responses and TLS/HTTP sniffing; proxied connections send the hostname
	// to the proxy whenever it is known.
	DNSAuto DNSMode = "auto"
	// DNSLocal never sends hostnames to proxies.
	DNSLocal DNSMode = "local"
	// DNSFakeIP answers DNS queries with synthetic addresses so every proxied
	// hostname is resolved by the proxy (no DNS leaks). Windows only.
	DNSFakeIP DNSMode = "fakeip"
)

// DNSSettings configures name resolution.
type DNSSettings struct {
	Mode DNSMode `json:"mode"`
	// FakeIPRange is the pool used by fake-IP mode.
	FakeIPRange string `json:"fakeIpRange"`
	// Upstreams are used by SentinelProxy's own resolver (ip or ip:port).
	Upstreams []string `json:"upstreams"`
	// Exclusions are always resolved locally (never faked).
	Exclusions []string `json:"exclusions"`
}

// UDPPolicy decides what happens to UDP when the selected route cannot carry it.
type UDPPolicy string

const (
	UDPBlock  UDPPolicy = "block"  // safest: apps fall back to TCP (e.g. QUIC -> HTTPS)
	UDPDirect UDPPolicy = "direct" // send it without the proxy
)

// Settings are profile-wide options.
type Settings struct {
	// Intercept enables system-wide transparent interception (WinDivert on
	// Windows, nftables on Linux).
	Intercept bool `json:"intercept"`
	// InterceptUDP also captures UDP flows.
	InterceptUDP bool `json:"interceptUdp"`
	// InterceptIPv6 also captures IPv6 flows.
	InterceptIPv6 bool `json:"interceptIpv6"`
	// UDPFallback applies when a route cannot carry UDP.
	UDPFallback UDPPolicy `json:"udpFallback"`
	// Sniff detects destination hostnames from TLS SNI and HTTP Host headers.
	Sniff bool `json:"sniff"`
	// RelayDirect sends direct connections through SentinelProxy's relay too
	// (full byte counts and hostname detection). When off, connections that
	// are certainly direct bypass the relay at packet level.
	RelayDirect bool `json:"relayDirect"`
	// LocalProxy runs a SOCKS5/SOCKS4/HTTP proxy server for apps configured
	// to use a proxy explicitly.
	LocalProxy       bool   `json:"localProxy"`
	LocalProxyListen string `json:"localProxyListen"`
	// LocalProxyUser/Password require authentication on the local proxy
	// (recommended when it listens on a LAN address).
	LocalProxyUser     string `json:"localProxyUser,omitempty"`
	LocalProxyPassword string `json:"localProxyPassword,omitempty"`
	// SystemProxy points the OS proxy settings at the local proxy server.
	SystemProxy bool `json:"systemProxy"`
	// ConnectTimeoutSec bounds the time to establish an upstream connection.
	ConnectTimeoutSec int `json:"connectTimeoutSec"`
	// HealthCheck enables periodic background checks of proxies used by groups.
	HealthCheck            bool        `json:"healthCheck"`
	HealthCheckIntervalSec int         `json:"healthCheckIntervalSec"`
	CheckURL               string      `json:"checkUrl"`
	DNS                    DNSSettings `json:"dns"`
	// LogConnections records one log line per connection.
	LogConnections bool   `json:"logConnections"`
	LogLevel       string `json:"logLevel"`
}

// Profile is a complete, self-contained routing configuration.
type Profile struct {
	Version       int      `json:"version"`
	Name          string   `json:"name"`
	Proxies       []Proxy  `json:"proxies"`
	Chains        []Chain  `json:"chains"`
	Rules         []Rule   `json:"rules"`
	DefaultAction Action   `json:"defaultAction"`
	Settings      Settings `json:"settings"`
}

// DefaultSettings returns the recommended settings.
func DefaultSettings() Settings {
	return Settings{
		Intercept:              true,
		InterceptUDP:           true,
		InterceptIPv6:          true,
		UDPFallback:            UDPBlock,
		Sniff:                  true,
		LocalProxy:             true,
		LocalProxyListen:       "127.0.0.1:2080",
		ConnectTimeoutSec:      10,
		HealthCheck:            true,
		HealthCheckIntervalSec: 120,
		CheckURL:               "http://www.gstatic.com/generate_204",
		DNS: DNSSettings{
			Mode:        DNSAuto,
			FakeIPRange: "198.18.0.0/15",
			Upstreams:   []string{"1.1.1.1", "8.8.8.8"},
			Exclusions:  []string{"localhost", "*.local", "*.lan", "*.home.arpa", "*.localdomain"},
		},
		LogConnections: true,
		LogLevel:       "info",
	}
}

// NewProfile returns a starter profile with the standard localhost rule.
func NewProfile(name string) *Profile {
	return &Profile{
		Version: SchemaVersion,
		Name:    name,
		Proxies: []Proxy{},
		Chains:  []Chain{},
		Rules: []Rule{{
			ID:      NewID(),
			Name:    "Localhost & LAN",
			Enabled: true,
			Hosts:   []string{"localhost", "127.0.0.0/8", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fe80::/10", "fc00::/7", "*.local"},
			Action:  Action{Type: ActionDirect},
		}},
		DefaultAction: Action{Type: ActionDirect},
		Settings:      DefaultSettings(),
	}
}

// NewID returns a short random identifier.
func NewID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// FindProxy returns the proxy with id or nil.
func (p *Profile) FindProxy(id string) *Proxy {
	for i := range p.Proxies {
		if p.Proxies[i].ID == id {
			return &p.Proxies[i]
		}
	}
	return nil
}

// FindChain returns the chain with id or nil.
func (p *Profile) FindChain(id string) *Chain {
	for i := range p.Chains {
		if p.Chains[i].ID == id {
			return &p.Chains[i]
		}
	}
	return nil
}

// TargetLabel names a proxy or chain target for display.
func (p *Profile) TargetLabel(id string) string {
	if px := p.FindProxy(id); px != nil {
		return px.Label()
	}
	if c := p.FindChain(id); c != nil {
		return c.Name
	}
	return "missing:" + id
}

// ActionLabel renders an action for display ("Direct", "Block", "Proxy: Name").
func (p *Profile) ActionLabel(a Action) string {
	switch a.Type {
	case ActionDirect:
		return "Direct"
	case ActionBlock:
		return "Block"
	case ActionProxy:
		return p.TargetLabel(a.Target)
	}
	return string(a.Type)
}

// Normalize fills defaults and repairs harmless inconsistencies (missing IDs,
// zero values) so older or imported profiles load cleanly.
func (p *Profile) Normalize() {
	if p.Version == 0 {
		p.Version = SchemaVersion
	}
	if p.Name == "" {
		p.Name = "Default"
	}
	d := DefaultSettings()
	s := &p.Settings
	if s.UDPFallback == "" {
		s.UDPFallback = d.UDPFallback
	}
	if s.LocalProxyListen == "" {
		s.LocalProxyListen = d.LocalProxyListen
	}
	if s.ConnectTimeoutSec <= 0 {
		s.ConnectTimeoutSec = d.ConnectTimeoutSec
	}
	if s.HealthCheckIntervalSec <= 0 {
		s.HealthCheckIntervalSec = d.HealthCheckIntervalSec
	}
	if s.CheckURL == "" {
		s.CheckURL = d.CheckURL
	}
	if s.DNS.Mode == "" {
		s.DNS.Mode = d.DNS.Mode
	}
	if s.DNS.FakeIPRange == "" {
		s.DNS.FakeIPRange = d.DNS.FakeIPRange
	}
	if len(s.DNS.Upstreams) == 0 {
		s.DNS.Upstreams = d.DNS.Upstreams
	}
	if s.LogLevel == "" {
		s.LogLevel = d.LogLevel
	}
	if p.Proxies == nil {
		p.Proxies = []Proxy{}
	}
	if p.Chains == nil {
		p.Chains = []Chain{}
	}
	if p.Rules == nil {
		p.Rules = []Rule{}
	}
	seen := map[string]bool{}
	fix := func(id *string) {
		if *id == "" || seen[*id] {
			*id = NewID()
		}
		seen[*id] = true
	}
	for i := range p.Proxies {
		fix(&p.Proxies[i].ID)
		p.Proxies[i].Type = ProxyType(strings.ToLower(string(p.Proxies[i].Type)))
		if p.Proxies[i].Port == 0 {
			p.Proxies[i].Port = p.Proxies[i].Type.DefaultPort()
		}
	}
	for i := range p.Chains {
		fix(&p.Chains[i].ID)
		if p.Chains[i].Mode == "" {
			p.Chains[i].Mode = ModeChain
		}
		if p.Chains[i].Members == nil {
			p.Chains[i].Members = []string{}
		}
	}
	for i := range p.Rules {
		fix(&p.Rules[i].ID)
		if p.Rules[i].Action.Type == "" {
			p.Rules[i].Action.Type = ActionDirect
		}
	}
	if p.DefaultAction.Type == "" {
		p.DefaultAction.Type = ActionDirect
	}
}

// Problem is one validation finding.
type Problem struct {
	// Kind is "proxy", "chain", "rule", "default" or "settings".
	Kind    string `json:"kind"`
	ID      string `json:"id,omitempty"`
	Message string `json:"message"`
}

func (pr Problem) Error() string { return pr.Kind + " " + pr.ID + ": " + pr.Message }

// Validate checks referential integrity and field values. It returns every
// problem found rather than stopping at the first.
func (p *Profile) Validate() []Problem {
	var out []Problem
	add := func(kind, id, format string, a ...any) {
		out = append(out, Problem{Kind: kind, ID: id, Message: fmt.Sprintf(format, a...)})
	}
	ids := map[string]string{}
	for _, px := range p.Proxies {
		if !px.Type.Valid() {
			add("proxy", px.ID, "unknown type %q", px.Type)
		}
		if strings.TrimSpace(px.Host) == "" {
			add("proxy", px.ID, "host is required")
		}
		if px.Port < 1 || px.Port > 65535 {
			add("proxy", px.ID, "port %d is out of range", px.Port)
		}
		if prev, dup := ids[px.ID]; dup {
			add("proxy", px.ID, "duplicate id (also used by %s)", prev)
		}
		ids[px.ID] = "proxy"
	}
	for _, c := range p.Chains {
		if prev, dup := ids[c.ID]; dup {
			add("chain", c.ID, "duplicate id (also used by %s)", prev)
		}
		ids[c.ID] = "chain"
	}
	for _, c := range p.Chains {
		if !c.Mode.Valid() {
			add("chain", c.ID, "unknown mode %q", c.Mode)
		}
		if len(c.Members) == 0 {
			add("chain", c.ID, "%q has no members", c.Name)
		}
		for _, m := range c.Members {
			kind, ok := ids[m]
			if !ok {
				add("chain", c.ID, "%q references a missing member %q", c.Name, m)
				continue
			}
			if c.Mode == ModeChain && kind == "chain" {
				add("chain", c.ID, "%q: a strict chain can only contain proxies", c.Name)
			}
		}
	}
	if err := p.checkCycles(); err != nil {
		add("chain", "", "%v", err)
	}
	checkAction := func(kind, id string, a Action) {
		switch a.Type {
		case ActionDirect, ActionBlock:
		case ActionProxy:
			if _, ok := ids[a.Target]; !ok {
				add(kind, id, "routes to a missing proxy or chain %q", a.Target)
			}
		default:
			add(kind, id, "unknown action %q", a.Type)
		}
	}
	for _, r := range p.Rules {
		checkAction("rule", r.ID, r.Action)
		if r.Protocol != ProtoAny && r.Protocol != ProtoTCP && r.Protocol != ProtoUDP {
			add("rule", r.ID, "unknown protocol %q", r.Protocol)
		}
	}
	checkAction("default", "", p.DefaultAction)
	switch p.Settings.DNS.Mode {
	case DNSAuto, DNSLocal, DNSFakeIP:
	default:
		add("settings", "", "unknown DNS mode %q", p.Settings.DNS.Mode)
	}
	if p.Settings.LocalProxy {
		if _, _, err := net.SplitHostPort(p.Settings.LocalProxyListen); err != nil {
			add("settings", "", "local proxy address %q is invalid", p.Settings.LocalProxyListen)
		}
	}
	return out
}

// ErrCycle reports a chain that (indirectly) contains itself.
var ErrCycle = errors.New("chain cycle")

func (p *Profile) checkCycles() error {
	const (
		white = iota
		grey
		black
	)
	color := map[string]int{}
	var visit func(id string) error
	visit = func(id string) error {
		c := p.FindChain(id)
		if c == nil {
			return nil
		}
		switch color[id] {
		case grey:
			return fmt.Errorf("%w: %q contains itself", ErrCycle, c.Name)
		case black:
			return nil
		}
		color[id] = grey
		for _, m := range c.Members {
			if err := visit(m); err != nil {
				return err
			}
		}
		color[id] = black
		return nil
	}
	for _, c := range p.Chains {
		if err := visit(c.ID); err != nil {
			return err
		}
	}
	return nil
}

// Clone returns a deep copy.
func (p *Profile) Clone() *Profile {
	cp := *p
	cp.Proxies = append([]Proxy(nil), p.Proxies...)
	for i := range cp.Proxies {
		cp.Proxies[i].Tags = append([]string(nil), cp.Proxies[i].Tags...)
	}
	cp.Chains = append([]Chain(nil), p.Chains...)
	for i := range cp.Chains {
		cp.Chains[i].Members = append([]string(nil), cp.Chains[i].Members...)
	}
	cp.Rules = append([]Rule(nil), p.Rules...)
	for i := range cp.Rules {
		r := &cp.Rules[i]
		r.Apps = append([]string(nil), r.Apps...)
		r.Hosts = append([]string(nil), r.Hosts...)
		r.Ports = append([]string(nil), r.Ports...)
	}
	cp.Settings.DNS.Upstreams = append([]string(nil), p.Settings.DNS.Upstreams...)
	cp.Settings.DNS.Exclusions = append([]string(nil), p.Settings.DNS.Exclusions...)
	return &cp
}

// SplitList splits a Proxifier-style list ("a; b, c\nd") into trimmed items.
func SplitList(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == '\n' || r == '\r' })
	out := make([]string, 0, len(f))
	for _, x := range f {
		x = strings.TrimSpace(x)
		x = strings.Trim(x, `"`)
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}
