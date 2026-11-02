// Package engine routes connections: it applies rules, dials through
// proxies, relays bytes, tracks every connection and owns DNS state. Traffic
// reaches it from interceptors (transparent capture) and the local proxy
// listener.
package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/dnsx"
	"github.com/DestroyersTaken/SentinelProxy/internal/logx"
	"github.com/DestroyersTaken/SentinelProxy/internal/match"
	"github.com/DestroyersTaken/SentinelProxy/internal/proxy"
	"github.com/DestroyersTaken/SentinelProxy/internal/rules"
	"github.com/DestroyersTaken/SentinelProxy/internal/sniff"
	"golang.org/x/net/dns/dnsmessage"
)

// Flow describes a new connection handed to the engine.
type Flow struct {
	Network string // "tcp" or "udp"
	Inbound string // "intercept" or "local-proxy"
	Src     netip.AddrPort
	// Dst is the destination IP endpoint. For local-proxy requests by
	// hostname it may be invalid, with Domain and Port set instead.
	Dst    netip.AddrPort
	Domain string
	Port   uint16
	App    match.AppInfo
}

func (f *Flow) port() uint16 {
	if f.Dst.IsValid() {
		return f.Dst.Port()
	}
	return f.Port
}

type state struct {
	profile  *config.Profile
	rules    *rules.Engine
	router   *proxy.Router
	fake     *dnsx.FakeIP
	resolver proxy.Resolver
	own      *dnsx.Resolver
	exclude  *match.HostMatcher
}

// Engine is the routing core. It is safe for concurrent use.
type Engine struct {
	Log      *logx.Log
	Tracker  *Tracker
	Health   *proxy.Health
	DNSCache *dnsx.Cache

	st      atomic.Pointer[state]
	udp     udpTable
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	checkMu sync.Mutex
}

// New creates an engine with an empty profile.
func New(log *logx.Log) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{Log: log, Tracker: NewTracker(), Health: proxy.NewHealth(), DNSCache: dnsx.NewCache(50000), ctx: ctx, cancel: cancel}
	e.udp.init()
	if err := e.Apply(config.NewProfile("Default")); err != nil {
		panic(err)
	}
	e.wg.Add(1)
	go e.background()
	return e
}

// Close stops background work and closes UDP sessions.
func (e *Engine) Close() {
	e.cancel()
	e.udp.closeAll()
	e.wg.Wait()
}

// Profile returns the active profile (do not modify).
func (e *Engine) Profile() *config.Profile { return e.st.Load().profile }

// Rules returns the active compiled rules.
func (e *Engine) Rules() *rules.Engine { return e.st.Load().rules }

// Router returns the active router.
func (e *Engine) Router() *proxy.Router { return e.st.Load().router }

// FakeIP returns the fake-IP pool (nil unless fake-IP mode is on).
func (e *Engine) FakeIP() *dnsx.FakeIP { return e.st.Load().fake }

// Apply compiles and activates a profile. Rules with bad patterns are
// skipped and logged; structural errors reject the profile.
func (e *Engine) Apply(p *config.Profile) error {
	p = p.Clone()
	p.Normalize()
	if probs := p.Validate(); len(probs) > 0 {
		msgs := make([]string, len(probs))
		for i, pr := range probs {
			msgs[i] = pr.Error()
		}
		return fmt.Errorf("profile has problems: %s", strings.Join(msgs, "; "))
	}
	re, errs := rules.Compile(p)
	for _, ce := range errs {
		e.Log.Warnf("Rule %q skipped: %v", ce.RuleName, ce.Err)
	}
	servers, err := dnsx.ParseServers(p.Settings.DNS.Upstreams)
	if err != nil {
		return err
	}
	direct := &proxy.Direct{}
	own := &dnsx.Resolver{Servers: servers, Dial: direct.DialContext, Observe: e.observe}
	ns := &state{profile: p, rules: re, own: own}
	if p.Settings.DNS.Mode == config.DNSFakeIP {
		if old := e.st.Load(); old != nil && old.fake != nil && old.fake.Prefix().String() == p.Settings.DNS.FakeIPRange {
			ns.fake = old.fake // keep mappings so live apps keep working
		} else if ns.fake, err = dnsx.NewFakeIP(p.Settings.DNS.FakeIPRange); err != nil {
			return err
		}
		// The system resolver would be answered by our own fake DNS.
		ns.resolver = own
	} else {
		ns.resolver = systemResolver{}
	}
	excl := append([]string{}, p.Settings.DNS.Exclusions...)
	for _, px := range p.Proxies {
		excl = append(excl, px.Host)
	}
	if ns.exclude, err = match.NewHostMatcher(excl); err != nil {
		return fmt.Errorf("DNS exclusions: %w", err)
	}
	router, err := proxy.NewRouter(p, e.Health, proxy.Options{LocalDNS: p.Settings.DNS.Mode == config.DNSLocal, Resolver: ns.resolver})
	if err != nil {
		return err
	}
	ns.router = router
	keep := map[string]bool{}
	for _, px := range p.Proxies {
		keep[px.ID] = true
	}
	for _, c := range p.Chains {
		keep[c.ID] = true
	}
	e.Health.Forget(keep)
	e.Log.SetLevel(p.Settings.LogLevel)
	e.st.Store(ns)
	go func() {
		ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
		defer cancel()
		router.ResolveEndpoints(ctx, ns.resolver)
	}()
	return nil
}

type systemResolver struct{}

func (systemResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

// observe feeds DNS answers into the reverse cache.
func (e *Engine) observe(recs []dnsx.Record) {
	for _, r := range recs {
		e.DNSCache.Put(r.IP, r.Domain, r.TTL)
	}
}

// ObserveDNSResponse learns hostnames from a DNS response seen on the wire.
func (e *Engine) ObserveDNSResponse(msg []byte) {
	if recs, err := dnsx.ParseResponse(msg); err == nil {
		e.observe(recs)
	}
}

// AnswerDNS returns a synthetic answer for query in fake-IP mode. ok is
// false when the query should go to the real DNS server unchanged.
func (e *Engine) AnswerDNS(query []byte) (resp []byte, ok bool) {
	st := e.st.Load()
	if st.fake == nil {
		return nil, false
	}
	name, qt, _, err := dnsx.Question(query)
	if err != nil || name == "" || !strings.Contains(name, ".") {
		return nil, false
	}
	if st.exclude.Match(match.Target{Domain: name}) == match.Yes || strings.HasSuffix(name, ".arpa") {
		return nil, false
	}
	switch qt {
	case dnsmessage.TypeA:
		ip := st.fake.Allocate(name)
		resp, err = dnsx.FakeAnswer(query, ip, 1)
	case dnsmessage.TypeAAAA, dnsmessage.Type(65), dnsmessage.Type(64): // AAAA, HTTPS, SVCB: answer empty
		resp, err = dnsx.FakeAnswer(query, netip.Addr{}, 1)
	default:
		return nil, false
	}
	return resp, err == nil
}

// IsFakeIP reports whether ip belongs to the fake-IP pool.
func (e *Engine) IsFakeIP(ip netip.Addr) bool {
	f := e.st.Load().fake
	return f != nil && f.Contains(ip)
}

// domainFor returns the best known hostname for an IP.
func (e *Engine) domainFor(st *state, ip netip.Addr) (string, string) {
	if st.fake != nil {
		if d, ok := st.fake.Lookup(ip); ok {
			return d, "fakeip"
		}
	}
	if d, ok := e.DNSCache.Lookup(ip); ok {
		return d, "dns"
	}
	return "", ""
}

func meta(f *Flow, domain string) rules.Meta {
	t := match.Target{Domain: domain, Port: f.port()}
	if f.Dst.IsValid() {
		t.IP = f.Dst.Addr().Unmap()
	}
	return rules.Meta{App: f.App, Target: t, Network: config.Protocol(f.Network)}
}

// Verdict is the packet-level decision an interceptor needs at SYN time.
type Verdict struct {
	// Redirect sends the flow through the engine. When false the packets
	// pass untouched and Bypass (if set) receives byte counts.
	Redirect bool
	Bypass   *Conn
}

// Classify decides, from the IP alone, whether a new flow must go through
// the engine. Flows that are certainly direct bypass the relay unless
// RelayDirect is on; they are still listed as connections.
func (e *Engine) Classify(f Flow) Verdict {
	st := e.st.Load()
	if st.fake != nil && f.Dst.IsValid() && st.fake.Contains(f.Dst.Addr()) {
		return Verdict{Redirect: true}
	}
	if st.profile.Settings.RelayDirect {
		return Verdict{Redirect: true}
	}
	loop := f.Dst.IsValid() && st.router.IsProxyEndpoint(f.Dst)
	domain, src := e.domainFor(st, f.Dst.Addr())
	d, certain := st.rules.DecideEarly(meta(&f, ""))
	if !loop && (!certain || d.Action.Type != config.ActionDirect) {
		return Verdict{Redirect: true}
	}
	if loop {
		d = rules.Decision{Action: config.Action{Type: config.ActionDirect}, RuleName: "Proxy server (loop prevention)", Index: -2}
	}
	st.rules.Hit(d)
	c := e.Tracker.Open(f.Network, "bypass", f.Src, f.Dst, f.port(), f.App.Name, f.App.PID, f.App.Path)
	if domain != "" {
		c.SetHost(domain, src)
	}
	e.Tracker.Route(c, "direct", d.RuleName, d.RuleID, "")
	c.SetState("active")
	return Verdict{Bypass: c}
}

var sniffPorts = map[uint16]bool{80: true, 443: true, 8080: true, 8443: true, 8000: true, 8880: true}

// TCPHook lets the inbound adapt the client before relaying (the local
// proxy sends its SOCKS/HTTP reply here). err is the upstream dial result.
type TCPHook func(err error) error

// HandleTCP routes one TCP connection and relays it until either side
// closes. It blocks; call it in its own goroutine.
func (e *Engine) HandleTCP(client net.Conn, f Flow, onConnect TCPHook) {
	st := e.st.Load()
	s := &st.profile.Settings
	cn := e.Tracker.Open("tcp", f.Inbound, f.Src, f.Dst, f.port(), f.App.Name, f.App.PID, f.App.Path)
	defer e.Tracker.Close(cn)
	defer client.Close()
	cn.SetCloser(func() { client.Close() })

	domain, hostSrc := f.Domain, "request"
	if domain != "" {
		if ip, err := netip.ParseAddr(domain); err == nil {
			f.Dst = netip.AddrPortFrom(ip.Unmap(), f.port())
			domain, hostSrc = "", ""
		}
	}
	var guess, guessSrc string
	if domain == "" && f.Dst.IsValid() {
		guess, guessSrc = e.domainFor(st, f.Dst.Addr())
		if guessSrc == "fakeip" {
			domain, hostSrc, guess = guess, guessSrc, ""
		}
	}
	if domain != "" {
		cn.SetHost(domain, hostSrc)
	} else if guess != "" {
		cn.SetHost(guess, guessSrc)
	}

	var d rules.Decision
	loop := f.Dst.IsValid() && st.router.IsProxyEndpoint(f.Dst) || domain != "" && st.router.IsProxyHost(domain, f.port())
	switch {
	case loop:
		d = rules.Decision{Action: config.Action{Type: config.ActionDirect}, RuleName: "Proxy server (loop prevention)", Index: -2}
	case domain != "":
		d = st.rules.Decide(meta(&f, domain))
	default:
		var certain bool
		d, certain = st.rules.DecideEarly(meta(&f, ""))
		wantSniff := s.Sniff && f.Inbound == "intercept" && (sniffPorts[f.port()] || !certain)
		if wantSniff {
			wait := 400 * time.Millisecond
			if !sniffPorts[f.port()] {
				wait = 150 * time.Millisecond
			}
			var res sniff.Result
			res, client = sniff.Peek(client, wait)
			if res.Host != "" {
				domain, hostSrc = res.Host, res.Protocol
				cn.SetHost(domain, hostSrc)
				if f.Dst.IsValid() {
					e.DNSCache.Put(f.Dst.Addr(), domain, 10*time.Minute)
				}
			}
		}
		if !certain {
			h := domain
			if h == "" {
				h = guess
			}
			d = st.rules.Decide(meta(&f, h))
		}
	}
	st.rules.Hit(d)

	routeLabel := ""
	if d.Action.Type == config.ActionProxy {
		routeLabel = st.profile.TargetLabel(d.Action.Target)
	}
	e.Tracker.Route(cn, string(d.Action.Type), d.RuleName, d.RuleID, routeLabel)
	who := f.App.Name
	if who == "" {
		who = "unknown app"
	}
	shown := domain
	if shown == "" {
		shown = guess
	}
	if shown == "" && f.Dst.IsValid() {
		shown = f.Dst.Addr().String()
	}
	dest := net.JoinHostPort(shown, fmt.Sprint(f.port()))

	if d.Action.Type == config.ActionBlock {
		cn.SetState("blocked")
		if s.LogConnections {
			e.Log.Add(slog.LevelInfo, "conn", fmt.Sprintf("%s → %s blocked by rule %q", who, dest, d.RuleName))
		}
		if onConnect != nil {
			_ = onConnect(errBlocked)
		}
		return
	}

	ctx, cancel := context.WithTimeout(e.ctx, time.Duration(s.ConnectTimeoutSec)*time.Second)
	upstream, hops, err := e.dial(ctx, st, d, &f, domain)
	cancel()
	if err != nil {
		cn.Fail(err)
		e.Log.Warnf("%s → %s via %s failed: %v", who, dest, actionText(d, routeLabel), err)
		if onConnect != nil {
			_ = onConnect(err)
		}
		return
	}
	defer upstream.Close()
	e.Tracker.SetHops(cn, hops)
	if d.Action.Type != config.ActionProxy && !f.Dst.IsValid() {
		if ta, ok := upstream.RemoteAddr().(*net.TCPAddr); ok {
			cn.SetDst(ta.AddrPort())
		}
	}
	if onConnect != nil {
		if err := onConnect(nil); err != nil {
			return
		}
	}
	cn.SetState("active")
	cn.SetCloser(func() { client.Close(); upstream.Close() })
	if s.LogConnections {
		e.Log.Add(slog.LevelInfo, "conn", fmt.Sprintf("%s → %s via %s (rule %q)", who, dest, actionText(d, strings.Join(hops, " → ")), d.RuleName))
	}
	relay(client, upstream, cn)
}

var errBlocked = errors.New("blocked by rule")

// IsBlocked reports whether err means a rule blocked the connection.
func IsBlocked(err error) bool { return errors.Is(err, errBlocked) }

func actionText(d rules.Decision, route string) string {
	switch d.Action.Type {
	case config.ActionProxy:
		if route == "" {
			return "proxy"
		}
		return route
	case config.ActionBlock:
		return "block"
	}
	return "direct"
}

// dial opens the upstream side according to the decision.
func (e *Engine) dial(ctx context.Context, st *state, d rules.Decision, f *Flow, domain string) (net.Conn, []string, error) {
	port := f.port()
	var target proxy.Addr
	isFake := f.Dst.IsValid() && st.fake != nil && st.fake.Contains(f.Dst.Addr())
	switch {
	case domain != "" && (isFake || !f.Dst.IsValid() || d.Action.Type == config.ActionProxy && st.profile.Settings.DNS.Mode != config.DNSLocal):
		// Hostname known: proxies resolve it remotely (no DNS leak, correct
		// CDN for the exit location); direct fake-IP flows resolve locally.
		target = proxy.Addr{Host: domain, Port: port}
	case f.Dst.IsValid():
		target = proxy.AddrFromAddrPort(f.Dst)
	default:
		return nil, nil, fmt.Errorf("no destination")
	}
	if d.Action.Type == config.ActionProxy {
		rt := st.router.Route(d.Action.Target)
		if rt == nil {
			return nil, nil, fmt.Errorf("route %q is missing", d.Action.Target)
		}
		return rt.Dial(ctx, target)
	}
	c, err := (&proxy.Direct{Resolver: st.resolver}).DialContext(ctx, "tcp", target.String())
	return c, nil, err
}

type closeWriter interface{ CloseWrite() error }

// relay copies both directions, propagating half-closes.
func relay(client, upstream net.Conn, cn *Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	var once sync.Once
	closeBoth := func() { once.Do(func() { client.Close(); upstream.Close() }) }
	pump := func(dst, src net.Conn, count func(int)) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				count(n)
				if _, werr := dst.Write(buf[:n]); werr != nil {
					closeBoth()
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					if cw, ok := dst.(closeWriter); ok {
						if cw.CloseWrite() == nil {
							return
						}
					}
				}
				closeBoth()
				return
			}
		}
	}
	go pump(upstream, client, cn.AddUp)
	go pump(client, upstream, cn.AddDown)
	wg.Wait()
	closeBoth()
}

// background ticks the tracker and runs health checks.
func (e *Engine) background() {
	defer e.wg.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastCheck time.Time
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-tick.C:
			e.Tracker.Tick()
			e.udp.expire()
			s := e.Profile().Settings
			if s.HealthCheck && time.Since(lastCheck) >= time.Duration(s.HealthCheckIntervalSec)*time.Second {
				lastCheck = time.Now()
				go e.CheckGroups()
			}
		}
	}
}

// CheckGroups probes every member of every group so failover and
// fastest-mode selection have fresh data.
func (e *Engine) CheckGroups() {
	if !e.checkMu.TryLock() {
		return
	}
	defer e.checkMu.Unlock()
	st := e.st.Load()
	seen := map[string]bool{}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for _, c := range st.profile.Chains {
		rt := st.router.Route(c.ID)
		for _, m := range proxy.Members(rt) {
			if seen[m.ID()] {
				continue
			}
			seen[m.ID()] = true
			wg.Add(1)
			go func(m proxy.Route) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				e.CheckRoute(m, false)
			}(m)
		}
	}
	wg.Wait()
}

// CheckRoute runs the proxy checker against one route and records health.
func (e *Engine) CheckRoute(rt proxy.Route, full bool) proxy.CheckResult {
	st := e.st.Load()
	ctx, cancel := context.WithTimeout(e.ctx, 30*time.Second)
	defer cancel()
	res := proxy.Check(ctx, rt, st.router.Base, proxy.CheckOptions{URL: st.profile.Settings.CheckURL, ExitIP: full, UDP: full, Timeout: 10 * time.Second})
	if res.OK {
		e.Health.MarkOK(rt.ID(), time.Duration(max(res.LatencyMs, 1))*time.Millisecond)
	} else {
		e.Health.MarkFail(rt.ID(), errors.New(res.Error), 0)
	}
	return res
}
