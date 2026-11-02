package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
)

// TargetError means the proxy works but could not reach the destination
// (refused, unreachable, ...). Groups do not fail over on these.
type TargetError struct{ Err error }

func (e *TargetError) Error() string { return e.Err.Error() }
func (e *TargetError) Unwrap() error { return e.Err }

// Route is a way to reach destinations: a single proxy, a strict chain or a
// group of other routes.
type Route interface {
	ID() string
	Label() string
	// Dial opens a tunnel to target. path lists the proxies actually used.
	Dial(ctx context.Context, target Addr) (conn net.Conn, path []string, err error)
	// ListenPacket opens a UDP association, or returns ErrUDPUnsupported.
	ListenPacket(ctx context.Context) (PacketConn, []string, error)
	// FirstHop is the proxy contacted first, nil for groups.
	FirstHop() *config.Proxy
}

type proxyEndpoint struct {
	addr       string
	user, pass string
}

// Options tune how routes are built.
type Options struct {
	// LocalDNS resolves every hostname locally before handing it to a proxy.
	LocalDNS bool
	Resolver Resolver
}

// hop dials through one proxy, reaching the proxy server via next.
type hop struct {
	p    *config.Proxy
	next Dialer
	opts *Options
}

func (h *hop) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	t, err := ParseAddr(address)
	if err != nil {
		return nil, err
	}
	return h.dial(ctx, t)
}

func (h *hop) dial(ctx context.Context, target Addr) (net.Conn, error) {
	p := h.p
	conn, err := h.next.DialContext(ctx, "tcp", p.Address())
	if err != nil {
		return nil, fmt.Errorf("connect to proxy %s: %w", p.Label(), err)
	}
	fail := func(err error) (net.Conn, error) {
		conn.Close()
		return nil, err
	}
	if p.Type == config.HTTPS {
		sni := p.TLSServerName
		if sni == "" {
			sni = p.Host
		}
		tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: p.TLSInsecure, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			return fail(fmt.Errorf("TLS to proxy %s: %w", p.Label(), err))
		}
		conn = tc
	}
	if _, isIP := target.IP(); !isIP && (h.opts.LocalDNS || p.LocalDNS || p.Type == config.SOCKS4) {
		ip, err := resolveOne(ctx, h.opts.Resolver, target.Host)
		if err != nil {
			return fail(fmt.Errorf("resolve %s: %w", target.Host, err))
		}
		target.Host = ip.String()
	}
	switch p.Type {
	case config.SOCKS5:
		_, err = socks5Handshake(ctx, conn, cmdConnect, target, p.Username, p.Password)
	case config.SOCKS4, config.SOCKS4A:
		err = socks4Handshake(ctx, conn, target, p.Username, p.Type == config.SOCKS4A)
	case config.HTTP, config.HTTPS:
		var c net.Conn
		c, err = httpConnect(ctx, conn, target, p.Username, p.Password)
		if err == nil {
			conn = c
		}
	default:
		err = fmt.Errorf("unsupported proxy type %q", p.Type)
	}
	if err != nil {
		if strings.HasPrefix(err.Error(), "proxy: ") && !errors.Is(err, ErrAuth) && !strings.Contains(err.Error(), "general") {
			err = &TargetError{err}
		}
		return fail(fmt.Errorf("%s: %w", p.Label(), err))
	}
	return conn, nil
}

// ---------------------------------------------------------------- single proxy

type proxyRoute struct {
	p    *config.Proxy
	base Dialer
	opts *Options
}

func (r *proxyRoute) ID() string              { return r.p.ID }
func (r *proxyRoute) Label() string           { return r.p.Label() }
func (r *proxyRoute) FirstHop() *config.Proxy { return r.p }

func (r *proxyRoute) Dial(ctx context.Context, t Addr) (net.Conn, []string, error) {
	c, err := (&hop{p: r.p, next: r.base, opts: r.opts}).dial(ctx, t)
	return c, []string{r.p.Label()}, err
}

func (r *proxyRoute) ListenPacket(ctx context.Context) (PacketConn, []string, error) {
	if !r.p.Type.SupportsUDP() {
		return nil, nil, ErrUDPUnsupported
	}
	c, err := newSOCKS5PacketConn(ctx, r.base, proxyEndpoint{addr: r.p.Address(), user: r.p.Username, pass: r.p.Password})
	return c, []string{r.p.Label()}, err
}

// ---------------------------------------------------------------- strict chain

type chainRoute struct {
	c     *config.Chain
	hops  []*config.Proxy
	base  Dialer
	opts  *Options
	label string
}

func (r *chainRoute) ID() string    { return r.c.ID }
func (r *chainRoute) Label() string { return r.label }
func (r *chainRoute) FirstHop() *config.Proxy {
	if len(r.hops) == 0 {
		return nil
	}
	return r.hops[0]
}

func (r *chainRoute) path() []string {
	out := make([]string, len(r.hops))
	for i, p := range r.hops {
		out[i] = p.Label()
	}
	return out
}

func (r *chainRoute) Dial(ctx context.Context, t Addr) (net.Conn, []string, error) {
	if len(r.hops) == 0 {
		return nil, nil, fmt.Errorf("chain %q is empty", r.c.Name)
	}
	var d Dialer = r.base
	for _, p := range r.hops {
		d = &hop{p: p, next: d, opts: r.opts}
	}
	c, err := d.(*hop).dial(ctx, t)
	return c, r.path(), err
}

func (r *chainRoute) ListenPacket(ctx context.Context) (PacketConn, []string, error) {
	if len(r.hops) == 1 && r.hops[0].Type.SupportsUDP() {
		return (&proxyRoute{p: r.hops[0], base: r.base, opts: r.opts}).ListenPacket(ctx)
	}
	return nil, nil, ErrUDPUnsupported
}

// ---------------------------------------------------------------- groups

type groupRoute struct {
	c       *config.Chain
	members []Route
	health  *Health
	rr      atomic.Uint32
}

func (g *groupRoute) ID() string              { return g.c.ID }
func (g *groupRoute) Label() string           { return g.c.Name }
func (g *groupRoute) FirstHop() *config.Proxy { return nil }

// Candidates returns members in the order they should be tried.
func (g *groupRoute) Candidates() []Route {
	up := make([]Route, 0, len(g.members))
	var down []Route
	for _, m := range g.members {
		if g.health.IsDown(m.ID()) {
			down = append(down, m)
		} else {
			up = append(up, m)
		}
	}
	switch g.c.Mode {
	case config.ModeRoundRobin:
		if n := len(up); n > 1 {
			s := int(g.rr.Add(1)-1) % n
			up = append(up[s:], up[:s]...)
		}
	case config.ModeRandom:
		rand.Shuffle(len(up), func(i, j int) { up[i], up[j] = up[j], up[i] })
	case config.ModeFastest:
		sort.SliceStable(up, func(i, j int) bool {
			a, b := g.health.Latency(up[i].ID()), g.health.Latency(up[j].ID())
			if a <= 0 {
				return false
			}
			return b <= 0 || a < b
		})
	}
	return append(up, down...)
}

func (g *groupRoute) Dial(ctx context.Context, t Addr) (net.Conn, []string, error) {
	cands := g.Candidates()
	if len(cands) == 0 {
		return nil, nil, fmt.Errorf("group %q is empty", g.c.Name)
	}
	var errs []string
	for i, m := range cands {
		actx, cancel := attemptContext(ctx, len(cands)-i)
		start := time.Now()
		c, path, err := m.Dial(actx, t)
		cancel()
		if err == nil {
			g.health.MarkOK(m.ID(), 0)
			return c, path, nil
		}
		var te *TargetError
		if errors.As(err, &te) {
			return nil, path, err
		}
		if ctx.Err() != nil {
			return nil, path, err
		}
		g.health.MarkFail(m.ID(), err, time.Since(start))
		errs = append(errs, m.Label()+": "+err.Error())
	}
	return nil, nil, fmt.Errorf("all members of %q failed: %s", g.c.Name, strings.Join(errs, "; "))
}

// attemptContext splits the remaining time so a hanging member cannot use
// up the whole budget before failover.
func attemptContext(ctx context.Context, remaining int) (context.Context, context.CancelFunc) {
	dl, ok := ctx.Deadline()
	if !ok || remaining <= 1 {
		return context.WithCancel(ctx)
	}
	left := time.Until(dl)
	slice := left / time.Duration(remaining)
	if slice < 3*time.Second {
		slice = 3 * time.Second
	}
	if slice > left {
		slice = left
	}
	return context.WithTimeout(ctx, slice)
}

func (g *groupRoute) ListenPacket(ctx context.Context) (PacketConn, []string, error) {
	var lastErr error = ErrUDPUnsupported
	for _, m := range g.Candidates() {
		c, path, err := m.ListenPacket(ctx)
		if err == nil {
			return c, path, nil
		}
		if !errors.Is(err, ErrUDPUnsupported) {
			lastErr = err
		}
	}
	return nil, nil, lastErr
}

// ---------------------------------------------------------------- router

// Router holds the compiled routes of one profile.
type Router struct {
	routes    map[string]Route
	Base      *Direct
	health    *Health
	mu        sync.RWMutex
	endpoints map[netip.AddrPort]bool
	hostEnds  map[string]bool
}

// NewRouter compiles every proxy and chain of p into routes.
func NewRouter(p *config.Profile, health *Health, opts Options) (*Router, error) {
	base := &Direct{Resolver: opts.Resolver}
	o := &opts
	r := &Router{routes: map[string]Route{}, Base: base, health: health, endpoints: map[netip.AddrPort]bool{}, hostEnds: map[string]bool{}}
	for i := range p.Proxies {
		px := &p.Proxies[i]
		r.routes[px.ID] = &proxyRoute{p: px, base: base, opts: o}
		if ip, err := netip.ParseAddr(px.Host); err == nil {
			r.endpoints[netip.AddrPortFrom(ip.Unmap(), uint16(px.Port))] = true
		} else {
			r.hostEnds[strings.ToLower(px.Host)+":"+fmt.Sprint(px.Port)] = true
		}
	}
	building := map[string]bool{}
	var build func(id string) (Route, error)
	build = func(id string) (Route, error) {
		if rt, ok := r.routes[id]; ok {
			return rt, nil
		}
		c := p.FindChain(id)
		if c == nil {
			return nil, fmt.Errorf("unknown proxy or chain %q", id)
		}
		if building[id] {
			return nil, fmt.Errorf("chain %q contains itself", c.Name)
		}
		building[id] = true
		defer delete(building, id)
		if c.Mode == config.ModeChain {
			cr := &chainRoute{c: c, base: base, opts: o}
			var names []string
			for _, m := range c.Members {
				px := p.FindProxy(m)
				if px == nil {
					return nil, fmt.Errorf("chain %q: member %q is not a proxy", c.Name, m)
				}
				cr.hops = append(cr.hops, px)
				names = append(names, px.Label())
			}
			cr.label = c.Name
			if cr.label == "" {
				cr.label = strings.Join(names, " → ")
			}
			r.routes[id] = cr
			return cr, nil
		}
		g := &groupRoute{c: c, health: health}
		for _, m := range c.Members {
			mr, err := build(m)
			if err != nil {
				return nil, err
			}
			g.members = append(g.members, mr)
		}
		r.routes[id] = g
		return g, nil
	}
	for i := range p.Chains {
		if _, err := build(p.Chains[i].ID); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Route returns the route with id, or nil.
func (r *Router) Route(id string) Route { return r.routes[id] }

// Health returns the shared health table.
func (r *Router) Health() *Health { return r.health }

// ResolveEndpoints resolves hostname-configured proxy servers so loop
// detection can recognise them by IP. Best effort.
func (r *Router) ResolveEndpoints(ctx context.Context, res Resolver) {
	if res == nil {
		res = net.DefaultResolver
	}
	for hp := range r.hostEnds {
		h, ps, _ := net.SplitHostPort(hp)
		var port int
		fmt.Sscan(ps, &port)
		ips, err := res.LookupNetIP(ctx, "ip", h)
		if err != nil {
			continue
		}
		r.mu.Lock()
		for _, ip := range ips {
			r.endpoints[netip.AddrPortFrom(ip.Unmap(), uint16(port))] = true
		}
		r.mu.Unlock()
	}
}

// IsProxyEndpoint reports whether ap is one of the configured proxy servers,
// which must always be reached directly (connection loop prevention).
func (r *Router) IsProxyEndpoint(ap netip.AddrPort) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.endpoints[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())]
}

// IsProxyHost reports whether host:port names a configured proxy server.
func (r *Router) IsProxyHost(host string, port uint16) bool {
	return r.hostEnds[strings.ToLower(host)+":"+fmt.Sprint(port)]
}

// Members lists the routes of a group (nil for non-groups).
func Members(rt Route) []Route {
	if g, ok := rt.(*groupRoute); ok {
		return g.members
	}
	return nil
}

// IsGroup reports whether rt is a failover/load-balancing group.
func IsGroup(rt Route) bool { _, ok := rt.(*groupRoute); return ok }
