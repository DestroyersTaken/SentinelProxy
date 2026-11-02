package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/proxy"
	"github.com/DestroyersTaken/SentinelProxy/internal/rules"
)

// UDPReply sends a datagram back to the client of a UDP flow.
type UDPReply func(payload []byte)

type udpSession struct {
	key     string
	conn    *Conn
	target  proxy.Addr
	pc      proxy.PacketConn
	blocked bool
	idle    time.Duration
	last    atomic.Int64 // unix nano
	ready   chan struct{}
	mu      sync.Mutex
	queue   [][]byte
	closed  atomic.Bool
}

type udpTable struct {
	mu sync.Mutex
	m  map[string]*udpSession
}

func (t *udpTable) init() { t.m = map[string]*udpSession{} }

func (t *udpTable) closeAll() {
	t.mu.Lock()
	all := t.m
	t.m = map[string]*udpSession{}
	t.mu.Unlock()
	for _, s := range all {
		s.close()
	}
}

func (t *udpTable) expire() {
	now := time.Now().UnixNano()
	t.mu.Lock()
	var dead []*udpSession
	for k, s := range t.m {
		if time.Duration(now-s.last.Load()) > s.idle || s.closed.Load() {
			dead = append(dead, s)
			delete(t.m, k)
		}
	}
	t.mu.Unlock()
	for _, s := range dead {
		s.close()
	}
}

func (t *udpTable) remove(s *udpSession) {
	t.mu.Lock()
	if t.m[s.key] == s {
		delete(t.m, s.key)
	}
	t.mu.Unlock()
}

func (s *udpSession) close() {
	s.mu.Lock()
	if s.closed.Swap(true) {
		s.mu.Unlock()
		return
	}
	pc := s.pc
	s.mu.Unlock()
	if pc != nil {
		pc.Close()
	}
}

// setPC installs the packet conn unless the session was closed meanwhile.
func (s *udpSession) setPC(pc proxy.PacketConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		pc.Close()
		return false
	}
	s.pc = pc
	return true
}

// UDPSessions returns the number of live UDP sessions.
func (e *Engine) UDPSessions() int {
	e.udp.mu.Lock()
	defer e.udp.mu.Unlock()
	return len(e.udp.m)
}

// HandleUDP routes one datagram. Sessions are keyed by client and
// destination; the first datagram decides the route for the session. It
// never blocks the caller for long: session setup happens asynchronously
// and datagrams are queued meanwhile.
func (e *Engine) HandleUDP(f Flow, payload []byte, reply UDPReply) {
	key := f.Src.String() + ">" + f.Dst.String() + "|" + f.Domain
	e.udp.mu.Lock()
	s := e.udp.m[key]
	if s == nil {
		idle := 60 * time.Second
		if f.port() == 53 {
			idle = 15 * time.Second
		}
		s = &udpSession{key: key, ready: make(chan struct{}), idle: idle}
		s.last.Store(time.Now().UnixNano())
		e.udp.m[key] = s
		e.udp.mu.Unlock()
		s.queue = append(s.queue, append([]byte(nil), payload...))
		go e.setupUDP(s, f, reply)
		return
	}
	e.udp.mu.Unlock()
	s.last.Store(time.Now().UnixNano())
	select {
	case <-s.ready:
	default:
		s.mu.Lock()
		select {
		case <-s.ready:
			s.mu.Unlock()
		default:
			if len(s.queue) < 64 {
				s.queue = append(s.queue, append([]byte(nil), payload...))
			}
			s.mu.Unlock()
			return
		}
	}
	if s.blocked || s.pc == nil || s.closed.Load() {
		return
	}
	if _, err := s.pc.WriteTo(payload, s.target); err == nil {
		s.conn.AddUp(len(payload))
	}
}

func (e *Engine) setupUDP(s *udpSession, f Flow, reply UDPReply) {
	st := e.st.Load()
	set := &st.profile.Settings
	cn := e.Tracker.Open("udp", f.Inbound, f.Src, f.Dst, f.port(), f.App.Name, f.App.PID, f.App.Path)
	s.conn = cn
	domain, src := f.Domain, "request"
	if domain == "" && f.Dst.IsValid() {
		domain, src = e.domainFor(st, f.Dst.Addr())
	}
	if domain != "" {
		cn.SetHost(domain, src)
	}
	var d rules.Decision
	if f.Dst.IsValid() && st.router.IsProxyEndpoint(f.Dst) {
		d = rules.Decision{Action: config.Action{Type: config.ActionDirect}, RuleName: "Proxy server (loop prevention)", Index: -2}
	} else {
		d = st.rules.Decide(meta(&f, domain))
	}
	st.rules.Hit(d)
	routeLabel := ""
	if d.Action.Type == config.ActionProxy {
		routeLabel = st.profile.TargetLabel(d.Action.Target)
	}
	e.Tracker.Route(cn, string(d.Action.Type), d.RuleName, d.RuleID, routeLabel)

	isFake := f.Dst.IsValid() && st.fake != nil && st.fake.Contains(f.Dst.Addr())
	s.target = proxy.AddrFromAddrPort(f.Dst)
	if isFake || !f.Dst.IsValid() {
		s.target = proxy.Addr{Host: domain, Port: f.port()}
	}
	who := f.App.Name
	if who == "" {
		who = "unknown app"
	}
	finish := func() {
		s.mu.Lock()
		q := s.queue
		s.queue = nil
		close(s.ready)
		s.mu.Unlock()
		if s.pc == nil || s.blocked {
			return
		}
		for _, p := range q {
			if _, err := s.pc.WriteTo(p, s.target); err == nil {
				cn.AddUp(len(p))
			}
		}
	}
	fail := func(err error) {
		cn.Fail(err)
		s.blocked = true
		finish()
		e.Log.Warnf("%s → %s (UDP) via %s failed: %v", who, s.target, actionText(d, routeLabel), err)
		go func() { time.Sleep(5 * time.Second); s.close(); e.udp.remove(s); e.Tracker.Close(cn) }()
	}

	var hops []string
	switch d.Action.Type {
	case config.ActionBlock:
		cn.SetState("blocked")
		s.blocked = true
		finish()
		if set.LogConnections {
			e.Log.Add(slog.LevelInfo, "conn", fmt.Sprintf("%s → %s (UDP) blocked by rule %q", who, s.target, d.RuleName))
		}
		// Keep the session briefly so retries are dropped cheaply.
		s.idle = 10 * time.Second
		go e.closeWhenExpired(s)
		return
	case config.ActionProxy:
		rt := st.router.Route(d.Action.Target)
		if rt == nil {
			fail(fmt.Errorf("route %q is missing", d.Action.Target))
			return
		}
		ctx, cancel := context.WithTimeout(e.ctx, time.Duration(set.ConnectTimeoutSec)*time.Second)
		pc, path, err := rt.ListenPacket(ctx)
		cancel()
		if errors.Is(err, proxy.ErrUDPUnsupported) {
			if set.UDPFallback != config.UDPDirect {
				cn.SetState("blocked")
				cn.set(func(c *Conn) { c.err = "route cannot carry UDP (blocked by UDP fallback setting)" })
				s.blocked = true
				s.idle = 10 * time.Second
				finish()
				if set.LogConnections {
					e.Log.Add(slog.LevelInfo, "conn", fmt.Sprintf("%s → %s (UDP) blocked: %s cannot carry UDP", who, s.target, routeLabel))
				}
				go e.closeWhenExpired(s)
				return
			}
			e.Tracker.Route(cn, "direct", d.RuleName+" (UDP fallback)", d.RuleID, "")
			pc, err = e.directPacketConn(st)
			path = nil
		}
		if err != nil {
			fail(err)
			return
		}
		if !s.setPC(pc) {
			e.Tracker.Close(cn)
			return
		}
		hops = path
	default:
		pc, err := e.directPacketConn(st)
		if err != nil {
			fail(err)
			return
		}
		if !s.setPC(pc) {
			e.Tracker.Close(cn)
			return
		}
	}
	e.Tracker.SetHops(cn, hops)
	cn.SetState("active")
	cn.SetCloser(func() { s.close(); e.udp.remove(s) })
	if set.LogConnections && f.port() != 53 {
		e.Log.Add(slog.LevelInfo, "conn", fmt.Sprintf("%s → %s (UDP) via %s (rule %q)", who, s.target, actionText(d, joinHops(hops)), d.RuleName))
	}
	finish()
	go func() {
		defer e.Tracker.Close(cn)
		defer e.udp.remove(s)
		defer s.close()
		buf := make([]byte, 65535)
		for !s.closed.Load() {
			_ = s.pc.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, from, err := s.pc.ReadFrom(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					if time.Duration(time.Now().UnixNano()-s.last.Load()) > s.idle {
						return
					}
					continue
				}
				return
			}
			_ = from
			s.last.Store(time.Now().UnixNano())
			cn.AddDown(n)
			if f.port() == 53 {
				e.ObserveDNSResponse(buf[:n])
			}
			reply(append([]byte(nil), buf[:n]...))
		}
	}()
}

func joinHops(h []string) string {
	out := ""
	for i, x := range h {
		if i > 0 {
			out += " → "
		}
		out += x
	}
	return out
}

func (e *Engine) closeWhenExpired(s *udpSession) {
	for !s.closed.Load() {
		time.Sleep(time.Second)
		if time.Duration(time.Now().UnixNano()-s.last.Load()) > s.idle {
			s.close()
			e.udp.remove(s)
		}
	}
	e.Tracker.Close(s.conn)
}

type directPC struct {
	*net.UDPConn
	res proxy.Resolver
}

func (d *directPC) WriteTo(p []byte, dst proxy.Addr) (int, error) {
	ip, ok := dst.IP()
	if !ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := d.res.LookupNetIP(ctx, "ip4", dst.Host)
		cancel()
		if err != nil || len(ips) == 0 {
			return 0, fmt.Errorf("resolve %s: %v", dst.Host, err)
		}
		ip = ips[0].Unmap()
	}
	return d.UDPConn.WriteToUDPAddrPort(p, netip.AddrPortFrom(ip, dst.Port))
}

func (d *directPC) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	n, a, err := d.UDPConn.ReadFromUDPAddrPort(p)
	return n, netip.AddrPortFrom(a.Addr().Unmap(), a.Port()), err
}

func (e *Engine) directPacketConn(st *state) (proxy.PacketConn, error) {
	u, err := st.router.Base.ListenUDP()
	if err != nil {
		return nil, err
	}
	return &directPC{UDPConn: u, res: st.resolver}, nil
}
