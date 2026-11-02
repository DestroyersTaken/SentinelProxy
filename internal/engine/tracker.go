package engine

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Conn is one tracked connection or UDP session.
type Conn struct {
	ID      uint64
	Network string // "tcp" or "udp"
	Inbound string // "intercept", "local-proxy" or "bypass"
	Src     netip.AddrPort
	Start   time.Time

	up, down atomic.Uint64

	mu         sync.Mutex
	dst        netip.AddrPort
	app        string
	pid        uint32
	path       string
	host       string
	hostSource string
	port       uint16
	rule       string
	ruleID     string
	action     string
	route      string
	hops       []string
	state      string
	err        string
	end        time.Time
	closeFn    func()

	// Owned by Tracker.tick (under tracker lock).
	prevUp, prevDown   uint64
	speedUp, speedDown uint64
	acctUp, acctDown   uint64
}

// ConnView is the JSON shape the UI receives.
type ConnView struct {
	ID         uint64   `json:"id"`
	Network    string   `json:"network"`
	Inbound    string   `json:"inbound"`
	App        string   `json:"app"`
	PID        uint32   `json:"pid"`
	Path       string   `json:"path"`
	Src        string   `json:"src"`
	Dst        string   `json:"dst"`
	Host       string   `json:"host"`
	HostSource string   `json:"hostSource"`
	Port       uint16   `json:"port"`
	Rule       string   `json:"rule"`
	RuleID     string   `json:"ruleId"`
	Action     string   `json:"action"`
	Route      string   `json:"route"`
	Hops       []string `json:"hops"`
	State      string   `json:"state"`
	Error      string   `json:"error,omitempty"`
	Start      int64    `json:"start"` // unix ms
	End        int64    `json:"end,omitempty"`
	Up         uint64   `json:"up"`
	Down       uint64   `json:"down"`
	SpeedUp    uint64   `json:"speedUp"`
	SpeedDown  uint64   `json:"speedDown"`
}

// AddUp counts bytes sent by the client.
func (c *Conn) AddUp(n int) { c.up.Add(uint64(n)) }

// AddDown counts bytes received by the client.
func (c *Conn) AddDown(n int) { c.down.Add(uint64(n)) }

func (c *Conn) set(fn func(c *Conn)) {
	c.mu.Lock()
	fn(c)
	c.mu.Unlock()
}

// SetHost records the destination hostname and where it was learned.
func (c *Conn) SetHost(host, source string) {
	c.set(func(c *Conn) { c.host, c.hostSource = host, source })
}

// SetDst records the destination IP once it is known (for example after a
// direct connection to a hostname).
func (c *Conn) SetDst(ap netip.AddrPort) { c.set(func(c *Conn) { c.dst = ap }) }

func apString(ap netip.AddrPort) string {
	if !ap.IsValid() {
		return ""
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
}

// SetState updates the lifecycle state.
func (c *Conn) SetState(s string) { c.set(func(c *Conn) { c.state = s }) }

// Fail marks the connection failed.
func (c *Conn) Fail(err error) {
	c.set(func(c *Conn) {
		c.state = "failed"
		if err != nil {
			c.err = err.Error()
		}
	})
}

func (c *Conn) view(t *Tracker) ConnView {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := ConnView{
		ID: c.ID, Network: c.Network, Inbound: c.Inbound, App: c.app, PID: c.pid, Path: c.path,
		Src: apString(c.Src), Dst: apString(c.dst), Host: c.host, HostSource: c.hostSource, Port: c.port,
		Rule: c.rule, RuleID: c.ruleID, Action: c.action, Route: c.route, Hops: c.hops, State: c.state, Error: c.err,
		Start: c.Start.UnixMilli(), Up: c.up.Load(), Down: c.down.Load(), SpeedUp: c.speedUp, SpeedDown: c.speedDown,
	}
	if !c.end.IsZero() {
		v.End = c.end.UnixMilli()
	}
	return v
}

// Point is one second of traffic history.
type Point struct {
	T    int64  `json:"t"` // unix seconds
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// AppStat aggregates traffic per application.
type AppStat struct {
	Name      string `json:"name"`
	Path      string `json:"path"`
	Up        uint64 `json:"up"`
	Down      uint64 `json:"down"`
	Conns     uint64 `json:"conns"`
	Active    int    `json:"active"`
	Blocked   uint64 `json:"blocked"`
	Proxied   uint64 `json:"proxied"`
	SpeedUp   uint64 `json:"speedUp"`
	SpeedDown uint64 `json:"speedDown"`
	LastSeen  int64  `json:"lastSeen"`
}

// RouteStat aggregates traffic per proxy/chain.
type RouteStat struct {
	Name   string `json:"name"`
	Up     uint64 `json:"up"`
	Down   uint64 `json:"down"`
	Conns  uint64 `json:"conns"`
	Active int    `json:"active"`
	Errors uint64 `json:"errors"`
}

// HostStat aggregates traffic per destination host.
type HostStat struct {
	Host  string `json:"host"`
	Up    uint64 `json:"up"`
	Down  uint64 `json:"down"`
	Conns uint64 `json:"conns"`
}

// Summary is the once-per-second dashboard payload.
type Summary struct {
	SpeedUp    uint64  `json:"speedUp"`
	SpeedDown  uint64  `json:"speedDown"`
	TotalUp    uint64  `json:"totalUp"`
	TotalDown  uint64  `json:"totalDown"`
	Active     int     `json:"active"`
	ActiveTCP  int     `json:"activeTcp"`
	ActiveUDP  int     `json:"activeUdp"`
	TotalConns uint64  `json:"totalConns"`
	Proxied    uint64  `json:"proxied"`
	Direct     uint64  `json:"direct"`
	Blocked    uint64  `json:"blocked"`
	Failed     uint64  `json:"failed"`
	History    []Point `json:"history"`
	Since      int64   `json:"since"`
}

const historyLen = 300

// Tracker records live and recently closed connections and aggregates.
type Tracker struct {
	nextID atomic.Uint64

	mu      sync.Mutex
	active  map[uint64]*Conn
	closed  []ConnView // ring, newest last
	maxDone int
	apps    map[string]*AppStat
	routes  map[string]*RouteStat
	hosts   map[string]*HostStat
	history []Point
	since   time.Time

	totalUp, totalDown                           uint64
	totalConns, proxied, direct, blocked, failed uint64
	speedUp, speedDown                           uint64
}

// NewTracker creates a tracker.
func NewTracker() *Tracker {
	return &Tracker{active: map[uint64]*Conn{}, maxDone: 500, apps: map[string]*AppStat{}, routes: map[string]*RouteStat{}, hosts: map[string]*HostStat{}, since: time.Now()}
}

// Open registers a new connection.
func (t *Tracker) Open(network, inbound string, src, dst netip.AddrPort, port uint16, app string, pid uint32, path string) *Conn {
	if port == 0 {
		port = dst.Port()
	}
	c := &Conn{ID: t.nextID.Add(1), Network: network, Inbound: inbound, Src: src, dst: dst, Start: time.Now(), app: app, pid: pid, path: path, port: port, state: "connecting"}
	t.mu.Lock()
	t.active[c.ID] = c
	t.totalConns++
	a := t.app(app, path)
	a.Conns++
	a.LastSeen = time.Now().Unix()
	t.mu.Unlock()
	return c
}

func appKey(app string) string {
	if app == "" {
		return "Unknown"
	}
	return strings.ToLower(app)
}

func (t *Tracker) app(name, path string) *AppStat {
	k := appKey(name)
	a := t.apps[k]
	if a == nil {
		if name == "" {
			name = "Unknown"
		}
		a = &AppStat{Name: name, Path: path}
		t.apps[k] = a
	}
	if a.Path == "" {
		a.Path = path
	}
	return a
}

// Route records the decision for a connection.
func (t *Tracker) Route(c *Conn, action, rule, ruleID, route string) {
	c.set(func(c *Conn) { c.action, c.rule, c.ruleID, c.route = action, rule, ruleID, route })
	t.mu.Lock()
	switch action {
	case "proxy":
		t.proxied++
		t.app(c.app, c.path).Proxied++
		rs := t.routes[route]
		if rs == nil {
			rs = &RouteStat{Name: route}
			t.routes[route] = rs
		}
		rs.Conns++
	case "block":
		t.blocked++
		t.app(c.app, c.path).Blocked++
	default:
		t.direct++
	}
	t.mu.Unlock()
}

// SetHops records the proxies actually used.
func (t *Tracker) SetHops(c *Conn, hops []string) { c.set(func(c *Conn) { c.hops = hops }) }

// SetCloser installs the function that force-closes the connection.
func (c *Conn) SetCloser(fn func()) { c.set(func(c *Conn) { c.closeFn = fn }) }

// Close finishes a connection and moves it to the recent list.
func (t *Tracker) Close(c *Conn) {
	c.mu.Lock()
	if !c.end.IsZero() {
		c.mu.Unlock()
		return
	}
	c.end = time.Now()
	if c.state == "connecting" || c.state == "active" {
		c.state = "closed"
	}
	failed := c.state == "failed"
	route, action := c.route, c.action
	c.closeFn = nil
	c.mu.Unlock()

	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.active[c.ID]; !ok {
		return
	}
	delete(t.active, c.ID)
	t.account(c)
	if failed {
		t.failed++
		if action == "proxy" {
			if rs := t.routes[route]; rs != nil {
				rs.Errors++
			}
		}
	}
	c.speedUp, c.speedDown = 0, 0
	v := c.view(t)
	t.closed = append(t.closed, v)
	if len(t.closed) > t.maxDone {
		t.closed = append([]ConnView(nil), t.closed[len(t.closed)-t.maxDone:]...)
	}
}

// account moves byte deltas into aggregates (tracker lock held).
func (t *Tracker) account(c *Conn) {
	up, down := c.up.Load(), c.down.Load()
	du, dd := up-c.acctUp, down-c.acctDown
	if du == 0 && dd == 0 {
		return
	}
	c.acctUp, c.acctDown = up, down
	t.totalUp += du
	t.totalDown += dd
	c.mu.Lock()
	app, path, route, action, host, dst := c.app, c.path, c.route, c.action, c.host, c.dst
	c.mu.Unlock()
	a := t.app(app, path)
	a.Up += du
	a.Down += dd
	a.LastSeen = time.Now().Unix()
	if action == "proxy" {
		if rs := t.routes[route]; rs != nil {
			rs.Up += du
			rs.Down += dd
		}
	}
	if host == "" && dst.IsValid() {
		host = dst.Addr().String()
	}
	if host == "" {
		host = "unknown"
	}
	hs := t.hosts[host]
	if hs == nil {
		if len(t.hosts) > 5000 {
			t.hosts = map[string]*HostStat{}
		}
		hs = &HostStat{Host: host}
		t.hosts[host] = hs
	}
	hs.Up += du
	hs.Down += dd
	if du+dd > 0 && c.acctUp+c.acctDown == du+dd {
		hs.Conns++
	}
}

// Tick computes per-second speeds; call once per second.
func (t *Tracker) Tick() {
	t.mu.Lock()
	defer t.mu.Unlock()
	var su, sd uint64
	for _, a := range t.apps {
		a.SpeedUp, a.SpeedDown, a.Active = 0, 0, 0
	}
	for _, r := range t.routes {
		r.Active = 0
	}
	for _, c := range t.active {
		up, down := c.up.Load(), c.down.Load()
		c.speedUp, c.speedDown = up-c.prevUp, down-c.prevDown
		c.prevUp, c.prevDown = up, down
		su += c.speedUp
		sd += c.speedDown
		t.account(c)
		c.mu.Lock()
		app, path, route, action := c.app, c.path, c.route, c.action
		c.mu.Unlock()
		a := t.app(app, path)
		a.SpeedUp += c.speedUp
		a.SpeedDown += c.speedDown
		a.Active++
		if action == "proxy" {
			if rs := t.routes[route]; rs != nil {
				rs.Active++
			}
		}
	}
	// Bytes of connections that closed during the last second are already
	// in the totals; include them in the speed too so short transfers show.
	t.speedUp, t.speedDown = su, sd
	t.history = append(t.history, Point{T: time.Now().Unix(), Up: su, Down: sd})
	if len(t.history) > historyLen {
		t.history = t.history[len(t.history)-historyLen:]
	}
}

// Summary returns the dashboard figures.
func (t *Tracker) Summary() Summary {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := Summary{SpeedUp: t.speedUp, SpeedDown: t.speedDown, TotalUp: t.totalUp, TotalDown: t.totalDown, Active: len(t.active),
		TotalConns: t.totalConns, Proxied: t.proxied, Direct: t.direct, Blocked: t.blocked, Failed: t.failed,
		History: append([]Point(nil), t.history...), Since: t.since.Unix()}
	for _, c := range t.active {
		if c.Network == "udp" {
			s.ActiveUDP++
		} else {
			s.ActiveTCP++
		}
	}
	return s
}

// Connections returns active connections plus up to recent closed ones,
// newest first.
func (t *Tracker) Connections(includeClosed bool) []ConnView {
	t.mu.Lock()
	out := make([]ConnView, 0, len(t.active)+len(t.closed))
	for _, c := range t.active {
		out = append(out, c.view(t))
	}
	if includeClosed {
		out = append(out, t.closed...)
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

// Apps returns per-application stats sorted by total bytes.
func (t *Tracker) Apps() []AppStat {
	t.mu.Lock()
	out := make([]AppStat, 0, len(t.apps))
	for _, a := range t.apps {
		out = append(out, *a)
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Up+out[i].Down > out[j].Up+out[j].Down })
	return out
}

// Routes returns per-route stats.
func (t *Tracker) Routes() []RouteStat {
	t.mu.Lock()
	out := make([]RouteStat, 0, len(t.routes))
	for _, r := range t.routes {
		out = append(out, *r)
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Up+out[i].Down > out[j].Up+out[j].Down })
	return out
}

// TopHosts returns the n busiest destinations.
func (t *Tracker) TopHosts(n int) []HostStat {
	t.mu.Lock()
	out := make([]HostStat, 0, len(t.hosts))
	for _, h := range t.hosts {
		out = append(out, *h)
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Up+out[i].Down > out[j].Up+out[j].Down })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Kill force-closes an active connection.
func (t *Tracker) Kill(id uint64) bool {
	t.mu.Lock()
	c := t.active[id]
	t.mu.Unlock()
	if c == nil {
		return false
	}
	c.mu.Lock()
	fn := c.closeFn
	c.mu.Unlock()
	if fn != nil {
		fn()
	}
	return true
}

// KillWhere closes every active connection matching pred.
func (t *Tracker) KillWhere(pred func(ConnView) bool) int {
	n := 0
	for _, v := range t.Connections(false) {
		if pred(v) && t.Kill(v.ID) {
			n++
		}
	}
	return n
}

// ClearClosed forgets closed connections.
func (t *Tracker) ClearClosed() {
	t.mu.Lock()
	t.closed = nil
	t.mu.Unlock()
}

// ResetStats zeroes aggregates (active connections keep running).
func (t *Tracker) ResetStats() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.apps = map[string]*AppStat{}
	t.routes = map[string]*RouteStat{}
	t.hosts = map[string]*HostStat{}
	t.history = nil
	t.totalUp, t.totalDown, t.totalConns, t.proxied, t.direct, t.blocked, t.failed = 0, 0, 0, 0, 0, 0, 0
	t.since = time.Now()
	for _, c := range t.active {
		c.acctUp, c.acctDown = c.up.Load(), c.down.Load()
	}
}
