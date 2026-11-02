// Package dnsx provides the DNS pieces of the engine: a reverse cache that
// remembers which hostname an IP came from, a fake-IP pool, DNS message
// helpers and a small upstream resolver that never goes through the
// system resolver (so it cannot be intercepted by SentinelProxy itself).
package dnsx

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// ---------------------------------------------------------------- reverse cache

type cacheEntry struct {
	domain  string
	expires time.Time
}

// Cache maps IP addresses to the hostname they were resolved from.
type Cache struct {
	mu    sync.Mutex
	m     map[netip.Addr]cacheEntry
	order []netip.Addr
	max   int
}

// NewCache returns a cache bounded to max entries.
func NewCache(max int) *Cache { return &Cache{m: map[netip.Addr]cacheEntry{}, max: max} }

// Put records ip -> domain for ttl (minimum 60s, so short TTLs from CDNs
// still label the connections that follow).
func (c *Cache) Put(ip netip.Addr, domain string, ttl time.Duration) {
	if ttl < time.Minute {
		ttl = time.Minute
	}
	if ttl > 6*time.Hour {
		ttl = 6 * time.Hour
	}
	ip = ip.Unmap()
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.m[ip]; !ok {
		c.order = append(c.order, ip)
		if len(c.order) > c.max {
			drop := len(c.order) - c.max
			for _, old := range c.order[:drop] {
				delete(c.m, old)
			}
			c.order = append([]netip.Addr(nil), c.order[drop:]...)
		}
	}
	c.m[ip] = cacheEntry{domain, time.Now().Add(ttl)}
}

// Lookup returns the hostname for ip, if known and fresh.
func (c *Cache) Lookup(ip netip.Addr) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[ip.Unmap()]
	if !ok || time.Now().After(e.expires) {
		return "", false
	}
	return e.domain, true
}

// Len returns the number of entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// ---------------------------------------------------------------- fake IP

// FakeIP hands out synthetic addresses from a prefix and maps them back to
// hostnames. Addresses are recycled least-recently-allocated first.
type FakeIP struct {
	mu     sync.Mutex
	prefix netip.Prefix
	first  netip.Addr
	size   uint32
	next   uint32
	byIP   map[netip.Addr]string
	byName map[string]netip.Addr
}

// NewFakeIP creates a pool. The prefix must be IPv4 and at least a /24.
func NewFakeIP(cidr string) (*FakeIP, error) {
	pf, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	pf = pf.Masked()
	if !pf.Addr().Is4() || pf.Bits() > 24 {
		return nil, fmt.Errorf("fake-IP range must be an IPv4 /24 or larger, got %s", cidr)
	}
	size := uint32(1) << (32 - pf.Bits())
	return &FakeIP{prefix: pf, first: pf.Addr(), size: size - 2, next: 0, byIP: map[netip.Addr]string{}, byName: map[string]netip.Addr{}}, nil
}

// Contains reports whether ip belongs to the pool.
func (f *FakeIP) Contains(ip netip.Addr) bool { return f != nil && f.prefix.Contains(ip.Unmap()) }

// Prefix returns the pool range.
func (f *FakeIP) Prefix() netip.Prefix { return f.prefix }

func addU32(a netip.Addr, n uint32) netip.Addr {
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v += n
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Allocate returns the fake address for domain, allocating one if needed.
func (f *FakeIP) Allocate(domain string) netip.Addr {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	f.mu.Lock()
	defer f.mu.Unlock()
	if ip, ok := f.byName[domain]; ok {
		return ip
	}
	ip := addU32(f.first, 1+f.next%f.size) // skip network address
	f.next++
	if old, ok := f.byIP[ip]; ok {
		delete(f.byName, old)
	}
	f.byIP[ip] = domain
	f.byName[domain] = ip
	return ip
}

// Lookup returns the domain behind a fake address.
func (f *FakeIP) Lookup(ip netip.Addr) (string, bool) {
	if f == nil {
		return "", false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.byIP[ip.Unmap()]
	return d, ok
}

// ---------------------------------------------------------------- messages

// Record is one address answer extracted from a DNS response.
type Record struct {
	Domain string
	IP     netip.Addr
	TTL    time.Duration
}

// ParseResponse extracts A/AAAA answers. CNAME chains are resolved so the
// addresses are attributed to the name that was originally asked for.
func ParseResponse(msg []byte) ([]Record, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil, err
	}
	if !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return nil, nil
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) == 0 {
		return nil, err
	}
	asked := strings.TrimSuffix(strings.ToLower(qs[0].Name.String()), ".")
	var out []Record
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return out, err
		}
		ttl := time.Duration(ah.TTL) * time.Second
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return out, err
			}
			out = append(out, Record{asked, netip.AddrFrom4(r.A), ttl})
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return out, err
			}
			out = append(out, Record{asked, netip.AddrFrom16(r.AAAA).Unmap(), ttl})
		default:
			if err := p.SkipAnswer(); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}

// Question returns the first question of a query.
func Question(msg []byte) (name string, qtype dnsmessage.Type, id uint16, err error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return "", 0, 0, err
	}
	if h.Response {
		return "", 0, 0, errors.New("not a query")
	}
	q, err := p.Question()
	if err != nil {
		return "", 0, 0, err
	}
	return strings.TrimSuffix(strings.ToLower(q.Name.String()), "."), q.Type, h.ID, nil
}

// FakeAnswer builds a response to query: an A record with ip for A
// questions, and an empty NOERROR answer for AAAA (so clients use IPv4).
func FakeAnswer(query []byte, ip netip.Addr, ttl uint32) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true, OpCode: h.OpCode})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if q.Type == dnsmessage.TypeA && ip.Is4() {
		if err := b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: ttl}, dnsmessage.AResource{A: ip.As4()}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// BuildQuery builds a recursive query.
func BuildQuery(name string, t dnsmessage.Type) ([]byte, uint16, error) {
	n, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, 0, err
	}
	id := uint16(rand.Uint32())
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, 0, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET}); err != nil {
		return nil, 0, err
	}
	msg, err := b.Finish()
	return msg, id, err
}

// ---------------------------------------------------------------- resolver

// Resolver queries upstream DNS servers directly over UDP (TCP on
// truncation). It implements proxy.Resolver.
type Resolver struct {
	Servers []netip.AddrPort
	// Dial opens the sockets (so they can carry the engine's bypass mark).
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Observe, when set, receives every answer (the engine feeds its cache).
	Observe func([]Record)

	mu    sync.Mutex
	cache map[string]resolverEntry
}

type resolverEntry struct {
	ips     []netip.Addr
	expires time.Time
}

// ParseServers turns "1.1.1.1", "8.8.8.8:53", "[2606:4700::1111]:53" into endpoints.
func ParseServers(list []string) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ap, err := netip.ParseAddrPort(s); err == nil {
			out = append(out, ap)
			continue
		}
		ip, err := netip.ParseAddr(strings.Trim(s, "[]"))
		if err != nil {
			return nil, fmt.Errorf("bad DNS server %q", s)
		}
		out = append(out, netip.AddrPortFrom(ip, 53))
	}
	return out, nil
}

// LookupNetIP resolves host (network is "ip", "ip4" or "ip6").
func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	key := network + "|" + host
	r.mu.Lock()
	if e, ok := r.cache[key]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		return e.ips, nil
	}
	r.mu.Unlock()

	types := []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	switch network {
	case "ip4":
		types = types[:1]
	case "ip6":
		types = types[1:]
	}
	var ips []netip.Addr
	var ttl time.Duration = time.Hour
	var lastErr error
	for _, t := range types {
		recs, err := r.query(ctx, host, t)
		if err != nil {
			lastErr = err
			continue
		}
		for _, rec := range recs {
			ips = append(ips, rec.IP)
			if rec.TTL < ttl {
				ttl = rec.TTL
			}
		}
		if len(ips) > 0 && t == dnsmessage.TypeA && network == "ip" {
			break // IPv4 is enough, skip the AAAA round trip
		}
	}
	if len(ips) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("no such host %s", host)
		}
		return nil, lastErr
	}
	if ttl < 30*time.Second {
		ttl = 30 * time.Second
	}
	r.mu.Lock()
	if r.cache == nil || len(r.cache) > 4096 {
		r.cache = map[string]resolverEntry{}
	}
	r.cache[key] = resolverEntry{ips, time.Now().Add(ttl)}
	r.mu.Unlock()
	return ips, nil
}

func (r *Resolver) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if r.Dial != nil {
		return r.Dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func (r *Resolver) query(ctx context.Context, host string, t dnsmessage.Type) ([]Record, error) {
	if len(r.Servers) == 0 {
		return nil, errors.New("no DNS servers configured")
	}
	msg, id, err := BuildQuery(host, t)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, srv := range r.Servers {
		qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		resp, err := r.exchange(qctx, srv, msg, id)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		recs, err := ParseResponse(resp)
		if err != nil {
			lastErr = err
			continue
		}
		if r.Observe != nil {
			r.Observe(recs)
		}
		return recs, nil
	}
	return nil, lastErr
}

func (r *Resolver) exchange(ctx context.Context, srv netip.AddrPort, msg []byte, id uint16) ([]byte, error) {
	c, err := r.dial(ctx, "udp", srv.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 12 || uint16(buf[0])<<8|uint16(buf[1]) != id {
			continue
		}
		if buf[2]&0x02 != 0 { // truncated: retry over TCP
			return r.exchangeTCP(ctx, srv, msg)
		}
		return buf[:n], nil
	}
}

func (r *Resolver) exchangeTCP(ctx context.Context, srv netip.AddrPort, msg []byte) ([]byte, error) {
	c, err := r.dial(ctx, "tcp", srv.String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(append([]byte{byte(len(msg) >> 8), byte(len(msg))}, msg...)); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := ioReadFull(c, l[:]); err != nil {
		return nil, err
	}
	out := make([]byte, int(l[0])<<8|int(l[1]))
	_, err = ioReadFull(c, out)
	return out, err
}

func ioReadFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
