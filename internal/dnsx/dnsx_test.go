package dnsx

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestFakeIPRoundTrip(t *testing.T) {
	f, err := NewFakeIP("198.18.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	a := f.Allocate("Example.com.")
	if !f.Contains(a) || a == netip.MustParseAddr("198.18.0.0") {
		t.Fatalf("bad ip %s", a)
	}
	if b := f.Allocate("example.com"); b != a {
		t.Fatal("not stable")
	}
	if d, ok := f.Lookup(a); !ok || d != "example.com" {
		t.Fatal("lookup failed")
	}
	// Exhaust and recycle.
	for i := 0; i < 300; i++ {
		f.Allocate("h" + string(rune('a'+i%26)) + string(rune('a'+i/26)))
	}
	if _, ok := f.Lookup(a); ok {
		if d, _ := f.Lookup(a); d == "example.com" {
			t.Fatal("expected recycling")
		}
	}
	if _, err := NewFakeIP("10.0.0.0/30"); err == nil {
		t.Fatal("tiny pool should fail")
	}
}

func TestFakeAnswerAndParse(t *testing.T) {
	q, id, err := BuildQuery("www.test.io", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	name, qt, qid, err := Question(q)
	if err != nil || name != "www.test.io" || qt != dnsmessage.TypeA || qid != id {
		t.Fatalf("%s %v %d %v", name, qt, qid, err)
	}
	resp, err := FakeAnswer(q, netip.MustParseAddr("198.18.0.7"), 5)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := ParseResponse(resp)
	if err != nil || len(recs) != 1 || recs[0].Domain != "www.test.io" || recs[0].IP.String() != "198.18.0.7" {
		t.Fatalf("%+v %v", recs, err)
	}
	q6, _, _ := BuildQuery("www.test.io", dnsmessage.TypeAAAA)
	resp6, _ := FakeAnswer(q6, netip.MustParseAddr("198.18.0.7"), 5)
	if recs, _ := ParseResponse(resp6); len(recs) != 0 {
		t.Fatal("AAAA must be empty")
	}
}

func TestCache(t *testing.T) {
	c := NewCache(2)
	c.Put(netip.MustParseAddr("1.1.1.1"), "one.one.", 0)
	c.Put(netip.MustParseAddr("2.2.2.2"), "two", time.Hour)
	c.Put(netip.MustParseAddr("3.3.3.3"), "three", time.Hour)
	if _, ok := c.Lookup(netip.MustParseAddr("1.1.1.1")); ok {
		t.Fatal("oldest should be evicted")
	}
	if d, ok := c.Lookup(netip.MustParseAddr("::ffff:3.3.3.3")); !ok || d != "three" {
		t.Fatal("mapped lookup failed")
	}
}

// fakeDNSServer answers every A query with 10.9.8.7.
func fakeDNSServer(t *testing.T) netip.AddrPort {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp, _ := FakeAnswer(buf[:n], netip.MustParseAddr("10.9.8.7"), 300)
			pc.WriteTo(resp, a)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestResolver(t *testing.T) {
	var seen []Record
	r := &Resolver{Servers: []netip.AddrPort{fakeDNSServer(t)}, Observe: func(rs []Record) { seen = append(seen, rs...) }}
	ips, err := r.LookupNetIP(context.Background(), "ip", "Some.Host")
	if err != nil || len(ips) != 1 || ips[0].String() != "10.9.8.7" {
		t.Fatalf("%v %v", ips, err)
	}
	if len(seen) != 1 || seen[0].Domain != "some.host" {
		t.Fatalf("observe %+v", seen)
	}
	srv, err := ParseServers([]string{"1.1.1.1", "8.8.8.8:5353", "[::1]:53"})
	if err != nil || len(srv) != 3 || srv[1].Port() != 5353 {
		t.Fatalf("%v %v", srv, err)
	}
}
