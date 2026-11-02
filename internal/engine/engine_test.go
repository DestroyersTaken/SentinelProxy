package engine

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/dnsx"
	"github.com/DestroyersTaken/SentinelProxy/internal/logx"
	"github.com/DestroyersTaken/SentinelProxy/internal/match"
	"golang.org/x/net/dns/dnsmessage"
)

func dnsServer(t *testing.T, answer string) string {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, a, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp, _ := dnsx.FakeAnswer(buf[:n], netip.MustParseAddr(answer), 60)
			pc.WriteTo(resp, a)
		}
	}()
	return pc.LocalAddr().String()
}

func TestFakeIPEndToEnd(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			io.Copy(c, c)
			c.Close()
		}
	}()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	e := New(logx.New(100))
	defer e.Close()
	p := config.NewProfile("t")
	p.Settings.DNS.Mode = config.DNSFakeIP
	p.Settings.DNS.Upstreams = []string{dnsServer(t, "127.0.0.1")}
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	q, _, _ := dnsx.BuildQuery("svc.example.com", dnsmessage.TypeA)
	resp, ok := e.AnswerDNS(q)
	if !ok {
		t.Fatal("expected a fake answer")
	}
	recs, _ := dnsx.ParseResponse(resp)
	fake := recs[0].IP
	if !e.IsFakeIP(fake) {
		t.Fatalf("%s not fake", fake)
	}
	// Excluded names go to the real DNS.
	q2, _, _ := dnsx.BuildQuery("printer.local", dnsmessage.TypeA)
	if _, ok := e.AnswerDNS(q2); ok {
		t.Fatal("*.local must not be faked")
	}

	if v := e.Classify(Flow{Network: "tcp", Dst: netip.AddrPortFrom(fake, port)}); !v.Redirect {
		t.Fatal("fake IP flows must be redirected")
	}
	v := e.Classify(Flow{Network: "tcp", Src: netip.MustParseAddrPort("10.0.0.2:5555"), Dst: netip.MustParseAddrPort("192.168.1.1:80"), App: match.AppInfo{Name: "x.exe"}})
	if v.Redirect || v.Bypass == nil {
		t.Fatalf("LAN should bypass: %+v", v)
	}
	e.Tracker.Close(v.Bypass)

	client, server := net.Pipe()
	go e.HandleTCP(server, Flow{Network: "tcp", Inbound: "intercept", Src: netip.MustParseAddrPort("10.0.0.2:1234"), Dst: netip.AddrPortFrom(fake, port), App: match.AppInfo{Name: "app.exe"}}, nil)
	client.SetDeadline(time.Now().Add(3 * time.Second))
	client.Write([]byte("abc"))
	b := make([]byte, 3)
	if _, err := io.ReadFull(client, b); err != nil || string(b) != "abc" {
		t.Fatalf("relay via fake IP: %q %v", b, err)
	}
	client.Close()
	time.Sleep(50 * time.Millisecond)
	var found bool
	for _, c := range e.Tracker.Connections(true) {
		if c.Host == "svc.example.com" && c.HostSource == "fakeip" && c.Up == 3 && c.Down == 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("connection not tracked correctly: %+v", e.Tracker.Connections(true))
	}
	e.Tracker.Tick()
	if s := e.Tracker.Summary(); s.TotalUp != 3 || s.TotalDown != 3 || s.TotalConns != 2 {
		t.Fatalf("summary %+v", s)
	}
}

func TestSniffDecidesHostRule(t *testing.T) {
	e := New(logx.New(100))
	defer e.Close()
	p := config.NewProfile("t")
	p.Rules = []config.Rule{{ID: "b", Name: "Block social", Enabled: true, Hosts: []string{"*.social.test"}, Action: config.Action{Type: config.ActionBlock}}}
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		e.HandleTCP(server, Flow{Network: "tcp", Inbound: "intercept", Dst: netip.MustParseAddrPort("203.0.113.9:80"), App: match.AppInfo{Name: "browser.exe"}}, nil)
		close(done)
	}()
	client.Write([]byte("GET / HTTP/1.1\r\nHost: www.social.test\r\n\r\n"))
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("blocked connection not closed")
	}
	c := e.Tracker.Connections(true)[0]
	if c.State != "blocked" || c.Host != "www.social.test" || c.HostSource != "http" {
		t.Fatalf("%+v", c)
	}
	// The sniffed name is now cached for this IP.
	if d, ok := e.DNSCache.Lookup(netip.MustParseAddr("203.0.113.9")); !ok || d != "www.social.test" {
		t.Fatal("sniffed host not cached")
	}
}
