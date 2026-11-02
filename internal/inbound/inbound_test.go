package inbound

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/engine"
	"github.com/DestroyersTaken/SentinelProxy/internal/logx"
	"github.com/DestroyersTaken/SentinelProxy/internal/proxy"
)

func echo(t *testing.T) string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// upstream is a SOCKS5 proxy that sends every request to a fixed address and
// records what the client asked for.
func upstream(t *testing.T, to string) (string, chan string) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	asked := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				br.ReadByte()
				req, err := proxy.ServeSOCKS5(struct {
					io.Reader
					io.Writer
				}{br, c}, nil)
				if err != nil {
					return
				}
				asked <- req.Target.String()
				up, err := net.Dial("tcp", to)
				if err != nil {
					proxy.SOCKS5Reply(c, proxy.RepRefused, proxy.Addr{})
					return
				}
				defer up.Close()
				proxy.SOCKS5Reply(c, proxy.RepSuccess, proxy.Addr{})
				go io.Copy(up, br)
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String(), asked
}

func setup(t *testing.T, mutate func(p *config.Profile)) (*engine.Engine, *Server) {
	e := engine.New(logx.New(500))
	t.Cleanup(e.Close)
	p := config.NewProfile("t")
	p.Rules = nil // LAN rule would make everything on 127.0.0.1 direct
	mutate(p)
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	s, err := Listen(e, "127.0.0.1:0", "", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return e, s
}

func socksDial(t *testing.T, proxyAddr, target string) (net.Conn, error) {
	a, _ := proxy.ParseAddr(proxyAddr)
	p := config.Proxy{ID: "x", Type: config.SOCKS5, Host: a.Host, Port: int(a.Port)}
	pr := config.NewProfile("c")
	pr.Proxies = []config.Proxy{p}
	r, _ := proxy.NewRouter(pr, proxy.NewHealth(), proxy.Options{})
	ta, _ := proxy.ParseAddr(target)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := r.Route("x").Dial(ctx, ta)
	return c, err
}

func ping(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(c, "ping!")
	b := make([]byte, 5)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "ping!" {
		t.Fatalf("echo %q %v", b, err)
	}
}

func TestRoutesByHostnameThroughUpstream(t *testing.T) {
	echoAddr := echo(t)
	upAddr, asked := upstream(t, echoAddr)
	uh, up, _ := net.SplitHostPort(upAddr)
	upPort, _ := strconv.Atoi(up)
	e, s := setup(t, func(p *config.Profile) {
		p.Proxies = []config.Proxy{{ID: "up", Name: "Upstream", Type: config.SOCKS5, Host: uh, Port: upPort}}
		p.Rules = []config.Rule{{ID: "r", Name: "Example via upstream", Enabled: true, Hosts: []string{"*.example.test"}, Action: config.Action{Type: config.ActionProxy, Target: "up"}}}
	})
	c, err := socksDial(t, s.Addr(), "echo.example.test:4242")
	if err != nil {
		t.Fatal(err)
	}
	ping(t, c)
	if got := <-asked; got != "echo.example.test:4242" {
		t.Fatalf("upstream was asked for %q (hostname must be passed through)", got)
	}
	c.Close()
	// Direct by IP for everything else.
	c, err = socksDial(t, s.Addr(), echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	ping(t, c)
	c.Close()

	time.Sleep(100 * time.Millisecond)
	conns := e.Tracker.Connections(true)
	if len(conns) != 2 {
		t.Fatalf("tracked %d connections", len(conns))
	}
	exe, _ := os.Executable()
	for _, v := range conns {
		if v.App != filepath.Base(exe) {
			t.Errorf("app = %q, want %q (process lookup)", v.App, filepath.Base(exe))
		}
	}
	byHost := map[string]engine.ConnView{}
	for _, v := range conns {
		byHost[v.Host+v.Dst] = v
	}
	var proxied engine.ConnView
	for _, v := range conns {
		if v.Action == "proxy" {
			proxied = v
		}
	}
	if proxied.Host != "echo.example.test" || proxied.Route != "Upstream" || proxied.Up != 5 || proxied.Down != 5 || proxied.Rule != "Example via upstream" {
		t.Fatalf("proxied conn %+v", proxied)
	}
	if e.Rules().Hits()["r"] != 1 {
		t.Fatal("rule hit not counted")
	}
}

func TestBlockRuleAndPerAppRule(t *testing.T) {
	echoAddr := echo(t)
	exe, _ := os.Executable()
	_, s := setup(t, func(p *config.Profile) {
		p.Rules = []config.Rule{
			{ID: "b", Name: "No ads", Enabled: true, Hosts: []string{"keyword:ads"}, Action: config.Action{Type: config.ActionBlock}},
			{ID: "a", Name: "Block this app on 9", Enabled: true, Apps: []string{filepath.Base(exe)}, Ports: []string{"9"}, Action: config.Action{Type: config.ActionBlock}},
		}
	})
	if _, err := socksDial(t, s.Addr(), "ads.example:80"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected block, got %v", err)
	}
	if _, err := socksDial(t, s.Addr(), "127.0.0.1:9"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected per-app block, got %v", err)
	}
	c, err := socksDial(t, s.Addr(), echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	ping(t, c)
	c.Close()
}

func TestHTTPProxyModes(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s", r.URL.Path)
	}))
	defer origin.Close()
	_, s := setup(t, func(p *config.Profile) {})
	pu, _ := url.Parse("http://" + s.Addr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 5 * time.Second}
	resp, err := client.Get(origin.URL + "/forward")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "hello /forward" {
		t.Fatalf("forward body %q", b)
	}
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secure") }))
	defer tls.Close()
	tr := tls.Client().Transport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(pu)
	resp, err = (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get(tls.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "secure" {
		t.Fatalf("connect body %q", b)
	}
}

func TestUDPAssociateDirect(t *testing.T) {
	u, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer u.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := u.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			u.WriteToUDPAddrPort(append([]byte("re:"), buf[:n]...), a)
		}
	}()
	e, s := setup(t, func(p *config.Profile) {})
	a, _ := proxy.ParseAddr(s.Addr())
	pr := config.NewProfile("c")
	pr.Proxies = []config.Proxy{{ID: "x", Type: config.SOCKS5, Host: a.Host, Port: int(a.Port)}}
	r, _ := proxy.NewRouter(pr, proxy.NewHealth(), proxy.Options{})
	pc, _, err := r.Route("x").ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := proxy.AddrFromAddrPort(u.LocalAddr().(*net.UDPAddr).AddrPort())
	for i := 0; i < 3; i++ {
		pc.WriteTo([]byte("udp"+strconv.Itoa(i)), dst)
	}
	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 100)
	got := map[string]bool{}
	for i := 0; i < 3; i++ {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		got[string(buf[:n])] = true
	}
	if !got["re:udp0"] || !got["re:udp2"] {
		t.Fatalf("got %v", got)
	}
	if e.UDPSessions() != 1 {
		t.Fatalf("sessions %d", e.UDPSessions())
	}
}
