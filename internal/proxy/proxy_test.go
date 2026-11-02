package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
)

// echoServer echoes everything back.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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

// testProxy is a minimal SOCKS4/5 + HTTP CONNECT server built on the
// package's own server-side handshakes.
type testProxy struct {
	addr     string
	user     string
	pass     string
	seen     chan string
	udpRelay *net.UDPConn
}

func startTestProxy(t *testing.T, user, pass string) *testProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tp := &testProxy{addr: ln.Addr().String(), user: user, pass: pass, seen: make(chan string, 64)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go tp.handle(t, c)
		}
	}()
	return tp
}

func (tp *testProxy) auth() Credentials {
	if tp.user == "" {
		return nil
	}
	return func(u, p string) bool { return u == tp.user && p == tp.pass }
}

func (tp *testProxy) handle(t *testing.T, c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	rw := struct {
		io.Reader
		io.Writer
	}{br, c}
	var target Addr
	switch first[0] {
	case 5:
		br.ReadByte()
		req, err := ServeSOCKS5(rw, tp.auth())
		if err != nil {
			return
		}
		if req.Command == CmdUDPAssociate {
			tp.serveUDP(c)
			return
		}
		target = req.Target
		up, err := net.Dial("tcp", target.String())
		if err != nil {
			SOCKS5Reply(c, RepRefused, Addr{})
			return
		}
		defer up.Close()
		SOCKS5Reply(c, RepSuccess, Addr{Host: "127.0.0.1", Port: 1})
		tp.seen <- "socks5 " + target.String()
		pipe(WrapBuffered(c, br), up)
	case 4:
		br.ReadByte()
		req, err := ServeSOCKS4(br)
		if err != nil {
			return
		}
		target = req.Target
		up, err := net.Dial("tcp", target.String())
		if err != nil {
			SOCKS4Reply(c, false)
			return
		}
		defer up.Close()
		SOCKS4Reply(c, true)
		tp.seen <- "socks4 " + target.String()
		pipe(WrapBuffered(c, br), up)
	default:
		req, err := http.ReadRequest(br)
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		if tp.user != "" {
			u, p, ok := ParseProxyAuthorization(req.Header.Get("Proxy-Authorization"))
			if !ok || u != tp.user || p != tp.pass {
				io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
				return
			}
		}
		up, err := net.Dial("tcp", req.Host)
		if err != nil {
			io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer up.Close()
		io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		tp.seen <- "http " + req.Host
		pipe(WrapBuffered(c, br), up)
	}
}

func (tp *testProxy) serveUDP(ctrl net.Conn) {
	relay, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer relay.Close()
	port := relay.LocalAddr().(*net.UDPAddr).Port
	SOCKS5Reply(ctrl, RepSuccess, Addr{Host: "0.0.0.0", Port: uint16(port)})
	go func() {
		buf := make([]byte, 65535)
		var client netip.AddrPort
		for {
			n, from, err := relay.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if !client.IsValid() || from == client {
				client = from
				dst, payload, err := ParseUDPRequest(buf[:n])
				if err != nil {
					continue
				}
				ip, _ := dst.IP()
				relay.WriteToUDPAddrPort(payload, netip.AddrPortFrom(ip, dst.Port))
				continue
			}
			relay.WriteToUDPAddrPort(BuildUDPResponse(from, buf[:n]), client)
		}
	}()
	io.Copy(io.Discard, ctrl)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

func hostPort(t *testing.T, s string) (string, int) {
	h, p, _ := net.SplitHostPort(s)
	n, _ := strconv.Atoi(p)
	return h, n
}

func mkProxy(t *testing.T, id string, typ config.ProxyType, tp *testProxy) config.Proxy {
	h, p := hostPort(t, tp.addr)
	return config.Proxy{ID: id, Name: id, Type: typ, Host: h, Port: p, Username: tp.user, Password: tp.pass}
}

func roundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("hello sentinel")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 14)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello sentinel" {
		t.Fatalf("echo failed: %q %v", buf, err)
	}
}

func TestEveryProtocolAndChain(t *testing.T) {
	echo := echoServer(t)
	eh, ep := hostPort(t, echo)
	target := Addr{Host: eh, Port: uint16(ep)}
	open := startTestProxy(t, "", "")
	authed := startTestProxy(t, "alice", "s3cret")

	p := config.NewProfile("t")
	p.Proxies = []config.Proxy{
		mkProxy(t, "s5", config.SOCKS5, authed),
		mkProxy(t, "s4", config.SOCKS4, open),
		mkProxy(t, "s4a", config.SOCKS4A, open),
		mkProxy(t, "http", config.HTTP, authed),
	}
	p.Chains = []config.Chain{{ID: "ch", Name: "Chain", Mode: config.ModeChain, Members: []string{"s5", "http", "s4a"}}}
	r, err := NewRouter(p, NewHealth(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, id := range []string{"s5", "s4", "s4a", "http", "ch"} {
		c, path, err := r.Route(id).Dial(ctx, target)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		roundTrip(t, c)
		c.Close()
		if id == "ch" && strings.Join(path, ",") != "s5,http,s4a" {
			t.Fatalf("path %v", path)
		}
	}
	// SOCKS4a sends hostnames; SOCKS4 must resolve locally.
	c, _, err := r.Route("s4a").Dial(ctx, Addr{Host: "localhost", Port: uint16(ep)})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	drain(open.seen)
}

func drain(ch chan string) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func TestAuthFailure(t *testing.T) {
	authed := startTestProxy(t, "alice", "s3cret")
	p := config.NewProfile("t")
	bad := mkProxy(t, "s5", config.SOCKS5, authed)
	bad.Password = "wrong"
	badHTTP := mkProxy(t, "h", config.HTTP, authed)
	badHTTP.Password = "wrong"
	p.Proxies = []config.Proxy{bad, badHTTP}
	r, _ := NewRouter(p, NewHealth(), Options{})
	for _, id := range []string{"s5", "h"} {
		_, _, err := r.Route(id).Dial(context.Background(), Addr{Host: "127.0.0.1", Port: 1})
		if !errors.Is(err, ErrAuth) {
			t.Fatalf("%s: want ErrAuth, got %v", id, err)
		}
	}
}

func TestFailoverGroup(t *testing.T) {
	echo := echoServer(t)
	eh, ep := hostPort(t, echo)
	good := startTestProxy(t, "", "")
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()
	dh, dp := hostPort(t, deadAddr)

	p := config.NewProfile("t")
	p.Proxies = []config.Proxy{
		{ID: "dead", Name: "dead", Type: config.SOCKS5, Host: dh, Port: dp},
		mkProxy(t, "good", config.SOCKS5, good),
	}
	p.Chains = []config.Chain{{ID: "g", Name: "G", Mode: config.ModeFailover, Members: []string{"dead", "good"}}}
	h := NewHealth()
	r, err := NewRouter(p, h, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, path, err := r.Route("g").Dial(ctx, Addr{Host: eh, Port: uint16(ep)})
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, c)
	c.Close()
	if path[0] != "good" || !h.IsDown("dead") {
		t.Fatalf("path=%v down=%v", path, h.IsDown("dead"))
	}
	// The dead member is now skipped first.
	if got := r.Route("g").(*groupRoute).Candidates()[0].ID(); got != "good" {
		t.Fatalf("first candidate %s", got)
	}
	// A refused target is not the proxy's fault: no failover, no health hit.
	_, _, err = r.Route("g").Dial(ctx, Addr{Host: dh, Port: uint16(dp)})
	var te *TargetError
	if !errors.As(err, &te) || h.IsDown("good") {
		t.Fatalf("want TargetError, got %v (good down=%v)", err, h.IsDown("good"))
	}
}

func TestSOCKS5UDP(t *testing.T) {
	// UDP echo target.
	u, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer u.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := u.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			u.WriteToUDPAddrPort(buf[:n], a)
		}
	}()
	tp := startTestProxy(t, "bob", "pw")
	p := config.NewProfile("t")
	p.Proxies = []config.Proxy{mkProxy(t, "s5", config.SOCKS5, tp), mkProxy(t, "h", config.HTTP, tp)}
	r, _ := NewRouter(p, NewHealth(), Options{})
	if _, _, err := r.Route("h").ListenPacket(context.Background()); !errors.Is(err, ErrUDPUnsupported) {
		t.Fatalf("http UDP: %v", err)
	}
	pc, _, err := r.Route("s5").ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	dst := u.LocalAddr().(*net.UDPAddr).AddrPort()
	if _, err := pc.WriteTo([]byte("ping"), AddrFromAddrPort(dst)); err != nil {
		t.Fatal(err)
	}
	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 100)
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "ping" || from.Port() != dst.Port() {
		t.Fatalf("got %q from %v err %v", buf[:n], from, err)
	}
}

func TestCheck(t *testing.T) {
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(ln)
	defer srv.Close()
	tp := startTestProxy(t, "", "")
	p := config.NewProfile("t")
	p.Proxies = []config.Proxy{mkProxy(t, "s5", config.SOCKS5, tp)}
	r, _ := NewRouter(p, NewHealth(), Options{})
	res := Check(context.Background(), r.Route("s5"), r.Base, CheckOptions{URL: "http://" + ln.Addr().String() + "/x", Timeout: 3 * time.Second})
	if !res.OK || len(res.Stages) != 3 {
		t.Fatalf("%+v", res)
	}
}
