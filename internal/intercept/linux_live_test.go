//go:build linux

package intercept

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/engine"
	"github.com/DestroyersTaken/SentinelProxy/internal/logx"
	"github.com/DestroyersTaken/SentinelProxy/internal/proxy"
)

// TestLinuxLive exercises real nftables capture. It needs root and nft and
// changes the firewall, so it only runs with SENTINEL_LIVE=1.
func TestLinuxLive(t *testing.T) {
	if os.Getenv("SENTINEL_LIVE") != "1" {
		t.Skip("set SENTINEL_LIVE=1 to run (needs root + nftables)")
	}
	var hostIP net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
			hostIP = ipn.IP
		}
	}
	if hostIP == nil {
		t.Skip("no non-loopback IPv4 address")
	}
	listen := func() net.Listener {
		ln, err := net.Listen("tcp", net.JoinHostPort(hostIP.String(), "0"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		return ln
	}
	echo := listen()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	// Upstream SOCKS5 that tags traffic so we can tell it went through it.
	up := listen()
	asked := make(chan string, 4)
	go func() {
		for {
			c, err := up.Accept()
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
				// Dial like a remote proxy would: outside the capture.
				u, err := (&proxy.Direct{}).DialContext(context.Background(), "tcp", echo.Addr().String())
				if err != nil {
					return
				}
				defer u.Close()
				proxy.SOCKS5Reply(c, 0, proxy.Addr{})
				go io.Copy(u, br)
				io.Copy(c, u)
			}()
		}
	}()
	upPort := up.Addr().(*net.TCPAddr).Port
	echoPort := echo.Addr().(*net.TCPAddr).Port

	e := engine.New(logx.New(200))
	defer e.Close()
	p := config.NewProfile("live")
	p.Rules = []config.Rule{
		{ID: "blk", Name: "Block 4444", Enabled: true, Ports: []string{"4444"}, Action: config.Action{Type: config.ActionBlock}},
		{ID: "px", Name: "Echo via upstream", Enabled: true, Ports: []string{strconv.Itoa(echoPort)}, Action: config.Action{Type: config.ActionProxy, Target: "up"}},
	}
	p.Proxies = []config.Proxy{{ID: "up", Name: "Up", Type: config.SOCKS5, Host: hostIP.String(), Port: upPort}}
	if err := e.Apply(p); err != nil {
		t.Fatal(err)
	}
	ic, err := Start(e, p.Settings)
	if err != nil {
		t.Fatal(err)
	}
	defer ic.Close()

	c, err := net.DialTimeout("tcp", echo.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("live"))
	b := make([]byte, 4)
	if _, err := io.ReadFull(c, b); err != nil || string(b) != "live" {
		t.Fatalf("echo through capture: %q %v", b, err)
	}
	c.Close()
	select {
	case got := <-asked:
		if got != echo.Addr().String() {
			t.Fatalf("upstream asked for %s", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connection did not go through the upstream proxy")
	}
	// Blocked port: connection is accepted by the relay and closed at once.
	bc, err := net.DialTimeout("tcp", net.JoinHostPort(hostIP.String(), "4444"), 3*time.Second)
	if err == nil {
		bc.SetDeadline(time.Now().Add(2 * time.Second))
		n, rerr := bc.Read(make([]byte, 1))
		if n != 0 || rerr == nil {
			t.Fatal("blocked connection stayed open")
		}
		bc.Close()
	}
	time.Sleep(100 * time.Millisecond)
	var proxied, blocked bool
	for _, v := range e.Tracker.Connections(true) {
		if v.Action == "proxy" && v.Route == "Up" && v.Up == 4 {
			proxied = true
		}
		if v.State == "blocked" && v.Port == 4444 {
			blocked = true
		}
	}
	if !proxied || !blocked {
		t.Fatalf("tracker: %+v", e.Tracker.Connections(true))
	}
	if err := ic.Close(); err != nil {
		t.Fatal(err)
	}
	_ = engine.Flow{}
}
