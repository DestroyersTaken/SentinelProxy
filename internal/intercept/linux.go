//go:build linux

package intercept

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/engine"
	"github.com/DestroyersTaken/SentinelProxy/internal/match"
	"github.com/DestroyersTaken/SentinelProxy/internal/procinfo"
	"github.com/DestroyersTaken/SentinelProxy/internal/proxy"
)

// Linux backend: an nftables "redirect" in the output hook sends every
// locally generated TCP connection to the relay, which reads the original
// destination with SO_ORIGINAL_DST. The engine's own sockets carry a
// firewall mark and are skipped. UDP is not captured on Linux (it would
// need TPROXY); use the local proxy port for UDP apps.

const (
	nftTable   = "sentinelproxy"
	bypassMark = 0x5e17
)

type linuxInterceptor struct {
	eng     *engine.Engine
	ln      net.Listener
	wg      sync.WaitGroup
	closed  atomic.Bool
	stats   struct{ packets, redirected, errors atomic.Uint64 }
	lastErr atomic.Value
}

func available() (bool, string) {
	if os.Geteuid() != 0 {
		return false, "run SentinelProxy as root (or with CAP_NET_ADMIN) to capture traffic system-wide"
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return false, "the nft command (nftables) is not installed"
	}
	return true, ""
}

func start(eng *engine.Engine, s config.Settings) (Interceptor, error) {
	if ok, why := available(); !ok {
		return nil, errors.New(why)
	}
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	proxy.SetSocketControl(func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, bypassMark)
		})
		if err != nil {
			return err
		}
		return serr
	})
	v6 := ""
	if s.InterceptIPv6 {
		v6 = "ip6 daddr { ::1, fe80::/10, ff00::/8 } return\n    meta nfproto ipv6 meta l4proto tcp redirect to :" + fmt.Sprint(port) + "\n"
	} else {
		v6 = "meta nfproto ipv6 return\n"
	}
	rules := fmt.Sprintf(`table inet %s {
  chain output {
    type nat hook output priority -100; policy accept;
    meta mark 0x%x return
    ip daddr { 127.0.0.0/8, 224.0.0.0/4, 255.255.255.255 } return
    meta nfproto ipv4 meta l4proto tcp redirect to :%d
    %s  }
}
`, nftTable, bypassMark, port, v6)
	_ = exec.Command("nft", "delete", "table", "inet", nftTable).Run()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if out, err := cmd.CombinedOutput(); err != nil {
		ln.Close()
		proxy.SetSocketControl(nil)
		return nil, fmt.Errorf("nftables: %v: %s", err, strings.TrimSpace(string(out)))
	}
	li := &linuxInterceptor{eng: eng, ln: ln}
	li.wg.Add(1)
	go li.accept()
	eng.Log.Infof("Capturing TCP system-wide with nftables (relay port %d)", port)
	return li, nil
}

func (l *linuxInterceptor) Name() string { return "nftables" }

func (l *linuxInterceptor) Stats() Stats {
	st := Stats{Packets: l.stats.packets.Load(), Redirected: l.stats.redirected.Load(), Errors: l.stats.errors.Load()}
	if v, ok := l.lastErr.Load().(string); ok {
		st.LastError = v
	}
	return st
}

func (l *linuxInterceptor) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	err := exec.Command("nft", "delete", "table", "inet", nftTable).Run()
	l.ln.Close()
	l.wg.Wait()
	proxy.SetSocketControl(nil)
	return err
}

func (l *linuxInterceptor) accept() {
	defer l.wg.Done()
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if l.closed.Load() {
				return
			}
			continue
		}
		l.stats.redirected.Add(1)
		go l.handle(c.(*net.TCPConn))
	}
}

func (l *linuxInterceptor) handle(c *net.TCPConn) {
	dst, err := originalDst(c)
	if err != nil {
		l.stats.errors.Add(1)
		l.lastErr.Store(err.Error())
		c.Close()
		return
	}
	src := c.RemoteAddr().(*net.TCPAddr).AddrPort()
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	var app match.AppInfo
	if a, ok := procinfo.LookupTCP(src); ok {
		app = a
	}
	l.eng.HandleTCP(c, engine.Flow{Network: "tcp", Inbound: "intercept", Src: src, Dst: dst, App: app}, nil)
}

// originalDst reads the pre-NAT destination of a redirected connection.
func originalDst(c *net.TCPConn) (netip.AddrPort, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var out netip.AddrPort
	var serr error
	isV6 := c.LocalAddr().(*net.TCPAddr).IP.To4() == nil
	err = rc.Control(func(fd uintptr) {
		if !isV6 {
			var sa unix.RawSockaddrInet4
			sz := uint32(unsafe.Sizeof(sa))
			_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_IP, 80 /* SO_ORIGINAL_DST */, uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&sz)), 0)
			if e != 0 {
				serr = e
				return
			}
			port := uint16(sa.Port>>8) | uint16(sa.Port<<8)
			out = netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), port)
			return
		}
		var sa unix.RawSockaddrInet6
		sz := uint32(unsafe.Sizeof(sa))
		_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_IPV6, 80 /* IP6T_SO_ORIGINAL_DST */, uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&sz)), 0)
		if e != 0 {
			serr = e
			return
		}
		port := uint16(sa.Port>>8) | uint16(sa.Port<<8)
		out = netip.AddrPortFrom(netip.AddrFrom16(sa.Addr).Unmap(), port)
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	if serr != nil {
		return netip.AddrPort{}, fmt.Errorf("SO_ORIGINAL_DST: %w", serr)
	}
	return out, nil
}
