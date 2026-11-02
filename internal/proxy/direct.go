package proxy

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

// Dialer opens TCP connections.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// SocketControl, when set, is applied to every socket SentinelProxy opens
// itself. Interceptors use it to mark the engine's own traffic so it is never
// captured again (for example SO_MARK on Linux).
var socketControl atomic.Pointer[func(network, address string, c syscall.RawConn) error]

// SetSocketControl installs (or clears with nil) the socket control hook.
func SetSocketControl(fn func(network, address string, c syscall.RawConn) error) {
	if fn == nil {
		socketControl.Store(nil)
		return
	}
	socketControl.Store(&fn)
}

func control(network, address string, c syscall.RawConn) error {
	if fn := socketControl.Load(); fn != nil {
		return (*fn)(network, address, c)
	}
	return nil
}

// Direct dials without a proxy. Hostnames are resolved with Resolver.
type Direct struct {
	Resolver Resolver
}

// DialContext implements Dialer.
func (d *Direct) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, perr := netip.ParseAddr(host); perr != nil && d.Resolver != nil {
		ips, err := d.Resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		var lastErr error
		for _, ip := range sortV4First(ips) {
			c, err := d.dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return c, nil
			}
			lastErr = err
			if ctx.Err() != nil {
				break
			}
		}
		return nil, lastErr
	}
	return d.dial(ctx, network, address)
}

func (d *Direct) dial(ctx context.Context, network, address string) (net.Conn, error) {
	nd := net.Dialer{Control: control, KeepAlive: 30 * time.Second}
	return nd.DialContext(ctx, network, address)
}

// ListenUDP opens an unconnected UDP socket for direct datagrams.
func (d *Direct) ListenUDP() (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: control}
	pc, err := lc.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

func sortV4First(ips []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			out = append(out, ip)
		}
	}
	for _, ip := range ips {
		if !ip.Unmap().Is4() {
			out = append(out, ip)
		}
	}
	return out
}
