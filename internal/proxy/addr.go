// Package proxy implements upstream proxy clients (SOCKS4/4a/5, HTTP and
// HTTPS CONNECT), chains, failover/load-balancing groups, health tracking and
// the proxy checker. It also exposes the server-side SOCKS/HTTP handshakes
// used by the local proxy listener.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Addr is a destination: Host is a hostname or an IP literal.
type Addr struct {
	Host string
	Port uint16
}

// String is host:port.
func (a Addr) String() string { return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port))) }

// IP returns the host as an IP if it is a literal.
func (a Addr) IP() (netip.Addr, bool) {
	ip, err := netip.ParseAddr(a.Host)
	return ip.Unmap(), err == nil
}

// AddrFromAddrPort converts an IP endpoint.
func AddrFromAddrPort(ap netip.AddrPort) Addr {
	return Addr{Host: ap.Addr().Unmap().String(), Port: ap.Port()}
}

// ParseAddr parses host:port.
func ParseAddr(s string) (Addr, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return Addr{}, err
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 0 || n > 65535 {
		return Addr{}, fmt.Errorf("bad port in %q", s)
	}
	return Addr{Host: h, Port: uint16(n)}, nil
}

// Resolver resolves hostnames.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ErrUDPUnsupported is returned when a route cannot carry UDP.
var ErrUDPUnsupported = errors.New("route does not support UDP")

// resolveOne resolves a hostname to one address, preferring IPv4.
func resolveOne(ctx context.Context, r Resolver, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	if r == nil {
		r = net.DefaultResolver
	}
	ips, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if ip.Unmap().Is4() {
			return ip.Unmap(), nil
		}
	}
	if len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("no addresses for %s", host)
	}
	return ips[0].Unmap(), nil
}

// withDeadline applies ctx's deadline (and cancellation) to conn until the
// returned function is called.
func withDeadline(ctx context.Context, conn net.Conn) func() {
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	return func() {
		stop()
		_ = conn.SetDeadline(time.Time{})
	}
}
