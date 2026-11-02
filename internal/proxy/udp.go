package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// PacketConn carries UDP datagrams to arbitrary destinations.
type PacketConn interface {
	WriteTo(p []byte, dst Addr) (int, error)
	ReadFrom(p []byte) (int, netip.AddrPort, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// directPacketConn sends datagrams straight from a local UDP socket.
type directPacketConn struct {
	*net.UDPConn
	resolver Resolver
	mu       sync.Mutex
	cache    map[string]netip.Addr
}

func (c *directPacketConn) WriteTo(p []byte, dst Addr) (int, error) {
	ip, ok := dst.IP()
	if !ok {
		c.mu.Lock()
		ip, ok = c.cache[dst.Host]
		c.mu.Unlock()
		if !ok {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var err error
			if ip, err = resolveOne(ctx, c.resolver, dst.Host); err != nil {
				return 0, err
			}
			c.mu.Lock()
			c.cache[dst.Host] = ip
			c.mu.Unlock()
		}
	}
	return c.UDPConn.WriteToUDPAddrPort(p, netip.AddrPortFrom(ip, dst.Port))
}

func (c *directPacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	n, ap, err := c.UDPConn.ReadFromUDPAddrPort(p)
	return n, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), err
}

// socks5PacketConn implements SOCKS5 UDP ASSOCIATE.
type socks5PacketConn struct {
	ctrl  net.Conn
	udp   *net.UDPConn
	relay netip.AddrPort
	once  sync.Once
	done  chan struct{}
}

func newSOCKS5PacketConn(ctx context.Context, base Dialer, p proxyEndpoint) (*socks5PacketConn, error) {
	ctrl, err := base.DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return nil, err
	}
	udp, err := (&Direct{}).ListenUDP()
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	// Tell the proxy which address we will send from; 0.0.0.0:0 is accepted
	// by most servers and is required behind NAT.
	bound, err := socks5Handshake(ctx, ctrl, cmdUDPAssociate, Addr{Host: "0.0.0.0", Port: 0}, p.user, p.pass)
	if err != nil {
		ctrl.Close()
		udp.Close()
		return nil, err
	}
	relayIP, ok := bound.IP()
	if !ok {
		relayIP, err = resolveOne(ctx, nil, bound.Host)
		if err != nil {
			ctrl.Close()
			udp.Close()
			return nil, err
		}
	}
	if relayIP.IsUnspecified() {
		// Servers often answer 0.0.0.0, meaning "the address you connected to".
		if ta, ok := ctrl.RemoteAddr().(*net.TCPAddr); ok {
			relayIP = ta.AddrPort().Addr().Unmap()
		}
	}
	c := &socks5PacketConn{ctrl: ctrl, udp: udp, relay: netip.AddrPortFrom(relayIP, bound.Port), done: make(chan struct{})}
	// The association lives as long as the TCP control connection.
	go func() {
		_, _ = io.Copy(io.Discard, ctrl)
		c.Close()
	}()
	return c, nil
}

func (c *socks5PacketConn) WriteTo(p []byte, dst Addr) (int, error) {
	hdr, err := appendSocksAddr([]byte{0, 0, 0}, dst)
	if err != nil {
		return 0, err
	}
	if _, err := c.udp.WriteToUDPAddrPort(append(hdr, p...), c.relay); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *socks5PacketConn) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	buf := make([]byte, 65535)
	for {
		n, from, err := c.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		if from.Addr().Unmap() != c.relay.Addr() || n < 4 || buf[2] != 0 {
			continue // not from the relay, or fragmented: drop
		}
		r := bytes.NewReader(buf[3:n])
		src, err := readSocksAddr(r)
		if err != nil {
			continue
		}
		ip, ok := src.IP()
		if !ok {
			continue
		}
		m := copy(p, buf[n-r.Len():n])
		return m, netip.AddrPortFrom(ip, src.Port), nil
	}
}

func (c *socks5PacketConn) SetReadDeadline(t time.Time) error { return c.udp.SetReadDeadline(t) }

func (c *socks5PacketConn) Close() error {
	c.once.Do(func() {
		close(c.done)
		c.ctrl.Close()
		c.udp.Close()
	})
	return nil
}

// ErrClosed is returned after a PacketConn is closed.
var ErrClosed = errors.New("closed")

// ---------------------------------------------------------------- server side

// ParseUDPRequest parses a SOCKS5 UDP request datagram.
func ParseUDPRequest(b []byte) (Addr, []byte, error) {
	if len(b) < 4 {
		return Addr{}, nil, fmt.Errorf("short UDP request")
	}
	if b[2] != 0 {
		return Addr{}, nil, fmt.Errorf("fragmented UDP request")
	}
	r := bytes.NewReader(b[3:])
	a, err := readSocksAddr(r)
	if err != nil {
		return Addr{}, nil, err
	}
	return a, b[len(b)-r.Len():], nil
}

// BuildUDPResponse wraps a datagram from src in a SOCKS5 UDP header.
func BuildUDPResponse(src netip.AddrPort, payload []byte) []byte {
	b, _ := appendSocksAddr([]byte{0, 0, 0}, AddrFromAddrPort(src))
	return append(b, payload...)
}
