package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

const (
	socks5Version = 5
	socks4Version = 4

	cmdConnect      = 1
	cmdBind         = 2
	cmdUDPAssociate = 3

	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4

	authNone     = 0
	authPassword = 2
	authNoAccept = 0xff
)

var socks5Errors = map[byte]string{
	1: "general SOCKS server failure",
	2: "connection not allowed by ruleset",
	3: "network unreachable",
	4: "host unreachable",
	5: "connection refused",
	6: "TTL expired",
	7: "command not supported",
	8: "address type not supported",
}

// ErrAuth is returned when a proxy rejects credentials.
var ErrAuth = errors.New("proxy authentication failed")

// appendSocksAddr encodes ATYP+ADDR+PORT.
func appendSocksAddr(b []byte, a Addr) ([]byte, error) {
	if ip, ok := a.IP(); ok {
		if ip.Is4() {
			b = append(b, atypIPv4)
			v := ip.As4()
			b = append(b, v[:]...)
		} else {
			b = append(b, atypIPv6)
			v := ip.As16()
			b = append(b, v[:]...)
		}
	} else {
		if len(a.Host) > 255 {
			return nil, fmt.Errorf("hostname too long")
		}
		b = append(b, atypDomain, byte(len(a.Host)))
		b = append(b, a.Host...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port), nil
}

// readSocksAddr decodes ATYP+ADDR+PORT from r.
func readSocksAddr(r io.Reader) (Addr, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return Addr{}, err
	}
	var host string
	switch t[0] {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Addr{}, err
		}
		host = netip.AddrFrom4(b).String()
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Addr{}, err
		}
		host = netip.AddrFrom16(b).Unmap().String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Addr{}, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return Addr{}, err
		}
		host = string(b)
	default:
		return Addr{}, fmt.Errorf("unknown SOCKS address type %d", t[0])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return Addr{}, err
	}
	return Addr{Host: host, Port: binary.BigEndian.Uint16(p[:])}, nil
}

// socks5Handshake negotiates auth and sends a command. It returns the bound
// address from the reply.
func socks5Handshake(ctx context.Context, conn net.Conn, cmd byte, target Addr, user, pass string) (Addr, error) {
	defer withDeadline(ctx, conn)()
	methods := []byte{authNone}
	if user != "" || pass != "" {
		methods = []byte{authPassword, authNone}
	}
	if _, err := conn.Write(append([]byte{socks5Version, byte(len(methods))}, methods...)); err != nil {
		return Addr{}, err
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		return Addr{}, fmt.Errorf("reading SOCKS5 greeting: %w", err)
	}
	if sel[0] != socks5Version {
		return Addr{}, fmt.Errorf("not a SOCKS5 proxy (version byte %d)", sel[0])
	}
	switch sel[1] {
	case authNone:
	case authPassword:
		if len(user) > 255 || len(pass) > 255 {
			return Addr{}, fmt.Errorf("username or password too long")
		}
		req := []byte{1, byte(len(user))}
		req = append(req, user...)
		req = append(req, byte(len(pass)))
		req = append(req, pass...)
		if _, err := conn.Write(req); err != nil {
			return Addr{}, err
		}
		var st [2]byte
		if _, err := io.ReadFull(conn, st[:]); err != nil {
			return Addr{}, err
		}
		if st[1] != 0 {
			return Addr{}, ErrAuth
		}
	case authNoAccept:
		if user == "" {
			return Addr{}, fmt.Errorf("%w: the proxy requires a username and password", ErrAuth)
		}
		return Addr{}, fmt.Errorf("%w: no acceptable authentication method", ErrAuth)
	default:
		return Addr{}, fmt.Errorf("proxy chose unsupported auth method %d", sel[1])
	}
	req := []byte{socks5Version, cmd, 0}
	req, err := appendSocksAddr(req, target)
	if err != nil {
		return Addr{}, err
	}
	if _, err := conn.Write(req); err != nil {
		return Addr{}, err
	}
	var hdr [3]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return Addr{}, fmt.Errorf("reading SOCKS5 reply: %w", err)
	}
	if hdr[1] != 0 {
		msg := socks5Errors[hdr[1]]
		if msg == "" {
			msg = "error " + strconv.Itoa(int(hdr[1]))
		}
		return Addr{}, fmt.Errorf("proxy: %s", msg)
	}
	return readSocksAddr(conn)
}

// socks4Handshake performs a SOCKS4 or SOCKS4a CONNECT. For plain SOCKS4 the
// target must already be an IPv4 address.
func socks4Handshake(ctx context.Context, conn net.Conn, target Addr, user string, v4a bool) error {
	defer withDeadline(ctx, conn)()
	req := []byte{socks4Version, cmdConnect}
	req = binary.BigEndian.AppendUint16(req, target.Port)
	ip, isIP := target.IP()
	switch {
	case isIP && ip.Is4():
		v := ip.As4()
		req = append(req, v[:]...)
	case isIP:
		return fmt.Errorf("SOCKS4 cannot reach IPv6 address %s", ip)
	case v4a:
		req = append(req, 0, 0, 0, 1)
	default:
		return fmt.Errorf("SOCKS4 needs an IPv4 address")
	}
	req = append(req, user...)
	req = append(req, 0)
	if !isIP {
		req = append(req, target.Host...)
		req = append(req, 0)
	}
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var rep [8]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		return fmt.Errorf("reading SOCKS4 reply: %w", err)
	}
	switch rep[1] {
	case 90:
		return nil
	case 92, 93:
		return fmt.Errorf("%w: SOCKS4 identd check failed", ErrAuth)
	default:
		return fmt.Errorf("proxy: SOCKS4 request rejected (code %d)", rep[1])
	}
}

// ---------------------------------------------------------------- server side

// ServerRequest is a parsed client request on the local proxy listener.
type ServerRequest struct {
	Version int // 4 or 5
	Command byte
	Target  Addr
	User    string
}

// Credentials authenticates local proxy clients. A nil func accepts anyone.
type Credentials func(user, pass string) bool

// ServeSOCKS5 reads a SOCKS5 greeting and request (the version byte must
// already have been consumed by the caller).
func ServeSOCKS5(rw io.ReadWriter, auth Credentials) (*ServerRequest, error) {
	var n [1]byte
	if _, err := io.ReadFull(rw, n[:]); err != nil {
		return nil, err
	}
	methods := make([]byte, n[0])
	if _, err := io.ReadFull(rw, methods); err != nil {
		return nil, err
	}
	want := byte(authNone)
	if auth != nil {
		want = authPassword
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
		}
	}
	if !ok {
		_, _ = rw.Write([]byte{socks5Version, authNoAccept})
		return nil, fmt.Errorf("client offered no acceptable auth method")
	}
	if _, err := rw.Write([]byte{socks5Version, want}); err != nil {
		return nil, err
	}
	req := &ServerRequest{Version: 5}
	if want == authPassword {
		var h [2]byte
		if _, err := io.ReadFull(rw, h[:]); err != nil {
			return nil, err
		}
		u := make([]byte, h[1])
		if _, err := io.ReadFull(rw, u); err != nil {
			return nil, err
		}
		var pl [1]byte
		if _, err := io.ReadFull(rw, pl[:]); err != nil {
			return nil, err
		}
		p := make([]byte, pl[0])
		if _, err := io.ReadFull(rw, p); err != nil {
			return nil, err
		}
		if !auth(string(u), string(p)) {
			_, _ = rw.Write([]byte{1, 1})
			return nil, ErrAuth
		}
		if _, err := rw.Write([]byte{1, 0}); err != nil {
			return nil, err
		}
		req.User = string(u)
	}
	var hdr [3]byte
	if _, err := io.ReadFull(rw, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != socks5Version {
		return nil, fmt.Errorf("bad SOCKS5 request version %d", hdr[0])
	}
	req.Command = hdr[1]
	t, err := readSocksAddr(rw)
	if err != nil {
		return nil, err
	}
	req.Target = t
	return req, nil
}

// SOCKS5Reply writes a reply with the given status and bound address.
func SOCKS5Reply(w io.Writer, status byte, bound Addr) error {
	if bound.Host == "" {
		bound = Addr{Host: "0.0.0.0"}
	}
	b, err := appendSocksAddr([]byte{socks5Version, status, 0}, bound)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// ServeSOCKS4 reads a SOCKS4/4a request (the version byte must already have
// been consumed).
func ServeSOCKS4(r io.Reader) (*ServerRequest, error) {
	var h [7]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	req := &ServerRequest{Version: 4, Command: h[0]}
	port := binary.BigEndian.Uint16(h[1:3])
	readZ := func() (string, error) {
		var out []byte
		var c [1]byte
		for len(out) < 512 {
			if _, err := io.ReadFull(r, c[:]); err != nil {
				return "", err
			}
			if c[0] == 0 {
				return string(out), nil
			}
			out = append(out, c[0])
		}
		return "", fmt.Errorf("SOCKS4 field too long")
	}
	user, err := readZ()
	if err != nil {
		return nil, err
	}
	req.User = user
	ip := netip.AddrFrom4([4]byte{h[3], h[4], h[5], h[6]})
	if h[3] == 0 && h[4] == 0 && h[5] == 0 && h[6] != 0 {
		host, err := readZ()
		if err != nil {
			return nil, err
		}
		req.Target = Addr{Host: host, Port: port}
	} else {
		req.Target = Addr{Host: ip.String(), Port: port}
	}
	return req, nil
}

// SOCKS4Reply writes a SOCKS4 reply (granted or rejected).
func SOCKS4Reply(w io.Writer, granted bool) error {
	code := byte(91)
	if granted {
		code = 90
	}
	_, err := w.Write([]byte{0, code, 0, 0, 0, 0, 0, 0})
	return err
}

// Command constants for server users.
const (
	CmdConnect      = cmdConnect
	CmdBind         = cmdBind
	CmdUDPAssociate = cmdUDPAssociate
)

// SOCKS5 reply codes.
const (
	RepSuccess         = 0
	RepGeneralFailure  = 1
	RepNotAllowed      = 2
	RepHostUnreachable = 4
	RepRefused         = 5
	RepCmdUnsupported  = 7
)
