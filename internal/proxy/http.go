package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// bufConn returns bytes already buffered by a bufio.Reader before reading
// from the underlying connection.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite half-closes the underlying connection when it supports it.
func (c *bufConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// WrapBuffered returns conn, preserving any bytes already buffered in r.
func WrapBuffered(conn net.Conn, r *bufio.Reader) net.Conn {
	if r == nil || r.Buffered() == 0 {
		return conn
	}
	return &bufConn{Conn: conn, r: r}
}

func basicAuth(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// httpConnect issues an HTTP CONNECT through conn.
func httpConnect(ctx context.Context, conn net.Conn, target Addr, user, pass string) (net.Conn, error) {
	defer withDeadline(ctx, conn)()
	hostport := target.String()
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", hostport, hostport)
	if user != "" || pass != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: %s\r\n", basicAuth(user, pass))
	}
	b.WriteString("Proxy-Connection: Keep-Alive\r\nUser-Agent: SentinelProxy\r\n\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("reading CONNECT response: %w", err)
	}
	if resp.StatusCode == http.StatusProxyAuthRequired {
		return nil, fmt.Errorf("%w (HTTP 407)", ErrAuth)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("proxy: CONNECT %s returned %s", hostport, resp.Status)
	}
	return WrapBuffered(conn, br), nil
}

// ParseProxyAuthorization extracts Basic credentials from a header value.
func ParseProxyAuthorization(v string) (user, pass string, ok bool) {
	const prefix = "basic "
	if len(v) < len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(raw), ":")
	return user, pass, ok
}
