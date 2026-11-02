// Package inbound runs the local proxy server: one port that speaks SOCKS5
// (TCP and UDP), SOCKS4/4a and HTTP (CONNECT and plain forwarding). Apps
// configured to use it get the full rule engine, including per-app rules on
// systems where the owning process can be looked up.
package inbound

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DestroyersTaken/SentinelProxy/internal/engine"
	"github.com/DestroyersTaken/SentinelProxy/internal/match"
	"github.com/DestroyersTaken/SentinelProxy/internal/procinfo"
	"github.com/DestroyersTaken/SentinelProxy/internal/proxy"
)

// Server is a running mixed proxy listener.
type Server struct {
	eng  *engine.Engine
	ln   net.Listener
	user string
	pass string
	wg   sync.WaitGroup
}

// Listen starts a mixed proxy server on addr.
func Listen(eng *engine.Engine, addr, user, pass string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{eng: eng, ln: ln, user: user, pass: pass}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

// Addr is the bound address.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Close stops accepting connections (active ones continue until done).
func (s *Server) Close() error {
	err := s.ln.Close()
	s.wg.Wait()
	return err
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
		go s.handle(c)
	}
}

func (s *Server) auth() proxy.Credentials {
	if s.user == "" && s.pass == "" {
		return nil
	}
	return func(u, p string) bool { return u == s.user && p == s.pass }
}

// appOf finds the client process when it runs on this machine.
func appOf(c net.Conn) match.AppInfo {
	ra, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return match.AppInfo{}
	}
	ap := ra.AddrPort()
	if !ap.Addr().Unmap().IsLoopback() {
		return match.AppInfo{Name: "LAN " + ap.Addr().Unmap().String()}
	}
	if app, ok := procinfo.LookupTCP(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())); ok {
		return app
	}
	return match.AppInfo{}
}

func remote(c net.Conn) netip.AddrPort {
	if ra, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		ap := ra.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

func flowFor(c net.Conn, network string, t proxy.Addr) engine.Flow {
	f := engine.Flow{Network: network, Inbound: "local-proxy", Src: remote(c), App: appOf(c), Port: t.Port}
	if ip, ok := t.IP(); ok {
		f.Dst = netip.AddrPortFrom(ip, t.Port)
	} else {
		f.Domain = strings.ToLower(t.Host)
	}
	return f
}

func (s *Server) handle(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	switch first[0] {
	case 5:
		br.ReadByte()
		s.socks5(c, br)
	case 4:
		br.ReadByte()
		s.socks4(c, br)
	default:
		s.http(c, br)
	}
}

func (s *Server) socks5(c net.Conn, br *bufio.Reader) {
	rw := struct {
		io.Reader
		io.Writer
	}{br, c}
	req, err := proxy.ServeSOCKS5(rw, s.auth())
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	switch req.Command {
	case proxy.CmdConnect:
		f := flowFor(c, "tcp", req.Target)
		s.eng.HandleTCP(proxy.WrapBuffered(c, br), f, func(err error) error {
			if err != nil {
				code := byte(proxy.RepHostUnreachable)
				if engine.IsBlocked(err) {
					code = proxy.RepNotAllowed
				}
				_ = proxy.SOCKS5Reply(c, code, proxy.Addr{})
				return err
			}
			return proxy.SOCKS5Reply(c, proxy.RepSuccess, proxy.Addr{Host: "0.0.0.0"})
		})
	case proxy.CmdUDPAssociate:
		s.udpAssociate(c)
	default:
		_ = proxy.SOCKS5Reply(c, proxy.RepCmdUnsupported, proxy.Addr{})
		c.Close()
	}
}

func (s *Server) udpAssociate(c net.Conn) {
	defer c.Close()
	la := c.LocalAddr().(*net.TCPAddr)
	u, err := net.ListenUDP("udp", &net.UDPAddr{IP: la.IP})
	if err != nil {
		_ = proxy.SOCKS5Reply(c, proxy.RepGeneralFailure, proxy.Addr{})
		return
	}
	defer u.Close()
	bound := u.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := proxy.SOCKS5Reply(c, proxy.RepSuccess, proxy.AddrFromAddrPort(bound)); err != nil {
		return
	}
	clientIP := remote(c).Addr()
	app := appOf(c)
	go func() {
		buf := make([]byte, 65535)
		var mu sync.Mutex
		var client netip.AddrPort
		for {
			n, from, err := u.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			if from.Addr() != clientIP {
				continue // only the client that opened the association
			}
			mu.Lock()
			client = from
			mu.Unlock()
			dst, payload, err := proxy.ParseUDPRequest(buf[:n])
			if err != nil {
				continue
			}
			f := engine.Flow{Network: "udp", Inbound: "local-proxy", Src: from, App: app, Port: dst.Port}
			var dstAP netip.AddrPort
			if ip, ok := dst.IP(); ok {
				f.Dst = netip.AddrPortFrom(ip, dst.Port)
				dstAP = f.Dst
			} else {
				f.Domain = strings.ToLower(dst.Host)
			}
			replyFrom := dstAP
			s.eng.HandleUDP(f, payload, func(p []byte) {
				mu.Lock()
				to := client
				mu.Unlock()
				src := replyFrom
				if !src.IsValid() {
					src = netip.AddrPortFrom(netip.IPv4Unspecified(), dst.Port)
				}
				_, _ = u.WriteToUDPAddrPort(proxy.BuildUDPResponse(src, p), to)
			})
		}
	}()
	// The association ends with the TCP connection.
	_, _ = io.Copy(io.Discard, c)
}

func (s *Server) socks4(c net.Conn, br *bufio.Reader) {
	req, err := proxy.ServeSOCKS4(br)
	if err != nil || req.Command != proxy.CmdConnect {
		_ = proxy.SOCKS4Reply(c, false)
		c.Close()
		return
	}
	if s.auth() != nil {
		// SOCKS4 has no passwords; refuse when authentication is required.
		_ = proxy.SOCKS4Reply(c, false)
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	f := flowFor(c, "tcp", req.Target)
	s.eng.HandleTCP(proxy.WrapBuffered(c, br), f, func(err error) error {
		if err != nil {
			_ = proxy.SOCKS4Reply(c, false)
			return err
		}
		return proxy.SOCKS4Reply(c, true)
	})
}

func (s *Server) http(c net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	if auth := s.auth(); auth != nil {
		u, p, ok := proxy.ParseProxyAuthorization(req.Header.Get("Proxy-Authorization"))
		if !ok || !auth(u, p) {
			io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"SentinelProxy\"\r\nContent-Length: 0\r\n\r\n")
			c.Close()
			return
		}
	}
	if req.Method == http.MethodConnect {
		t, err := proxy.ParseAddr(req.Host)
		if err != nil {
			io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
			c.Close()
			return
		}
		f := flowFor(c, "tcp", t)
		s.eng.HandleTCP(proxy.WrapBuffered(c, br), f, func(err error) error {
			if err != nil {
				return writeHTTPError(c, err)
			}
			_, err = io.WriteString(c, "HTTP/1.1 200 Connection established\r\nProxy-Agent: SentinelProxy\r\n\r\n")
			return err
		})
		return
	}
	// Plain HTTP forwarding: rewrite to origin form and close after one
	// request so every request is routed (and counted) separately.
	if req.URL.Host == "" {
		io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\nThis is SentinelProxy's local proxy port.")
		c.Close()
		return
	}
	host := req.URL.Host
	port := 80
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		port, _ = strconv.Atoi(p)
	}
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.Header.Set("Connection", "close")
	req.Close = true
	req.RequestURI = ""
	var head bytes.Buffer
	if err := req.Write(&head); err != nil {
		c.Close()
		return
	}
	f := flowFor(c, "tcp", proxy.Addr{Host: host, Port: uint16(port)})
	pc := &prefixConn{Conn: c, prefix: head.Bytes(), rest: br}
	s.eng.HandleTCP(pc, f, func(err error) error {
		if err != nil {
			return writeHTTPError(c, err)
		}
		return nil
	})
}

func writeHTTPError(c net.Conn, err error) error {
	status := "502 Bad Gateway"
	if engine.IsBlocked(err) {
		status = "403 Forbidden"
	}
	body := "SentinelProxy: " + err.Error()
	fmt.Fprintf(c, "HTTP/1.1 %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, len(body), body)
	return err
}

// prefixConn reads prefix first, then the rest of the client stream.
type prefixConn struct {
	net.Conn
	prefix []byte
	rest   io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(b, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.rest.Read(b)
}

func (p *prefixConn) CloseWrite() error {
	if cw, ok := p.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
