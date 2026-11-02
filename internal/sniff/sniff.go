// Package sniff extracts the destination hostname from the first bytes a
// client sends: the TLS ClientHello SNI or the HTTP Host header.
package sniff

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

// ErrNeedMore means the buffer holds an incomplete message.
var ErrNeedMore = errors.New("need more data")

// ErrNotFound means the protocol was recognised but carries no hostname, or
// the data is not TLS/HTTP at all.
var ErrNotFound = errors.New("no hostname")

// TLSServerName parses a TLS ClientHello (possibly spanning several records)
// and returns the SNI hostname.
func TLSServerName(b []byte) (string, error) {
	if len(b) < 5 {
		return "", ErrNeedMore
	}
	if b[0] != 0x16 || b[1] != 3 {
		return "", ErrNotFound
	}
	// Reassemble handshake data from consecutive handshake records.
	var hs []byte
	rest := b
	for len(rest) >= 5 && rest[0] == 0x16 {
		n := int(binary.BigEndian.Uint16(rest[3:5]))
		if len(rest) < 5+n {
			hs = append(hs, rest[5:]...)
			rest = nil
			break
		}
		hs = append(hs, rest[5:5+n]...)
		rest = rest[5+n:]
		if len(hs) >= 4 && len(hs) >= 4+int(uint32(hs[1])<<16|uint32(hs[2])<<8|uint32(hs[3])) {
			break
		}
	}
	if len(hs) < 4 {
		return "", ErrNeedMore
	}
	if hs[0] != 1 { // client_hello
		return "", ErrNotFound
	}
	msgLen := int(uint32(hs[1])<<16 | uint32(hs[2])<<8 | uint32(hs[3]))
	if len(hs) < 4+msgLen {
		return "", ErrNeedMore
	}
	p := hs[4 : 4+msgLen]
	// version(2) random(32)
	if len(p) < 34 {
		return "", ErrNotFound
	}
	p = p[34:]
	skip := func(lenBytes int) bool {
		if len(p) < lenBytes {
			return false
		}
		n := 0
		for i := 0; i < lenBytes; i++ {
			n = n<<8 | int(p[i])
		}
		if len(p) < lenBytes+n {
			return false
		}
		p = p[lenBytes+n:]
		return true
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return "", ErrNotFound
	}
	if len(p) < 2 {
		return "", ErrNotFound
	}
	ext := p[2:]
	if n := int(binary.BigEndian.Uint16(p)); n < len(ext) {
		ext = ext[:n]
	}
	for len(ext) >= 4 {
		typ := binary.BigEndian.Uint16(ext)
		n := int(binary.BigEndian.Uint16(ext[2:]))
		if len(ext) < 4+n {
			return "", ErrNotFound
		}
		data := ext[4 : 4+n]
		ext = ext[4+n:]
		if typ != 0 || len(data) < 2 {
			continue
		}
		list := data[2:]
		for len(list) >= 3 {
			nt := list[0]
			nl := int(binary.BigEndian.Uint16(list[1:]))
			if len(list) < 3+nl {
				break
			}
			if nt == 0 {
				name := strings.ToLower(string(list[3 : 3+nl]))
				if validHost(name) {
					return name, nil
				}
			}
			list = list[3+nl:]
		}
	}
	return "", ErrNotFound
}

var httpMethods = []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "}

// HTTPHost returns the Host header of an HTTP/1.x request.
func HTTPHost(b []byte) (string, error) {
	isHTTP := false
	for _, m := range httpMethods {
		if len(b) < len(m) {
			if bytes.HasPrefix([]byte(m), b) {
				return "", ErrNeedMore
			}
			continue
		}
		if bytes.HasPrefix(b, []byte(m)) {
			isHTTP = true
			break
		}
	}
	if !isHTTP {
		return "", ErrNotFound
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	head := b
	if end >= 0 {
		head = b[:end]
	}
	for _, line := range bytes.Split(head, []byte("\r\n"))[1:] {
		k, v, ok := bytes.Cut(line, []byte(":"))
		if ok && strings.EqualFold(string(bytes.TrimSpace(k)), "host") {
			h := strings.ToLower(strings.TrimSpace(string(v)))
			if host, _, err := net.SplitHostPort(h); err == nil {
				h = host
			}
			h = strings.Trim(h, "[]")
			if validHost(h) {
				return h, nil
			}
			return "", ErrNotFound
		}
	}
	if end < 0 && len(b) < 8192 {
		return "", ErrNeedMore
	}
	return "", ErrNotFound
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == ':') {
			return false
		}
	}
	return true
}

// Result describes what was sniffed.
type Result struct {
	Host     string
	Protocol string // "tls", "http" or ""
}

// Detect inspects a buffer.
func Detect(b []byte) (Result, error) {
	if len(b) == 0 {
		return Result{}, ErrNeedMore
	}
	if b[0] == 0x16 {
		h, err := TLSServerName(b)
		return Result{Host: h, Protocol: "tls"}, err
	}
	h, err := HTTPHost(b)
	if err == ErrNotFound {
		return Result{}, err
	}
	return Result{Host: h, Protocol: "http"}, err
}

// Peek reads the client's first bytes (up to wait) without consuming them:
// the returned conn replays everything that was read.
func Peek(c net.Conn, wait time.Duration) (Result, net.Conn) {
	buf := make([]byte, 0, 4096)
	deadline := time.Now().Add(wait)
	_ = c.SetReadDeadline(deadline)
	defer c.SetReadDeadline(time.Time{})
	var res Result
	tmp := make([]byte, 4096)
	for len(buf) < 16384 {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if n > 0 {
			r, derr := Detect(buf)
			if derr != ErrNeedMore {
				res = r
				if derr != nil {
					res.Host = ""
				}
				break
			}
		}
		if err != nil {
			break
		}
	}
	return res, &replayConn{Conn: c, pending: buf}
}

type replayConn struct {
	net.Conn
	pending []byte
}

func (r *replayConn) Read(p []byte) (int, error) {
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		r.pending = r.pending[n:]
		return n, nil
	}
	return r.Conn.Read(p)
}

// CloseWrite forwards half-close when supported.
func (r *replayConn) CloseWrite() error {
	if cw, ok := r.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
