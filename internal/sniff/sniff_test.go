package sniff

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func clientHello(t *testing.T, sni string) []byte {
	a, b := net.Pipe()
	go func() {
		c := tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		c.Handshake()
	}()
	buf := make([]byte, 16384)
	b.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := io.ReadAtLeast(b, buf, 5)
	// Read the rest of the record(s).
	for {
		b.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		m, err := b.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	a.Close()
	b.Close()
	return buf[:n]
}

func TestTLSServerName(t *testing.T) {
	hello := clientHello(t, "Www.Example.COM")
	if h, err := TLSServerName(hello); err != nil || h != "www.example.com" {
		t.Fatalf("got %q %v", h, err)
	}
	if _, err := TLSServerName(hello[:40]); err != ErrNeedMore {
		t.Fatalf("partial: %v", err)
	}
	// Split into two TLS records.
	body := hello[5:]
	cut := len(body) / 2
	rec := func(p []byte) []byte {
		return append([]byte{0x16, 3, 1, byte(len(p) >> 8), byte(len(p))}, p...)
	}
	split := append(rec(body[:cut]), rec(body[cut:])...)
	if h, err := TLSServerName(split); err != nil || h != "www.example.com" {
		t.Fatalf("split: %q %v", h, err)
	}
}

func TestHTTPHost(t *testing.T) {
	cases := map[string]string{
		"GET / HTTP/1.1\r\nHost: example.org:8080\r\nUser-Agent: x\r\n\r\n": "example.org",
		"POST /a HTTP/1.1\r\nhost: API.test\r\n\r\n":                        "api.test",
	}
	for in, want := range cases {
		if h, err := HTTPHost([]byte(in)); err != nil || h != want {
			t.Errorf("%q: %q %v", in, h, err)
		}
	}
	if _, err := HTTPHost([]byte("GE")); err != ErrNeedMore {
		t.Error("prefix should need more")
	}
	if _, err := HTTPHost([]byte("SSH-2.0-OpenSSH")); err != ErrNotFound {
		t.Error("ssh is not http")
	}
}

func TestPeekReplays(t *testing.T) {
	a, b := net.Pipe()
	go func() { a.Write([]byte("GET / HTTP/1.1\r\nHost: h.io\r\n\r\nBODY")); a.Close() }()
	res, c := Peek(b, time.Second)
	if res.Host != "h.io" || res.Protocol != "http" {
		t.Fatalf("%+v", res)
	}
	all, _ := io.ReadAll(c)
	if string(all) != "GET / HTTP/1.1\r\nHost: h.io\r\n\r\nBODY" {
		t.Fatalf("replay %q", all)
	}
}

func TestPeekTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	start := time.Now()
	res, _ := Peek(b, 100*time.Millisecond)
	if res.Host != "" || time.Since(start) > time.Second {
		t.Fatalf("%+v", res)
	}
}
