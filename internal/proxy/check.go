package proxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Stage is one step of a proxy check.
type Stage struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Ms     int64  `json:"ms"`
	Detail string `json:"detail,omitempty"`
}

// CheckResult is the outcome of a proxy check.
type CheckResult struct {
	ID        string   `json:"id"`
	OK        bool     `json:"ok"`
	LatencyMs int64    `json:"latencyMs"`
	ExitIP    string   `json:"exitIp,omitempty"`
	UDP       string   `json:"udp"` // "ok", "failed", "unsupported" or "skipped"
	Stages    []Stage  `json:"stages"`
	Error     string   `json:"error,omitempty"`
	Path      []string `json:"path,omitempty"`
}

// CheckOptions configures Check.
type CheckOptions struct {
	URL     string // HTTP(S) URL fetched through the route
	ExitIP  bool   // also look up the public exit IP
	UDP     bool   // also test UDP association (SOCKS5 only)
	Timeout time.Duration
}

// HTTPClient returns an http.Client whose connections go through rt.
func HTTPClient(rt Route, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			a, err := ParseAddr(address)
			if err != nil {
				return nil, err
			}
			c, _, err := rt.Dial(ctx, a)
			return c, err
		},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
	}
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Check tests a route end to end: reaching the first proxy, opening a
// tunnel, an HTTP request, optionally the exit IP and UDP support.
func Check(ctx context.Context, rt Route, base Dialer, opts CheckOptions) CheckResult {
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.URL == "" {
		opts.URL = "http://www.gstatic.com/generate_204"
	}
	res := CheckResult{ID: rt.ID(), UDP: "skipped"}
	add := func(name string, start time.Time, err error, detail string) bool {
		st := Stage{Name: name, OK: err == nil, Ms: time.Since(start).Milliseconds(), Detail: detail}
		if err != nil {
			st.Detail = err.Error()
			if res.Error == "" {
				res.Error = name + ": " + err.Error()
			}
		}
		res.Stages = append(res.Stages, st)
		return err == nil
	}

	if fh := rt.FirstHop(); fh != nil {
		start := time.Now()
		cctx, cancel := context.WithTimeout(ctx, opts.Timeout)
		c, err := base.DialContext(cctx, "tcp", fh.Address())
		cancel()
		if err == nil {
			c.Close()
		}
		if !add("Reach proxy server", start, err, fh.Address()) {
			return res
		}
	}

	u, err := url.Parse(opts.URL)
	if err != nil || u.Host == "" {
		add("Open tunnel", time.Now(), fmt.Errorf("bad check URL %q", opts.URL), "")
		return res
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443"}[u.Scheme]
		if port == "" {
			port = "80"
		}
	}
	target, _ := ParseAddr(net.JoinHostPort(u.Hostname(), port))
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	c, path, err := rt.Dial(cctx, target)
	cancel()
	res.Path = path
	if err == nil {
		c.Close()
	}
	tunnelMs := time.Since(start).Milliseconds()
	if !add("Open tunnel", start, err, "via "+strings.Join(path, " → ")) {
		return res
	}

	client := HTTPClient(rt, opts.Timeout)
	start = time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, opts.URL, nil)
	req.Header.Set("User-Agent", "SentinelProxy-Checker")
	resp, err := client.Do(req)
	detail := ""
	if err == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		detail = resp.Status
		if resp.StatusCode >= 500 {
			err = fmt.Errorf("server answered %s", resp.Status)
		}
	}
	httpMs := time.Since(start).Milliseconds()
	if !add("HTTP request", start, err, detail) {
		return res
	}
	res.OK = true
	res.LatencyMs = httpMs
	if tunnelMs > 0 && tunnelMs < httpMs {
		// Report the cheaper of the two measurements as the latency figure,
		// it is the closest to a round trip through the proxy.
		res.LatencyMs = tunnelMs
	}

	if opts.ExitIP {
		start = time.Now()
		ip, err := exitIP(ctx, client)
		res.ExitIP = ip
		add("Exit IP", start, err, ip)
		if err != nil {
			res.Error = "" // informational only
		}
	}
	if opts.UDP {
		start = time.Now()
		uctx, cancel := context.WithTimeout(ctx, opts.Timeout)
		err := checkUDP(uctx, rt)
		cancel()
		switch {
		case err == ErrUDPUnsupported:
			res.UDP = "unsupported"
		case err != nil:
			res.UDP = "failed"
			add("UDP (DNS query)", start, err, "")
			res.Error = ""
		default:
			res.UDP = "ok"
			add("UDP (DNS query)", start, nil, "1.1.1.1:53 answered")
		}
	}
	return res
}

func exitIP(ctx context.Context, c *http.Client) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org?format=json", nil)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var v struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&v); err != nil {
		return "", err
	}
	return v.IP, nil
}

// checkUDP sends a DNS query for example.com through the route.
func checkUDP(ctx context.Context, rt Route) error {
	pc, _, err := rt.ListenPacket(ctx)
	if err != nil {
		return err
	}
	defer pc.Close()
	q := []byte{0x13, 0x37, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if _, err := pc.WriteTo(q, Addr{Host: "1.1.1.1", Port: 53}); err != nil {
		return err
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(5 * time.Second)
	}
	_ = pc.SetReadDeadline(dl)
	buf := make([]byte, 1500)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("no answer: %w", err)
		}
		if n >= 12 && binary.BigEndian.Uint16(buf) == 0x1337 {
			return nil
		}
	}
}
