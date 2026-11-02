package importexport

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
)

var schemeTypes = map[string]config.ProxyType{
	"socks5": config.SOCKS5, "socks5h": config.SOCKS5, "socks": config.SOCKS5,
	"socks4": config.SOCKS4, "socks4a": config.SOCKS4A,
	"http": config.HTTP, "https": config.HTTPS,
}

// ParseProxyLine parses one proxy in any common notation. defType is used
// when the line has no scheme.
func ParseProxyLine(line string, defType config.ProxyType) (config.Proxy, error) {
	line = strings.TrimSpace(line)
	p := config.Proxy{Type: defType}
	if i := strings.Index(line, "://"); i > 0 {
		u, err := url.Parse(line)
		if err != nil {
			return p, err
		}
		t, ok := schemeTypes[strings.ToLower(u.Scheme)]
		if !ok {
			return p, fmt.Errorf("unsupported scheme %q", u.Scheme)
		}
		p.Type = t
		p.Host = u.Hostname()
		port, _ := strconv.Atoi(u.Port())
		p.Port = port
		if u.User != nil {
			p.Username = u.User.Username()
			p.Password, _ = u.User.Password()
		}
		p.Name = u.Fragment
		if strings.EqualFold(u.Scheme, "socks5") && u.Query().Get("remote_dns") == "0" {
			p.LocalDNS = true
		}
		if p.Port == 0 {
			p.Port = p.Type.DefaultPort()
		}
		return p, validProxy(p)
	}
	// "type host port [user pass]"
	if f := strings.Fields(line); len(f) >= 3 {
		if t, ok := schemeTypes[strings.ToLower(f[0])]; ok {
			p.Type = t
			p.Host = f[1]
			p.Port, _ = strconv.Atoi(f[2])
			if len(f) >= 5 {
				p.Username, p.Password = f[3], f[4]
			}
			return p, validProxy(p)
		}
	}
	// user:pass@host:port
	if at := strings.LastIndex(line, "@"); at > 0 {
		cred, hp := line[:at], line[at+1:]
		h, port, err := net.SplitHostPort(hp)
		if err != nil {
			return p, fmt.Errorf("bad address %q", hp)
		}
		p.Host = h
		p.Port, _ = strconv.Atoi(port)
		p.Username, p.Password, _ = strings.Cut(cred, ":")
		return p, validProxy(p)
	}
	// [v6]:port, host:port, host:port:user:pass
	if strings.HasPrefix(line, "[") {
		end := strings.Index(line, "]")
		if end < 0 {
			return p, fmt.Errorf("bad IPv6 address")
		}
		p.Host = line[1:end]
		rest := strings.Split(strings.TrimPrefix(line[end+1:], ":"), ":")
		p.Port, _ = strconv.Atoi(rest[0])
		if len(rest) >= 3 {
			p.Username, p.Password = rest[1], strings.Join(rest[2:], ":")
		}
		return p, validProxy(p)
	}
	parts := strings.Split(line, ":")
	switch {
	case len(parts) == 2:
		p.Host = parts[0]
		p.Port, _ = strconv.Atoi(parts[1])
	case len(parts) >= 4:
		p.Host = parts[0]
		p.Port, _ = strconv.Atoi(parts[1])
		p.Username = parts[2]
		p.Password = strings.Join(parts[3:], ":")
	default:
		return p, fmt.Errorf("unrecognised proxy %q", line)
	}
	return p, validProxy(p)
}

func validProxy(p config.Proxy) error {
	if p.Host == "" {
		return fmt.Errorf("missing host")
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("bad port")
	}
	return nil
}

func importList(data []byte) (*Result, error) {
	r := newResult("list")
	plain := 0
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		p, err := ParseProxyLine(line, config.SOCKS5)
		if err != nil {
			r.warn("line %d skipped: %v", i+1, err)
			continue
		}
		if !strings.Contains(line, "://") {
			if f := strings.Fields(line); len(f) < 3 || schemeTypes[strings.ToLower(f[0])] == "" {
				plain++
			}
		}
		r.Profile.Proxies = append(r.Profile.Proxies, p)
	}
	if plain > 0 {
		r.warn("%d proxies without a type were imported as SOCKS5; change the type if they are HTTP proxies.", plain)
	}
	return r, nil
}

// ProxyURI renders a proxy as a URI.
func ProxyURI(p config.Proxy) string {
	u := url.URL{Scheme: string(p.Type), Host: net.JoinHostPort(p.Host, strconv.Itoa(p.Port))}
	if p.Username != "" || p.Password != "" {
		u.User = url.UserPassword(p.Username, p.Password)
	}
	if p.Name != "" {
		u.Fragment = p.Name
	}
	return u.String()
}

func exportList(p *config.Profile) []byte {
	var b bytes.Buffer
	for _, px := range p.Proxies {
		b.WriteString(ProxyURI(px))
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func importCSV(data []byte) (*Result, error) {
	r := newResult("csv")
	cr := csv.NewReader(bytes.NewReader(data))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return r, nil
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	get := func(row []string, names ...string) string {
		for _, n := range names {
			if i, ok := col[n]; ok && i < len(row) {
				return strings.TrimSpace(row[i])
			}
		}
		return ""
	}
	start := 1
	if _, ok := col["host"]; !ok {
		if _, ok := col["server"]; !ok {
			if _, ok := col["address"]; !ok {
				// No header: name-less "host,port,user,pass" rows.
				col = map[string]int{"host": 0, "port": 1, "username": 2, "password": 3}
				start = 0
			}
		}
	}
	for i, row := range rows[start:] {
		p := config.Proxy{
			Name:     get(row, "name", "title", "label"),
			Host:     get(row, "host", "server", "address", "hostname", "ip"),
			Username: get(row, "username", "user", "login"),
			Password: get(row, "password", "pass"),
			Type:     config.SOCKS5,
		}
		if t, ok := schemeTypes[strings.ToLower(get(row, "type", "protocol", "scheme"))]; ok {
			p.Type = t
		}
		p.Port, _ = strconv.Atoi(get(row, "port"))
		if err := validProxy(p); err != nil {
			r.warn("row %d skipped: %v", i+start+1, err)
			continue
		}
		r.Profile.Proxies = append(r.Profile.Proxies, p)
	}
	return r, nil
}

func exportCSV(p *config.Profile) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	w.Write([]string{"name", "type", "host", "port", "username", "password"})
	for _, px := range p.Proxies {
		w.Write([]string{px.Name, string(px.Type), px.Host, strconv.Itoa(px.Port), px.Username, px.Password})
	}
	w.Flush()
	return b.Bytes(), w.Error()
}

func importFoxy(data []byte) (*Result, error) {
	r := newResult("foxyproxy")
	var v8 struct {
		Data []struct {
			Active   *bool  `json:"active"`
			Title    string `json:"title"`
			Type     string `json:"type"`
			Hostname string `json:"hostname"`
			Port     any    `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
			ProxyDNS *bool  `json:"proxyDNS"`
		} `json:"data"`
		ProxySettings []struct {
			Title    string `json:"title"`
			Type     int    `json:"type"`
			Address  string `json:"address"`
			Port     any    `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"proxySettings"`
	}
	if err := json.Unmarshal(data, &v8); err != nil {
		return nil, fmt.Errorf("not a FoxyProxy export: %w", err)
	}
	port := func(v any) int {
		switch x := v.(type) {
		case float64:
			return int(x)
		case string:
			n, _ := strconv.Atoi(x)
			return n
		}
		return 0
	}
	for _, d := range v8.Data {
		t, ok := schemeTypes[strings.ToLower(d.Type)]
		if !ok {
			r.warn("%q skipped: type %q is not a proxy SentinelProxy can use", d.Title, d.Type)
			continue
		}
		p := config.Proxy{Name: d.Title, Type: t, Host: d.Hostname, Port: port(d.Port), Username: d.Username, Password: d.Password}
		if d.ProxyDNS != nil && !*d.ProxyDNS {
			p.LocalDNS = true
		}
		if validProxy(p) == nil {
			r.Profile.Proxies = append(r.Profile.Proxies, p)
		}
	}
	v7types := map[int]config.ProxyType{1: config.HTTP, 2: config.HTTPS, 3: config.SOCKS5, 4: config.SOCKS4}
	for _, d := range v8.ProxySettings {
		t, ok := v7types[d.Type]
		if !ok {
			continue
		}
		p := config.Proxy{Name: d.Title, Type: t, Host: d.Address, Port: port(d.Port), Username: d.Username, Password: d.Password}
		if validProxy(p) == nil {
			r.Profile.Proxies = append(r.Profile.Proxies, p)
		}
	}
	return r, nil
}
