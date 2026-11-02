// Package match implements the condition matchers used by rules: application
// names/paths, destination hosts/IPs and ports.
package match

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Tri is a three-valued match result. Unknown means the answer depends on
// information that is not available yet (typically the hostname of a
// connection that so far is only known by IP).
type Tri uint8

const (
	No Tri = iota
	Yes
	Unknown
)

// Wildcard reports whether s matches pattern, where * matches any run of
// characters and ? matches exactly one. Both inputs must already be
// lower-cased by the caller when case-insensitivity is wanted.
func Wildcard(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			star = p
			mark = i
			p++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func hasWild(s string) bool { return strings.ContainsAny(s, "*?") }

// ---------------------------------------------------------------- apps

// AppInfo identifies the process that owns a connection.
type AppInfo struct {
	Name string // executable base name, e.g. "chrome.exe"
	Path string // full path when known
	PID  uint32
}

type appPattern struct {
	pat      string
	fullPath bool
	noExt    bool // pattern like "chrome" also matches "chrome.exe"
}

// AppMatcher matches applications. The zero value (or an empty list) matches
// everything.
type AppMatcher struct{ pats []appPattern }

// NewAppMatcher compiles application patterns.
func NewAppMatcher(patterns []string) (*AppMatcher, error) {
	m := &AppMatcher{}
	for _, raw := range patterns {
		p := strings.ToLower(strings.TrimSpace(strings.Trim(raw, `"`)))
		if p == "" {
			continue
		}
		p = strings.ReplaceAll(p, `\`, "/")
		ap := appPattern{pat: p, fullPath: strings.Contains(p, "/")}
		if !ap.fullPath && !hasWild(p) && !strings.Contains(p, ".") {
			ap.noExt = true
		}
		m.pats = append(m.pats, ap)
	}
	return m, nil
}

// Empty reports whether the matcher has no conditions.
func (m *AppMatcher) Empty() bool { return m == nil || len(m.pats) == 0 }

// Match tests an application. An unknown application (no name and no path)
// only matches an empty matcher.
func (m *AppMatcher) Match(a AppInfo) bool {
	if m.Empty() {
		return true
	}
	name := strings.ToLower(a.Name)
	path := strings.ToLower(strings.ReplaceAll(a.Path, `\`, "/"))
	if name == "" && path != "" {
		name = path[strings.LastIndex(path, "/")+1:]
	}
	if name == "" {
		return false
	}
	for _, p := range m.pats {
		if p.fullPath {
			if path != "" && Wildcard(p.pat, path) {
				return true
			}
			continue
		}
		if Wildcard(p.pat, name) {
			return true
		}
		if p.noExt {
			if i := strings.LastIndex(name, "."); i > 0 && name[:i] == p.pat {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------- hosts

type hostKind uint8

const (
	hkAny hostKind = iota
	hkPrefix
	hkRange
	hkIPGlob
	hkDomainExact
	hkDomainSuffix // example.com and *.example.com
	hkDomainGlob
	hkKeyword
	hkRegex
)

type hostPattern struct {
	kind   hostKind
	prefix netip.Prefix
	lo, hi netip.Addr
	s      string
	re     *regexp.Regexp
}

func (h hostPattern) isIP() bool {
	return h.kind == hkPrefix || h.kind == hkRange || h.kind == hkIPGlob
}

// HostMatcher matches destinations by hostname and/or IP address.
type HostMatcher struct {
	pats      []hostPattern
	hasDomain bool
	hasAny    bool
}

// Target describes a destination. Domain may be empty when only the IP is
// known; IP may be invalid when only the domain is known.
type Target struct {
	Domain string
	IP     netip.Addr
	Port   uint16
}

var ipGlobRe = regexp.MustCompile(`^[0-9*?]{1,3}(\.[0-9*?]{1,3}){3}$`)

// ParseHostPattern validates a single host pattern and describes its kind.
func ParseHostPattern(raw string) (string, error) {
	h, err := parseHost(raw)
	if err != nil {
		return "", err
	}
	return [...]string{"any", "network", "ip range", "ip wildcard", "domain", "domain + subdomains", "domain wildcard", "keyword", "regex"}[h.kind], nil
}

func parseHost(raw string) (hostPattern, error) {
	s := strings.ToLower(strings.TrimSpace(strings.Trim(raw, `"`)))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return hostPattern{}, fmt.Errorf("empty host pattern")
	}
	if s == "*" {
		return hostPattern{kind: hkAny}, nil
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	switch {
	case strings.HasPrefix(s, "re:"), strings.HasPrefix(s, "regex:"):
		expr := s[strings.Index(s, ":")+1:]
		re, err := regexp.Compile(expr)
		if err != nil {
			return hostPattern{}, fmt.Errorf("bad regex %q: %v", expr, err)
		}
		return hostPattern{kind: hkRegex, re: re}, nil
	case strings.HasPrefix(s, "keyword:"):
		return hostPattern{kind: hkKeyword, s: strings.TrimPrefix(s, "keyword:")}, nil
	case strings.HasPrefix(s, "domain:"):
		return hostPattern{kind: hkDomainSuffix, s: strings.TrimPrefix(s, "domain:")}, nil
	case strings.HasPrefix(s, "+."):
		return hostPattern{kind: hkDomainSuffix, s: s[2:]}, nil
	case strings.HasPrefix(s, ".") && len(s) > 1:
		return hostPattern{kind: hkDomainSuffix, s: s[1:]}, nil
	}
	if strings.Contains(s, "/") {
		pf, err := netip.ParsePrefix(s)
		if err != nil {
			return hostPattern{}, fmt.Errorf("bad network %q", raw)
		}
		return hostPattern{kind: hkPrefix, prefix: pf.Masked()}, nil
	}
	if i := strings.Index(s, "-"); i > 0 {
		lo, err1 := netip.ParseAddr(strings.TrimSpace(s[:i]))
		hi, err2 := netip.ParseAddr(strings.TrimSpace(s[i+1:]))
		if err1 == nil && err2 == nil {
			if lo.Is4() != hi.Is4() {
				return hostPattern{}, fmt.Errorf("range %q mixes IPv4 and IPv6", raw)
			}
			if hi.Less(lo) {
				lo, hi = hi, lo
			}
			return hostPattern{kind: hkRange, lo: lo.Unmap(), hi: hi.Unmap()}, nil
		}
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		ip = ip.Unmap()
		return hostPattern{kind: hkPrefix, prefix: netip.PrefixFrom(ip, ip.BitLen())}, nil
	}
	if ipGlobRe.MatchString(s) {
		return hostPattern{kind: hkIPGlob, s: s}, nil
	}
	if hasWild(s) {
		return hostPattern{kind: hkDomainGlob, s: s}, nil
	}
	return hostPattern{kind: hkDomainExact, s: s}, nil
}

// NewHostMatcher compiles host patterns.
func NewHostMatcher(patterns []string) (*HostMatcher, error) {
	m := &HostMatcher{}
	for _, raw := range patterns {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		h, err := parseHost(raw)
		if err != nil {
			return nil, err
		}
		if h.kind == hkAny {
			m.hasAny = true
		}
		if !h.isIP() && h.kind != hkAny {
			m.hasDomain = true
		}
		m.pats = append(m.pats, h)
	}
	return m, nil
}

// Empty reports whether the matcher has no conditions.
func (m *HostMatcher) Empty() bool { return m == nil || len(m.pats) == 0 }

// NeedsDomain reports whether any pattern looks at hostnames.
func (m *HostMatcher) NeedsDomain() bool { return m != nil && m.hasDomain }

func matchDomain(h hostPattern, d string) bool {
	switch h.kind {
	case hkDomainExact:
		return d == h.s
	case hkDomainSuffix:
		return d == h.s || strings.HasSuffix(d, "."+h.s)
	case hkDomainGlob:
		return Wildcard(h.s, d)
	case hkKeyword:
		return strings.Contains(d, h.s)
	case hkRegex:
		return h.re.MatchString(d)
	}
	return false
}

func matchIP(h hostPattern, ip netip.Addr) bool {
	switch h.kind {
	case hkPrefix:
		return h.prefix.Contains(ip)
	case hkRange:
		return ip.Is4() == h.lo.Is4() && !ip.Less(h.lo) && !h.hi.Less(ip)
	case hkIPGlob:
		return ip.Is4() && Wildcard(h.s, ip.String())
	}
	return false
}

// Match tests a target. It returns Unknown only when no pattern matched, the
// domain is not known yet and at least one domain pattern could still match.
func (m *HostMatcher) Match(t Target) Tri {
	if m.Empty() || m.hasAny {
		return Yes
	}
	domain := strings.TrimSuffix(strings.ToLower(t.Domain), ".")
	ip := t.IP.Unmap()
	if domain != "" {
		if lit, err := netip.ParseAddr(strings.Trim(domain, "[]")); err == nil {
			if !ip.IsValid() {
				ip = lit.Unmap()
			}
			domain = ""
		}
	}
	for _, h := range m.pats {
		if h.isIP() {
			if ip.IsValid() && matchIP(h, ip) {
				return Yes
			}
			continue
		}
		if domain != "" && matchDomain(h, domain) {
			return Yes
		}
	}
	if domain == "" && m.hasDomain {
		return Unknown
	}
	return No
}

// ---------------------------------------------------------------- ports

type portRange struct{ lo, hi uint16 }

// PortMatcher matches destination ports.
type PortMatcher struct{ ranges []portRange }

// NewPortMatcher compiles port patterns ("80", "8000-9000", "*").
func NewPortMatcher(patterns []string) (*PortMatcher, error) {
	m := &PortMatcher{}
	for _, raw := range patterns {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if s == "*" {
			return &PortMatcher{}, nil
		}
		lo, hi, found := strings.Cut(s, "-")
		a, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		b := a
		if found {
			if b, err = parsePort(hi); err != nil {
				return nil, err
			}
		}
		if b < a {
			a, b = b, a
		}
		m.ranges = append(m.ranges, portRange{a, b})
	}
	return m, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return uint16(n), nil
}

// Empty reports whether the matcher has no conditions.
func (m *PortMatcher) Empty() bool { return m == nil || len(m.ranges) == 0 }

// Match tests a port.
func (m *PortMatcher) Match(port uint16) bool {
	if m.Empty() {
		return true
	}
	for _, r := range m.ranges {
		if port >= r.lo && port <= r.hi {
			return true
		}
	}
	return false
}
