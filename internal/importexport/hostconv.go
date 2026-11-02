package importexport

import (
	"net/netip"
	"regexp"
	"strings"
)

// hostKind classifies a SentinelProxy host pattern for converters.
type hostForm struct {
	kind  string // exact, suffix, wildcard, keyword, regex, cidr, range, ipglob, any
	value string
}

var ipGlob = regexp.MustCompile(`^[0-9*]{1,3}(\.[0-9*]{1,3}){3}$`)

func classifyHost(h string) hostForm {
	s := strings.ToLower(strings.TrimSpace(h))
	switch {
	case s == "*":
		return hostForm{"any", ""}
	case strings.HasPrefix(s, "re:"):
		return hostForm{"regex", s[3:]}
	case strings.HasPrefix(s, "regex:"):
		return hostForm{"regex", s[6:]}
	case strings.HasPrefix(s, "keyword:"):
		return hostForm{"keyword", s[8:]}
	case strings.HasPrefix(s, "domain:"):
		return hostForm{"suffix", s[7:]}
	case strings.HasPrefix(s, "+."):
		return hostForm{"suffix", s[2:]}
	case strings.HasPrefix(s, ".") && len(s) > 1:
		return hostForm{"suffix", s[1:]}
	case strings.Contains(s, "/"):
		if pf, err := netip.ParsePrefix(s); err == nil {
			return hostForm{"cidr", pf.Masked().String()}
		}
	case strings.Count(s, "-") == 1:
		a, b, _ := strings.Cut(s, "-")
		if _, err := netip.ParseAddr(strings.TrimSpace(a)); err == nil {
			if _, err := netip.ParseAddr(strings.TrimSpace(b)); err == nil {
				return hostForm{"range", s}
			}
		}
	}
	if ip, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return hostForm{"cidr", netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()).String()}
	}
	if ipGlob.MatchString(s) && strings.Contains(s, "*") {
		return hostForm{"ipglob", s}
	}
	if strings.HasPrefix(s, "*.") && !strings.ContainsAny(s[2:], "*?") {
		return hostForm{"wildsub", s[2:]}
	}
	if strings.ContainsAny(s, "*?") {
		return hostForm{"wildcard", s}
	}
	return hostForm{"exact", s}
}

// globToRegex converts a * / ? wildcard into an anchored regex.
func globToRegex(g string) string {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range g {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return b.String()
}

// rangeToPrefixes splits an IP range into the minimal list of CIDRs.
func rangeToPrefixes(r string) []netip.Prefix {
	a, b, _ := strings.Cut(r, "-")
	lo, err1 := netip.ParseAddr(strings.TrimSpace(a))
	hi, err2 := netip.ParseAddr(strings.TrimSpace(b))
	if err1 != nil || err2 != nil || lo.Is4() != hi.Is4() {
		return nil
	}
	if hi.Less(lo) {
		lo, hi = hi, lo
	}
	var out []netip.Prefix
	for {
		bits := lo.BitLen()
		// Grow the prefix while it stays aligned and inside the range.
		for bits > 0 {
			pf := netip.PrefixFrom(lo, bits-1).Masked()
			if pf.Addr() != lo || lastAddr(pf).Compare(hi) > 0 {
				break
			}
			bits--
		}
		pf := netip.PrefixFrom(lo, bits)
		out = append(out, pf)
		last := lastAddr(pf)
		if last.Compare(hi) >= 0 || len(out) > 64 {
			return out
		}
		lo = last.Next()
	}
}

func lastAddr(pf netip.Prefix) netip.Addr {
	a := pf.Masked().Addr().AsSlice()
	bits := pf.Bits()
	for i := range a {
		for j := 0; j < 8; j++ {
			if i*8+j >= bits {
				a[i] |= 1 << (7 - j)
			}
		}
	}
	ip, _ := netip.AddrFromSlice(a)
	return ip
}

// ipGlobToPrefix turns "192.168.*.*" into 192.168.0.0/16 when the
// wildcards are trailing whole octets.
func ipGlobToPrefix(g string) (netip.Prefix, bool) {
	parts := strings.Split(g, ".")
	var b [4]byte
	bits := 0
	wild := false
	for i, p := range parts {
		if p == "*" {
			wild = true
			continue
		}
		if wild || strings.Contains(p, "*") {
			return netip.Prefix{}, false
		}
		var n int
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return netip.Prefix{}, false
		}
		b[i] = byte(n)
		bits += 8
	}
	return netip.PrefixFrom(netip.AddrFrom4(b), bits), true
}
