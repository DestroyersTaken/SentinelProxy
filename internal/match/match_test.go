package match

import (
	"net/netip"
	"testing"
)

func TestWildcard(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "", true}, {"*.google.com", "www.google.com", true}, {"*.google.com", "google.com", false},
		{"a?c", "abc", true}, {"a?c", "ac", false}, {"*a*b*", "xxaxxbxx", true}, {"*a*b", "ab", true},
		{"steam*", "steamwebhelper.exe", true}, {"*.exe", "chrome.exe", true}, {"*x", "abc", false},
	}
	for _, c := range cases {
		if got := Wildcard(c.p, c.s); got != c.want {
			t.Errorf("Wildcard(%q,%q)=%v", c.p, c.s, got)
		}
	}
}

func TestAppMatcher(t *testing.T) {
	m, _ := NewAppMatcher([]string{"Chrome.exe", "steam", `"C:\Games\*"`, "discord*"})
	cases := []struct {
		a    AppInfo
		want bool
	}{
		{AppInfo{Name: "chrome.exe"}, true},
		{AppInfo{Name: "steam.exe"}, true},
		{AppInfo{Name: "steamwebhelper.exe"}, false},
		{AppInfo{Name: "x.exe", Path: `C:\Games\Foo\x.exe`}, true},
		{AppInfo{Path: `c:\games\bar.exe`}, true},
		{AppInfo{Name: "DiscordPTB.exe"}, true},
		{AppInfo{Name: "firefox.exe"}, false},
		{AppInfo{}, false},
	}
	for _, c := range cases {
		if got := m.Match(c.a); got != c.want {
			t.Errorf("Match(%+v)=%v", c.a, got)
		}
	}
	empty, _ := NewAppMatcher(nil)
	if !empty.Match(AppInfo{}) {
		t.Error("empty matcher must match anything")
	}
}

func TestHostMatcher(t *testing.T) {
	m, err := NewHostMatcher([]string{"*.google.com", ".example.org", "10.0.0.0/8", "192.168.1.10-192.168.1.20", "172.16.*.*", "exact.net", "keyword:tracker", "re:^api[0-9]+\\.svc$", "::1"})
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr
	cases := []struct {
		t    Target
		want Tri
	}{
		{Target{Domain: "mail.google.com"}, Yes},
		{Target{Domain: "google.com"}, No},
		{Target{Domain: "example.org"}, Yes},
		{Target{Domain: "a.b.example.org"}, Yes},
		{Target{Domain: "badexample.org"}, No},
		{Target{Domain: "EXACT.net."}, Yes},
		{Target{Domain: "ads.tracker.io"}, Yes},
		{Target{Domain: "api12.svc"}, Yes},
		{Target{IP: ip("10.1.2.3")}, Yes},
		{Target{IP: ip("192.168.1.15")}, Yes},
		{Target{IP: ip("192.168.1.21")}, Unknown},
		{Target{IP: ip("172.16.5.9")}, Yes},
		{Target{IP: ip("::1")}, Yes},
		{Target{Domain: "10.9.9.9"}, Yes},
		{Target{Domain: "other.com", IP: ip("10.0.0.1")}, Yes},
		{Target{Domain: "other.com", IP: ip("8.8.8.8")}, No},
		{Target{IP: ip("::ffff:10.0.0.1")}, Yes},
	}
	for _, c := range cases {
		if got := m.Match(c.t); got != c.want {
			t.Errorf("Match(%+v)=%v want %v", c.t, got, c.want)
		}
	}
	ipOnly, _ := NewHostMatcher([]string{"1.1.1.1"})
	if got := ipOnly.Match(Target{IP: ip("8.8.8.8")}); got != No {
		t.Errorf("IP-only matcher must not return Unknown, got %v", got)
	}
	if _, err := NewHostMatcher([]string{"10.0.0.0/99"}); err == nil {
		t.Error("expected error for bad prefix")
	}
}

func TestPortMatcher(t *testing.T) {
	m, err := NewPortMatcher([]string{"80", "8000-8100", " 443 "})
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[uint16]bool{80: true, 81: false, 8050: true, 443: true, 9000: false} {
		if m.Match(p) != want {
			t.Errorf("port %d", p)
		}
	}
	if _, err := NewPortMatcher([]string{"70000"}); err == nil {
		t.Error("expected error")
	}
}
