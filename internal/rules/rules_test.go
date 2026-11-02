package rules

import (
	"net/netip"
	"testing"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/match"
)

func profile() *config.Profile {
	p := config.NewProfile("t")
	p.Proxies = []config.Proxy{{ID: "px", Name: "P", Type: config.SOCKS5, Host: "h", Port: 1}}
	p.Rules = append(p.Rules,
		config.Rule{ID: "chrome", Name: "Chrome Google", Enabled: true, Apps: []string{"chrome.exe"}, Hosts: []string{"*.google.com"}, Action: config.Action{Type: config.ActionProxy, Target: "px"}},
		config.Rule{ID: "block", Name: "Block telemetry", Enabled: true, Hosts: []string{"keyword:telemetry"}, Action: config.Action{Type: config.ActionBlock}},
		config.Rule{ID: "games", Name: "Steam", Enabled: true, Apps: []string{"steam*"}, Ports: []string{"27000-27100"}, Protocol: config.ProtoUDP, Action: config.Action{Type: config.ActionProxy, Target: "px"}},
		config.Rule{ID: "off", Name: "Disabled", Enabled: false, Action: config.Action{Type: config.ActionBlock}},
	)
	return p
}

func TestDecide(t *testing.T) {
	e, errs := Compile(profile())
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	chrome := match.AppInfo{Name: "chrome.exe"}
	d := e.Decide(Meta{App: chrome, Target: match.Target{Domain: "www.google.com", Port: 443}, Network: config.ProtoTCP})
	if d.RuleID != "chrome" {
		t.Fatalf("got %+v", d)
	}
	d = e.Decide(Meta{App: chrome, Target: match.Target{IP: netip.MustParseAddr("192.168.1.1"), Port: 80}})
	if d.Index != 0 || d.Action.Type != config.ActionDirect {
		t.Fatalf("LAN should be direct, got %+v", d)
	}
	d = e.Decide(Meta{App: match.AppInfo{Name: "steam.exe"}, Target: match.Target{IP: netip.MustParseAddr("1.2.3.4"), Port: 27015}, Network: config.ProtoTCP})
	if d.RuleID != "" {
		t.Fatalf("TCP must not match UDP rule, got %+v", d)
	}
	d = e.Decide(Meta{App: match.AppInfo{Name: "steam.exe"}, Target: match.Target{IP: netip.MustParseAddr("1.2.3.4"), Port: 27015}, Network: config.ProtoUDP})
	if d.RuleID != "games" {
		t.Fatalf("got %+v", d)
	}
	e.Hit(d)
	if e.Hits()["games"] != 1 {
		t.Fatal("hit not recorded")
	}
}

func TestDecideEarly(t *testing.T) {
	e, _ := Compile(profile())
	ip := netip.MustParseAddr("142.250.1.1")
	// Chrome to an unknown host could be proxied (google) or blocked (telemetry): uncertain.
	if _, certain := e.DecideEarly(Meta{App: match.AppInfo{Name: "chrome.exe"}, Target: match.Target{IP: ip, Port: 443}}); certain {
		t.Fatal("chrome should need the hostname")
	}
	// LAN IP is decided by an IP rule first: certain.
	if d, certain := e.DecideEarly(Meta{App: match.AppInfo{Name: "chrome.exe"}, Target: match.Target{IP: netip.MustParseAddr("10.0.0.1"), Port: 443}}); !certain || d.Index != 0 {
		t.Fatalf("got %+v %v", d, certain)
	}
	// Only Direct outcomes possible: certain even with unknown hosts.
	p := config.NewProfile("t2")
	p.Rules = append(p.Rules, config.Rule{ID: "x", Enabled: true, Hosts: []string{"*.example.com"}, Action: config.Action{Type: config.ActionDirect}})
	e2, _ := Compile(p)
	if _, certain := e2.DecideEarly(Meta{Target: match.Target{IP: ip, Port: 443}}); !certain {
		t.Fatal("all-direct outcomes should be certain")
	}
}

func TestExplain(t *testing.T) {
	d, steps := Explain(profile(), Meta{App: match.AppInfo{Name: "chrome.exe"}, Target: match.Target{Domain: "a.telemetry.net", Port: 443}, Network: config.ProtoTCP})
	if d.RuleID != "block" {
		t.Fatalf("got %+v", d)
	}
	if len(steps) != 5 || !steps[2].Matched || steps[1].Hosts != "no" || steps[1].Apps != "yes" {
		t.Fatalf("steps %+v", steps)
	}
}
