package importexport

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
)

func load(t *testing.T, name string) []byte {
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustImport(t *testing.T, name string, data []byte, wantFormat string) *Result {
	t.Helper()
	if got := Detect(name, data); got != wantFormat {
		t.Fatalf("Detect(%s) = %s, want %s", name, got, wantFormat)
	}
	r, err := Import(name, data, "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestProxifierImport(t *testing.T) {
	r := mustImport(t, "sample.ppx", load(t, "sample.ppx"), "proxifier")
	p := r.Profile
	if len(p.Proxies) != 2 || p.Proxies[0].Username != "alice" || p.Proxies[0].Password != "pw" || p.Proxies[1].Type != config.HTTP {
		t.Fatalf("proxies %+v", p.Proxies)
	}
	if len(p.Chains) != 2 || p.Chains[0].Mode != config.ModeChain || p.Chains[1].Mode != config.ModeFailover || len(p.Chains[0].Members) != 2 {
		t.Fatalf("chains %+v", p.Chains)
	}
	if len(p.Rules) != 4 {
		t.Fatalf("rules %+v", p.Rules)
	}
	br := p.Rules[1]
	if len(br.Apps) != 3 || br.Apps[2] != `C:\Program Files\My App\app.exe` || len(br.Ports) != 2 {
		t.Fatalf("browser rule %+v", br)
	}
	if p.Rules[0].Hosts[len(p.Rules[0].Hosts)-1] != "::1" {
		t.Fatalf("%%ComputerName%% should be dropped: %v", p.Rules[0].Hosts)
	}
	if p.Rules[2].Enabled || p.Rules[2].Action.Target != p.Chains[0].ID {
		t.Fatalf("work rule %+v", p.Rules[2])
	}
	if !r.HasDefault || p.DefaultAction.Target != p.Chains[1].ID {
		t.Fatalf("default %+v", p.DefaultAction)
	}
	if probs := p.Validate(); len(probs) != 0 {
		t.Fatalf("imported profile invalid: %v", probs)
	}
	// Round trip through our exporter.
	out, _, warn, err := Export(p, "proxifier")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Import("x.ppx", out, "")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(r2.Profile.Rules) != 4 || len(r2.Profile.Proxies) != 2 || len(r2.Profile.Chains) != 2 || r2.Profile.Rules[1].Apps[2] != br.Apps[2] {
		t.Fatalf("round trip lost data: %+v (warnings %v)", r2.Profile, warn)
	}
}

func TestProxifierEncryptedPasswords(t *testing.T) {
	data := strings.Replace(string(load(t, "sample.ppx")), `mode="disabled"`, `mode="basic"`, 1)
	r, err := Import("a.ppx", []byte(data), "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Profile.Proxies[0].Password != "" || len(r.Warnings) == 0 {
		t.Fatal("encrypted passwords must be dropped with a warning")
	}
}

func TestClashRoundTrip(t *testing.T) {
	r := mustImport(t, "clash.yaml", load(t, "clash.yaml"), "clash")
	p := r.Profile
	if len(p.Proxies) != 2 || p.Proxies[1].Type != config.HTTPS {
		t.Fatalf("proxies %+v", p.Proxies)
	}
	if len(p.Chains) != 2 || p.Chains[0].Mode != config.ModeFastest {
		t.Fatalf("chains %+v", p.Chains)
	}
	// The two DOMAIN-SUFFIX rules to Auto merge into one rule.
	if len(p.Rules) != 4 || len(p.Rules[0].Hosts) != 2 || p.Rules[0].Hosts[0] != ".google.com" {
		t.Fatalf("rules %+v", p.Rules)
	}
	if p.Rules[1].Action.Type != config.ActionBlock || p.Rules[2].Apps[0] != "telegram.exe" {
		t.Fatalf("rules %+v", p.Rules)
	}
	if !r.HasDefault || p.DefaultAction.Target != p.Chains[1].ID {
		t.Fatal("MATCH not mapped")
	}
	if len(r.Warnings) < 2 {
		t.Fatalf("expected ss/GEOIP warnings, got %v", r.Warnings)
	}
	if probs := p.Validate(); len(probs) != 0 {
		t.Fatal(probs)
	}
	out, _, _, err := Export(p, "clash")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Import("x.yaml", out, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r2.Profile.Proxies) != 2 || len(r2.Profile.Chains) != 2 || len(r2.Profile.Rules) != 4 {
		t.Fatalf("round trip %+v\n%s", r2.Profile.Rules, out)
	}
}

func TestClashExportMultiCondition(t *testing.T) {
	p := config.NewProfile("m")
	p.Proxies = []config.Proxy{{ID: "a", Name: "A", Type: config.SOCKS5, Host: "h", Port: 1}}
	p.Rules = []config.Rule{{ID: "r", Name: "x", Enabled: true, Apps: []string{"chrome.exe"}, Hosts: []string{"*.google.com", "10.0.0.1-10.0.0.6"}, Action: config.Action{Type: config.ActionProxy, Target: "a"}}}
	out, _, _, err := Export(p, "clash")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "AND,((PROCESS-NAME,chrome.exe),(OR,((DOMAIN-SUFFIX,google.com),(IP-CIDR,10.0.0.1/32),(IP-CIDR,10.0.0.2/31),(IP-CIDR,10.0.0.4/31),(IP-CIDR,10.0.0.6/32)))),A") {
		t.Fatalf("unexpected export:\n%s", s)
	}
}

func TestSingbox(t *testing.T) {
	r := mustImport(t, "singbox.json", load(t, "singbox.json"), "singbox")
	p := r.Profile
	if len(p.Proxies) != 2 || p.Proxies[1].Type != config.HTTPS || !p.Proxies[1].TLSInsecure {
		t.Fatalf("proxies %+v", p.Proxies)
	}
	var group, chain *config.Chain
	for i := range p.Chains {
		switch p.Chains[i].Mode {
		case config.ModeFailover:
			group = &p.Chains[i]
		case config.ModeChain:
			chain = &p.Chains[i]
		}
	}
	if chain == nil || len(chain.Members) != 2 || group == nil || group.Members[0] != p.Proxies[0].ID {
		t.Fatalf("chains %+v", p.Chains)
	}
	if group.Members[1] != chain.ID {
		t.Fatal("detour chain must replace the plain member")
	}
	if len(p.Rules) != 3 || p.Rules[1].Protocol != config.ProtoUDP || p.Rules[1].Ports[0] != "6000-7000" || p.Rules[1].Action.Type != config.ActionBlock {
		t.Fatalf("rules %+v", p.Rules)
	}
	if p.DefaultAction.Target != group.ID {
		t.Fatal("final not mapped")
	}
	out, _, _, err := Export(p, "singbox")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Import("x.json", out, "")
	if err != nil {
		t.Fatal(err)
	}
	if r2.Format != "singbox" || len(r2.Profile.Rules) != 3 || len(r2.Profile.Proxies) < 2 {
		t.Fatalf("round trip %+v", r2.Profile)
	}
}

func TestProxyBridgeAndMerge(t *testing.T) {
	r := mustImport(t, "rules.json", load(t, "proxybridge.json"), "proxybridge")
	if len(r.Profile.Rules) != 3 || len(r.Profile.Rules[0].Apps) != 2 || len(r.Profile.Rules[0].Hosts) != 0 || r.Profile.Rules[0].Ports[1] != "443" {
		t.Fatalf("%+v", r.Profile.Rules)
	}
	if r.Profile.Rules[1].Enabled || r.Profile.Rules[2].Protocol != config.ProtoUDP {
		t.Fatalf("%+v", r.Profile.Rules)
	}
	dst := config.NewProfile("mine")
	dst.Proxies = []config.Proxy{{ID: "hs", Name: "home socks", Type: config.SOCKS5, Host: "h", Port: 1}}
	merged, sum := Merge(dst, r.Profile, MergeOptions{Rules: true, RulesOnTop: true})
	if merged.Rules[0].Action.Target != "hs" || sum.RulesAdded != 3 || len(sum.Warnings) != 0 {
		t.Fatalf("name link failed: %+v %+v", merged.Rules[0], sum)
	}
	if probs := merged.Validate(); len(probs) != 0 {
		t.Fatal(probs)
	}
	// No proxy with that name and none at all: disabled + warning.
	merged, sum = Merge(config.NewProfile("empty"), r.Profile, MergeOptions{Rules: true})
	if merged.Rules[1].Enabled || len(sum.Warnings) != 1 {
		t.Fatalf("%+v %+v", merged.Rules[1], sum)
	}
	out, _, _, err := Export(merged, "proxybridge")
	if err != nil || !strings.Contains(string(out), `"processNames": "chrome.exe; msedge.exe"`) {
		t.Fatalf("%v %s", err, out)
	}
}

func TestMergeDedupes(t *testing.T) {
	dst := config.NewProfile("d")
	dst.Proxies = []config.Proxy{{ID: "x", Name: "A", Type: config.SOCKS5, Host: "1.1.1.1", Port: 1080}}
	src := config.NewProfile("s")
	src.Proxies = []config.Proxy{{ID: "x", Name: "A", Type: config.SOCKS5, Host: "1.1.1.1", Port: 1080}, {ID: "y", Name: "A", Type: config.HTTP, Host: "2.2.2.2", Port: 80}}
	src.Chains = []config.Chain{{ID: "c", Name: "G", Mode: config.ModeFailover, Members: []string{"x", "y"}}}
	src.Rules = []config.Rule{{ID: "r", Name: "r", Enabled: true, Action: config.Action{Type: config.ActionProxy, Target: "c"}}}
	m, sum := Merge(dst, src, MergeOptions{Proxies: true, Chains: true, Rules: true})
	if len(m.Proxies) != 2 || sum.ProxiesSame != 1 || sum.ProxiesAdded != 1 || m.Proxies[1].Name != "A (2)" {
		t.Fatalf("%+v %+v", m.Proxies, sum)
	}
	if m.Chains[0].Members[0] != "x" || len(m.Validate()) != 0 {
		t.Fatalf("%+v %v", m.Chains, m.Validate())
	}
	rep, _ := Merge(dst, src, MergeOptions{Replace: true, Proxies: true, Chains: true, Rules: true})
	if len(rep.Rules) != 1 || len(rep.Proxies) != 2 {
		t.Fatalf("replace %+v", rep)
	}
}

func TestProxyLines(t *testing.T) {
	data := `# my proxies
socks5://bob:s%40crt@1.2.3.4:1080#Home
http://5.6.7.8:3128
9.9.9.9:8080
9.9.9.9:8080:user:pa:ss
u:p@[2001:db8::1]:1080
https 10.0.0.1 443 a b
garbage line
`
	r := mustImport(t, "", []byte(data), "list")
	ps := r.Profile.Proxies
	if len(ps) != 6 || len(r.Warnings) != 2 {
		t.Fatalf("%+v %v", ps, r.Warnings)
	}
	if ps[0].Password != "s@crt" || ps[0].Name != "Home" || ps[3].Password != "pa:ss" || ps[4].Host != "2001:db8::1" || ps[5].Type != config.HTTPS || ps[5].Username != "a" {
		t.Fatalf("%+v", ps)
	}
	out, _, _, _ := Export(r.Profile, "list")
	r2, err := Import("", out, "list")
	if err != nil || len(r2.Profile.Proxies) != 6 || r2.Profile.Proxies[0].Password != "s@crt" {
		t.Fatalf("round trip: %v %+v", err, r2)
	}
	csvOut, _, _, _ := Export(r.Profile, "csv")
	r3 := mustImport(t, "p.csv", csvOut, "csv")
	if len(r3.Profile.Proxies) != 6 || r3.Profile.Proxies[5].Type != config.HTTPS {
		t.Fatalf("%+v", r3.Profile.Proxies)
	}
}

func TestFoxy(t *testing.T) {
	data := `{"mode":"disable","data":[{"active":true,"title":"F1","type":"socks5","hostname":"4.4.4.4","port":"1080","username":"","password":"","proxyDNS":true},{"type":"pac","title":"x","hostname":""}]}`
	r := mustImport(t, "foxy.json", []byte(data), "foxyproxy")
	if len(r.Profile.Proxies) != 1 || r.Profile.Proxies[0].Port != 1080 {
		t.Fatalf("%+v", r.Profile.Proxies)
	}
}

func TestSentinelRoundTrip(t *testing.T) {
	p := config.NewProfile("Mine")
	p.Proxies = []config.Proxy{{ID: "a", Name: "A", Type: config.SOCKS5, Host: "h", Port: 1}}
	out, name, _, err := Export(p, "sentinel")
	if err != nil || name != "Mine.json" {
		t.Fatal(err, name)
	}
	r := mustImport(t, name, out, "sentinel")
	if r.Profile.Proxies[0].ID != "a" || !r.HasSettings {
		t.Fatal("round trip failed")
	}
}

func TestRangeToPrefixes(t *testing.T) {
	got := rangeToPrefixes("192.168.0.0-192.168.1.255")
	if len(got) != 1 || got[0] != netip.MustParsePrefix("192.168.0.0/23") {
		t.Fatalf("%v", got)
	}
	got = rangeToPrefixes("10.0.0.5-10.0.0.5")
	if len(got) != 1 || got[0].Bits() != 32 {
		t.Fatalf("%v", got)
	}
}
