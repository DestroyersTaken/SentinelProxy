package service

import (
	"testing"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/importexport"
)

func TestImportRuleTestAndQuickRule(t *testing.T) {
	a, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Shutdown()

	pv, err := a.PreviewImport("list.txt", "socks5://u:p@10.0.0.9:1080#Office\nhttp://10.0.0.10:3128", false, "")
	if err != nil || len(pv.Profile.Proxies) != 2 {
		t.Fatalf("preview: %v %+v", err, pv)
	}
	res, err := a.ApplyImport(pv.Token, importexport.MergeOptions{Proxies: true}, "")
	if err != nil || !res.Save.OK || res.Summary.ProxiesAdded != 2 {
		t.Fatalf("apply: %v %+v", err, res)
	}
	if _, err := a.ApplyImport(pv.Token, importexport.MergeOptions{Proxies: true}, ""); err == nil {
		t.Fatal("a token must only be usable once")
	}
	office := a.GetProfile().Proxies[0]

	q := a.AddQuickRule(QuickRuleInput{App: "chrome.exe", Host: "www.example.co.uk", Scope: "domain", Action: config.Action{Type: config.ActionProxy, Target: office.ID}})
	if !q.OK {
		t.Fatalf("quick rule: %+v", q)
	}
	p := a.GetProfile()
	if p.Rules[0].Hosts[0] != ".example.co.uk" {
		t.Fatalf("registrable domain: %v", p.Rules[0].Hosts)
	}
	tr := a.TestRule(TestInput{App: "firefox.exe", Host: "img.example.co.uk:443", Protocol: "tcp"}, nil)
	if tr.Decision.RuleID != p.Rules[0].ID || tr.Label != "Office" {
		t.Fatalf("test rule: %+v", tr)
	}
	tr = a.TestRule(TestInput{App: "x.exe", Host: "192.168.1.5", Port: 80}, nil)
	if tr.Decision.RuleName != "Localhost & LAN" {
		t.Fatalf("LAN: %+v", tr.Decision)
	}

	// Invalid profiles are rejected with problems, not saved.
	bad := a.GetProfile()
	bad.Rules[0].Action.Target = "missing"
	if r := a.SaveProfile(bad); r.OK || len(r.Problems) == 0 {
		t.Fatalf("bad profile accepted: %+v", r)
	}

	if _, err := a.CreateProfile("Work", true); err != nil {
		t.Fatal(err)
	}
	if st := a.GetState(); st.Profile != "Work" || len(st.Profiles) != 2 {
		t.Fatalf("state %+v", st)
	}
	if _, err := a.DeleteProfile("Work"); err == nil {
		t.Fatal("deleting the active profile must fail")
	}
	out, err := a.Export("proxifier", false)
	if err != nil || out.FileName != "Work.ppx" || len(out.Content) == 0 {
		t.Fatalf("export: %v %+v", err, out)
	}
}
