package config

import (
	"errors"
	"testing"
)

func TestValidateCatchesProblems(t *testing.T) {
	p := NewProfile("t")
	p.Proxies = append(p.Proxies, Proxy{ID: "p1", Type: SOCKS5, Host: "1.2.3.4", Port: 1080})
	p.Chains = []Chain{
		{ID: "c1", Name: "A", Mode: ModeFailover, Members: []string{"c2"}},
		{ID: "c2", Name: "B", Mode: ModeFailover, Members: []string{"c1"}},
		{ID: "c3", Name: "C", Mode: ModeChain, Members: []string{"c1", "nope"}},
	}
	p.Rules = append(p.Rules, Rule{ID: "r1", Action: Action{Type: ActionProxy, Target: "gone"}})
	probs := p.Validate()
	want := map[string]bool{"cycle": false, "strict": false, "missingMember": false, "missingTarget": false}
	for _, pr := range probs {
		switch {
		case pr.Kind == "chain" && pr.ID == "":
			want["cycle"] = true
		case pr.Kind == "chain" && pr.ID == "c3" && contains(pr.Message, "strict"):
			want["strict"] = true
		case pr.Kind == "chain" && pr.ID == "c3" && contains(pr.Message, "missing member"):
			want["missingMember"] = true
		case pr.Kind == "rule" && pr.ID == "r1":
			want["missingTarget"] = true
		}
	}
	for k, v := range want {
		if !v {
			t.Errorf("expected a %s problem, got %v", k, probs)
		}
	}
	if err := p.checkCycles(); !errors.Is(err, ErrCycle) {
		t.Fatalf("checkCycles = %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestNormalizeFixesIDs(t *testing.T) {
	p := &Profile{Proxies: []Proxy{{Type: "SOCKS5", Host: "h"}, {ID: "x", Type: HTTP, Host: "h"}, {ID: "x", Type: HTTP, Host: "h"}}}
	p.Normalize()
	if p.Proxies[0].ID == "" || p.Proxies[0].Type != SOCKS5 || p.Proxies[0].Port != 1080 {
		t.Fatalf("bad normalize: %+v", p.Proxies[0])
	}
	if p.Proxies[1].ID == p.Proxies[2].ID {
		t.Fatal("duplicate ids not repaired")
	}
	if len(p.Validate()) != 0 {
		t.Fatalf("normalized profile invalid: %v", p.Validate())
	}
}

func TestStoreRoundTrip(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.LoadActive()
	if err != nil || p.Name != "Default" {
		t.Fatalf("LoadActive = %v, %v", p, err)
	}
	p.Proxies = append(p.Proxies, Proxy{ID: "a", Name: "A", Type: HTTP, Host: "h", Port: 8080})
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	if err := s.Rename("Default", "Work/Home"); err != nil {
		t.Fatal(err)
	}
	q, err := s.Load("Work/Home")
	if err != nil || len(q.Proxies) != 1 {
		t.Fatalf("Load = %+v, %v", q, err)
	}
	names, _ := s.List()
	if len(names) != 1 || names[0] != "Work/Home" {
		t.Fatalf("List = %v", names)
	}
}

func TestSplitList(t *testing.T) {
	got := SplitList(`chrome.exe; firefox.exe,"steam.exe"` + "\n  opera.exe ;;")
	want := []string{"chrome.exe", "firefox.exe", "steam.exe", "opera.exe"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v", got)
		}
	}
}
