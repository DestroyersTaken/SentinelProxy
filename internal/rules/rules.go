// Package rules compiles profile rules into a fast, immutable decision
// engine.
package rules

import (
	"fmt"
	"sync/atomic"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/match"
)

// Meta is everything known about a connection when it is routed.
type Meta struct {
	App     match.AppInfo
	Target  match.Target
	Network config.Protocol // ProtoTCP or ProtoUDP
}

// Decision is the routing outcome.
type Decision struct {
	Action   config.Action `json:"action"`
	RuleID   string        `json:"ruleId"`   // "" for the default rule
	RuleName string        `json:"ruleName"` // "Default" for the default rule
	Index    int           `json:"index"`    // rule position, -1 for default
}

type compiled struct {
	rule  config.Rule
	index int
	apps  *match.AppMatcher
	hosts *match.HostMatcher
	ports *match.PortMatcher
}

// Engine is an immutable compiled rule set. Hit counters are the only
// mutable state and are safe for concurrent use.
type Engine struct {
	rules   []compiled
	def     config.Action
	hits    map[string]*atomic.Uint64
	defHits atomic.Uint64
}

// CompileError reports a rule that could not be compiled; it is skipped.
type CompileError struct {
	RuleID, RuleName string
	Err              error
}

func (e CompileError) Error() string { return fmt.Sprintf("rule %q: %v", e.RuleName, e.Err) }

// Compile builds an engine from a profile. Disabled rules are skipped, and
// rules with invalid patterns are skipped and reported.
func Compile(p *config.Profile) (*Engine, []CompileError) {
	e := &Engine{def: p.DefaultAction, hits: map[string]*atomic.Uint64{}}
	var errs []CompileError
	for i, r := range p.Rules {
		e.hits[r.ID] = new(atomic.Uint64)
		if !r.Enabled {
			continue
		}
		c, err := CompileRule(r)
		if err != nil {
			errs = append(errs, CompileError{r.ID, r.Name, err})
			continue
		}
		c.index = i
		e.rules = append(e.rules, *c)
	}
	return e, errs
}

// CompileRule compiles a single rule (used for validation in the UI too).
func CompileRule(r config.Rule) (*compiled, error) {
	apps, err := match.NewAppMatcher(r.Apps)
	if err != nil {
		return nil, err
	}
	hosts, err := match.NewHostMatcher(r.Hosts)
	if err != nil {
		return nil, err
	}
	ports, err := match.NewPortMatcher(r.Ports)
	if err != nil {
		return nil, err
	}
	return &compiled{rule: r, apps: apps, hosts: hosts, ports: ports}, nil
}

func (c *compiled) eval(m Meta) match.Tri {
	if c.rule.Protocol != config.ProtoAny && m.Network != "" && c.rule.Protocol != m.Network {
		return match.No
	}
	if !c.ports.Match(m.Target.Port) {
		return match.No
	}
	if !c.apps.Match(m.App) {
		return match.No
	}
	return c.hosts.Match(m.Target)
}

func (c *compiled) decision() Decision {
	return Decision{Action: c.rule.Action, RuleID: c.rule.ID, RuleName: c.rule.Name, Index: c.index}
}

func (e *Engine) defaultDecision() Decision {
	return Decision{Action: e.def, RuleName: "Default", Index: -1}
}

// Decide routes a connection with everything that is known. Domain patterns
// that cannot be evaluated (no hostname) do not match.
func (e *Engine) Decide(m Meta) Decision {
	for i := range e.rules {
		if e.rules[i].eval(m) == match.Yes {
			return e.rules[i].decision()
		}
	}
	return e.defaultDecision()
}

// DecideEarly routes a connection whose hostname is not known yet. certain
// is false when learning the hostname could change the action; the caller
// should then sniff the hostname and call Decide.
func (e *Engine) DecideEarly(m Meta) (d Decision, certain bool) {
	var pending []config.Action
	for i := range e.rules {
		switch e.rules[i].eval(m) {
		case match.Yes:
			d = e.rules[i].decision()
			return d, allSame(pending, d.Action)
		case match.Unknown:
			pending = append(pending, e.rules[i].rule.Action)
		}
	}
	d = e.defaultDecision()
	return d, allSame(pending, d.Action)
}

func allSame(list []config.Action, a config.Action) bool {
	for _, x := range list {
		if x != a {
			return false
		}
	}
	return true
}

// Hit records that a decision was applied.
func (e *Engine) Hit(d Decision) {
	if d.RuleID == "" {
		e.defHits.Add(1)
		return
	}
	if h := e.hits[d.RuleID]; h != nil {
		h.Add(1)
	}
}

// Hits returns hit counts by rule ID ("" is the default rule).
func (e *Engine) Hits() map[string]uint64 {
	out := make(map[string]uint64, len(e.hits)+1)
	for id, h := range e.hits {
		out[id] = h.Load()
	}
	out[""] = e.defHits.Load()
	return out
}

// Step explains how one rule evaluated against a test connection.
type Step struct {
	RuleID   string `json:"ruleId"`
	RuleName string `json:"ruleName"`
	Enabled  bool   `json:"enabled"`
	Apps     string `json:"apps"`  // "yes", "no" or "any"
	Hosts    string `json:"hosts"` // "yes", "no", "unknown" or "any"
	Ports    string `json:"ports"`
	Protocol string `json:"protocol"`
	Matched  bool   `json:"matched"`
	Error    string `json:"error,omitempty"`
}

// Explain evaluates every rule (including disabled ones, which never match)
// and returns the decision plus a per-rule trace. It powers the rule tester.
func Explain(p *config.Profile, m Meta) (Decision, []Step) {
	yn := func(empty, ok bool) string {
		switch {
		case empty:
			return "any"
		case ok:
			return "yes"
		}
		return "no"
	}
	var steps []Step
	var final *Decision
	for i, r := range p.Rules {
		st := Step{RuleID: r.ID, RuleName: r.Name, Enabled: r.Enabled}
		c, err := CompileRule(r)
		if err != nil {
			st.Error = err.Error()
			steps = append(steps, st)
			continue
		}
		c.index = i
		st.Apps = yn(c.apps.Empty(), c.apps.Match(m.App))
		st.Ports = yn(c.ports.Empty(), c.ports.Match(m.Target.Port))
		st.Protocol = yn(r.Protocol == config.ProtoAny, m.Network == "" || r.Protocol == m.Network)
		switch t := c.hosts.Match(m.Target); {
		case c.hosts.Empty():
			st.Hosts = "any"
		case t == match.Yes:
			st.Hosts = "yes"
		case t == match.Unknown:
			st.Hosts = "unknown"
		default:
			st.Hosts = "no"
		}
		st.Matched = r.Enabled && final == nil && c.eval(m) == match.Yes
		if st.Matched {
			d := c.decision()
			final = &d
		}
		steps = append(steps, st)
	}
	if final == nil {
		d := Decision{Action: p.DefaultAction, RuleName: "Default", Index: -1}
		final = &d
	}
	return *final, steps
}
