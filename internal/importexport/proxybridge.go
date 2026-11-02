package importexport

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
)

// namePrefix marks an action target that refers to a proxy by name; Merge
// resolves it against the profile the rules are imported into.
const namePrefix = "name:"

type pbRule struct {
	Name              string `json:"name"`
	LocalhostViaProxy bool   `json:"localhostViaProxy"`
	ProcessNames      string `json:"processNames"`
	TargetHosts       string `json:"targetHosts"`
	TargetPorts       string `json:"targetPorts"`
	Protocol          string `json:"protocol"`
	RuleProtocol      string `json:"ruleProtocol,omitempty"`
	Action            string `json:"action"`
	RuleAction        string `json:"ruleAction,omitempty"`
	Proxy             string `json:"proxy"`
	Enabled           *bool  `json:"enabled,omitempty"`
}

func pbList(s string) []string {
	var out []string
	for _, x := range config.SplitList(s) {
		if x != "*" {
			out = append(out, x)
		}
	}
	return out
}

func importProxyBridge(data []byte) (*Result, error) {
	var rules []pbRule
	if err := json.Unmarshal(data, &rules); err != nil {
		var one pbRule
		if err2 := json.Unmarshal(data, &one); err2 != nil {
			return nil, fmt.Errorf("not a ProxyBridge rule export: %w", err)
		}
		rules = []pbRule{one}
	}
	r := newResult("proxybridge")
	for i, pr := range rules {
		nr := config.Rule{ID: config.NewID(), Name: pr.Name, Enabled: pr.Enabled == nil || *pr.Enabled,
			Apps: pbList(pr.ProcessNames), Hosts: pbList(pr.TargetHosts), Ports: pbList(pr.TargetPorts)}
		if nr.Name == "" {
			nr.Name = fmt.Sprintf("ProxyBridge rule %d", i+1)
		}
		proto := strings.ToUpper(pr.Protocol)
		if proto == "" {
			proto = strings.ToUpper(pr.RuleProtocol)
		}
		switch proto {
		case "TCP":
			nr.Protocol = config.ProtoTCP
		case "UDP":
			nr.Protocol = config.ProtoUDP
		}
		act := strings.ToUpper(pr.Action)
		if act == "" {
			act = strings.ToUpper(pr.RuleAction)
		}
		switch act {
		case "DIRECT":
			nr.Action = config.Action{Type: config.ActionDirect}
		case "BLOCK":
			nr.Action = config.Action{Type: config.ActionBlock}
		default:
			// "PROXY", or (macOS exports) a proxy UUID in ruleAction.
			name := pr.Proxy
			if name == "" && act != "PROXY" {
				name = pr.RuleAction
			}
			nr.Action = config.Action{Type: config.ActionProxy, Target: namePrefix + name}
		}
		if len(nr.Apps)+len(nr.Hosts)+len(nr.Ports) == 0 && nr.Protocol == "" {
			r.warn("Rule %q matches everything; imported as a normal rule (move it to the bottom or use it as the default)", nr.Name)
		}
		r.Profile.Rules = append(r.Profile.Rules, nr)
	}
	r.warn("ProxyBridge exports do not include proxy servers: rules are linked to your proxies by name when you import them.")
	return r, nil
}

func exportProxyBridge(p *config.Profile) ([]byte, []string, error) {
	var warn []string
	out := make([]pbRule, 0, len(p.Rules))
	for _, ru := range p.Rules {
		en := ru.Enabled
		pr := pbRule{Name: ru.Name, ProcessNames: strings.Join(ru.Apps, "; "), TargetHosts: strings.Join(ru.Hosts, "; "),
			TargetPorts: strings.Join(ru.Ports, "; "), Protocol: "BOTH", Enabled: &en}
		if pr.ProcessNames == "" {
			pr.ProcessNames = "*"
		}
		if pr.TargetHosts == "" {
			pr.TargetHosts = "*"
		}
		if pr.TargetPorts == "" {
			pr.TargetPorts = "*"
		}
		switch ru.Protocol {
		case config.ProtoTCP:
			pr.Protocol = "TCP"
		case config.ProtoUDP:
			pr.Protocol = "UDP"
		}
		pr.RuleProtocol = pr.Protocol
		switch ru.Action.Type {
		case config.ActionDirect:
			pr.Action = "DIRECT"
		case config.ActionBlock:
			pr.Action = "BLOCK"
		default:
			pr.Action = "PROXY"
			pr.Proxy = p.TargetLabel(ru.Action.Target)
			if p.FindChain(ru.Action.Target) != nil {
				warn = append(warn, fmt.Sprintf("Rule %q uses chain %q; ProxyBridge has no chains, so it refers to it by name only", ru.Name, pr.Proxy))
			}
		}
		pr.RuleAction = pr.Action
		out = append(out, pr)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	return b, warn, err
}
