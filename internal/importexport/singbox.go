package importexport

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
)

type sbTLS struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name,omitempty"`
	Insecure   bool   `json:"insecure,omitempty"`
}

type sbOutbound struct {
	Type       string   `json:"type"`
	Tag        string   `json:"tag"`
	Server     string   `json:"server,omitempty"`
	ServerPort int      `json:"server_port,omitempty"`
	Version    string   `json:"version,omitempty"`
	Username   string   `json:"username,omitempty"`
	Password   string   `json:"password,omitempty"`
	TLS        *sbTLS   `json:"tls,omitempty"`
	Detour     string   `json:"detour,omitempty"`
	Outbounds  []string `json:"outbounds,omitempty"`
	Default    string   `json:"default,omitempty"`
	URL        string   `json:"url,omitempty"`
	Interval   string   `json:"interval,omitempty"`
}

type sbRule struct {
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	DomainRegex   []string `json:"domain_regex,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
	Port          []int    `json:"port,omitempty"`
	PortRange     []string `json:"port_range,omitempty"`
	ProcessName   []string `json:"process_name,omitempty"`
	ProcessPath   []string `json:"process_path,omitempty"`
	ProcessPathRE []string `json:"process_path_regex,omitempty"`
	Network       any      `json:"network,omitempty"`
	Protocol      any      `json:"protocol,omitempty"`
	RuleSet       any      `json:"rule_set,omitempty"`
	GeoIP         any      `json:"geoip,omitempty"`
	Geosite       any      `json:"geosite,omitempty"`
	Inbound       any      `json:"inbound,omitempty"`
	Action        string   `json:"action,omitempty"`
	Outbound      string   `json:"outbound,omitempty"`
}

type sbConfig struct {
	Log       map[string]any   `json:"log,omitempty"`
	Inbounds  []map[string]any `json:"inbounds,omitempty"`
	Outbounds []sbOutbound     `json:"outbounds"`
	Route     struct {
		Rules               []sbRule `json:"rules"`
		Final               string   `json:"final,omitempty"`
		AutoDetectInterface bool     `json:"auto_detect_interface,omitempty"`
	} `json:"route"`
}

// one-element-or-list JSON values used by sing-box ("network": "tcp").
func strList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := []string{}
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func importSingbox(data []byte) (*Result, error) {
	var c sbConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("not a valid sing-box config: %w", err)
	}
	r := newResult("singbox")
	ids := map[string]string{}
	kind := map[string]string{}
	byTag := map[string]sbOutbound{}
	skipped := map[string]int{}
	for _, o := range c.Outbounds {
		byTag[o.Tag] = o
		kind[o.Tag] = o.Type
		switch o.Type {
		case "socks", "http":
			p := config.Proxy{ID: config.NewID(), Name: o.Tag, Host: o.Server, Port: o.ServerPort, Username: o.Username, Password: o.Password}
			if o.Type == "socks" {
				switch o.Version {
				case "4":
					p.Type = config.SOCKS4
				case "4a":
					p.Type = config.SOCKS4A
				default:
					p.Type = config.SOCKS5
				}
			} else {
				p.Type = config.HTTP
				if o.TLS != nil && o.TLS.Enabled {
					p.Type = config.HTTPS
					p.TLSServerName = o.TLS.ServerName
					p.TLSInsecure = o.TLS.Insecure
				}
			}
			ids[o.Tag] = p.ID
			r.Profile.Proxies = append(r.Profile.Proxies, p)
		case "direct", "block", "dns", "selector", "urltest":
		default:
			skipped[o.Type]++
		}
	}
	for t, n := range skipped {
		r.warn("%d %s outbound(s) skipped (SentinelProxy speaks SOCKS and HTTP proxies)", n, t)
	}
	// detour chains: X with detour Y means Y -> X.
	for _, o := range c.Outbounds {
		if o.Detour == "" || ids[o.Tag] == "" || r.Profile.FindProxy(ids[o.Tag]) == nil {
			continue
		}
		hops := []string{ids[o.Tag]}
		seen := map[string]bool{o.Tag: true}
		for d := o.Detour; d != "" && !seen[d]; d = byTag[d].Detour {
			seen[d] = true
			id, ok := ids[d]
			if !ok || r.Profile.FindProxy(id) == nil {
				break
			}
			hops = append([]string{id}, hops...)
		}
		if len(hops) > 1 {
			ch := config.Chain{ID: config.NewID(), Name: o.Tag + " chain", Mode: config.ModeChain, Members: hops}
			r.Profile.Chains = append(r.Profile.Chains, ch)
			ids[o.Tag] = ch.ID
		}
	}
	for _, o := range c.Outbounds {
		if o.Type == "selector" || o.Type == "urltest" {
			ids[o.Tag] = config.NewID()
		}
	}
	for _, o := range c.Outbounds {
		if o.Type != "selector" && o.Type != "urltest" {
			continue
		}
		ch := config.Chain{ID: ids[o.Tag], Name: o.Tag, Mode: config.ModeFailover}
		if o.Type == "urltest" {
			ch.Mode = config.ModeFastest
		}
		members := o.Outbounds
		if o.Default != "" {
			// The selected member goes first so failover prefers it.
			ordered := []string{o.Default}
			for _, m := range members {
				if m != o.Default {
					ordered = append(ordered, m)
				}
			}
			members = ordered
		}
		for _, m := range members {
			if id, ok := ids[m]; ok {
				ch.Members = append(ch.Members, id)
			}
		}
		if len(ch.Members) == 0 {
			delete(ids, o.Tag)
			r.warn("Group %q has no usable members and was skipped", o.Tag)
			continue
		}
		r.Profile.Chains = append(r.Profile.Chains, ch)
	}
	action := func(rule sbRule) (config.Action, bool) {
		if rule.Action == "reject" {
			return config.Action{Type: config.ActionBlock}, true
		}
		if rule.Action != "" && rule.Action != "route" {
			return config.Action{}, false
		}
		switch kind[rule.Outbound] {
		case "direct":
			return config.Action{Type: config.ActionDirect}, true
		case "block":
			return config.Action{Type: config.ActionBlock}, true
		}
		if id, ok := ids[rule.Outbound]; ok {
			return config.Action{Type: config.ActionProxy, Target: id}, true
		}
		return config.Action{}, false
	}
	for i, rule := range c.Route.Rules {
		if rule.RuleSet != nil || rule.GeoIP != nil || rule.Geosite != nil || rule.Protocol != nil || rule.Inbound != nil {
			r.warn("Route rule %d skipped: rule sets, geoip/geosite, protocol and inbound conditions are not supported", i+1)
			continue
		}
		a, ok := action(rule)
		if !ok {
			if rule.Action != "sniff" && rule.Action != "hijack-dns" && rule.Action != "resolve" {
				r.warn("Route rule %d skipped: outbound %q is not available", i+1, rule.Outbound)
			}
			continue
		}
		nr := config.Rule{ID: config.NewID(), Enabled: true, Action: a, Name: fmt.Sprintf("sing-box rule %d", i+1)}
		nr.Hosts = append(nr.Hosts, rule.Domain...)
		for _, s := range rule.DomainSuffix {
			nr.Hosts = append(nr.Hosts, "."+strings.TrimPrefix(s, "."))
		}
		for _, s := range rule.DomainKeyword {
			nr.Hosts = append(nr.Hosts, "keyword:"+s)
		}
		for _, s := range rule.DomainRegex {
			nr.Hosts = append(nr.Hosts, "re:"+s)
		}
		nr.Hosts = append(nr.Hosts, rule.IPCIDR...)
		for _, p := range rule.Port {
			nr.Ports = append(nr.Ports, strconv.Itoa(p))
		}
		for _, pr := range rule.PortRange {
			nr.Ports = append(nr.Ports, strings.Replace(pr, ":", "-", 1))
		}
		nr.Apps = append(append(nr.Apps, rule.ProcessName...), rule.ProcessPath...)
		if len(rule.ProcessPathRE) > 0 {
			r.warn("Route rule %d: process_path_regex is not supported and was dropped", i+1)
		}
		if nets := strList(rule.Network); len(nets) == 1 {
			nr.Protocol = config.Protocol(nets[0])
		}
		if len(nr.Hosts)+len(nr.Ports)+len(nr.Apps) == 0 && nr.Protocol == "" {
			continue
		}
		r.Profile.Rules = append(r.Profile.Rules, nr)
	}
	if c.Route.Final != "" {
		if a, ok := action(sbRule{Outbound: c.Route.Final}); ok {
			r.Profile.DefaultAction = a
			r.HasDefault = true
		}
	} else if len(c.Outbounds) > 0 {
		if a, ok := action(sbRule{Outbound: c.Outbounds[0].Tag}); ok {
			r.Profile.DefaultAction = a // sing-box uses the first outbound as final
			r.HasDefault = true
		}
	}
	return r, nil
}

func exportSingbox(p *config.Profile) ([]byte, []string, error) {
	var warn []string
	var c sbConfig
	c.Log = map[string]any{"level": "info"}
	c.Inbounds = []map[string]any{{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}}
	tags := map[string]string{}
	taken := map[string]bool{"direct": true}
	uniq := func(n string) string {
		if n == "" {
			n = "proxy"
		}
		base := n
		for i := 2; taken[n]; i++ {
			n = fmt.Sprintf("%s %d", base, i)
		}
		taken[n] = true
		return n
	}
	mk := func(px config.Proxy, tag, detour string) sbOutbound {
		o := sbOutbound{Tag: tag, Server: px.Host, ServerPort: px.Port, Username: px.Username, Password: px.Password, Detour: detour}
		switch px.Type {
		case config.SOCKS5:
			o.Type, o.Version = "socks", "5"
		case config.SOCKS4:
			o.Type, o.Version = "socks", "4"
		case config.SOCKS4A:
			o.Type, o.Version = "socks", "4a"
		case config.HTTP:
			o.Type = "http"
		case config.HTTPS:
			o.Type = "http"
			o.TLS = &sbTLS{Enabled: true, ServerName: px.TLSServerName, Insecure: px.TLSInsecure}
		}
		return o
	}
	c.Outbounds = append(c.Outbounds, sbOutbound{Type: "direct", Tag: "direct"})
	for _, px := range p.Proxies {
		t := uniq(px.Label())
		tags[px.ID] = t
		c.Outbounds = append(c.Outbounds, mk(px, t, ""))
	}
	for _, ch := range p.Chains {
		tags[ch.ID] = uniq(ch.Name)
	}
	for _, ch := range p.Chains {
		if ch.Mode == config.ModeChain {
			// Copies of each hop linked by detour; the last hop carries the chain's tag.
			prev := ""
			for i, m := range ch.Members {
				px := p.FindProxy(m)
				if px == nil {
					continue
				}
				tag := tags[ch.ID]
				if i < len(ch.Members)-1 {
					tag = uniq(ch.Name + " hop " + strconv.Itoa(i+1))
				}
				c.Outbounds = append(c.Outbounds, mk(*px, tag, prev))
				prev = tag
			}
			continue
		}
		o := sbOutbound{Tag: tags[ch.ID], Type: "urltest", URL: p.Settings.CheckURL, Interval: "3m"}
		if ch.Mode == config.ModeFailover {
			o.Type = "selector"
			warn = append(warn, fmt.Sprintf("%s: exported as a sing-box selector (manual choice, first member selected)", ch.Name))
		} else if ch.Mode != config.ModeFastest {
			warn = append(warn, fmt.Sprintf("%s: sing-box has no %s mode; exported as urltest", ch.Name, ch.Mode))
		}
		for _, m := range ch.Members {
			if t, ok := tags[m]; ok {
				o.Outbounds = append(o.Outbounds, t)
			}
		}
		if o.Type == "selector" && len(o.Outbounds) > 0 {
			o.Default = o.Outbounds[0]
		}
		c.Outbounds = append(c.Outbounds, o)
	}
	route := func(a config.Action) (string, string) {
		switch a.Type {
		case config.ActionBlock:
			return "reject", ""
		case config.ActionProxy:
			if t, ok := tags[a.Target]; ok {
				return "route", t
			}
		}
		return "route", "direct"
	}
	for _, ru := range p.Rules {
		if !ru.Enabled {
			continue
		}
		var sr sbRule
		for _, h := range ru.Hosts {
			f := classifyHost(h)
			switch f.kind {
			case "exact":
				sr.Domain = append(sr.Domain, f.value)
			case "suffix":
				sr.DomainSuffix = append(sr.DomainSuffix, f.value)
			case "wildsub":
				sr.DomainRegex = append(sr.DomainRegex, globToRegex("*."+f.value))
			case "keyword":
				sr.DomainKeyword = append(sr.DomainKeyword, f.value)
			case "regex":
				sr.DomainRegex = append(sr.DomainRegex, f.value)
			case "wildcard":
				sr.DomainRegex = append(sr.DomainRegex, globToRegex(f.value))
			case "cidr":
				sr.IPCIDR = append(sr.IPCIDR, f.value)
			case "range":
				for _, pf := range rangeToPrefixes(f.value) {
					sr.IPCIDR = append(sr.IPCIDR, pf.String())
				}
			case "ipglob":
				if pf, ok := ipGlobToPrefix(f.value); ok {
					sr.IPCIDR = append(sr.IPCIDR, pf.String())
				}
			}
		}
		for _, pt := range ru.Ports {
			if lo, hi, ok := strings.Cut(pt, "-"); ok {
				sr.PortRange = append(sr.PortRange, strings.TrimSpace(lo)+":"+strings.TrimSpace(hi))
			} else if n, err := strconv.Atoi(strings.TrimSpace(pt)); err == nil {
				sr.Port = append(sr.Port, n)
			}
		}
		for _, a := range ru.Apps {
			switch {
			case strings.ContainsAny(a, `/\`) && strings.ContainsAny(a, "*?"):
				sr.ProcessPathRE = append(sr.ProcessPathRE, globToRegex(a))
			case strings.ContainsAny(a, `/\`):
				sr.ProcessPath = append(sr.ProcessPath, a)
			case strings.ContainsAny(a, "*?"):
				warn = append(warn, fmt.Sprintf("Rule %q: sing-box has no process-name wildcards; %q skipped", ru.Name, a))
			default:
				sr.ProcessName = append(sr.ProcessName, a)
			}
		}
		if ru.Protocol != config.ProtoAny {
			sr.Network = string(ru.Protocol)
		}
		sr.Action, sr.Outbound = route(ru.Action)
		c.Route.Rules = append(c.Route.Rules, sr)
	}
	act, out := route(p.DefaultAction)
	if act == "reject" {
		c.Outbounds = append(c.Outbounds, sbOutbound{Type: "block", Tag: "block"})
		out = "block"
		warn = append(warn, "The default action Block uses a legacy block outbound")
	}
	c.Route.Final = out
	c.Route.AutoDetectInterface = true
	b, err := json.MarshalIndent(c, "", "  ")
	return b, warn, err
}
