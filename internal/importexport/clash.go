package importexport

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
)

type clashProxy struct {
	Name           string `yaml:"name"`
	Type           string `yaml:"type"`
	Server         string `yaml:"server"`
	Port           any    `yaml:"port"`
	Username       string `yaml:"username,omitempty"`
	Password       string `yaml:"password,omitempty"`
	TLS            bool   `yaml:"tls,omitempty"`
	SNI            string `yaml:"sni,omitempty"`
	SkipCertVerify bool   `yaml:"skip-cert-verify,omitempty"`
	UDP            bool   `yaml:"udp,omitempty"`
	DialerProxy    string `yaml:"dialer-proxy,omitempty"`
}

type clashGroup struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Proxies  []string `yaml:"proxies"`
	URL      string   `yaml:"url,omitempty"`
	Interval int      `yaml:"interval,omitempty"`
	Strategy string   `yaml:"strategy,omitempty"`
}

type clashConfig struct {
	MixedPort   int          `yaml:"mixed-port,omitempty"`
	Mode        string       `yaml:"mode,omitempty"`
	Proxies     []clashProxy `yaml:"proxies"`
	ProxyGroups []clashGroup `yaml:"proxy-groups"`
	Rules       []string     `yaml:"rules"`
}

func anyInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

func importClash(data []byte) (*Result, error) {
	var c clashConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("not valid Clash YAML: %w", err)
	}
	r := newResult("clash")
	ids := map[string]string{} // clash name -> id
	skipped := map[string]int{}
	for _, cp := range c.Proxies {
		p := config.Proxy{ID: config.NewID(), Name: cp.Name, Host: cp.Server, Port: anyInt(cp.Port), Username: cp.Username, Password: cp.Password}
		switch strings.ToLower(cp.Type) {
		case "socks5":
			p.Type = config.SOCKS5
		case "http":
			p.Type = config.HTTP
			if cp.TLS {
				p.Type = config.HTTPS
				p.TLSServerName = cp.SNI
				p.TLSInsecure = cp.SkipCertVerify
			}
		default:
			skipped[cp.Type]++
			continue
		}
		ids[cp.Name] = p.ID
		r.Profile.Proxies = append(r.Profile.Proxies, p)
	}
	for t, n := range skipped {
		r.warn("%d %s proxies skipped (SentinelProxy speaks SOCKS and HTTP proxies)", n, t)
	}
	// dialer-proxy builds two-hop chains.
	for _, cp := range c.Proxies {
		if cp.DialerProxy == "" || ids[cp.Name] == "" {
			continue
		}
		if via, ok := ids[cp.DialerProxy]; ok && r.Profile.FindProxy(via) != nil {
			ch := config.Chain{ID: config.NewID(), Name: cp.Name + " (via " + cp.DialerProxy + ")", Mode: config.ModeChain, Members: []string{via, ids[cp.Name]}}
			r.Profile.Chains = append(r.Profile.Chains, ch)
			ids[cp.Name] = ch.ID
		}
	}
	// Groups may reference groups defined later: allocate IDs first.
	for _, g := range c.ProxyGroups {
		ids[g.Name] = config.NewID()
	}
	for _, g := range c.ProxyGroups {
		ch := config.Chain{ID: ids[g.Name], Name: g.Name}
		switch strings.ToLower(g.Type) {
		case "relay":
			ch.Mode = config.ModeChain
		case "url-test":
			ch.Mode = config.ModeFastest
		case "load-balance":
			ch.Mode = config.ModeRoundRobin
		default: // select, fallback
			ch.Mode = config.ModeFailover
		}
		for _, m := range g.Proxies {
			id, ok := ids[m]
			if !ok {
				if m != "DIRECT" && m != "REJECT" {
					r.warn("Group %q: member %q is not available", g.Name, m)
				}
				continue
			}
			if ch.Mode == config.ModeChain && r.Profile.FindProxy(id) == nil {
				r.warn("Relay %q: nested group %q flattened away", g.Name, m)
				continue
			}
			ch.Members = append(ch.Members, id)
		}
		if len(ch.Members) == 0 {
			r.warn("Group %q has no usable members and was skipped", g.Name)
			delete(ids, g.Name)
			continue
		}
		r.Profile.Chains = append(r.Profile.Chains, ch)
	}
	target := func(name string) (config.Action, bool) {
		switch strings.ToUpper(name) {
		case "DIRECT":
			return config.Action{Type: config.ActionDirect}, true
		case "REJECT", "REJECT-DROP", "REJECT-TINYGIF":
			return config.Action{Type: config.ActionBlock}, true
		}
		if id, ok := ids[name]; ok {
			return config.Action{Type: config.ActionProxy, Target: id}, true
		}
		return config.Action{}, false
	}
	unsupported := map[string]int{}
	var prev *config.Rule
	var prevField string
	for _, line := range c.Rules {
		parts := strings.Split(line, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		typ := strings.ToUpper(parts[0])
		if typ == "MATCH" || typ == "FINAL" {
			if len(parts) >= 2 {
				if a, ok := target(parts[1]); ok {
					r.Profile.DefaultAction = a
					r.HasDefault = true
				}
			}
			continue
		}
		if len(parts) < 3 {
			continue
		}
		val, tgt := parts[1], parts[2]
		a, ok := target(tgt)
		if !ok {
			unsupported["target "+tgt]++
			continue
		}
		field, item := "", ""
		switch typ {
		case "DOMAIN":
			field, item = "hosts", val
		case "DOMAIN-SUFFIX":
			field, item = "hosts", "."+val
		case "DOMAIN-KEYWORD":
			field, item = "hosts", "keyword:"+val
		case "DOMAIN-REGEX":
			field, item = "hosts", "re:"+val
		case "DOMAIN-WILDCARD":
			field, item = "hosts", val
		case "IP-CIDR", "IP-CIDR6", "IP-SUFFIX":
			field, item = "hosts", val
		case "PROCESS-NAME":
			field, item = "apps", val
		case "PROCESS-PATH":
			field, item = "apps", val
		case "DST-PORT":
			field, item = "ports", val
		default:
			unsupported[typ]++
			continue
		}
		// Adjacent rules with the same field and target merge into one.
		if prev != nil && prevField == field && prev.Action == a {
			switch field {
			case "hosts":
				prev.Hosts = append(prev.Hosts, item)
			case "apps":
				prev.Apps = append(prev.Apps, item)
			case "ports":
				prev.Ports = append(prev.Ports, item)
			}
			continue
		}
		nr := config.Rule{ID: config.NewID(), Enabled: true, Action: a, Name: fmt.Sprintf("%s → %s", strings.ToLower(typ), tgt)}
		switch field {
		case "hosts":
			nr.Hosts = []string{item}
		case "apps":
			nr.Apps = []string{item}
		case "ports":
			nr.Ports = []string{item}
		}
		r.Profile.Rules = append(r.Profile.Rules, nr)
		prev = &r.Profile.Rules[len(r.Profile.Rules)-1]
		prevField = field
	}
	keys := make([]string, 0, len(unsupported))
	for k := range unsupported {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r.warn("%d rule(s) of type %s skipped (not supported)", unsupported[k], k)
	}
	for i := range r.Profile.Rules {
		ru := &r.Profile.Rules[i]
		n := len(ru.Hosts) + len(ru.Apps) + len(ru.Ports)
		if n > 1 {
			ru.Name = fmt.Sprintf("%s (%d)", ru.Name, n)
		}
	}
	return r, nil
}

func exportClash(p *config.Profile) ([]byte, []string, error) {
	var warn []string
	c := clashConfig{MixedPort: 7890, Mode: "rule"}
	names := map[string]string{}
	taken := map[string]bool{"DIRECT": true, "REJECT": true}
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
	for _, px := range p.Proxies {
		n := uniq(px.Label())
		names[px.ID] = n
		cp := clashProxy{Name: n, Server: px.Host, Port: px.Port, Username: px.Username, Password: px.Password}
		switch px.Type {
		case config.SOCKS5:
			cp.Type = "socks5"
			cp.UDP = true
		case config.HTTP:
			cp.Type = "http"
		case config.HTTPS:
			cp.Type = "http"
			cp.TLS = true
			cp.SNI = px.TLSServerName
			cp.SkipCertVerify = px.TLSInsecure
		default:
			warn = append(warn, fmt.Sprintf("%s: Clash has no SOCKS4 support; skipped", px.Label()))
			delete(names, px.ID)
			continue
		}
		c.Proxies = append(c.Proxies, cp)
	}
	for _, ch := range p.Chains {
		names[ch.ID] = uniq(ch.Name)
	}
	for _, ch := range p.Chains {
		g := clashGroup{Name: names[ch.ID]}
		switch ch.Mode {
		case config.ModeChain:
			g.Type = "relay"
		case config.ModeFastest:
			g.Type, g.URL, g.Interval = "url-test", p.Settings.CheckURL, 300
		case config.ModeFailover:
			g.Type, g.URL, g.Interval = "fallback", p.Settings.CheckURL, 300
		default:
			g.Type, g.URL, g.Interval, g.Strategy = "load-balance", p.Settings.CheckURL, 300, "round-robin"
		}
		for _, m := range ch.Members {
			if n, ok := names[m]; ok {
				g.Proxies = append(g.Proxies, n)
			}
		}
		c.ProxyGroups = append(c.ProxyGroups, g)
	}
	tgt := func(a config.Action) string {
		switch a.Type {
		case config.ActionBlock:
			return "REJECT"
		case config.ActionProxy:
			if n, ok := names[a.Target]; ok {
				return n
			}
		}
		return "DIRECT"
	}
	for _, ru := range p.Rules {
		if !ru.Enabled {
			continue
		}
		t := tgt(ru.Action)
		var hostConds, appConds, portConds []string
		for _, h := range ru.Hosts {
			f := classifyHost(h)
			switch f.kind {
			case "exact":
				hostConds = append(hostConds, "DOMAIN,"+f.value)
			case "suffix", "wildsub":
				hostConds = append(hostConds, "DOMAIN-SUFFIX,"+f.value)
			case "keyword":
				hostConds = append(hostConds, "DOMAIN-KEYWORD,"+f.value)
			case "regex":
				hostConds = append(hostConds, "DOMAIN-REGEX,"+f.value)
			case "wildcard":
				hostConds = append(hostConds, "DOMAIN-REGEX,"+globToRegex(f.value))
			case "cidr":
				kind := "IP-CIDR"
				if strings.Contains(f.value, ":") {
					kind = "IP-CIDR6"
				}
				hostConds = append(hostConds, kind+","+f.value+",no-resolve")
			case "range":
				for _, pf := range rangeToPrefixes(f.value) {
					kind := "IP-CIDR"
					if pf.Addr().Is6() {
						kind = "IP-CIDR6"
					}
					hostConds = append(hostConds, kind+","+pf.String()+",no-resolve")
				}
			case "ipglob":
				if pf, ok := ipGlobToPrefix(f.value); ok {
					hostConds = append(hostConds, "IP-CIDR,"+pf.String()+",no-resolve")
				} else {
					warn = append(warn, fmt.Sprintf("Rule %q: %q cannot be expressed in Clash", ru.Name, h))
				}
			}
		}
		for _, a := range ru.Apps {
			if strings.ContainsAny(a, `/\`) {
				if strings.ContainsAny(a, "*?") {
					appConds = append(appConds, "PROCESS-PATH-REGEX,"+globToRegex(strings.ToLower(a)))
				} else {
					appConds = append(appConds, "PROCESS-PATH,"+a)
				}
			} else if strings.ContainsAny(a, "*?") {
				appConds = append(appConds, "PROCESS-NAME-REGEX,"+globToRegex(strings.ToLower(a)))
			} else {
				appConds = append(appConds, "PROCESS-NAME,"+a)
			}
		}
		for _, pt := range ru.Ports {
			portConds = append(portConds, "DST-PORT,"+pt)
		}
		if ru.Protocol != config.ProtoAny {
			warn = append(warn, fmt.Sprintf("Rule %q: protocol restriction dropped", ru.Name))
		}
		groups := [][]string{}
		for _, g := range [][]string{appConds, hostConds, portConds} {
			if len(g) > 0 {
				groups = append(groups, g)
			}
		}
		switch len(groups) {
		case 0:
			continue
		case 1:
			for _, cond := range groups[0] {
				c.Rules = append(c.Rules, injectTarget(cond, t))
			}
		default:
			// Mihomo logic rules: AND of ORs.
			var parts []string
			for gi := range groups {
				for ci := range groups[gi] {
					groups[gi][ci] = strings.TrimSuffix(groups[gi][ci], ",no-resolve")
				}
			}
			for _, g := range groups {
				if len(g) == 1 {
					parts = append(parts, "("+g[0]+")")
					continue
				}
				inner := make([]string, len(g))
				for i, x := range g {
					inner[i] = "(" + x + ")"
				}
				parts = append(parts, "(OR,("+strings.Join(inner, ",")+"))")
			}
			c.Rules = append(c.Rules, "AND,("+strings.Join(parts, ",")+"),"+t)
		}
	}
	c.Rules = append(c.Rules, "MATCH,"+tgt(p.DefaultAction))
	b, err := yaml.Marshal(c)
	if err != nil {
		return nil, nil, err
	}
	header := "# Exported from SentinelProxy. Multi-condition rules use Mihomo (Clash Meta) AND/OR syntax.\n"
	return append([]byte(header), b...), warn, nil
}

// injectTarget places the target before an optional trailing ",no-resolve".
func injectTarget(cond, target string) string {
	if strings.HasSuffix(cond, ",no-resolve") {
		return strings.TrimSuffix(cond, ",no-resolve") + "," + target + ",no-resolve"
	}
	return cond + "," + target
}
