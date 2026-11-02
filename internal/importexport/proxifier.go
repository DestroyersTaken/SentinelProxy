package importexport

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
)

type ppxProfile struct {
	XMLName  xml.Name   `xml:"ProxifierProfile"`
	Version  string     `xml:"version,attr"`
	Platform string     `xml:"platform,attr"`
	ProdID   string     `xml:"product_id,attr"`
	MinVer   string     `xml:"product_minver,attr"`
	Options  ppxOptions `xml:"Options"`
	Proxies  []ppxProxy `xml:"ProxyList>Proxy"`
	Chains   []ppxChain `xml:"ChainList>Chain"`
	Rules    []ppxRule  `xml:"RuleList>Rule"`
}

type ppxEnabled struct {
	Enabled string `xml:"enabled,attr"`
}

type ppxOptions struct {
	Resolve struct {
		AutoModeDetection ppxEnabled `xml:"AutoModeDetection"`
		ViaProxy          struct {
			Enabled          string     `xml:"enabled,attr"`
			TryLocalDnsFirst ppxEnabled `xml:"TryLocalDnsFirst"`
		} `xml:"ViaProxy"`
		ExclusionList string `xml:"ExclusionList"`
		DnsUdpMode    string `xml:"DnsUdpMode,omitempty"`
	} `xml:"Resolve"`
	Encryption struct {
		Mode string `xml:"mode,attr"`
	} `xml:"Encryption"`
	HTTPProxiesSupport      ppxEnabled `xml:"HttpProxiesSupport"`
	HandleDirectConnections ppxEnabled `xml:"HandleDirectConnections"`
	ConnectionLoopDetection ppxEnabled `xml:"ConnectionLoopDetection"`
	ProcessServices         ppxEnabled `xml:"ProcessServices"`
	ProcessOtherUsers       ppxEnabled `xml:"ProcessOtherUsers"`
}

type ppxProxy struct {
	ID      string `xml:"id,attr"`
	Type    string `xml:"type,attr"`
	Label   string `xml:"Label,omitempty"`
	Address string `xml:"Address"`
	Port    int    `xml:"Port"`
	Options string `xml:"Options,omitempty"`
	Auth    *struct {
		Enabled  string `xml:"enabled,attr"`
		Username string `xml:"Username"`
		Password string `xml:"Password"`
	} `xml:"Authentication"`
}

type ppxChainProxy struct {
	Enabled string `xml:"enabled,attr"`
	ID      string `xml:",chardata"`
}

type ppxChain struct {
	ID      string          `xml:"id,attr"`
	Type    string          `xml:"type,attr"`
	Name    string          `xml:"Name"`
	Timeout string          `xml:"RedundancyTimeout,omitempty"`
	Proxies []ppxChainProxy `xml:"Proxy"`
}

type ppxRule struct {
	Enabled      string `xml:"enabled,attr"`
	Name         string `xml:"Name"`
	Applications string `xml:"Applications,omitempty"`
	Targets      string `xml:"Targets,omitempty"`
	Ports        string `xml:"Ports,omitempty"`
	Action       struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"Action"`
}

// splitProxifier splits "a; b c; "C:\Program Files\x.exe"" into items:
// separators are ';', ',' and whitespace outside double quotes.
func splitProxifier(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
		case !inQ && (r == ';' || r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func joinProxifier(items []string) string {
	out := make([]string, len(items))
	for i, it := range items {
		if strings.ContainsAny(it, " ;,") {
			it = `"` + it + `"`
		}
		out[i] = it
	}
	return strings.Join(out, "; ")
}

func importProxifier(data []byte) (*Result, error) {
	var x ppxProfile
	if err := xml.Unmarshal(data, &x); err != nil {
		return nil, fmt.Errorf("not a valid Proxifier profile: %w", err)
	}
	r := newResult("proxifier")
	r.HasSettings = true
	enc := strings.ToLower(x.Options.Encryption.Mode)
	passwordsEncrypted := enc != "" && enc != "disabled"
	for _, px := range x.Proxies {
		p := config.Proxy{ID: "ppx" + px.ID, Host: px.Address, Port: px.Port, Name: px.Label}
		switch strings.ToUpper(px.Type) {
		case "SOCKS5":
			p.Type = config.SOCKS5
		case "SOCKS4":
			p.Type = config.SOCKS4A // Proxifier's SOCKS4 sends hostnames when resolving via proxy
		case "HTTPS", "HTTP":
			// Proxifier's "HTTPS" is an HTTP proxy using CONNECT (not TLS to the proxy).
			p.Type = config.HTTP
		default:
			r.warn("Proxy %s:%d skipped: unknown type %q", px.Address, px.Port, px.Type)
			continue
		}
		if px.Auth != nil && strings.EqualFold(px.Auth.Enabled, "true") {
			p.Username = px.Auth.Username
			p.Password = px.Auth.Password
		}
		r.Profile.Proxies = append(r.Profile.Proxies, p)
	}
	if passwordsEncrypted {
		has := false
		for _, p := range r.Profile.Proxies {
			if p.Password != "" {
				has = true
			}
		}
		if has {
			r.warn("Proxifier encrypted the proxy passwords in this file, so they could not be read. Re-enter them, or in Proxifier set Profile → Advanced → Encryption to \"Do not encrypt\" and export again.")
			for i := range r.Profile.Proxies {
				r.Profile.Proxies[i].Password = ""
			}
		}
	}
	for _, c := range x.Chains {
		ch := config.Chain{ID: "ppx" + c.ID, Name: c.Name}
		switch strings.ToLower(c.Type) {
		case "redundancy":
			ch.Mode = config.ModeFailover
		case "load_balancing", "loadbalancing":
			ch.Mode = config.ModeRoundRobin
		default:
			ch.Mode = config.ModeChain
		}
		for _, m := range c.Proxies {
			if strings.EqualFold(m.Enabled, "false") {
				continue
			}
			ch.Members = append(ch.Members, "ppx"+strings.TrimSpace(m.ID))
		}
		r.Profile.Chains = append(r.Profile.Chains, ch)
	}
	for i, xr := range x.Rules {
		act := config.Action{}
		switch strings.ToLower(xr.Action.Type) {
		case "direct":
			act.Type = config.ActionDirect
		case "block":
			act.Type = config.ActionBlock
		case "proxy", "chain":
			act.Type = config.ActionProxy
			act.Target = "ppx" + strings.TrimSpace(xr.Action.Value)
		default:
			r.warn("Rule %q skipped: unknown action %q", xr.Name, xr.Action.Type)
			continue
		}
		rule := config.Rule{
			Name:    xr.Name,
			Enabled: !strings.EqualFold(xr.Enabled, "false"),
			Apps:    splitProxifier(xr.Applications),
			Hosts:   cleanTargets(splitProxifier(xr.Targets), r),
			Ports:   splitProxifier(xr.Ports),
			Action:  act,
		}
		isLast := i == len(x.Rules)-1
		if isLast && len(rule.Apps) == 0 && len(rule.Hosts) == 0 && len(rule.Ports) == 0 {
			r.Profile.DefaultAction = act
			r.HasDefault = true
			continue
		}
		r.Profile.Rules = append(r.Profile.Rules, rule)
	}
	via := strings.EqualFold(x.Options.Resolve.ViaProxy.Enabled, "true")
	auto := strings.EqualFold(x.Options.Resolve.AutoModeDetection.Enabled, "true")
	if via || auto {
		r.Profile.Settings.DNS.Mode = config.DNSAuto
	} else {
		r.Profile.Settings.DNS.Mode = config.DNSLocal
	}
	if ex := cleanTargets(splitProxifier(x.Options.Resolve.ExclusionList), nil); len(ex) > 0 {
		r.Profile.Settings.DNS.Exclusions = ex
	}
	return r, nil
}

// cleanTargets drops Proxifier macros SentinelProxy handles differently.
func cleanTargets(in []string, r *Result) []string {
	out := in[:0]
	for _, t := range in {
		if strings.EqualFold(t, "%ComputerName%") {
			continue // the local machine is never captured
		}
		if strings.Contains(t, "%") && r != nil {
			r.warn("Target %q uses a Proxifier variable and was skipped", t)
			continue
		}
		out = append(out, t)
	}
	return out
}

func exportProxifier(p *config.Profile) ([]byte, []string, error) {
	var warn []string
	x := ppxProfile{Version: "102", Platform: "Windows", ProdID: "0", MinVer: "400"}
	x.Options.Resolve.AutoModeDetection.Enabled = "false"
	x.Options.Resolve.ViaProxy.Enabled = strconv.FormatBool(p.Settings.DNS.Mode != config.DNSLocal)
	x.Options.Resolve.ViaProxy.TryLocalDnsFirst.Enabled = "false"
	x.Options.Resolve.ExclusionList = joinProxifier(append([]string{"%ComputerName%"}, p.Settings.DNS.Exclusions...))
	x.Options.Encryption.Mode = "disabled"
	x.Options.HTTPProxiesSupport.Enabled = "false"
	x.Options.HandleDirectConnections.Enabled = "false"
	x.Options.ConnectionLoopDetection.Enabled = "true"
	x.Options.ProcessServices.Enabled = "true"
	x.Options.ProcessOtherUsers.Enabled = "true"

	ids := map[string]string{}
	next := 100
	for _, px := range p.Proxies {
		ids[px.ID] = strconv.Itoa(next)
		next++
	}
	for _, c := range p.Chains {
		ids[c.ID] = strconv.Itoa(next)
		next++
	}
	for _, px := range p.Proxies {
		xp := ppxProxy{ID: ids[px.ID], Address: px.Host, Port: px.Port, Label: px.Name, Options: "48"}
		switch px.Type {
		case config.SOCKS5:
			xp.Type = "SOCKS5"
		case config.SOCKS4, config.SOCKS4A:
			xp.Type = "SOCKS4"
		case config.HTTP:
			xp.Type = "HTTPS"
		case config.HTTPS:
			xp.Type = "HTTPS"
			warn = append(warn, fmt.Sprintf("%s: Proxifier cannot connect to proxies over TLS; exported as a plain HTTP CONNECT proxy", px.Label()))
		}
		if px.Username != "" || px.Password != "" {
			xp.Auth = &struct {
				Enabled  string `xml:"enabled,attr"`
				Username string `xml:"Username"`
				Password string `xml:"Password"`
			}{"true", px.Username, px.Password}
		}
		x.Proxies = append(x.Proxies, xp)
	}
	for _, c := range p.Chains {
		xc := ppxChain{ID: ids[c.ID], Name: c.Name}
		switch c.Mode {
		case config.ModeChain:
			xc.Type = "simple"
		case config.ModeFailover, config.ModeFastest:
			xc.Type = "redundancy"
			xc.Timeout = "5"
			if c.Mode == config.ModeFastest {
				warn = append(warn, fmt.Sprintf("%s: Proxifier has no fastest-proxy mode; exported as redundancy", c.Name))
			}
		default:
			xc.Type = "load_balancing"
		}
		for _, m := range c.Members {
			if p.FindChain(m) != nil {
				warn = append(warn, fmt.Sprintf("%s: Proxifier chains cannot contain other chains; member skipped", c.Name))
				continue
			}
			xc.Proxies = append(xc.Proxies, ppxChainProxy{Enabled: "true", ID: ids[m]})
		}
		x.Chains = append(x.Chains, xc)
	}
	action := func(a config.Action) (string, string) {
		switch a.Type {
		case config.ActionBlock:
			return "Block", ""
		case config.ActionProxy:
			if p.FindChain(a.Target) != nil {
				return "Chain", ids[a.Target]
			}
			return "Proxy", ids[a.Target]
		}
		return "Direct", ""
	}
	for _, r := range p.Rules {
		xr := ppxRule{Enabled: strconv.FormatBool(r.Enabled), Name: r.Name, Applications: joinProxifier(r.Apps), Ports: joinProxifier(r.Ports)}
		var hosts []string
		for _, h := range r.Hosts {
			switch {
			case strings.HasPrefix(h, ".") || strings.HasPrefix(h, "+.") || strings.HasPrefix(h, "domain:"):
				base := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(h, "domain:"), "+"), ".")
				hosts = append(hosts, base, "*."+base)
			case strings.HasPrefix(h, "keyword:"):
				hosts = append(hosts, "*"+strings.TrimPrefix(h, "keyword:")+"*")
			case strings.HasPrefix(h, "re:") || strings.HasPrefix(h, "regex:"):
				warn = append(warn, fmt.Sprintf("Rule %q: Proxifier has no regex targets; %q skipped", r.Name, h))
			default:
				hosts = append(hosts, h)
			}
		}
		xr.Targets = joinProxifier(hosts)
		if r.Protocol == config.ProtoUDP {
			warn = append(warn, fmt.Sprintf("Rule %q is UDP-only; Proxifier rules apply to all protocols", r.Name))
		}
		xr.Action.Type, xr.Action.Value = action(r.Action)
		x.Rules = append(x.Rules, xr)
	}
	def := ppxRule{Enabled: "true", Name: "Default"}
	def.Action.Type, def.Action.Value = action(p.DefaultAction)
	x.Rules = append(x.Rules, def)

	out, err := xml.MarshalIndent(x, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+"\n"), out...), warn, nil
}
