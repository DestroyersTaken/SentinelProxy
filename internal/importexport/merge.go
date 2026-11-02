package importexport

import (
	"fmt"
	"strings"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
)

// MergeOptions controls how an import is applied to an existing profile.
type MergeOptions struct {
	// Replace discards the existing proxies, chains and rules.
	Replace bool `json:"replace"`
	// Proxies, Chains and Rules select what to take from the import.
	// Proxies referenced by imported chains or rules are always added.
	Proxies bool `json:"proxies"`
	Chains  bool `json:"chains"`
	Rules   bool `json:"rules"`
	// RulesOnTop inserts imported rules before the existing ones.
	RulesOnTop bool `json:"rulesOnTop"`
	// Settings and Default also take the imported settings / default action.
	Settings bool `json:"settings"`
	Default  bool `json:"default"`
}

// MergeSummary reports what changed.
type MergeSummary struct {
	ProxiesAdded int      `json:"proxiesAdded"`
	ProxiesSame  int      `json:"proxiesSame"`
	ChainsAdded  int      `json:"chainsAdded"`
	RulesAdded   int      `json:"rulesAdded"`
	Warnings     []string `json:"warnings"`
}

func proxyKey(p *config.Proxy) string {
	return fmt.Sprintf("%s|%s|%d|%s", p.Type, strings.ToLower(p.Host), p.Port, p.Username)
}

// Merge applies src to a copy of dst and returns it. Proxies that already
// exist (same type, host, port and user) are reused instead of duplicated;
// every reference is remapped to the final IDs.
func Merge(dst, src *config.Profile, o MergeOptions) (*config.Profile, MergeSummary) {
	out := dst.Clone()
	sum := MergeSummary{Warnings: []string{}}
	if o.Replace {
		// Replacing is all-or-nothing so no rule can point at a removed proxy.
		out.Proxies, out.Chains, out.Rules = nil, nil, nil
		out.DefaultAction = config.Action{Type: config.ActionDirect}
	}
	idMap := map[string]string{}
	existing := map[string]string{}
	names := map[string]bool{}
	used := map[string]bool{}
	for _, p := range out.Proxies {
		existing[proxyKey(&p)] = p.ID
		names[strings.ToLower(p.Name)] = true
		used[p.ID] = true
	}
	for _, c := range out.Chains {
		used[c.ID] = true
		names[strings.ToLower(c.Name)] = true
	}
	freshID := func(id string) string {
		if id == "" || used[id] {
			id = config.NewID()
		}
		used[id] = true
		return id
	}
	uniqueName := func(n string) string {
		if n == "" || !names[strings.ToLower(n)] {
			names[strings.ToLower(n)] = true
			return n
		}
		for i := 2; ; i++ {
			c := fmt.Sprintf("%s (%d)", n, i)
			if !names[strings.ToLower(c)] {
				names[strings.ToLower(c)] = true
				return c
			}
		}
	}
	if o.Proxies || o.Chains || o.Rules {
		for _, p := range src.Proxies {
			if id, ok := existing[proxyKey(&p)]; ok {
				idMap[p.ID] = id
				sum.ProxiesSame++
				continue
			}
			np := p
			np.ID = freshID(p.ID)
			np.Name = uniqueName(p.Name)
			idMap[p.ID] = np.ID
			existing[proxyKey(&np)] = np.ID
			out.Proxies = append(out.Proxies, np)
			sum.ProxiesAdded++
		}
	}
	if o.Chains || o.Rules {
		for _, c := range src.Chains {
			idMap[c.ID] = freshID(c.ID)
		}
		for _, c := range src.Chains {
			nc := c
			nc.ID = idMap[c.ID]
			nc.Name = uniqueName(c.Name)
			nc.Members = nil
			for _, m := range c.Members {
				if id, ok := idMap[m]; ok {
					nc.Members = append(nc.Members, id)
				}
			}
			out.Chains = append(out.Chains, nc)
			sum.ChainsAdded++
		}
	}
	byName := func(name string) (string, bool) {
		for _, px := range out.Proxies {
			if strings.EqualFold(px.Name, name) || strings.EqualFold(px.Label(), name) || px.ID == name {
				return px.ID, true
			}
		}
		for _, c := range out.Chains {
			if strings.EqualFold(c.Name, name) || c.ID == name {
				return c.ID, true
			}
		}
		return "", false
	}
	remap := func(a config.Action) config.Action {
		if a.Type != config.ActionProxy {
			return a
		}
		if id, ok := idMap[a.Target]; ok {
			a.Target = id
			return a
		}
		if name, ok := strings.CutPrefix(a.Target, namePrefix); ok {
			if id, ok := byName(name); ok {
				a.Target = id
				return a
			}
			a.Target = namePrefix + name // unresolved: handled by the caller
		}
		return a
	}
	if o.Rules {
		var imported []config.Rule
		for _, r := range src.Rules {
			nr := r
			nr.ID = config.NewID()
			nr.Action = remap(r.Action)
			if name, ok := strings.CutPrefix(nr.Action.Target, namePrefix); ok {
				if len(out.Proxies) > 0 {
					nr.Action.Target = out.Proxies[0].ID
					sum.Warnings = append(sum.Warnings, fmt.Sprintf("Rule %q used proxy %q, which does not exist here; it now uses %q (change it if needed)", nr.Name, name, out.Proxies[0].Label()))
				} else {
					nr.Action = config.Action{Type: config.ActionDirect}
					nr.Enabled = false
					sum.Warnings = append(sum.Warnings, fmt.Sprintf("Rule %q used proxy %q, which does not exist; it was imported disabled", nr.Name, name))
				}
			}
			imported = append(imported, nr)
		}
		if o.RulesOnTop {
			out.Rules = append(imported, out.Rules...)
		} else {
			out.Rules = append(out.Rules, imported...)
		}
		sum.RulesAdded = len(imported)
	}
	if o.Default {
		out.DefaultAction = remap(src.DefaultAction)
	}
	if o.Settings {
		out.Settings = src.Settings
	}
	out.Normalize()
	return out, sum
}
