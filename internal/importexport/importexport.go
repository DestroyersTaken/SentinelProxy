// Package importexport converts SentinelProxy profiles to and from other
// tools' formats: Proxifier (.ppx), ProxyBridge rules, Clash/Mihomo YAML,
// sing-box JSON, FoxyProxy, proxy lists (URIs, host:port:user:pass) and CSV.
package importexport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
)

// Format describes a supported file format.
type Format struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Ext    string `json:"ext"`
	Import bool   `json:"import"`
	Export bool   `json:"export"`
	// Scope is what the format carries: "profile", "rules" or "proxies".
	Scope string `json:"scope"`
	Hint  string `json:"hint"`
}

// Formats lists every format in display order.
var Formats = []Format{
	{"sentinel", "SentinelProxy profile", ".json", true, true, "profile", "Everything: proxies, chains, rules and settings."},
	{"proxifier", "Proxifier profile", ".ppx", true, true, "profile", "Proxifier 3/4 profiles (File → Export Profile)."},
	{"clash", "Clash / Mihomo", ".yaml", true, true, "profile", "proxies, proxy-groups and rules (non-SOCKS/HTTP proxy types are skipped)."},
	{"singbox", "sing-box", ".json", true, true, "profile", "socks/http outbounds, selector/urltest groups, detour chains and route rules."},
	{"proxybridge", "ProxyBridge rules", ".json", true, true, "rules", "ProxyBridge's rule export (processNames, targetHosts, targetPorts…)."},
	{"foxyproxy", "FoxyProxy", ".json", true, false, "proxies", "FoxyProxy 7/8 settings export (proxies only)."},
	{"list", "Proxy list / URIs", ".txt", true, true, "proxies", "One per line: socks5://user:pass@host:port#Name, host:port:user:pass, user:pass@host:port, host:port."},
	{"csv", "CSV", ".csv", true, true, "proxies", "name,type,host,port,username,password"},
}

// FormatByID returns a format or nil.
func FormatByID(id string) *Format {
	for i := range Formats {
		if Formats[i].ID == id {
			return &Formats[i]
		}
	}
	return nil
}

// Result is an imported configuration plus anything worth telling the user.
type Result struct {
	Format   string          `json:"format"`
	Profile  *config.Profile `json:"profile"`
	Warnings []string        `json:"warnings"`
	// HasSettings is true when the source carried profile-wide settings.
	HasSettings bool `json:"hasSettings"`
	// HasDefault is true when the source defines a default (final) action.
	HasDefault bool `json:"hasDefault"`
}

func (r *Result) warn(format string, a ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, a...))
}

func newResult(format string) *Result {
	p := config.NewProfile("Imported")
	p.Rules = []config.Rule{}
	return &Result{Format: format, Profile: p, Warnings: []string{}}
}

// Detect guesses the format of data (name is the file name, may be empty).
func Detect(name string, data []byte) string {
	t := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	ext := strings.ToLower(filepath.Ext(name))
	switch {
	case ext == ".ppx" || bytes.Contains(t[:min(len(t), 512)], []byte("<ProxifierProfile")):
		return "proxifier"
	case len(t) > 0 && (t[0] == '{' || t[0] == '['):
		var probe any
		if json.Unmarshal(t, &probe) != nil {
			break
		}
		switch v := probe.(type) {
		case []any:
			if len(v) > 0 {
				if m, ok := v[0].(map[string]any); ok {
					if _, ok := m["processNames"]; ok {
						return "proxybridge"
					}
					if _, ok := m["targetHosts"]; ok {
						return "proxybridge"
					}
				}
			}
			return "proxybridge"
		case map[string]any:
			if _, ok := v["processNames"]; ok {
				return "proxybridge"
			}
			if _, ok := v["outbounds"]; ok {
				return "singbox"
			}
			if _, ok := v["proxySettings"]; ok {
				return "foxyproxy"
			}
			if d, ok := v["data"].([]any); ok && len(d) > 0 {
				if m, ok := d[0].(map[string]any); ok {
					if _, ok := m["hostname"]; ok {
						return "foxyproxy"
					}
				}
			}
			if _, ok := v["rules"]; ok {
				if _, ok := v["defaultAction"]; ok {
					return "sentinel"
				}
			}
			if _, ok := v["proxies"]; ok {
				return "sentinel"
			}
		}
	case ext == ".yaml" || ext == ".yml" || bytes.Contains(t, []byte("\nproxies:")) || bytes.HasPrefix(t, []byte("proxies:")) || bytes.Contains(t, []byte("proxy-groups:")):
		return "clash"
	case ext == ".csv" || isCSV(t):
		return "csv"
	}
	return "list"
}

func isCSV(t []byte) bool {
	line, _, _ := bytes.Cut(t, []byte("\n"))
	l := strings.ToLower(string(line))
	return strings.Count(l, ",") >= 1 && (strings.Contains(l, "host") || strings.Contains(l, "server") || strings.Contains(l, "address")) && strings.Contains(l, "port")
}

// Import parses data. format "" means auto-detect.
func Import(name string, data []byte, format string) (*Result, error) {
	if format == "" || format == "auto" {
		format = Detect(name, data)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var (
		r   *Result
		err error
	)
	switch format {
	case "sentinel":
		r, err = importSentinel(data)
	case "proxifier":
		r, err = importProxifier(data)
	case "clash":
		r, err = importClash(data)
	case "singbox":
		r, err = importSingbox(data)
	case "proxybridge":
		r, err = importProxyBridge(data)
	case "foxyproxy":
		r, err = importFoxy(data)
	case "list":
		r, err = importList(data)
	case "csv":
		r, err = importCSV(data)
	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
	if err != nil {
		return nil, err
	}
	r.Profile.Normalize()
	if len(r.Profile.Proxies) == 0 && len(r.Profile.Rules) == 0 && len(r.Profile.Chains) == 0 {
		return nil, fmt.Errorf("nothing to import was found in this %s file", FormatByID(format).Name)
	}
	return r, nil
}

// Export renders p in format and returns the bytes plus a suggested file name.
func Export(p *config.Profile, format string) ([]byte, string, []string, error) {
	f := FormatByID(format)
	if f == nil || !f.Export {
		return nil, "", nil, fmt.Errorf("cannot export to %q", format)
	}
	base := strings.TrimSuffix(config.FileName(p.Name), ".json")
	var (
		b    []byte
		warn []string
		err  error
	)
	switch format {
	case "sentinel":
		b, err = json.MarshalIndent(p, "", "  ")
	case "proxifier":
		b, warn, err = exportProxifier(p)
	case "clash":
		b, warn, err = exportClash(p)
	case "singbox":
		b, warn, err = exportSingbox(p)
	case "proxybridge":
		b, warn, err = exportProxyBridge(p)
	case "list":
		b = exportList(p)
	case "csv":
		b, err = exportCSV(p)
	}
	if warn == nil {
		warn = []string{}
	}
	return b, base + f.Ext, warn, err
}

func importSentinel(data []byte) (*Result, error) {
	var p config.Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("not a valid SentinelProxy profile: %w", err)
	}
	if p.Version > config.SchemaVersion {
		return nil, fmt.Errorf("this profile was made by a newer SentinelProxy (format %d)", p.Version)
	}
	r := &Result{Format: "sentinel", Profile: &p, Warnings: []string{}, HasSettings: true, HasDefault: true}
	return r, nil
}
