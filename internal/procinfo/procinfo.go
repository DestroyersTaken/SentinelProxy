// Package procinfo finds the process that owns a local socket.
package procinfo

import (
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/DestroyersTaken/SentinelProxy/internal/match"
)

// Self is the PID of this process.
var Self = uint32(selfPID())

type nameEntry struct {
	name, path string
	at         time.Time
}

var (
	namesMu sync.Mutex
	names   = map[uint32]nameEntry{}
)

// AppByPID resolves a PID to its executable, cached for a few seconds
// (PIDs are recycled, so entries are short-lived).
func AppByPID(pid uint32) match.AppInfo {
	if pid == 0 {
		return match.AppInfo{Name: "System Idle", PID: 0}
	}
	namesMu.Lock()
	e, ok := names[pid]
	namesMu.Unlock()
	if ok && time.Since(e.at) < 10*time.Second {
		return match.AppInfo{Name: e.name, Path: e.path, PID: pid}
	}
	path := exePath(pid)
	name := ""
	if path != "" {
		name = filepath.Base(strings.ReplaceAll(path, `\`, "/"))
	} else {
		name = fallbackName(pid)
	}
	namesMu.Lock()
	if len(names) > 4096 {
		names = map[uint32]nameEntry{}
	}
	names[pid] = nameEntry{name, path, time.Now()}
	namesMu.Unlock()
	return match.AppInfo{Name: name, Path: path, PID: pid}
}

// LookupTCP returns the process owning the TCP socket bound to local.
func LookupTCP(local netip.AddrPort) (match.AppInfo, bool) {
	pid, ok := tcpOwner(local)
	if !ok {
		return match.AppInfo{}, false
	}
	return AppByPID(pid), true
}

// LookupUDP returns the process owning the UDP socket bound to local.
func LookupUDP(local netip.AddrPort) (match.AppInfo, bool) {
	pid, ok := udpOwner(local)
	if !ok {
		return match.AppInfo{}, false
	}
	return AppByPID(pid), true
}

// PIDOfTCP returns only the owning PID (cheaper for loop checks).
func PIDOfTCP(local netip.AddrPort) (uint32, bool) { return tcpOwner(local) }

// PIDOfUDP returns only the owning PID.
func PIDOfUDP(local netip.AddrPort) (uint32, bool) { return udpOwner(local) }

// Process is a running program, for the rule editor's app picker.
type Process struct {
	PID  uint32 `json:"pid"`
	Name string `json:"name"`
	Path string `json:"path"`
}

// List returns running processes, one entry per executable path.
func List() []Process {
	all := listProcesses()
	seen := map[string]bool{}
	out := make([]Process, 0, len(all))
	for _, p := range all {
		k := strings.ToLower(p.Path)
		if k == "" {
			k = strings.ToLower(p.Name)
		}
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out
}
