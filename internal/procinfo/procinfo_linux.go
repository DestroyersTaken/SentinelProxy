//go:build linux

package procinfo

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func selfPID() int { return os.Getpid() }

func exePath(pid uint32) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(p, " (deleted)")
}

func fallbackName(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// parseProcAddr decodes "0100007F:1F90" (v4) or the 32-hex-digit v6 form.
func parseProcAddr(s string) (netip.AddrPort, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return netip.AddrPort{}, false
	}
	// The kernel prints each 32-bit word in host (little-endian) order.
	for i := 0; i+4 <= len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	var ip netip.Addr
	switch len(raw) {
	case 4:
		ip = netip.AddrFrom4([4]byte(raw))
	case 16:
		ip = netip.AddrFrom16([16]byte(raw)).Unmap()
	default:
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, uint16(port)), true
}

func findInode(files []string, local netip.AddrPort) (string, bool) {
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan() // header
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 {
				continue
			}
			ap, ok := parseProcAddr(fields[1])
			if !ok || ap.Port() != local.Port() {
				continue
			}
			if ap.Addr() == local.Addr() || ap.Addr().IsUnspecified() {
				fh.Close()
				return fields[9], true
			}
		}
		fh.Close()
	}
	return "", false
}

func ownerOfInode(inode string) (uint32, bool) {
	if inode == "" || inode == "0" {
		return 0, false
	}
	want := "socket:[" + inode + "]"
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join("/proc", p.Name(), "fd")
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			if l, err := os.Readlink(filepath.Join(dir, fd.Name())); err == nil && l == want {
				return uint32(pid), true
			}
		}
	}
	return 0, false
}

func tcpOwner(local netip.AddrPort) (uint32, bool) {
	ino, ok := findInode([]string{"/proc/net/tcp", "/proc/net/tcp6"}, local)
	if !ok {
		return 0, false
	}
	return ownerOfInode(ino)
}

func udpOwner(local netip.AddrPort) (uint32, bool) {
	ino, ok := findInode([]string{"/proc/net/udp", "/proc/net/udp6"}, local)
	if !ok {
		return 0, false
	}
	return ownerOfInode(ino)
}

func listProcesses() []Process {
	var out []Process
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		path := exePath(uint32(pid))
		name := filepath.Base(path)
		if path == "" {
			name = fallbackName(uint32(pid))
		}
		if name == "" {
			continue
		}
		out = append(out, Process{PID: uint32(pid), Name: name, Path: path})
	}
	return out
}
