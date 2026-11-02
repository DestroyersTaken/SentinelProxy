//go:build !linux && !windows

package procinfo

import (
	"net/netip"
	"os"
)

func selfPID() int                           { return os.Getpid() }
func exePath(uint32) string                  { return "" }
func fallbackName(uint32) string             { return "" }
func tcpOwner(netip.AddrPort) (uint32, bool) { return 0, false }
func udpOwner(netip.AddrPort) (uint32, bool) { return 0, false }

func listProcesses() []Process { return nil }
