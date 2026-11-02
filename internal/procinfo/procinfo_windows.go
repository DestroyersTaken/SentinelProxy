//go:build windows

package procinfo

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
	afInet              = 2
	afInet6             = 23
)

func selfPID() int { return int(windows.GetCurrentProcessId()) }

func exePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func fallbackName(pid uint32) string {
	switch pid {
	case 4:
		return "System"
	}
	return ""
}

// table caches a full table snapshot briefly: bursts of new connections
// (a browser opening a page) then cost one syscall instead of dozens.
type table struct {
	mu   sync.Mutex
	at   time.Time
	rows map[netip.AddrPort]uint32
	fill func() map[netip.AddrPort]uint32
}

func (t *table) lookup(local netip.AddrPort) (uint32, bool) {
	local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
	t.mu.Lock()
	defer t.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if t.rows == nil || time.Since(t.at) > 250*time.Millisecond || attempt == 1 {
			t.rows = t.fill()
			t.at = time.Now()
		}
		if pid, ok := t.rows[local]; ok {
			return pid, true
		}
		if pid, ok := t.rows[netip.AddrPortFrom(unspec(local.Addr()), local.Port())]; ok {
			return pid, true
		}
	}
	return 0, false
}

func unspec(a netip.Addr) netip.Addr {
	if a.Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

var tcpTable = &table{fill: func() map[netip.AddrPort]uint32 { return fillTable(procGetExtendedTcpTable, tcpTableOwnerPIDAll, true) }}
var udpTable = &table{fill: func() map[netip.AddrPort]uint32 { return fillTable(procGetExtendedUdpTable, udpTableOwnerPID, false) }}

func getTable(proc *windows.LazyProc, af, class uint32) []byte {
	size := uint32(64 << 10)
	for i := 0; i < 5; i++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(af), uintptr(class), 0)
		if r == 0 {
			return buf[:size]
		}
		if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil
		}
		size += 16 << 10
	}
	return nil
}

func fillTable(proc *windows.LazyProc, class uint32, tcp bool) map[netip.AddrPort]uint32 {
	rows := map[netip.AddrPort]uint32{}
	le := binary.LittleEndian
	// IPv4 rows: TCP {state, localAddr, localPort, remoteAddr, remotePort, pid} = 24 bytes;
	//            UDP {localAddr, localPort, pid} = 12 bytes.
	if b := getTable(proc, afInet, class); len(b) >= 4 {
		n := int(le.Uint32(b))
		rowSize, off := 12, 0
		if tcp {
			rowSize, off = 24, 4
		}
		for i := 0; i < n && 4+(i+1)*rowSize <= len(b); i++ {
			r := b[4+i*rowSize:]
			ip := netip.AddrFrom4([4]byte(r[off : off+4]))
			port := uint16(r[off+4])<<8 | uint16(r[off+5])
			pid := le.Uint32(r[rowSize-4:])
			rows[netip.AddrPortFrom(ip, port)] = pid
		}
	}
	// IPv6 rows: TCP {localAddr[16], scope, localPort, remoteAddr[16], scope, remotePort, state, pid} = 56;
	//            UDP {localAddr[16], scope, localPort, pid} = 28.
	if b := getTable(proc, afInet6, class); len(b) >= 4 {
		n := int(le.Uint32(b))
		rowSize := 28
		if tcp {
			rowSize = 56
		}
		for i := 0; i < n && 4+(i+1)*rowSize <= len(b); i++ {
			r := b[4+i*rowSize:]
			ip := netip.AddrFrom16([16]byte(r[0:16])).Unmap()
			port := uint16(r[20])<<8 | uint16(r[21])
			pid := le.Uint32(r[rowSize-4:])
			rows[netip.AddrPortFrom(ip, port)] = pid
		}
	}
	return rows
}

func tcpOwner(local netip.AddrPort) (uint32, bool) { return tcpTable.lookup(local) }
func udpOwner(local netip.AddrPort) (uint32, bool) { return udpTable.lookup(local) }

// Remember records a PID learned elsewhere (e.g. WinDivert socket events)
// so the next lookup for that port is free.
func Remember(tcp bool, local netip.AddrPort, pid uint32) {
	t := udpTable
	if tcp {
		t = tcpTable
	}
	t.mu.Lock()
	if t.rows == nil {
		t.rows = map[netip.AddrPort]uint32{}
	}
	t.rows[netip.AddrPortFrom(local.Addr().Unmap(), local.Port())] = pid
	t.mu.Unlock()
}

func listProcesses() []Process {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var out []Process
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		pid := e.ProcessID
		name := windows.UTF16ToString(e.ExeFile[:])
		if pid == 0 || name == "" {
			continue
		}
		out = append(out, Process{PID: pid, Name: name, Path: exePath(pid)})
	}
	return out
}
