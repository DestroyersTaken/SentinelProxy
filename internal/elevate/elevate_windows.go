//go:build windows

// Package elevate restarts SentinelProxy with administrator rights, which
// system-wide capture needs on Windows.
package elevate

import (
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// Supported reports whether elevation is possible on this OS.
func Supported() bool { return true }

// IsElevated reports whether the process runs as administrator.
func IsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// Relaunch starts a new elevated copy of this executable (UAC prompt) with
// args. The caller should quit right after; the child waits for it.
func Relaunch(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args = append(args, "--wait-pid", itoa(os.Getpid()))
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	return windows.ShellExecute(0, verb, file, params, nil, windows.SW_SHOWNORMAL)
}

// WaitForPID blocks until process pid exits (at most timeout).
func WaitForPID(pid int, timeout time.Duration) {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	windows.WaitForSingleObject(h, uint32(timeout.Milliseconds()))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
