//go:build !windows

// Package elevate restarts SentinelProxy with administrator rights, which
// system-wide capture needs on Windows.
package elevate

import (
	"errors"
	"os"
	"time"
)

// Supported reports whether elevation is possible on this OS.
func Supported() bool { return false }

// IsElevated reports whether the process runs as root.
func IsElevated() bool { return os.Geteuid() == 0 }

// Relaunch is only implemented on Windows.
func Relaunch([]string) error {
	return errors.New("restart SentinelProxy with sudo to capture traffic system-wide")
}

// WaitForPID is a no-op outside Windows.
func WaitForPID(int, time.Duration) {}
