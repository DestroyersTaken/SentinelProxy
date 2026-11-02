//go:build !windows

// Package sysproxy points the operating system's proxy settings at
// SentinelProxy's local proxy port, and restores them afterwards.
package sysproxy

import "errors"

// Supported reports whether this OS can be configured.
func Supported() bool { return false }

// Enable is not implemented on this platform.
func Enable(string) error {
	return errors.New("setting the system proxy is only supported on Windows; point your apps at the local proxy port")
}

// Disable is a no-op on this platform.
func Disable() error { return nil }
