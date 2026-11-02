//go:build windows

// Package sysproxy points the operating system's proxy settings at
// SentinelProxy's local proxy port, and restores them afterwards.
package sysproxy

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const key = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

var (
	wininet           = windows.NewLazySystemDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
)

type saved struct {
	enable   uint64
	server   string
	override string
	ok       bool
}

var prev saved

// Supported reports whether this OS can be configured.
func Supported() bool { return true }

// Enable sets the WinINet proxy (used by browsers and most apps) to addr.
func Enable(addr string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, key, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !prev.ok {
		prev.enable, _, _ = k.GetIntegerValue("ProxyEnable")
		prev.server, _, _ = k.GetStringValue("ProxyServer")
		prev.override, _, _ = k.GetStringValue("ProxyOverride")
		prev.ok = true
	}
	if err := k.SetStringValue("ProxyServer", addr); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyOverride", "<local>;localhost;127.*;10.*;172.16.*;192.168.*"); err != nil {
		return err
	}
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	refresh()
	return nil
}

// Disable restores the settings that were active before Enable.
func Disable() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if prev.ok {
		_ = k.SetStringValue("ProxyServer", prev.server)
		_ = k.SetStringValue("ProxyOverride", prev.override)
		_ = k.SetDWordValue("ProxyEnable", uint32(prev.enable))
		prev.ok = false
	} else {
		_ = k.SetDWordValue("ProxyEnable", 0)
	}
	refresh()
	return nil
}

func refresh() {
	const settingsChanged, refreshOpt = 39, 37
	internetSetOption.Call(0, settingsChanged, 0, 0)
	internetSetOption.Call(0, refreshOpt, 0, 0)
}
