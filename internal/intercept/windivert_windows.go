//go:build windows

package intercept

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Minimal WinDivert 2.2 binding loaded at run time from WinDivert.dll next
// to the executable (no cgo).

const (
	layerNetwork = 0
	layerSocket  = 3

	flagSniff    = 0x0001
	flagRecvOnly = 0x0004

	paramQueueLength = 0
	paramQueueTime   = 1
	paramQueueSize   = 2

	shutdownBoth = 3
)

// wdAddress mirrors WINDIVERT_ADDRESS (80 bytes).
type wdAddress struct {
	Timestamp int64
	bits      uint32
	_         uint32
	data      [64]byte
}

func (a *wdAddress) outbound() bool { return a.bits&(1<<17) != 0 }

func (a *wdAddress) setOutbound(v bool) {
	if v {
		a.bits |= 1 << 17
	} else {
		a.bits &^= 1 << 17
	}
}

// Socket-layer fields.
func (a *wdAddress) processID() uint32 { return binary.LittleEndian.Uint32(a.data[16:20]) }

func wdAddr(b []byte) netip.Addr {
	// UINT32[4] in host order, least significant word first.
	var out [16]byte
	for i := 0; i < 4; i++ {
		w := binary.LittleEndian.Uint32(b[4*(3-i):])
		binary.BigEndian.PutUint32(out[4*i:], w)
	}
	return netip.AddrFrom16(out).Unmap()
}

func (a *wdAddress) localAddr() netip.Addr { return wdAddr(a.data[20:36]) }
func (a *wdAddress) localPort() uint16     { return binary.LittleEndian.Uint16(a.data[52:54]) }
func (a *wdAddress) protocol() uint8       { return a.data[56] }

type winDivert struct {
	dll                                         *windows.DLL
	open, recv, send, close, shutdown, setParam *windows.Proc
	calcChecksums                               *windows.Proc
}

var (
	wdOnce sync.Once
	wd     *winDivert
	wdErr  error
)

// DriverDir returns where WinDivert.dll and WinDivert64.sys are expected.
func DriverDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func loadWinDivert() (*winDivert, error) {
	wdOnce.Do(func() {
		dir := DriverDir()
		dllPath := filepath.Join(dir, "WinDivert.dll")
		if _, err := os.Stat(dllPath); err != nil {
			wdErr = fmt.Errorf("WinDivert.dll not found next to SentinelProxy.exe (%s)", dir)
			return
		}
		if _, err := os.Stat(filepath.Join(dir, "WinDivert64.sys")); err != nil {
			wdErr = fmt.Errorf("WinDivert64.sys not found next to SentinelProxy.exe (%s)", dir)
			return
		}
		dll, err := windows.LoadDLL(dllPath)
		if err != nil {
			wdErr = fmt.Errorf("loading WinDivert.dll: %w", err)
			return
		}
		w := &winDivert{dll: dll}
		for name, dst := range map[string]**windows.Proc{
			"WinDivertOpen": &w.open, "WinDivertRecv": &w.recv, "WinDivertSend": &w.send,
			"WinDivertClose": &w.close, "WinDivertShutdown": &w.shutdown, "WinDivertSetParam": &w.setParam,
			"WinDivertHelperCalcChecksums": &w.calcChecksums,
		} {
			p, err := dll.FindProc(name)
			if err != nil {
				wdErr = fmt.Errorf("WinDivert.dll is missing %s (need WinDivert 2.2)", name)
				return
			}
			*dst = p
		}
		wd = w
	})
	return wd, wdErr
}

type wdHandle struct {
	w *winDivert
	h uintptr
}

func explainOpenError(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return errors.New("WinDivert needs administrator rights: run SentinelProxy as administrator")
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return errors.New("the WinDivert driver (WinDivert64.sys) was not found next to the executable")
	case errors.Is(err, windows.Errno(577)): // ERROR_INVALID_IMAGE_HASH
		return errors.New("Windows refused the WinDivert driver signature (Secure Boot / driver blocklist); update WinDivert or check Memory Integrity settings")
	case errors.Is(err, windows.Errno(1275)): // ERROR_DRIVER_BLOCKED
		return errors.New("the WinDivert driver was blocked by security software")
	case errors.Is(err, windows.Errno(87)): // ERROR_INVALID_PARAMETER
		return fmt.Errorf("WinDivert rejected the capture filter: %w", err)
	}
	return fmt.Errorf("WinDivertOpen: %w", err)
}

func (w *winDivert) Open(filter string, layer uint32, priority int16, flags uint64) (*wdHandle, error) {
	f, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	r, _, e := w.open.Call(uintptr(unsafe.Pointer(f)), uintptr(layer), uintptr(uint16(priority)), uintptr(flags))
	if r == uintptr(windows.InvalidHandle) {
		return nil, explainOpenError(e)
	}
	return &wdHandle{w: w, h: r}, nil
}

func (h *wdHandle) SetParam(param uint32, value uint64) {
	h.w.setParam.Call(h.h, uintptr(param), uintptr(value))
}

func (h *wdHandle) Recv(buf []byte, addr *wdAddress) (int, error) {
	var n uint32
	r, _, e := h.w.recv.Call(h.h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(addr)))
	if r == 0 {
		return 0, e
	}
	return int(n), nil
}

func (h *wdHandle) RecvEvent(addr *wdAddress) error {
	r, _, e := h.w.recv.Call(h.h, 0, 0, 0, uintptr(unsafe.Pointer(addr)))
	if r == 0 {
		return e
	}
	return nil
}

func (h *wdHandle) Send(pkt []byte, addr *wdAddress) error {
	var n uint32
	r, _, e := h.w.send.Call(h.h, uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(addr)))
	if r == 0 {
		return e
	}
	return nil
}

func (h *wdHandle) CalcChecksums(pkt []byte, addr *wdAddress) {
	h.w.calcChecksums.Call(uintptr(unsafe.Pointer(&pkt[0])), uintptr(len(pkt)), uintptr(unsafe.Pointer(addr)), 0)
}

func (h *wdHandle) Shutdown() { h.w.shutdown.Call(h.h, shutdownBoth) }
func (h *wdHandle) Close()    { h.w.close.Call(h.h) }

// Errors seen when a handle is shut down while a Recv is blocked.
func isShutdown(err error) bool {
	return errors.Is(err, windows.ERROR_NO_DATA) || errors.Is(err, windows.ERROR_INVALID_HANDLE) || errors.Is(err, windows.ERROR_OPERATION_ABORTED)
}
