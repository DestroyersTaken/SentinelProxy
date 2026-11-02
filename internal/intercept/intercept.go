// Package intercept captures traffic system-wide and hands it to the engine
// without any per-app proxy configuration: WinDivert on Windows, nftables on
// Linux.
package intercept

import (
	"errors"

	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/engine"
)

// Interceptor is a running capture.
type Interceptor interface {
	// Name describes the backend ("WinDivert", "nftables").
	Name() string
	// Stats returns backend counters for diagnostics.
	Stats() Stats
	Close() error
}

// Stats are backend counters.
type Stats struct {
	Packets    uint64 `json:"packets"`
	Redirected uint64 `json:"redirected"`
	Bypassed   uint64 `json:"bypassed"`
	DNSFaked   uint64 `json:"dnsFaked"`
	Flows      int    `json:"flows"`
	Errors     uint64 `json:"errors"`
	LastError  string `json:"lastError,omitempty"`
}

// ErrUnsupported is returned on platforms without a capture backend.
var ErrUnsupported = errors.New("system-wide interception is not available on this platform; use the local proxy port instead")

// Start begins capturing according to the settings.
func Start(eng *engine.Engine, s config.Settings) (Interceptor, error) {
	return start(eng, s)
}

// Available reports whether this platform has a capture backend and, if
// not, why.
func Available() (bool, string) { return available() }
