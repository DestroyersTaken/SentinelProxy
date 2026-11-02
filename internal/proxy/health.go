package proxy

import (
	"sync"
	"time"
)

// Status is the health of one proxy or chain.
type Status struct {
	ID        string    `json:"id"`
	State     string    `json:"state"` // "unknown", "up", "down"
	LatencyMs int64     `json:"latencyMs"`
	LastCheck time.Time `json:"lastCheck"`
	LastError string    `json:"lastError,omitempty"`
	Failures  int       `json:"failures"`
	DownUntil time.Time `json:"downUntil"`
}

// Health tracks proxy health. It survives profile reloads.
type Health struct {
	mu sync.RWMutex
	m  map[string]*Status
	// OnChange is called (without locks held) after a status changes state.
	OnChange func(Status)
}

// NewHealth returns an empty table.
func NewHealth() *Health { return &Health{m: map[string]*Status{}} }

func (h *Health) get(id string) *Status {
	s := h.m[id]
	if s == nil {
		s = &Status{ID: id, State: "unknown"}
		h.m[id] = s
	}
	return s
}

// IsDown reports whether id failed recently and is in back-off.
func (h *Health) IsDown(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := h.m[id]
	return s != nil && s.State == "down" && time.Now().Before(s.DownUntil)
}

// Latency returns the last measured latency in ms (0 if unknown).
func (h *Health) Latency(id string) int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if s := h.m[id]; s != nil && s.State == "up" {
		return s.LatencyMs
	}
	return 0
}

// MarkOK records a success; latency 0 keeps the previous measurement.
func (h *Health) MarkOK(id string, latency time.Duration) {
	h.mu.Lock()
	s := h.get(id)
	changed := s.State != "up"
	s.State = "up"
	s.Failures = 0
	s.LastError = ""
	s.DownUntil = time.Time{}
	if latency > 0 {
		s.LatencyMs = latency.Milliseconds()
		if s.LatencyMs == 0 {
			s.LatencyMs = 1
		}
		s.LastCheck = time.Now()
	}
	cp := *s
	h.mu.Unlock()
	if changed && h.OnChange != nil {
		h.OnChange(cp)
	}
}

// MarkFail records a failure and starts an exponential back-off.
func (h *Health) MarkFail(id string, err error, _ time.Duration) {
	h.mu.Lock()
	s := h.get(id)
	changed := s.State != "down"
	s.State = "down"
	s.Failures++
	if err != nil {
		s.LastError = err.Error()
	}
	back := 15 * time.Second << min(s.Failures-1, 5)
	if back > 5*time.Minute {
		back = 5 * time.Minute
	}
	s.DownUntil = time.Now().Add(back)
	s.LastCheck = time.Now()
	cp := *s
	h.mu.Unlock()
	if changed && h.OnChange != nil {
		h.OnChange(cp)
	}
}

// Snapshot returns a copy of every status.
func (h *Health) Snapshot() map[string]Status {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[string]Status, len(h.m))
	for k, v := range h.m {
		out[k] = *v
	}
	return out
}

// Forget drops ids that no longer exist.
func (h *Health) Forget(keep map[string]bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id := range h.m {
		if !keep[id] {
			delete(h.m, id)
		}
	}
}
