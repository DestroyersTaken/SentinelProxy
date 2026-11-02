// Package logx is SentinelProxy's log: a bounded in-memory ring the UI reads
// from, mirrored to a rotating file and exposed as a slog.Handler.
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Entry is one log line.
type Entry struct {
	Seq   uint64    `json:"seq"`
	Time  time.Time `json:"time"`
	Level string    `json:"level"` // debug, info, warn, error
	Kind  string    `json:"kind"`  // "conn" for connection lines, "" otherwise
	Msg   string    `json:"msg"`
}

// Log is a concurrency-safe ring of entries.
type Log struct {
	mu    sync.Mutex
	ring  []Entry
	size  int
	seq   uint64
	level slog.Level
	file  io.WriteCloser
	path  string
	fsize int64
}

// New creates a log keeping the last size entries.
func New(size int) *Log { return &Log{ring: make([]Entry, 0, size), size: size} }

// SetLevel changes the minimum level ("debug", "info", "warn", "error").
func (l *Log) SetLevel(s string) {
	var lv slog.Level
	switch strings.ToLower(s) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	l.mu.Lock()
	l.level = lv
	l.mu.Unlock()
}

// OpenFile mirrors the log to path, rotating at 5 MB (one backup kept).
func (l *Log) OpenFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, _ := f.Stat()
	l.mu.Lock()
	l.file, l.path = f, path
	if st != nil {
		l.fsize = st.Size()
	}
	l.mu.Unlock()
	return nil
}

// Close closes the file.
func (l *Log) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
}

func levelName(lv slog.Level) string {
	switch {
	case lv >= slog.LevelError:
		return "error"
	case lv >= slog.LevelWarn:
		return "warn"
	case lv >= slog.LevelInfo:
		return "info"
	}
	return "debug"
}

// Add appends an entry.
func (l *Log) Add(lv slog.Level, kind, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lv < l.level {
		return
	}
	l.seq++
	e := Entry{Seq: l.seq, Time: time.Now(), Level: levelName(lv), Kind: kind, Msg: msg}
	if len(l.ring) < l.size {
		l.ring = append(l.ring, e)
	} else {
		l.ring[int((l.seq-1)%uint64(l.size))] = e
	}
	if l.file != nil {
		line := fmt.Sprintf("%s [%s] %s\n", e.Time.Format("2006-01-02 15:04:05.000"), strings.ToUpper(e.Level), msg)
		n, _ := io.WriteString(l.file, line)
		l.fsize += int64(n)
		if l.fsize > 5<<20 {
			l.file.Close()
			_ = os.Rename(l.path, l.path+".1")
			if f, err := os.OpenFile(l.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); err == nil {
				l.file = f
			} else {
				l.file = nil
			}
			l.fsize = 0
		}
	}
}

// Infof logs at info level.
func (l *Log) Infof(format string, a ...any) { l.Add(slog.LevelInfo, "", fmt.Sprintf(format, a...)) }

// Warnf logs at warn level.
func (l *Log) Warnf(format string, a ...any) { l.Add(slog.LevelWarn, "", fmt.Sprintf(format, a...)) }

// Errorf logs at error level.
func (l *Log) Errorf(format string, a ...any) { l.Add(slog.LevelError, "", fmt.Sprintf(format, a...)) }

// Debugf logs at debug level.
func (l *Log) Debugf(format string, a ...any) { l.Add(slog.LevelDebug, "", fmt.Sprintf(format, a...)) }

// Since returns entries with Seq > after, oldest first (at most limit).
func (l *Log) Since(after uint64, limit int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Entry, 0, 64)
	n := len(l.ring)
	start := 0
	if n == l.size {
		start = int(l.seq % uint64(l.size))
	}
	for i := 0; i < n; i++ {
		e := l.ring[(start+i)%n]
		if e.Seq > after {
			out = append(out, e)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Clear drops all entries (the file is untouched).
func (l *Log) Clear() {
	l.mu.Lock()
	l.ring = l.ring[:0]
	l.mu.Unlock()
}

// Handler adapts the log to slog.
func (l *Log) Handler() slog.Handler { return &handler{l: l} }

type handler struct {
	l     *Log
	attrs []slog.Attr
	group string
}

func (h *handler) Enabled(_ context.Context, lv slog.Level) bool {
	h.l.mu.Lock()
	defer h.l.mu.Unlock()
	return lv >= h.l.level
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	write := func(a slog.Attr) bool {
		fmt.Fprintf(&b, " %s=%v", a.Key, a.Value.Any())
		return true
	}
	for _, a := range h.attrs {
		write(a)
	}
	r.Attrs(write)
	h.l.Add(r.Level, "", b.String())
	return nil
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	return &handler{l: h.l, attrs: append(append([]slog.Attr(nil), h.attrs...), as...), group: h.group}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{l: h.l, attrs: h.attrs, group: name}
}
