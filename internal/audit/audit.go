// Package audit writes one JSON line per decision and turns a log into a report.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Event struct {
	Time     string   `json:"time"`
	Server   string   `json:"server,omitempty"`
	Dir      string   `json:"dir"` // "client>server" or "server>client"
	Method   string   `json:"method,omitempty"`
	Tool     string   `json:"tool,omitempty"`
	Decision string   `json:"decision"` // allow, block, redact, flag, hide, drop
	Rules    []string `json:"rules,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	ArgKeys  []string `json:"arg_keys,omitempty"` // names only: values may be secret
	ArgHash  string   `json:"arg_hash,omitempty"`
	Monitor  bool     `json:"monitor,omitempty"` // the decision was not enforced
}

type Logger struct {
	mu  sync.Mutex
	w   io.Writer
	now func() time.Time
}

func NewLogger(w io.Writer) *Logger { return &Logger{w: w, now: time.Now} }

// SetClock replaces the clock, for tests.
func (l *Logger) SetClock(f func() time.Time) { l.now = f }

func (l *Logger) Log(e Event) {
	if l == nil || l.w == nil {
		return
	}
	e.Time = l.now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
}
