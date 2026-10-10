// Package events records and streams what caddyforge did.
//
// Every mutating action lands as one line in events.jsonl and is also pushed
// to live SSE subscribers. The ring keeps the UI fast without re-reading the
// file for every poll.
package events

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kind classifies an event.
type Kind string

const (
	KindInstall    Kind = "install"
	KindConfig     Kind = "config"
	KindSecret     Kind = "secret"
	KindService    Kind = "service"
	KindProxy      Kind = "proxy"
	KindPlugin     Kind = "plugin"
	KindCert       Kind = "cert"
	KindAuth       Kind = "auth"
	KindBackground Kind = "background"
	KindError      Kind = "error"
	// KindAudit is one mutating API call: who, what, result.
	KindAudit Kind = "audit"
)

// Event is one record. Value never contains a secret; Vars lists names only.
type Event struct {
	ID      string         `json:"id"`
	TS      time.Time      `json:"ts"`
	Kind    Kind           `json:"kind"`
	Step    string         `json:"step"`
	OK      bool           `json:"ok"`
	Error   string         `json:"error,omitempty"`
	Summary string         `json:"summary,omitempty"`
	Vars    []string       `json:"vars,omitempty"`
	Meta    map[string]any `json:"meta,omitempty"`
}

// Log is the persistent ring plus live fan-out.
type Log struct {
	mu   sync.Mutex
	path string
	ring []Event
	next int
	subs map[chan Event]struct{}
}

const ringSize = 512

// Open loads the tail of an existing log file.
func Open(path string) *Log {
	l := &Log{path: path, subs: map[chan Event]struct{}{}}
	l.ring = make([]Event, 0, ringSize)
	l.load()
	return l
}

func (l *Log) load() {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > ringSize {
		lines = lines[len(lines)-ringSize:]
	}
	for _, line := range lines {
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err == nil && e.ID != "" {
			l.ring = append(l.ring, e)
		}
	}
	l.next = len(l.ring)
}

// Record appends an event, persists it and notifies subscribers.
func (l *Log) Record(e Event) Event {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	if e.ID == "" {
		e.ID = formatID(e.TS, l.next)
	}
	l.mu.Lock()
	if len(l.ring) < ringSize {
		l.ring = append(l.ring, e)
		l.next = len(l.ring)
	} else {
		l.ring[l.next%ringSize] = e
		l.next++
	}
	subs := make([]chan Event, 0, len(l.subs))
	for c := range l.subs {
		subs = append(subs, c)
	}
	err := l.appendLocked(e)
	l.mu.Unlock()

	if err != nil {
		// Persistence failing must not break the running service; the caller
		// sees it as a degraded write in the response instead.
		e.Error = strings.TrimSpace(e.Error + " (event nicht persistiert: " + err.Error() + ")")
	}
	for _, c := range subs {
		select {
		case c <- e:
		default: // a slow consumer drops events rather than blocking caddy
		}
	}
	return e
}

func (l *Log) appendLocked(e Event) error {
	if l.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	return err
}

// Since returns events newer than after (an event ID or zero for all),
// ordered oldest first.
func (l *Log) Since(after string, limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, len(l.ring))
	copy(out, l.ring)
	sort.Slice(out, func(i, j int) bool { return out[i].TS.Before(out[j].TS) })
	if after == "" {
		if limit > 0 && len(out) > limit {
			out = out[len(out)-limit:]
		}
		return out
	}
	idx := -1
	for i, e := range out {
		if e.ID == after {
			idx = i
			break
		}
	}
	if idx < 0 {
		return out // unknown cursor: full window, the UI dedupes by id
	}
	res := out[idx+1:]
	if limit > 0 && len(res) > limit {
		res = res[len(res)-limit:]
	}
	return res
}

// Latest is the newest event or the zero value.
func (l *Log) Latest() (Event, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.ring) == 0 {
		return Event{}, false
	}
	best := l.ring[0]
	for _, e := range l.ring[1:] {
		if e.TS.After(best.TS) {
			best = e
		}
	}
	return best, true
}

// Subscribe registers a live consumer; the returned channel is closed by Cancel.
func (l *Log) Subscribe(depth int) (<-chan Event, func()) {
	if depth <= 0 || depth > ringSize {
		depth = 64
	}
	ch := make(chan Event, depth)
	l.mu.Lock()
	// Seed with the tail so a new listener sees context immediately.
	events := make([]Event, len(l.ring))
	copy(events, l.ring)
	l.subs[ch] = struct{}{}
	l.mu.Unlock()

	sort.Slice(events, func(i, j int) bool { return events[i].TS.Before(events[j].TS) })
	for _, e := range events[len(events)-depth:] {
		select {
		case ch <- e:
		default:
		}
	}
	return ch, func() {
		l.mu.Lock()
		delete(l.subs, ch)
		l.mu.Unlock()
		close(ch)
	}
}

func formatID(t time.Time, n int) string {
	return t.Format("20060102-150405.000") + "-" + pad(n)
}

func pad(n int) string {
	s := ""
	for i := 0; i < 4; i++ {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
