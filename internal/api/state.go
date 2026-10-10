package api

import (
	"sync"
	"time"

	"caddyforge/internal/events"
	"caddyforge/internal/plugins"
	"caddyforge/internal/secrets"
)

// credentialsAllowed refuses env keys the catalog does not know. The env file
// is a systemd EnvironmentFile, so an arbitrary key would be a code-execution
// step away (LD_PRELOAD, PATH) rather than a credential mistake.
func (s *Server) credentialsAllowed(set map[string]string, unset []string) error {
	known := map[string]bool{}
	for _, e := range plugins.All() {
		for _, v := range e.Env {
			known[v.Name] = true
		}
	}
	var bad []string
	check := func(k string) {
		if !known[k] {
			bad = append(bad, k)
		}
	}
	for k := range set {
		check(k)
	}
	for _, k := range unset {
		check(k)
	}
	if len(bad) > 0 {
		return &unknownKeyError{keys: bad}
	}
	return nil
}

type unknownKeyError struct{ keys []string }

func (e *unknownKeyError) Error() string {
	return "Zugangsdaten-Schlüssel nicht im Katalog: " + joinKeys(e.keys)
}

func joinKeys(v []string) string {
	out := ""
	for i, k := range v {
		if i > 0 {
			out += ", "
		}
		out += k
	}
	return out
}

// recordCredentialEvent logs key names only. Values never reach the event log.
func recordCredentialEvent(log *events.Log, changes []string) {
	if len(changes) == 0 {
		return
	}
	log.Record(events.Event{
		Kind:    events.KindSecret,
		Step:    "credentials",
		OK:      true,
		Summary: fmtChange(changes),
		Vars:    changes,
	})
}

func fmtChange(changes []string) string {
	if len(changes) == 1 {
		return "1 Schlüssel geändert"
	}
	return itoa(len(changes)) + " Schlüssel geändert"
}

// installLock serialises installs: two concurrent plans writing the same unit
// file is a corrupt system, not a race worth supporting.
type installLock struct {
	mu     sync.Mutex
	held   bool
	since  time.Time
	runID  string
	cancel func()
}

func (l *installLock) tryStart(runID string, cancel func()) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return &busyError{runID: l.runID, since: l.since}
	}
	l.held, l.since, l.runID, l.cancel = true, time.Now(), runID, cancel
	return nil
}

func (l *installLock) finish() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.held, l.runID, l.cancel, l.since = false, "", nil, time.Time{}
}

func (l *installLock) running() (string, time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.runID, l.since, l.held
}

func (l *installLock) abort() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.held || l.cancel == nil {
		return false
	}
	l.cancel()
	return true
}

type busyError struct {
	runID string
	since time.Time
}

func (e *busyError) Error() string {
	return "eine Installation läuft bereits (Run " + e.runID + " seit " + e.since.Format(time.RFC3339) + ")"
}

// envSnapshot reads the env file for status reporting, tolerating absence.
func (s *Server) envKeys() map[string]string {
	v, err := secrets.New(s.Paths.EnvFile).Read()
	if err != nil {
		return map[string]string{}
	}
	return v
}
