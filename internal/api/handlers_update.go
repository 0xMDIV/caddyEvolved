package api

import (
	"context"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"caddyevolved/internal/buildinfo"
	"caddyevolved/internal/events"
	"caddyevolved/internal/selfupdate"
)

// updateState caches the release check (GitHub rate-limits anonymous calls to
// 60/h) and serialises installs.
type updateState struct {
	mu      sync.Mutex
	info    selfupdate.Info
	err     string
	applyMu sync.Mutex
}

const updateCheckTTL = 30 * time.Minute

// handleUpdateCheck answers whether a newer caddyEvolved exists. ?refresh=1
// skips the cache.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	u := &s.update
	u.mu.Lock()
	fresh := !u.info.CheckedAt.IsZero() && time.Since(u.info.CheckedAt) < updateCheckTTL && u.info.Current == buildinfo.Version
	if !fresh || r.URL.Query().Get("refresh") == "1" {
		info, err := selfupdate.Check(r.Context(), buildinfo.Version)
		u.info, u.err = info, ""
		if err != nil {
			u.err = err.Error()
			u.info.CheckedAt = time.Now().UTC()
		}
	}
	info, errText := u.info, u.err
	u.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"update": info, "error": errText})
}

// handleUpdateApply installs a release and restarts the daemon. The answer goes
// out before the restart; the UI then polls /api/version for the new number.
func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	// Replacing the program is an admin act, like managing tokens: a leaked
	// API token must not be able to swap the binary.
	if !tokenAdmin(w, r) {
		return
	}
	var req struct {
		Version string `json:"version"`
	}
	if r.ContentLength > 0 {
		if err := decode(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
			return
		}
	}
	if !s.update.applyMu.TryLock() {
		writeErr(w, http.StatusConflict, "update_running", "Ein Update läuft bereits")
		return
	}
	defer s.update.applyMu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	var steps []string
	got, err := selfupdate.Apply(ctx, req.Version, s.Paths.Bin, func(line string) { steps = append(steps, line) })
	if err != nil {
		s.Events.Record(events.Event{Kind: events.KindService, Step: "update", OK: false, Summary: "Update fehlgeschlagen: " + err.Error()})
		writeErr(w, http.StatusBadGateway, "update_failed", errText(err))
		return
	}
	s.Events.Record(events.Event{Kind: events.KindService, Step: "update", OK: true, Summary: "caddyEvolved " + buildinfo.Version + " → " + got})

	restart := s.Systemd != nil && s.Systemd.Available(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": got, "steps": steps, "restarting": restart})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	if restart {
		// --no-block hands the job to systemd: it stops this process and
		// starts the new binary, the response above is already out.
		go func() {
			time.Sleep(700 * time.Millisecond)
			_ = exec.Command("systemctl", "--no-block", "restart", "caddyevolved.service").Run()
		}()
	}
}
