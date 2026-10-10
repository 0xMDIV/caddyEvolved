package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"caddyevolved/internal/events"
	"caddyevolved/internal/platform"
	"caddyevolved/internal/supervisor"
)

// handleEventStream is the live feed: install progress plus every later event.
// SSE is used instead of websockets because the UI only ever receives.
func (s *Server) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusNotImplemented, "no_stream", "Streaming wird vom Server nicht unterstützt")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, cancel := s.Events.Subscribe(32)
	defer cancel()

	// A client that reconnects with Last-Event-ID gets the gap filled first.
	if id := r.Header.Get("Last-Event-ID"); id != "" {
		for _, e := range s.Events.Since(id, 200) {
			if !sendEvent(w, e) {
				return
			}
		}
		flusher.Flush()
	}

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			if !sendEvent(w, e) {
				return
			}
			flusher.Flush()
		case <-keepalive.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func sendEvent(w http.ResponseWriter, e events.Event) bool {
	data, err := json.Marshal(e)
	if err != nil {
		return true // a broken record must not kill the stream
	}
	_, err = fmt.Fprintf(w, "event: %s\nid: %s\ndata: %s\n\n", e.Kind, e.ID, data)
	return err == nil
}

// handleLogs returns process logs from journalctl when systemd is present and
// from our own log file otherwise.
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	lines := parseIntDefault(q.Get("lines"), 100, 1, 2000)
	unit := q.Get("unit")
	if unit == "" {
		unit = "caddy"
	}
	switch unit {
	case "caddy", "caddy.service":
		unit = "caddy.service"
	case "caddyevolved", "caddyevolved.service":
		unit = "caddyevolved.service"
	default:
		writeErr(w, http.StatusBadRequest, "bad_unit", "unit ist caddy oder caddyevolved")
		return
	}

	ctx := r.Context()
	var (
		out  []string
		from string
	)
	if s.Systemd.Available(ctx) {
		text, err := s.Systemd.Journal(ctx, unit, lines)
		if err != nil {
			s.fail(w, r, err, 0)
			return
		}
		out, from = splitLines(text), "journalctl"
	} else {
		tail, err := supervisor.TailFile(s.Paths.LogFile, lines)
		if err != nil {
			s.fail(w, r, err, 0)
			return
		}
		out, from = tail, "datei"
	}
	if needle := q.Get("grep"); needle != "" {
		filtered := out[:0]
		for _, l := range out {
			if containsFold(l, needle) {
				filtered = append(filtered, l)
			}
		}
		out = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"unit": unit, "lines": out, "count": len(out), "source": from, "path": s.Paths.LogFile,
	})
}

// handleService drives start/stop/restart/reload for either unit.
func (s *Server) handleService(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	unit := r.URL.Query().Get("unit")
	if unit == "" {
		unit = "caddy.service"
	}
	if unit != "caddy.service" && unit != "caddyevolved.service" {
		writeErr(w, http.StatusBadRequest, "bad_unit", "unit ist caddy.service oder caddyevolved.service")
		return
	}
	allowed := map[string]bool{"start": true, "stop": true, "restart": true, "reload": true, "enable": true, "disable": true}
	if !allowed[action] {
		writeErr(w, http.StatusBadRequest, "bad_action", "erlaubte Aktionen: start, stop, restart, reload, enable, disable")
		return
	}

	ctx := r.Context()
	err := s.applyService(ctx, action, unit)
	ok := err == nil
	summary := fmt.Sprintf("%s %s", action, unit)
	if !ok {
		summary += " fehlgeschlagen"
	}
	s.Events.Record(events.Event{
		Kind: events.KindService, Step: action, OK: ok, Summary: summary,
		Error: errText(err), Meta: map[string]any{"unit": unit},
	})
	if !ok {
		s.fail(w, r, err, 0)
		return
	}
	state := "unknown"
	if s.Systemd.Available(ctx) {
		_, active, err := s.Systemd.Status(ctx, unit)
		if err == nil {
			state = active
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"action": action, "unit": unit, "state": state, "time": nowUTC()})
}

// applyService maps an action onto systemd, or onto our supervisor when the
// host has none — the UI must still be able to stop caddy in a prefix install.
func (s *Server) applyService(ctx context.Context, action, unit string) error {
	if s.Systemd.Available(ctx) {
		var err error
		switch action {
		case "start":
			err = s.Systemd.Start(ctx, unit)
		case "stop":
			err = s.Systemd.Stop(ctx, unit)
		case "restart":
			err = s.Systemd.Restart(ctx, unit)
		case "reload":
			// A reload must re-validate first: systemd would otherwise restart
			// on a config caddy rejects.
			if _, verr := s.Caddy.Validate(ctx, s.Paths.Caddyfile, "caddyfile"); verr != nil {
				return fmt.Errorf("Konfiguration ungültig, nicht geladen: %w", verr)
			}
			err = s.Systemd.ReloadOrRestart(ctx, unit)
		case "enable":
			err = s.Systemd.Enable(ctx, unit)
		case "disable":
			err = s.Systemd.Disable(ctx, unit)
		}
		return err
	}
	if unit != "caddy.service" {
		return fmt.Errorf("ohne systemd kann %s nicht verwaltet werden", unit)
	}
	switch action {
	case "start":
		_, err := s.Sup.Start(ctx)
		return err
	case "stop":
		return s.Sup.Stop(ctx)
	case "restart":
		if err := s.Sup.Stop(ctx); err != nil {
			return err
		}
		_, err := s.Sup.Start(ctx)
		return err
	case "reload":
		if _, verr := s.Caddy.Validate(ctx, s.Paths.Caddyfile, "caddyfile"); verr != nil {
			return fmt.Errorf("Konfiguration ungültig, nicht geladen: %w", verr)
		}
		return s.Caddy.Reload(ctx, s.Paths.Caddyfile)
	default:
		return fmt.Errorf("ohne systemd ist %q nicht möglich", action)
	}
}

// handleHostStatus exposes the platform view the installer wizard uses.
func (s *Server) handleHostStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	host := platform.Detect(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"host":    host,
		"ports":   platform.CheckPorts(ctx, 80, 443, 2019, 8484),
		"systemd": s.Systemd.Available(ctx),
	})
}

func splitLines(s string) []string {
	out := make([]string, 0, strings.Count(s, "\n")+1)
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func containsFold(hay, needle string) bool {
	if needle == "" {
		return true
	}
	return strings.Contains(strings.ToLower(hay), strings.ToLower(needle))
}
