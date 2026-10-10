package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"caddyevolved/internal/builder"
	"caddyevolved/internal/caddyctl"
	"caddyevolved/internal/config"
	"caddyevolved/internal/events"
	"caddyevolved/internal/plugins"
	"caddyevolved/internal/releases"
)

var reCaddyTag = regexp.MustCompile(`^v2\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

// versionCache keeps the GitHub release list for a while: the unauthenticated
// API allows 60 requests per hour, and the build page asks on every visit.
type versionCache struct {
	mu     sync.Mutex
	at     time.Time
	recent []string
}

func (s *Server) recentVersions(ctx context.Context) ([]string, error) {
	s.versions.mu.Lock()
	defer s.versions.mu.Unlock()
	if time.Since(s.versions.at) < 15*time.Minute && len(s.versions.recent) > 0 {
		return s.versions.recent, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tags, err := releases.Recent(ctx, "caddyserver/caddy", 8)
	if err != nil {
		return s.versions.recent, err
	}
	s.versions.recent, s.versions.at = tags, time.Now()
	return tags, nil
}

func (s *Server) handleBuildToolchain(w http.ResponseWriter, r *http.Request) {
	info := s.Builder.Toolchain(r.Context())
	running := s.Builder.Running()
	writeJSON(w, http.StatusOK, map[string]any{
		"go": info.Go, "xcaddy": info.Xcaddy, "cacheBytes": info.CacheBytes,
		"busy": running != "", "runningId": running,
	})
}

func (s *Server) handleBuildVersions(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"recent": []string{}}
	recent, err := s.recentVersions(r.Context())
	if len(recent) > 0 {
		out["recent"] = recent
		out["latest"] = recent[0]
	}
	if err != nil {
		out["warning"] = "GitHub nicht erreichbar: " + errText(err)
	}
	if v, err := s.Caddy.Version(r.Context()); err == nil {
		out["installed"] = v
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleBuildList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"builds":            s.Builder.List(),
		"activeId":          s.Builder.ActiveID(),
		"runningId":         s.Builder.Running(),
		"previousAvailable": s.Builder.PreviousAvailable(),
	})
}

type buildRequest struct {
	CaddyVersion string   `json:"caddyVersion"`
	Plugins      []string `json:"plugins"`
}

func (s *Server) handleBuildStart(w http.ResponseWriter, r *http.Request) {
	var req buildRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	version := strings.TrimSpace(req.CaddyVersion)
	if version == "" || version == "latest" {
		recent, err := s.recentVersions(r.Context())
		if len(recent) == 0 {
			writeErr(w, http.StatusBadGateway, "no_version", "Neueste caddy-Version nicht ermittelbar – bitte eine Version wie v2.11.7 angeben", errText(err))
			return
		}
		version = recent[0]
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	if !reCaddyTag.MatchString(version) {
		writeErr(w, http.StatusBadRequest, "bad_version", "caddy-Version muss wie v2.11.7 aussehen")
		return
	}
	var ids []string
	for _, p := range req.Plugins {
		if p = strings.TrimSpace(p); p != "" {
			ids = append(ids, p)
		}
	}
	res, err := plugins.Resolve(ids)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_plugin", errText(err))
		return
	}
	for _, m := range res.Modules {
		// Module paths reach xcaddy as argv, never through a shell; still,
		// refuse anything that is not shaped like a module path.
		if strings.ContainsAny(m, " \t\n;|&$`'\"\\") || strings.HasPrefix(m, "-") {
			writeErr(w, http.StatusBadRequest, "bad_plugin", "ungültiger Modulpfad: "+m)
			return
		}
	}
	b, err := s.Builder.Start(builder.Spec{CaddyVersion: version, Plugins: ids, Modules: res.Modules})
	if errors.Is(err, builder.ErrBusy) {
		writeErr(w, http.StatusConflict, "busy", errText(err))
		return
	}
	if err != nil {
		s.fail(w, r, err, 0)
		return
	}
	s.Events.Record(events.Event{
		Kind: events.KindPlugin, Step: "build", OK: true,
		Summary: fmt.Sprintf("Build %s gestartet: caddy %s, %d Modul(e)", b.ID, version, len(res.Modules)),
		Meta:    map[string]any{"build": b.ID, "modules": res.Modules},
	})
	go s.recordBuildOutcome(b.ID)
	writeJSON(w, http.StatusAccepted, map[string]any{"build": b, "notes": res.Notes})
}

// recordBuildOutcome writes one event when the build ends, so the dashboard
// shows it without the build page being open.
func (s *Server) recordBuildOutcome(id string) {
	_, ch, cancel, err := s.Builder.Subscribe(id)
	if err != nil || ch == nil {
		return
	}
	defer cancel()
	for msg := range ch {
		if msg.Kind != "done" {
			continue
		}
		b := msg.Build
		s.Events.Record(events.Event{
			Kind: events.KindPlugin, Step: "build", OK: b.Status == builder.StatusSucceeded,
			Summary: fmt.Sprintf("Build %s: %s (%ds)", b.ID, b.Status, b.DurationSec),
			Error:   b.Error,
			Meta:    map[string]any{"build": b.ID},
		})
		return
	}
}

func (s *Server) handleBuildGet(w http.ResponseWriter, r *http.Request) {
	b, lines, err := s.Builder.Get(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err, 0)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"build": b, "log": lines})
}

// handleBuildStream replays the log so far and then follows the build.
func (s *Server) handleBuildStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusNotImplemented, "no_stream", "Streaming wird vom Server nicht unterstützt")
		return
	}
	id := r.PathValue("id")
	backlog, ch, cancel, err := s.Builder.Subscribe(id)
	if err != nil {
		s.fail(w, r, err, 0)
		return
	}
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	send := func(event, data string) bool {
		var b strings.Builder
		b.WriteString("event: " + event + "\n")
		for _, l := range strings.Split(data, "\n") {
			b.WriteString("data: " + l + "\n")
		}
		b.WriteString("\n")
		_, err := w.Write([]byte(b.String()))
		return err == nil
	}
	sendBuild := func(event string, b builder.Build) bool {
		data, _ := json.Marshal(b)
		return send(event, string(data))
	}

	for _, l := range backlog {
		if !send("line", l) {
			return
		}
	}
	cur, _, _ := s.Builder.Get(id)
	if ch == nil {
		sendBuild("done", cur)
		flusher.Flush()
		return
	}
	sendBuild("status", cur)
	flusher.Flush()

	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			if _, err := w.Write([]byte(": keepalive\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case msg, ok := <-ch:
			if !ok {
				return
			}
			switch msg.Kind {
			case "line":
				if !send("line", msg.Line) {
					return
				}
			case "status":
				if !sendBuild("status", msg.Build) {
					return
				}
			case "done":
				sendBuild("done", msg.Build)
				flusher.Flush()
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) handleBuildCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Builder.Cancel(id); err != nil {
		writeErr(w, http.StatusConflict, "not_running", errText(err))
		return
	}
	b, _, _ := s.Builder.Get(id)
	writeJSON(w, http.StatusOK, map[string]any{"build": b})
}

func (s *Server) handleBuildDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.Builder.Delete(r.PathValue("id")); err != nil {
		s.fail(w, r, err, http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// buildHooks restart caddy through whatever manages it and wait for the
// admin API, the same health signal `caddyevolved status` uses.
func (s *Server) buildHooks() builder.Hooks {
	return builder.Hooks{
		Restart: func(ctx context.Context) error {
			return s.applyService(ctx, "restart", "caddy.service")
		},
		Healthy: func(ctx context.Context) error {
			return caddyctl.NewAdmin(caddyctl.AdminURL(s.stateAdminListen())).Sync(ctx)
		},
	}
}

func (s *Server) handleBuildActivate(w http.ResponseWriter, r *http.Request) {
	// The swap must finish even if the browser goes away mid-restart.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Minute)
	defer cancel()
	id := r.PathValue("id")
	b, err := s.Builder.Activate(ctx, id, s.buildHooks())
	if err != nil {
		var aerr *builder.ActivateError
		rolledBack := errors.As(err, &aerr) && aerr.RolledBack
		s.Events.Record(events.Event{
			Kind: events.KindPlugin, Step: "activate", OK: false,
			Summary: "Build " + id + " nicht aktiviert", Error: errText(err),
			Meta: map[string]any{"build": id, "rolledBack": rolledBack},
		})
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": errText(err), "code": "activate_failed", "rolledBack": rolledBack,
		})
		return
	}
	version, _ := s.Caddy.Version(ctx)
	s.recordBinaryState(ctx, version, b.Plugins)
	s.Events.Record(events.Event{
		Kind: events.KindPlugin, Step: "activate", OK: true,
		Summary: fmt.Sprintf("Build %s aktiv: caddy %s mit %d Modul(en)", id, version, len(b.Modules)),
		Meta:    map[string]any{"build": id, "sha256": b.SHA256},
	})
	writeJSON(w, http.StatusOK, map[string]any{"build": b, "caddyVersion": version, "rolledBack": false})
}

func (s *Server) handleBuildRollback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Minute)
	defer cancel()
	if err := s.Builder.Rollback(ctx, s.buildHooks()); err != nil {
		s.Events.Record(events.Event{Kind: events.KindPlugin, Step: "rollback", OK: false, Error: errText(err), Summary: "Rollback fehlgeschlagen"})
		s.fail(w, r, err, http.StatusBadGateway)
		return
	}
	version, _ := s.Caddy.Version(ctx)
	// No active build means the binary predates caddyevolved builds: no plugins.
	plugins := []string{}
	if id := s.Builder.ActiveID(); id != "" {
		if b, _, err := s.Builder.Get(id); err == nil {
			plugins = b.Plugins
		}
	}
	s.recordBinaryState(ctx, version, plugins)
	s.Events.Record(events.Event{Kind: events.KindPlugin, Step: "rollback", OK: true, Summary: "Vorherige caddy-Binary wieder aktiv (" + version + ")"})
	writeJSON(w, http.StatusOK, map[string]any{"caddyVersion": version})
}

// recordBinaryState keeps state.json in line with the binary on disk, so the
// plugin page marks the built modules as active.
func (s *Server) recordBinaryState(ctx context.Context, version string, pluginIDs []string) {
	st, err := config.LoadState(s.Paths.StateFile)
	if err != nil {
		return
	}
	if version != "" {
		st.CaddyVersion = version
	}
	st.BinarySource, st.Variant = "build", "custom"
	if pluginIDs != nil {
		st.Enabled = pluginIDs
	}
	st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	config.SaveState(s.Paths.StateFile, st)
}
