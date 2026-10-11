package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"caddyevolved/internal/events"
)

var analyticsRanges = map[string]time.Duration{
	"15m": 15 * time.Minute, "1h": time.Hour, "6h": 6 * time.Hour,
	"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
}

// hostsFor maps a site id onto its domains; an unknown id is taken as a host.
func (s *Server) hostsFor(site string) []string {
	if site == "" {
		return nil
	}
	if st, err := s.Sites.Get(site); err == nil {
		var hosts []string
		for _, d := range st.Domains {
			if i := strings.LastIndex(d, ":"); i >= 0 {
				d = d[:i]
			}
			if d != "" {
				hosts = append(hosts, d)
			}
		}
		return hosts
	}
	return []string{site}
}

func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	if s.Analytics == nil {
		writeErr(w, http.StatusServiceUnavailable, "no_analytics", "Analytics nicht aktiv")
		return
	}
	q := r.URL.Query()
	rngKey := q.Get("range")
	if rngKey == "" {
		rngKey = "24h"
	}
	rng, ok := analyticsRanges[rngKey]
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_range", "range: 15m, 1h, 6h, 24h, 7d oder 30d")
		return
	}
	rep := s.Analytics.Query(rng, s.hostsFor(q.Get("site")))
	writeJSON(w, http.StatusOK, map[string]any{"range": rngKey, "report": rep, "accessLog": s.Paths.AccessLog})
}

func (s *Server) handleAnalyticsRecent(w http.ResponseWriter, r *http.Request) {
	if s.Analytics == nil {
		writeErr(w, http.StatusServiceUnavailable, "no_analytics", "Analytics nicht aktiv")
		return
	}
	q := r.URL.Query()
	limit := parseIntDefault(q.Get("limit"), 100, 1, 300)
	writeJSON(w, http.StatusOK, map[string]any{"requests": s.Analytics.Recent(limit, s.hostsFor(q.Get("site")))})
}

// handleAudit lists mutating API calls, newest first.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit := parseIntDefault(r.URL.Query().Get("limit"), 200, 1, 1000)
	all := s.Events.Since("", 1000)
	out := make([]events.Event, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		e := all[i]
		if e.Kind == events.KindAudit || e.Kind == events.KindAuth {
			out = append(out, e)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// statusRecorder captures the status code of a mutation for the audit log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// audit records every mutating API call after it ran. Only unsafe methods are
// wrapped, so streaming GET handlers keep their http.Flusher.
func (s *Server) audit(w http.ResponseWriter, r *http.Request, sess Session, next http.HandlerFunc) {
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	start := time.Now()
	next(rec, r)
	actor := "session " + shortID(sess.ID)
	switch {
	case sess.Token != "":
		actor = "token " + sess.Token
		if via := r.Header.Get("X-CaddyEvolved-Via"); via != "" {
			actor += " (" + via + ")"
		}
	case sess.Bearer:
		actor = "cli " + shortID(sess.ID)
	}
	s.Events.Record(events.Event{
		Kind: events.KindAudit, Step: r.Method + " " + r.URL.Path, OK: rec.status < 400,
		Summary: fmt.Sprintf("%s %s → %d", r.Method, r.URL.Path, rec.status),
		Meta: map[string]any{
			"method": r.Method, "path": r.URL.Path, "status": rec.status,
			"remote": clientIP(r), "actor": actor, "ms": time.Since(start).Milliseconds(),
		},
	})
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// StartBackground prepares the access log directory, re-renders the sites
// with request logging when needed, and follows the log. It returns when
// ctx ends.
func (s *Server) StartBackground(ctx context.Context) {
	if s.Analytics == nil {
		return
	}
	if !s.Paths.IsPrefixed() {
		if err := ensureCaddyOwned(filepath.Dir(s.Paths.AccessLog)); err != nil {
			fmt.Fprintf(os.Stderr, "caddyevolved: Log-Verzeichnis: %v\n", err)
		}
		s.ensureAccessLog()
	}
	s.Sites.SetOptions(s.siteOptions())
	if s.Sites.NeedsSync() {
		var reloaded bool
		err := s.Sites.Sync(ctx, s.siteCommit(&reloaded))
		s.Events.Record(events.Event{
			Kind: events.KindConfig, Step: "sites-sync", OK: err == nil,
			Summary: "Sites mit Request-Log neu geschrieben", Error: errText(err),
		})
	}
	go s.autoBackupLoop(ctx)
	go s.Sys.Run(ctx, 5*time.Second)
	s.Analytics.Follow(ctx, s.Paths.AccessLog)
}

// ensureCaddyOwned makes the log directory writable for the caddy user, the
// process that writes the access log.
func ensureCaddyOwned(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	u, err := user.Lookup("caddy")
	if err != nil {
		return nil // no caddy user: prefix or foreign install, leave as is
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := os.Chown(dir, uid, gid); err != nil {
		return err
	}
	return os.Chmod(dir, 0o755)
}

// ensureAccessLog creates the access log owned by caddy before anything else
// can. `caddy validate` provisions the loggers, and run by this root daemon
// it would otherwise create the file as root 0600, which the caddy service
// then cannot open. Cheap enough to run before every validation.
func (s *Server) ensureAccessLog() {
	if s.Paths.IsPrefixed() || s.Analytics == nil {
		return
	}
	u, err := user.Lookup("caddy")
	if err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	f, err := os.OpenFile(s.Paths.AccessLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	f.Close()
	if st, err := os.Stat(s.Paths.AccessLog); err == nil {
		if sys, ok := fileOwner(st); ok && sys == uid {
			return
		}
	}
	os.Chown(s.Paths.AccessLog, uid, gid)
	os.Chmod(s.Paths.AccessLog, 0o640)
}
