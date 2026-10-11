package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"caddyevolved/internal/events"
	"caddyevolved/internal/sites"
)

// protectSettings are the operator's own path patterns that every site
// refuses on top of the built-in rules (sites/guard.go). Stored in
// /etc/caddyevolved/protect.json.
type protectSettings struct {
	Extra []string `json:"extra"`
}

func (s *Server) protectFile() string { return filepath.Join(s.Paths.Etc, "protect.json") }

func (s *Server) loadProtect() protectSettings {
	var ps protectSettings
	if data, err := os.ReadFile(s.protectFile()); err == nil {
		_ = json.Unmarshal(data, &ps)
	}
	if ps.Extra == nil {
		ps.Extra = []string{}
	}
	return ps
}

func (s *Server) handleProtectGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": sites.GuardRules, "extra": s.loadProtect().Extra})
}

// handleProtectCheck answers whether a path would be refused.
func (s *Server) handleProtectCheck(w http.ResponseWriter, r *http.Request) {
	p := urlPath(r.URL.Query().Get("path"))
	writeJSON(w, http.StatusOK, map[string]any{"path": p, "blocked": sites.GuardBlocks(p, s.loadProtect().Extra)})
}

// handleProtectSave stores the extra patterns and rewrites every site
// through the validate-and-reload transaction.
func (s *Server) handleProtectSave(w http.ResponseWriter, r *http.Request) {
	var req protectSettings
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	var clean []string
	seen := map[string]bool{}
	for _, p := range req.Extra {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		if err := sites.ValidGuardPattern(p); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_pattern", errText(err))
			return
		}
		seen[p] = true
		clean = append(clean, p)
	}
	if len(clean) > 200 {
		writeErr(w, http.StatusBadRequest, "bad_pattern", "höchstens 200 eigene Muster")
		return
	}
	if clean == nil {
		clean = []string{}
	}
	prev, _ := os.ReadFile(s.protectFile())
	data, _ := json.MarshalIndent(protectSettings{Extra: clean}, "", "  ")
	if err := os.WriteFile(s.protectFile(), data, 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "write", errText(err))
		return
	}
	s.Sites.SetOptions(s.siteOptions())
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	var reloaded bool
	if err := s.Sites.Sync(ctx, s.siteCommit(&reloaded)); err != nil {
		if prev != nil {
			_ = os.WriteFile(s.protectFile(), prev, 0o644)
		} else {
			_ = os.Remove(s.protectFile())
		}
		s.Sites.SetOptions(s.siteOptions())
		s.siteError(w, r, err)
		return
	}
	s.Events.Record(events.Event{Kind: events.KindConfig, Step: "protect", OK: true, Summary: "Gesperrte Pfade geändert", Meta: map[string]any{"extra": clean}})
	writeJSON(w, http.StatusOK, map[string]any{"extra": clean, "reloaded": reloaded})
}

// urlPath accepts a full URL as well as a bare path.
func urlPath(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.Index(p, "://"); i >= 0 {
		rest := p[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			p = rest[j:]
		} else {
			p = "/"
		}
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return p
}
