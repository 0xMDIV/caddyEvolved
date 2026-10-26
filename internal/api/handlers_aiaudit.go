package api

import (
	"net/http"
	"strconv"

	"caddyevolved/internal/aiaudit"
)

// The AI protocol has read routes only: nothing in caddyEvolved can change
// or delete an entry, not even the admin.

func (s *Server) handleAIAudit(w http.ResponseWriter, r *http.Request) {
	if s.AIAudit == nil {
		writeErr(w, http.StatusServiceUnavailable, "no_ai_audit", "KI-Protokoll nicht verfügbar – Rechte auf "+s.Paths.StateDir+" prüfen")
		return
	}
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit := parseIntDefault(q.Get("limit"), 100, 1, 1000)
	entries, total, err := s.AIAudit.List(max(offset, 0), limit, q.Get("chat"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read", errText(err))
		return
	}
	if entries == nil {
		entries = []aiaudit.Entry{}
	}
	ok, brokenAt, _ := s.AIAudit.Verify()
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries, "total": total, "ok": ok, "brokenAt": brokenAt, "sizeBytes": s.AIAudit.Size(),
	})
}

func (s *Server) handleAIAuditExport(w http.ResponseWriter, r *http.Request) {
	if s.AIAudit == nil {
		writeErr(w, http.StatusServiceUnavailable, "no_ai_audit", "KI-Protokoll nicht verfügbar")
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="caddyevolved-ai-audit.jsonl"`)
	_ = s.AIAudit.Export(w)
}
