package api

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"caddyforge/internal/auth"
	"caddyforge/internal/events"
)

// tokenAdmin refuses token management through an API token: a leaked token
// must not be able to mint itself successors.
func tokenAdmin(w http.ResponseWriter, r *http.Request) bool {
	sess, _ := sessionFromContext(r.Context())
	if sess.Token != "" {
		writeErr(w, http.StatusForbidden, "token_forbidden", "API-Tokens können nur mit einer Anmeldung verwaltet werden, nicht mit einem Token")
		return false
	}
	return true
}

func (s *Server) handleTokenList(w http.ResponseWriter, r *http.Request) {
	if !tokenAdmin(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": s.Auth.ListTokens()})
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	if !tokenAdmin(w, r) {
		return
	}
	var req struct {
		Name    string `json:"name"`
		Scope   string `json:"scope"`
		TTLDays int    `json:"ttlDays"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	if req.Scope == "" {
		req.Scope = auth.ScopeRead
	}
	plain, t, err := s.Auth.CreateToken(req.Name, req.Scope, time.Duration(req.TTLDays)*24*time.Hour)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_token", errText(err))
		return
	}
	s.Events.Record(events.Event{Kind: events.KindAuth, Step: "token", OK: true, Summary: "API-Token " + t.Name + " (" + t.Scope + ") erstellt"})
	t.Hash = ""
	writeJSON(w, http.StatusCreated, map[string]any{"token": plain, "info": t})
}

// handleMCPInfo feeds the "KI / MCP" page: endpoint and tool list.
func (s *Server) handleMCPInfo(w http.ResponseWriter, r *http.Request) {
	tools := make([]map[string]any, 0, len(mcpTools))
	for _, t := range mcpTools {
		tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "readOnly": t.ReadOnly})
	}
	_, certErr := os.Stat(s.certFile())
	scheme := "https"
	if s.Insecure {
		scheme = "http"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint": fmt.Sprintf("%s://%s/mcp", scheme, r.Host), "tools": tools,
		"uiCertAvailable": certErr == nil, "protocolVersions": append([]string{mcpModern}, mcpLegacy...),
	})
}

// handleUICert serves the daemon's self-signed certificate (public data) so a
// client can pin it.
func (s *Server) handleUICert(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.certFile())
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "kein UI-Zertifikat (läuft ohne TLS?)")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="caddyforge-ui.crt"`)
	w.Write(data)
}

func (s *Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if !tokenAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.Auth.RevokeToken(id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", errText(err))
		return
	}
	s.Events.Record(events.Event{Kind: events.KindAuth, Step: "token", OK: true, Summary: "API-Token " + id + " widerrufen"})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
