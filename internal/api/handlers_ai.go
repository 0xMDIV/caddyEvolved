package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	"caddyevolved/internal/ai"
)

// The AI chat runs in the browser session of the logged-in admin: every
// tool call is an in-process API request with that session, and changes
// run only after the user clicked "Ausführen" on the proposal.

func (s *Server) aiConfigFile() string { return filepath.Join(s.Paths.Etc, "ai.json") }

func (s *Server) loadAIConfig() ai.Config {
	c, _ := ai.LoadConfig(s.aiConfigFile())
	return c
}

func (s *Server) newAIProvider(c ai.Config) (ai.Provider, error) {
	if s.aiProvider != nil {
		return s.aiProvider(c)
	}
	return ai.NewProvider(c)
}

// browserOnly refuses API tokens: they use the MCP endpoint, the chat
// belongs to someone sitting at the UI who can approve.
func (s *Server) browserOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sess, _ := sessionFromContext(r.Context()); sess.Token != "" || sess.Bearer {
			writeErr(w, http.StatusForbidden, "ai_session_only", "Der KI-Chat ist nur in der Weboberfläche verfügbar – API-Tokens nutzen /mcp")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleAISettingsGet(w http.ResponseWriter, r *http.Request) {
	out := s.loadAIConfig().Public()
	out["presets"] = ai.Presets
	out["defaultModel"] = ai.DefaultModel
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAISettingsSave(w http.ResponseWriter, r *http.Request) {
	var in ai.Config
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	// The UI never sees the key, so empty keeps it – but only for the same
	// endpoint: otherwise anyone could point the URL at their host and test.
	if old := s.loadAIConfig(); in.APIKey == "" && old.Kind == in.Kind && old.BaseURL == in.BaseURL {
		in.APIKey = old.APIKey
	}
	if err := in.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_settings", errText(err))
		return
	}
	if err := ai.SaveConfig(s.aiConfigFile(), in); err != nil {
		writeErr(w, http.StatusInternalServerError, "write", errText(err))
		return
	}
	writeJSON(w, http.StatusOK, in.Public())
}

// handleAITest sends one short message, so a wrong URL, key or model shows
// up in the settings and not in the first chat.
func (s *Server) handleAITest(w http.ResponseWriter, r *http.Request) {
	c := s.loadAIConfig()
	p, err := s.newAIProvider(c)
	if err != nil || !c.Configured() {
		writeErr(w, http.StatusBadRequest, "ai_unconfigured", "Erst Anbieter, URL und Modell speichern")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	start := time.Now()
	m, err := p.Turn(ctx, "Antworte nur mit dem Wort OK.", nil, []ai.Message{{Role: ai.RoleUser, Text: "Verbindungstest"}})
	if err != nil {
		writeErr(w, http.StatusBadGateway, "ai_failed", errText(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reply": m.Text, "ms": time.Since(start).Milliseconds()})
}

func (s *Server) handleAIModels(w http.ResponseWriter, r *http.Request) {
	p, err := s.newAIProvider(s.loadAIConfig())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ai_unconfigured", errText(err))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	models, err := p.Models(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "ai_failed", errText(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": models})
}

// chatView is what the UI gets: no provider history, it can be large and
// carries Claude's opaque blocks.
func chatView(c *ai.Chat) map[string]any {
	return map[string]any{
		"id": c.ID, "title": c.Title, "created": c.Created, "updated": c.Updated,
		"display": c.Display, "proposals": c.Proposals, "pending": c.Pending(),
	}
}

func (s *Server) handleAIChatList(w http.ResponseWriter, r *http.Request) {
	list, err := s.AIChats.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read", errText(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"chats": list, "configured": s.loadAIConfig().Configured()})
}

func (s *Server) handleAIChatCreate(w http.ResponseWriter, r *http.Request) {
	c, err := s.AIChats.Create()
	if err == nil {
		err = s.AIChats.Save(c)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "write", errText(err))
		return
	}
	writeJSON(w, http.StatusOK, chatView(c))
}

func (s *Server) loadChat(w http.ResponseWriter, r *http.Request) (*ai.Chat, bool) {
	c, err := s.AIChats.Get(r.PathValue("id"))
	if errors.Is(err, ai.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "Chat nicht gefunden")
		return nil, false
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read", errText(err))
		return nil, false
	}
	return c, true
}

func (s *Server) handleAIChatGet(w http.ResponseWriter, r *http.Request) {
	if c, ok := s.loadChat(w, r); ok {
		writeJSON(w, http.StatusOK, chatView(c))
	}
}

func (s *Server) handleAIChatDelete(w http.ResponseWriter, r *http.Request) {
	defer s.AIChats.Lock(r.PathValue("id"))()
	if err := s.AIChats.Delete(r.PathValue("id")); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "Chat nicht gefunden")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": r.PathValue("id")})
}

// engine builds the engine for one request of the logged-in user.
func (s *Server) engine(w http.ResponseWriter, r *http.Request, chat string) (*ai.Engine, bool) {
	if s.AIAudit == nil {
		writeErr(w, http.StatusServiceUnavailable, "no_ai_audit", errText(ai.ErrNoAudit))
		return nil, false
	}
	cfg := s.loadAIConfig()
	if !cfg.Configured() {
		writeErr(w, http.StatusBadRequest, "ai_unconfigured", "KI ist nicht eingerichtet – Einstellungen → KI")
		return nil, false
	}
	p, err := s.newAIProvider(cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ai_unconfigured", errText(err))
		return nil, false
	}
	sess, _ := sessionFromContext(r.Context())
	return &ai.Engine{
		Provider: p, Exec: &aiExecutor{s: s, r: r, chat: chat}, Audit: s.AIAudit,
		Actor: "session " + shortID(sess.ID) + " (" + clientIP(r) + ")", Model: cfg.Model, System: mcpInstructions,
	}, true
}

// aiContext keeps a turn running when the browser goes away (the result is
// saved and shown on the next load), but not forever.
func aiContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Minute)
}

func (s *Server) handleAIChatMessage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Text    string `json:"text"`
		Context string `json:"context"`
	}
	if err := decode(r, &in); err != nil || in.Text == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "Nachricht fehlt")
		return
	}
	defer s.AIChats.Lock(r.PathValue("id"))()
	c, ok := s.loadChat(w, r)
	if !ok {
		return
	}
	e, ok := s.engine(w, r, c.ID)
	if !ok {
		return
	}
	ctx, cancel := aiContext(r)
	defer cancel()
	err := e.Send(ctx, c, in.Text, in.Context)
	if serr := s.AIChats.Save(c); serr != nil {
		writeErr(w, http.StatusInternalServerError, "write", errText(serr))
		return
	}
	out := chatView(c)
	if err != nil {
		out["error"] = errText(err)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAIProposal(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Approve bool `json:"approve"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	defer s.AIChats.Lock(r.PathValue("id"))()
	c, ok := s.loadChat(w, r)
	if !ok {
		return
	}
	e, ok := s.engine(w, r, c.ID)
	if !ok {
		return
	}
	ctx, cancel := aiContext(r)
	defer cancel()
	err := e.Decide(ctx, c, r.PathValue("pid"), in.Approve)
	if serr := s.AIChats.Save(c); serr != nil {
		writeErr(w, http.StatusInternalServerError, "write", errText(serr))
		return
	}
	switch {
	case errors.Is(err, ai.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "Vorschlag nicht gefunden")
	case errors.Is(err, ai.ErrDecided), errors.Is(err, ai.ErrExpired):
		writeErr(w, http.StatusConflict, "decided", errText(err))
	default:
		out := chatView(c)
		if err != nil {
			out["error"] = errText(err)
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// aiExecutor runs the MCP tools for the chat with the request's session.
type aiExecutor struct {
	s    *Server
	r    *http.Request
	chat string
}

func (x *aiExecutor) Tools() []ai.ToolSpec {
	out := make([]ai.ToolSpec, 0, len(mcpTools))
	for _, t := range mcpTools {
		out = append(out, ai.ToolSpec{Name: t.Name, Description: t.Description, Schema: t.Schema, ReadOnly: t.ReadOnly})
	}
	return out
}

func toolArgs(raw json.RawMessage) map[string]any {
	args := map[string]any{}
	_ = json.Unmarshal(raw, &args)
	return args
}

func (x *aiExecutor) Run(ctx context.Context, tool string, raw json.RawMessage) ai.RunResult {
	t, ok := mcpToolByName(tool)
	if !ok {
		return ai.RunResult{Text: "Unbekanntes Werkzeug " + tool, IsError: true}
	}
	text, isErr, method, path, status := x.s.callTool(ctx, x.r, t, toolArgs(raw), "ai", x.chat)
	return ai.RunResult{Text: text, IsError: isErr, Method: method, Path: path, Status: status}
}

func (x *aiExecutor) Describe(tool string, raw json.RawMessage) (string, string, error) {
	t, ok := mcpToolByName(tool)
	if !ok {
		return "", "", errors.New("unbekanntes Werkzeug " + tool)
	}
	method, path, _, err := t.Request(toolArgs(raw))
	return method, path, err
}
