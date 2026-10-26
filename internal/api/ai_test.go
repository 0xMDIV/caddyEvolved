package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"caddyevolved/internal/ai"
	"caddyevolved/internal/aiaudit"
	"caddyevolved/internal/events"
)

type scriptedProvider struct{ replies []ai.Message }

func (p *scriptedProvider) Turn(context.Context, string, []ai.ToolDef, []ai.Message) (ai.Message, error) {
	if len(p.replies) == 0 {
		return ai.Message{Role: ai.RoleAssistant, Text: "fertig"}, nil
	}
	r := p.replies[0]
	p.replies = p.replies[1:]
	return r, nil
}

func (p *scriptedProvider) Models(context.Context) ([]string, error) { return []string{"m1"}, nil }

func aiServer(t *testing.T, replies ...ai.Message) (*Server, func(method, path, body string) (int, map[string]any), string) {
	t.Helper()
	s, read, _ := testServer(t)
	prov := &scriptedProvider{replies: replies}
	s.aiProvider = func(ai.Config) (ai.Provider, error) { return prov, nil }
	if err := ai.SaveConfig(s.aiConfigFile(), ai.Config{Kind: ai.KindOpenAI, BaseURL: "http://x", Model: "m"}); err != nil {
		t.Fatal(err)
	}
	sess, err := s.Auth.Login("Sehr-Geheim-123!", "test", "127.0.0.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path, body string) (int, map[string]any) {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.ID})
		req.Header.Set(HeaderGate, "1")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	return s, do, read
}

func TestAIChatProposalFlow(t *testing.T) {
	s, do, _ := aiServer(t, ai.Message{Role: ai.RoleAssistant, Text: "Ich sperre die IP.", Calls: []ai.ToolCall{
		{ID: "c1", Name: "firewall_ip", Args: json.RawMessage(`{"ip":"203.0.113.9","action":"block"}`)},
	}})
	code, chat := do("POST", "/api/ai/chats", `{}`)
	if code != 200 {
		t.Fatalf("create %d %v", code, chat)
	}
	id := chat["id"].(string)
	code, chat = do("POST", "/api/ai/chats/"+id+"/messages", `{"text":"sperr 203.0.113.9","context":"/firewall"}`)
	props, _ := chat["proposals"].([]any)
	if code != 200 || len(props) != 1 || props[0].(map[string]any)["state"] != "pending" {
		t.Fatalf("message %d %v", code, chat)
	}
	if _, has := chat["history"]; has {
		t.Error("Verlauf für das Modell an die UI geschickt")
	}
	if len(s.auditEventsVia("ai")) != 0 {
		t.Fatal("vor der Freigabe ausgeführt")
	}
	pid := props[0].(map[string]any)["id"].(string)
	code, chat = do("POST", "/api/ai/chats/"+id+"/proposals/"+pid, `{"approve":true}`)
	props, _ = chat["proposals"].([]any)
	if code != 200 || props[0].(map[string]any)["state"] != "approved" {
		t.Fatalf("approve %d %v", code, chat)
	}
	ev := s.auditEventsVia("ai")
	if len(ev) != 1 || ev[0].Meta["path"] != "/api/firewall/quick" || !strings.HasPrefix(ev[0].Meta["actor"].(string), "ai (chat "+id) {
		t.Fatalf("audit %+v", ev)
	}
	if st, _ := ev[0].Meta["status"].(int); st == 401 || st == 403 {
		t.Fatalf("Sitzung nicht durchgereicht: %d", st)
	}
	if code, _ = do("POST", "/api/ai/chats/"+id+"/proposals/"+pid, `{"approve":true}`); code != 409 {
		t.Fatalf("zweite Freigabe: %d", code)
	}
	entries, _, _ := s.AIAudit.List(0, 50, id)
	var kinds []string
	for _, e := range entries {
		kinds = append(kinds, e.Kind)
	}
	joined := strings.Join(kinds, ",")
	for _, k := range []string{aiaudit.KindRequest, aiaudit.KindProposal, aiaudit.KindApproved, aiaudit.KindExecuted} {
		if !strings.Contains(joined, k) {
			t.Errorf("Protokoll ohne %s: %v", k, kinds)
		}
	}
}

func TestAIChatRefusesTokens(t *testing.T) {
	s, _, read := aiServer(t)
	req := httptest.NewRequest("POST", "/api/ai/chats", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer "+read)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Token durfte chatten: %d", rec.Code)
	}
}

func TestAISettingsKeepAndHideKey(t *testing.T) {
	s, do, _ := aiServer(t)
	if code, out := do("PUT", "/api/ai/settings", `{"kind":"openai","baseUrl":"https://openrouter.ai/api/v1","model":"x/y","apiKey":"sk-or-1234567890"}`); code != 200 || out["keyHint"] != "sk-o******" {
		t.Fatalf("put %d %v", code, out)
	}
	if code, out := do("PUT", "/api/ai/settings", `{"kind":"openai","baseUrl":"https://openrouter.ai/api/v1","model":"x/z"}`); code != 200 {
		t.Fatalf("put ohne Key %d %v", code, out)
	}
	c, _ := ai.LoadConfig(s.aiConfigFile())
	if c.APIKey != "sk-or-1234567890" || c.Model != "x/z" {
		t.Fatalf("Key verloren: %+v", c)
	}
	_, out := do("GET", "/api/ai/settings", "")
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "1234567890") {
		t.Fatalf("Key im Klartext: %s", raw)
	}
	if code, _ := do("PUT", "/api/ai/settings", `{"kind":"nope","baseUrl":"x","model":""}`); code != 400 {
		t.Fatalf("ungültig angenommen: %d", code)
	}
}

// auditEventsVia returns the audit events of mutations made through via.
func (s *Server) auditEventsVia(via string) []events.Event {
	var out []events.Event
	for _, e := range s.Events.Since("", 1000) {
		if a, _ := e.Meta["actor"].(string); e.Kind == events.KindAudit && strings.HasPrefix(a, via+" (") {
			out = append(out, e)
		}
	}
	return out
}

func TestAIChatRefusedWithoutProtocol(t *testing.T) {
	s, do, _ := aiServer(t)
	s.AIAudit = nil
	_, chat := do("POST", "/api/ai/chats", `{}`)
	if code, _ := do("POST", "/api/ai/chats/"+chat["id"].(string)+"/messages", `{"text":"x"}`); code != http.StatusServiceUnavailable {
		t.Fatalf("ohne Protokoll: %d", code)
	}
}

func TestAISettingsDropKeyOnNewURL(t *testing.T) {
	s, do, _ := aiServer(t)
	do("PUT", "/api/ai/settings", `{"kind":"openai","baseUrl":"https://openrouter.ai/api/v1","model":"m","apiKey":"sk-or-1234567890"}`)
	do("PUT", "/api/ai/settings", `{"kind":"openai","baseUrl":"https://evil.example/v1","model":"m"}`)
	if c, _ := ai.LoadConfig(s.aiConfigFile()); c.APIKey != "" {
		t.Fatalf("Key an neue URL weitergegeben: %+v", c)
	}
}

func TestViaHeaderFromOutsideIgnored(t *testing.T) {
	s, _, _ := aiServer(t)
	sess, _ := s.Auth.Login("Sehr-Geheim-123!", "test", "127.0.0.1", time.Hour)
	req := httptest.NewRequest("POST", "/api/ai/chats", bytes.NewBufferString(`{}`))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sess.ID})
	req.Header.Set(HeaderGate, "1")
	req.Header.Set("X-CaddyEvolved-Via", "ai")
	req.Header.Set("X-CaddyEvolved-Chat", "gefaelscht")
	s.Handler().ServeHTTP(httptest.NewRecorder(), req)
	if ev := s.auditEventsVia("ai"); len(ev) != 0 {
		t.Fatalf("Absender gefälscht: %+v", ev)
	}
}
