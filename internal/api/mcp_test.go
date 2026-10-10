package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"caddyevolved/internal/auth"
	"caddyevolved/internal/config"
	"caddyevolved/internal/events"
)

func testServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	root := t.TempDir()
	paths := config.NewPaths(root)
	store, err := auth.LoadStore(filepath.Join(root, "auth.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetPassword("Sehr-Geheim-123!"); err != nil {
		t.Fatal(err)
	}
	read, _, err := store.CreateToken("leser", auth.ScopeRead, 0)
	if err != nil {
		t.Fatal(err)
	}
	write, _, err := store.CreateToken("schreiber", auth.ScopeWrite, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := New(&Server{Paths: paths, Auth: store, Events: events.Open(filepath.Join(root, "events.jsonl")), Insecure: true, Bind: "127.0.0.1"})
	return s, read, write
}

func rpc(t *testing.T, s *Server, token string, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestMCPLegacyAndModern(t *testing.T) {
	s, read, write := testServer(t)

	code, out := rpc(t, s, read, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`, nil)
	res, _ := out["result"].(map[string]any)
	if code != 200 || res["protocolVersion"] != "2025-06-18" {
		t.Fatalf("initialize: %d %v", code, out)
	}

	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}`
	code, out = rpc(t, s, read, `{"jsonrpc":"2.0","id":"d","method":"server/discover","params":{`+meta+`}}`, map[string]string{"Mcp-Method": "server/discover"})
	res, _ = out["result"].(map[string]any)
	if code != 200 || res["resultType"] != "complete" || res["supportedVersions"] == nil {
		t.Fatalf("discover: %d %v", code, out)
	}

	code, out = rpc(t, s, read, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{`+meta+`}}`, nil)
	res, _ = out["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	for _, x := range tools {
		if x.(map[string]any)["name"] == "create_site" {
			t.Error("Lese-Token sieht schreibende Tools")
		}
	}
	if len(tools) < 10 {
		t.Errorf("zu wenige Tools: %d", len(tools))
	}

	// A read token calling a write tool is refused by the API itself.
	_, out = rpc(t, s, read, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"create_site","arguments":{"domains":["a.lan"],"upstreams":["x:1"]}}}`, nil)
	res, _ = out["result"].(map[string]any)
	if res["isError"] != true || !strings.Contains(firstText(res), "403") {
		t.Errorf("Lese-Token schrieb: %v", out)
	}

	// The write token gets through to validation (no caddy binary here, so
	// the commit fails — what matters is that auth and routing worked).
	_, out = rpc(t, s, write, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_site_preview","arguments":{"domains":["a.lan"],"upstreams":["10.0.0.1:80"]}}}`, nil)
	res, _ = out["result"].(map[string]any)
	if res["isError"] == true || !strings.Contains(firstText(res), "reverse_proxy 10.0.0.1:80") {
		t.Errorf("preview über MCP: %v", out)
	}

	code, out = rpc(t, s, read, `{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"1900-01-01"}}}`, nil)
	if e, _ := out["error"].(map[string]any); e == nil || e["code"].(float64) != -32022 {
		t.Errorf("unbekannte Version: %d %v", code, out)
	}

	code, _ = rpc(t, s, "cev_falsch", `{"jsonrpc":"2.0","id":6,"method":"tools/list"}`, nil)
	if code != 401 {
		t.Errorf("falsches Token: %d", code)
	}
}

func TestTokenCannotMintTokens(t *testing.T) {
	s, _, write := testServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewBufferString(`{"name":"x","scope":"write"}`))
	req.Header.Set("Authorization", "Bearer "+write)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Token erzeugte Token: %d %s", rec.Code, rec.Body)
	}
}

func firstText(res map[string]any) string {
	c, _ := res["content"].([]any)
	if len(c) == 0 {
		return ""
	}
	m, _ := c[0].(map[string]any)
	s, _ := m["text"].(string)
	return s
}
