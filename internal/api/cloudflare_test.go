package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"caddyevolved/internal/cloudflare"
	"caddyevolved/internal/sites"
)

func TestCloudflareSettingsAndSync(t *testing.T) {
	s, do, _ := aiServer(t)
	var posted []map[string]any
	var auth string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		result := any([]any{})
		switch {
		case r.URL.Path == "/zones":
			result = []map[string]string{{"id": "z1", "name": "example.com"}}
		case r.Method == "POST":
			var rec map[string]any
			json.NewDecoder(r.Body).Decode(&rec)
			posted = append(posted, rec)
			result = rec
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer fake.Close()
	s.cloudflareAPI = fake.URL
	s.publicIP = func(context.Context) (string, error) { return "203.0.113.7", nil }

	site := sites.Site{ID: "app", Domains: []string{"app.example.com"}, Enabled: true, Cloudflare: &sites.CloudflareDNS{Proxied: true}}
	if res := s.syncCloudflare(context.Background(), site); len(res) != 1 || res[0].Action != "error" {
		t.Fatalf("ohne Token: %+v", res)
	}

	// The DNS plugin's token is used when there is no own one.
	os.MkdirAll(filepath.Dir(s.Paths.EnvFile), 0o755)
	os.WriteFile(s.Paths.EnvFile, []byte("CF_API_TOKEN=plugin-tok\n"), 0o600)
	code, out := do("GET", "/api/cloudflare", "")
	if code != 200 || out["source"] != "plugin" || out["configured"] != true {
		t.Fatalf("GET: %d %v", code, out)
	}

	code, out = do("PUT", "/api/cloudflare", `{"apiToken":"eigener-token-123456","target":"","proxied":true}`)
	if code != 200 || out["source"] != "own" || strings.Contains(out["keyHint"].(string), "eigener-token-123456") {
		t.Fatalf("PUT: %d %v", code, out)
	}
	// An empty token keeps the stored one.
	do("PUT", "/api/cloudflare", `{"target":"home.example.net"}`)
	if c, _ := cloudflare.LoadConfig(s.cloudflareFile()); c.APIToken != "eigener-token-123456" || c.Target != "home.example.net" {
		t.Fatalf("gespeichert: %+v", c)
	}
	if code, _ := do("PUT", "/api/cloudflare", `{"target":"https://x.de"}`); code != 400 {
		t.Errorf("ungültiges Ziel: %d", code)
	}

	code, out = do("POST", "/api/cloudflare/test", "")
	if code != 200 || out["type"] != "CNAME" || len(out["zones"].([]any)) != 1 {
		t.Fatalf("test: %d %v", code, out)
	}

	res := s.syncCloudflare(context.Background(), site)
	if len(res) != 1 || res[0].Action != "created" || len(posted) != 1 || posted[0]["content"] != "home.example.net" || posted[0]["proxied"] != true {
		t.Fatalf("sync: %+v %v", res, posted)
	}
	if auth != "Bearer eigener-token-123456" {
		t.Errorf("Auth %q", auth)
	}

	// Without the switch nothing is touched.
	site.Cloudflare = nil
	if res := s.syncCloudflare(context.Background(), site); res != nil {
		t.Errorf("ohne Schalter: %+v", res)
	}

	code, out = do("DELETE", "/api/cloudflare/token", "")
	if code != 200 || out["source"] != "plugin" {
		t.Fatalf("DELETE: %d %v", code, out)
	}
}
