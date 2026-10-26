package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"caddyevolved/internal/aiaudit"
)

func TestAIAuditRoutes(t *testing.T) {
	log, err := aiaudit.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	log.Append(aiaudit.Entry{Chat: "c1", Kind: aiaudit.KindRequest, Text: "hallo"})
	log.Append(aiaudit.Entry{Chat: "c2", Kind: aiaudit.KindNote, Text: "notiz"})
	s := &Server{AIAudit: log}

	rec := httptest.NewRecorder()
	s.handleAIAudit(rec, httptest.NewRequest("GET", "/api/ai/audit?chat=c2", nil))
	var out struct {
		Entries []aiaudit.Entry `json:"entries"`
		Total   int             `json:"total"`
		OK      bool            `json:"ok"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Total != 1 || !out.OK || out.Entries[0].Text != "notiz" {
		t.Fatalf("audit: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.handleAIAuditExport(rec, httptest.NewRequest("GET", "/api/ai/audit/export", nil))
	if strings.Count(rec.Body.String(), "\n") != 2 || !strings.Contains(rec.Header().Get("Content-Disposition"), "ai-audit") {
		t.Fatalf("export: %q %v", rec.Body.String(), rec.Header())
	}
	// No route may change the protocol; other methods only reach the SPA.
	for _, m := range []string{"DELETE", "PUT", "POST", "PATCH"} {
		rec = httptest.NewRecorder()
		New(&Server{AIAudit: log}).mux.ServeHTTP(rec, httptest.NewRequest(m, "/api/ai/audit", nil))
		if strings.Contains(rec.Body.String(), `"entries"`) {
			t.Errorf("%s /api/ai/audit erreicht den Handler", m)
		}
	}
	if _, total, _ := log.List(0, 10, ""); total != 2 {
		t.Fatalf("Protokoll verändert: %d Einträge", total)
	}
}
