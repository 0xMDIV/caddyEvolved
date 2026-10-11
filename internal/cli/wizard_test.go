package cli

import (
	"strings"
	"testing"

	"caddyevolved/internal/install"
	"caddyevolved/internal/plugins"
)

func TestConflictIn(t *testing.T) {
	if msg := conflictIn([]string{"coraza", "caddy-ratelimit", "caddy-waf"}); msg == "" {
		t.Fatal("coraza + caddy-waf not reported")
	}
	if msg := conflictIn([]string{"coraza", "caddy-ratelimit", "caddy-defender"}); msg != "" {
		t.Fatalf("unexpected conflict: %s", msg)
	}
}

// TestPluginItemsRecommendedFirst keeps the checklist promise: recommended
// plugins on top and preselected, nothing deprecated offered.
func TestPluginItemsRecommendedFirst(t *testing.T) {
	items := pluginItems()
	rec := 0
	for _, e := range plugins.All() {
		if e.Recommended {
			rec++
		}
	}
	if rec == 0 {
		t.Fatal("catalog has no recommended plugins")
	}
	for i, it := range items {
		if i < rec && (!it.Selected || it.Tag == "") {
			t.Errorf("item %d %s should be recommended and preselected", i, it.ID)
		}
		if i >= rec && it.Selected {
			t.Errorf("item %d %s preselected but not recommended", i, it.ID)
		}
		if e, ok := plugins.ByID(it.ID); ok && e.Deprecated {
			t.Errorf("deprecated %s offered", it.ID)
		}
	}
}

func TestValidEmail(t *testing.T) {
	for v, ok := range map[string]bool{
		"admin@beispiel.de": true,
		"admin@example.org": false,
		"kein-at":           false,
		"a@localhost":       false,
		"Name <a@b.de>":     false,
	} {
		if got := validEmail(v) == nil; got != ok {
			t.Errorf("validEmail(%q) ok=%v, want %v", v, got, ok)
		}
	}
}

func TestPrintLoginShowsURLAndPassword(t *testing.T) {
	var b strings.Builder
	printLogin(&b, install.Answers{UIBind: "192.168.10.50", UIPort: 8484}, "Geheim-123", false)
	out := b.String()
	for _, want := range []string{"https://192.168.10.50:8484", "Geheim-123", "melde dich jetzt an"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	t.Log("\n" + out)
}
