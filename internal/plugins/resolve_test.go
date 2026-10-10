package plugins

import (
	"strings"
	"testing"
)

func TestResolveKnownDNSProviderKeepsMajorSuffix(t *testing.T) {
	// xcaddy resolves an unsuffixed path to the oldest major, so dropping "/v2"
	// here would silently install a 2025-era provider build.
	res, err := Resolve([]string{"hetzner"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Modules) != 1 || res.Modules[0] != "github.com/caddy-dns/hetzner/v2" {
		t.Fatalf("Modules = %v, wollen genau github.com/caddy-dns/hetzner/v2", res.Modules)
	}
	if res.Variant != "standard" {
		t.Errorf("Variant = %q, wollen standard (hetzner ist im Standard-Bundle)", res.Variant)
	}
}

func TestResolveRequiresCustomVariantForUntrackedPath(t *testing.T) {
	path := "github.com/example/whatever"
	res, err := Resolve([]string{path})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Untracked) != 1 || res.Untracked[0] != path {
		t.Errorf("Untracked = %v, wollen den Pfad wiederfinden", res.Untracked)
	}
	if res.Variant != "custom" {
		t.Errorf("Variant = %q, wollen custom (unkatalogisiert zwingt zum Build)", res.Variant)
	}
}

func TestResolveEmptySelectionIsPlainCaddy(t *testing.T) {
	res, err := Resolve(nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Variant != "caddy" || len(res.Modules) != 0 {
		t.Errorf("Resolution = %+v, wollen Variante caddy ohne Module", res)
	}
	if !res.CaddyfileManaged {
		t.Error("CaddyfileManaged muss ohne Auswahl wahr bleiben")
	}
}

func TestResolveRejectsUnknownNameThatIsNotAPath(t *testing.T) {
	// Whitespace entries are dropped, not treated as a module.
	if _, err := Resolve([]string{"  ", ""}); err != nil {
		t.Errorf("leere Auswahl darf nicht fehlschlagen: %v", err)
	}
	// A typo without a slash must not be mistaken for a Go module path.
	if _, err := Resolve([]string{"cloudfire"}); err == nil {
		t.Error("Tippfehler ohne Schrägstrich muss abgelehnt werden, nicht als Modulpfad durchgehen")
	}
}

func TestResolveRejectsDeprecated(t *testing.T) {
	for _, e := range entries {
		if !e.Deprecated {
			continue
		}
		if _, err := Resolve([]string{e.ID}); err == nil {
			t.Errorf("veraltetes Modul %q wurde ohne Fehler angenommen", e.ID)
		}
	}
}

func TestByIDAcceptsModulePath(t *testing.T) {
	e, ok := ByID("github.com/caddy-dns/cloudflare")
	if !ok {
		t.Fatal("Suche über den Modulpfad fand nichts")
	}
	if e.ID != "cloudflare" {
		t.Errorf("ID = %q, wollen cloudflare", e.ID)
	}
	if len(e.Env) == 0 {
		t.Fatal("Cloudflare-Eintrag hat keine Zugangsdaten – Interpolation würde ins Leere laufen")
	}
	// lego reads CF_API_TOKEN directly; the name is load-bearing for the env file.
	if e.Env[0].Name != "CF_API_TOKEN" {
		t.Errorf("erste Variable = %q, wollen CF_API_TOKEN", e.Env[0].Name)
	}
}

func TestCatalogIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range All() {
		if seen[e.ID] {
			t.Errorf("doppelte ID %q", e.ID)
		}
		seen[e.ID] = true
	}
}

// TestCatalogProviderNamesMatchCaddyfile guards the invariant that dnsBlock can
// derive a usable `dns <name>` argument from every DNS entry.
func TestCatalogProviderNamesMatchCaddyfile(t *testing.T) {
	for _, e := range All() {
		if e.Category != CatDNS {
			continue
		}
		name := strings.TrimPrefix(e.Module, "github.com/caddy-dns/")
		if name == e.Module {
			continue // not a caddy-dns provider
		}
		name = strings.TrimSuffix(name, "/v2")
		if name == "" {
			t.Errorf("%s: kein Kürzel aus %q ableitbar", e.ID, e.Module)
		}
	}
}
