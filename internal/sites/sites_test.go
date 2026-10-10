package sites

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestManager(t *testing.T) (*Manager, string) {
	t.Helper()
	dir := t.TempDir()
	cf := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(cf, []byte("{\n\tadmin localhost:2019\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return New(filepath.Join(dir, "sites.json"), filepath.Join(dir, "sites"), cf), cf
}

func ok(context.Context) (string, error) { return "Valid configuration", nil }

func TestRenderProxy(t *testing.T) {
	s := Site{ID: "app", Domains: []string{"app.example.com"}, Upstreams: []string{"10.0.0.5:8080"}, Compress: true, Enabled: true}
	s.Normalize()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	got := Render(s)
	for _, want := range []string{"app.example.com {", "encode zstd gzip", "reverse_proxy 10.0.0.5:8080\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("fehlt %q in\n%s", want, got)
		}
	}
}

func TestRenderOptions(t *testing.T) {
	s := Site{ID: "x", Domains: []string{"x.lan"}, TLS: TLSOff, Upstreams: []string{"a:1", "b:1"}, LBPolicy: "least_conn", UpstreamInsecure: true}
	s.Normalize()
	got := Render(s)
	for _, want := range []string{"http://x.lan {", "reverse_proxy a:1 b:1 {", "lb_policy least_conn", "tls_insecure_skip_verify"} {
		if !strings.Contains(got, want) {
			t.Errorf("fehlt %q in\n%s", want, got)
		}
	}
}

func TestValidateRejectsInjection(t *testing.T) {
	cases := []Site{
		{ID: "a", Domains: []string{"a.com {\n respond hi"}, Upstreams: []string{"x:1"}},
		{ID: "a", Domains: []string{"a.com"}, Upstreams: []string{"x:1\nimport /etc/passwd"}},
		{ID: "a", Domains: []string{"a.com"}, Upstreams: []string{"x:1"}, LBPolicy: "first }"},
		{ID: "a", Domains: []string{"a.com"}, Upstreams: []string{"x:1"}, Extra: "}"},
		{ID: "a", Domains: []string{"a.com"}, Mode: ModeRedirect, RedirectTo: "https://b.com {"},
		{ID: "../x", Domains: []string{"a.com"}, Upstreams: []string{"x:1"}},
	}
	for i, c := range cases {
		c.Normalize()
		if err := c.Validate(); err == nil {
			t.Errorf("Fall %d: hätte abgelehnt werden müssen: %+v", i, c)
		}
	}
}

func TestUpsertWritesSnippetAndImport(t *testing.T) {
	m, cf := newTestManager(t)
	ctx := context.Background()
	s, err := m.Upsert(ctx, Site{Domains: []string{"Cloud.Example.com"}, Upstreams: []string{"10.0.0.2:80"}, Enabled: true}, true, ok)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != "cloud-example-com" {
		t.Errorf("id = %q", s.ID)
	}
	if _, err := os.Stat(filepath.Join(m.Dir(), s.ID+".caddy")); err != nil {
		t.Errorf("Snippet fehlt: %v", err)
	}
	main, _ := os.ReadFile(cf)
	if !HasImport(string(main), m.ImportLine()) {
		t.Errorf("Import fehlt:\n%s", main)
	}
	// Idempotent: a second change must not add a second import line.
	if _, err := m.SetEnabled(ctx, s.ID, false, ok); err != nil {
		t.Fatal(err)
	}
	main, _ = os.ReadFile(cf)
	if n := strings.Count(string(main), m.ImportLine()); n != 1 {
		t.Errorf("Import %d-mal vorhanden", n)
	}
	if _, err := os.Stat(filepath.Join(m.Dir(), s.ID+".caddy")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("deaktivierte Site hat noch ein Snippet")
	}
}

func TestCommitFailureRestores(t *testing.T) {
	m, cf := newTestManager(t)
	ctx := context.Background()
	first, err := m.Upsert(ctx, Site{ID: "one", Domains: []string{"one.lan"}, Upstreams: []string{"a:1"}, Enabled: true}, true, ok)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(m.Dir(), "one.caddy"))
	mainBefore, _ := os.ReadFile(cf)

	reject := func(context.Context) (string, error) { return "Error: bad", errors.New("exit 1") }
	changed := first
	changed.Upstreams = []string{"b:2"}
	_, err = m.Upsert(ctx, changed, false, reject)
	var inv *ErrInvalid
	if !errors.As(err, &inv) || inv.Output != "Error: bad" {
		t.Fatalf("err = %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(m.Dir(), "one.caddy"))
	if string(after) != string(before) {
		t.Errorf("Snippet nicht wiederhergestellt:\n%s", after)
	}
	mainAfter, _ := os.ReadFile(cf)
	if string(mainAfter) != string(mainBefore) {
		t.Errorf("Caddyfile verändert")
	}
	got, _ := m.Get("one")
	if got.Upstreams[0] != "a:1" {
		t.Errorf("sites.json nicht wiederhergestellt: %v", got.Upstreams)
	}
	if _, err := m.Upsert(ctx, Site{ID: "two", Domains: []string{"two.lan"}, Upstreams: []string{"c:3"}, Enabled: true}, true, reject); err == nil {
		t.Fatal("abgelehnte Site angelegt")
	}
	if _, err := os.Stat(filepath.Join(m.Dir(), "two.caddy")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("abgelehnte Site hinterlässt Snippet")
	}
}

func TestDuplicateDomainRefused(t *testing.T) {
	m, _ := newTestManager(t)
	ctx := context.Background()
	if _, err := m.Upsert(ctx, Site{ID: "a", Domains: []string{"x.lan"}, Upstreams: []string{"a:1"}, Enabled: true}, true, ok); err != nil {
		t.Fatal(err)
	}
	_, err := m.Upsert(ctx, Site{ID: "b", Domains: []string{"X.lan"}, Upstreams: []string{"a:1"}, Enabled: true}, true, ok)
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("doppelte Domain nicht abgelehnt: %v", err)
	}
}
