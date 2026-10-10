package builder

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestParseModules(t *testing.T) {
	out := `dns.providers.cloudflare v0.2.1 github.com/caddy-dns/cloudflare
http.handlers.rate_limit v0.1.0 github.com/mholt/caddy-ratelimit

  Standard modules: 120

  Non-standard modules: 2

  Unknown modules: 0
`
	mods := ParseModules(out)
	if len(mods) != 2 {
		t.Fatalf("got %d modules: %+v", len(mods), mods)
	}
	if mods[0].ID != "dns.providers.cloudflare" || mods[0].Package != "github.com/caddy-dns/cloudflare" || mods[0].Version != "v0.2.1" {
		t.Errorf("parsed %+v", mods[0])
	}
	if !HasPackage(mods, "github.com/caddy-dns/cloudflare") {
		t.Error("cloudflare nicht erkannt")
	}
	if HasPackage(mods, "github.com/caddy-dns/cloud") {
		t.Error("Präfix ohne / darf nicht matchen")
	}
	if !HasPackage(mods, "github.com/mholt/caddy-ratelimit/sub") {
		t.Error("Unterpaket eines Moduls nicht erkannt")
	}
}

func TestExtractRefusesTraversal(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar.gz")
	f, _ := os.Create(archive)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := []byte("x")
	tw.WriteHeader(&tar.Header{Name: "go/../../evil", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	tw.Write(body)
	tw.Close()
	gz.Close()
	f.Close()
	if err := extractTarGz(archive, filepath.Join(dir, "out"), "go/"); err == nil {
		t.Fatal("Pfad außerhalb des Ziels wurde entpackt")
	}
}

func TestExtractStripsPrefix(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "a.tar.gz")
	f, _ := os.Create(archive)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "go/", Mode: 0o755, Typeflag: tar.TypeDir})
	tw.WriteHeader(&tar.Header{Name: "go/bin/go", Mode: 0o755, Size: 2, Typeflag: tar.TypeReg})
	tw.Write([]byte("hi"))
	tw.Close()
	gz.Close()
	f.Close()
	out := filepath.Join(dir, "out")
	if err := extractTarGz(archive, out, "go/"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(out, "bin", "go")); err != nil || string(data) != "hi" {
		t.Fatalf("bin/go: %q %v", data, err)
	}
}

func TestDeleteRefusesActive(t *testing.T) {
	m, err := New(Config{Dir: t.TempDir(), CaddyBin: filepath.Join(t.TempDir(), "caddy")})
	if err != nil {
		t.Fatal(err)
	}
	b := &Build{ID: "b1", Status: StatusSucceeded, Active: true}
	os.MkdirAll(m.buildDir("b1"), 0o750)
	m.builds["b1"] = b
	if err := m.Delete("b1"); err == nil {
		t.Fatal("aktiver Build gelöscht")
	}
}
