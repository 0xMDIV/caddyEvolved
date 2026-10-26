package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"caddyevolved/internal/config"
)

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func fixture(t *testing.T) config.Paths {
	p := config.NewPaths(t.TempDir())
	write(t, p.SitesFile, `{"schema":1,"sites":[{"id":"a"},{"id":"b"}]}`)
	write(t, p.EnvFile, "CF_API_TOKEN=geheim\n")
	write(t, p.AuthFile, `{"hash":"x"}`)
	write(t, p.Caddyfile, "import sites/*.caddy\n")
	write(t, filepath.Join(p.CaddyEtc, "Caddyfile.caddyevolved-prev"), "alt")
	write(t, filepath.Join(p.SitesDir, "a.caddy"), "a {}\n")
	write(t, filepath.Join(p.SitesDir, "b.caddy"), "b {}\n")
	write(t, filepath.Join(p.CaddyStorage, "certificates", "acme", "a", "a.crt"), "CERT")
	write(t, filepath.Join(p.CaddyStorage, "locks", "x.lock"), "lock")
	return p
}

func TestRoundTrip(t *testing.T) {
	for _, pass := range []string{"", "korrekt pferd batterie"} {
		p := fixture(t)
		var buf bytes.Buffer
		m, err := Create(p, &buf, Options{Certs: true, Passphrase: pass, Version: "test"})
		if err != nil {
			t.Fatal(err)
		}
		if m.Sites != 2 || !m.Secrets || !m.Certs || m.Encrypted != (pass != "") {
			t.Fatalf("manifest: %+v", m)
		}
		if pass != "" && (!IsEncrypted(buf.Bytes()) || bytes.Contains(buf.Bytes(), []byte("geheim"))) {
			t.Fatal("archive not sealed")
		}

		// Inspect lists members, never the .prev copy or the locks.
		_, names, err := Inspect(buf.Bytes(), pass)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(names, " ")
		if strings.Contains(joined, "prev") || strings.Contains(joined, "locks") || !strings.Contains(joined, "caddy-data/certificates/acme/a/a.crt") {
			t.Fatalf("members: %v", names)
		}

		// Change everything, add a site, then restore.
		write(t, p.EnvFile, "CF_API_TOKEN=neu\n")
		write(t, filepath.Join(p.SitesDir, "c.caddy"), "c {}\n")
		os.Remove(filepath.Join(p.SitesDir, "b.caddy"))
		write(t, filepath.Join(p.CaddyStorage, "certificates", "acme", "a", "a.crt"), "NEU")
		if _, err := Restore(p, buf.Bytes(), pass, RestoreOptions{Certs: true}); err != nil {
			t.Fatal(err)
		}
		if read(t, p.EnvFile) != "CF_API_TOKEN=geheim\n" || read(t, filepath.Join(p.SitesDir, "b.caddy")) != "b {}\n" {
			t.Fatal("files not restored")
		}
		if _, err := os.Stat(filepath.Join(p.SitesDir, "c.caddy")); !os.IsNotExist(err) {
			t.Fatal("site added after the backup was not removed")
		}
		if read(t, filepath.Join(p.CaddyStorage, "certificates", "acme", "a", "a.crt")) != "CERT" {
			t.Fatal("certificate not restored")
		}
		if info, _ := os.Stat(p.EnvFile); info.Mode().Perm() != 0o600 {
			t.Fatalf("env mode %v", info.Mode().Perm())
		}
	}
}

func TestWrongPassphrase(t *testing.T) {
	p := fixture(t)
	var buf bytes.Buffer
	if _, err := Create(p, &buf, Options{Passphrase: "richtig"}); err != nil {
		t.Fatal(err)
	}
	for _, pass := range []string{"", "falsch"} {
		if _, _, err := Inspect(buf.Bytes(), pass); !errors.Is(err, ErrPassphrase) {
			t.Fatalf("passphrase %q: %v", pass, err)
		}
	}
}

func TestRestoreRefusesTraversal(t *testing.T) {
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	put := func(name, body string) {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	put("manifest.json", `{"format":1}`)
	put("caddyevolved-etc/../../evil", "x")
	tw.Close()
	gz.Close()
	p := config.NewPaths(t.TempDir())
	if _, err := Restore(p, raw.Bytes(), "", RestoreOptions{}); err == nil {
		t.Fatal("traversal accepted")
	}
}

func TestStorePrune(t *testing.T) {
	s := Store{Dir: t.TempDir(), Settings: filepath.Join(t.TempDir(), "backup.json")}
	base := time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		name := FileName("auto", "Mein Server", base.Add(time.Duration(i)*24*time.Hour), false)
		if err := s.Save(name, []byte("x")); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(filepath.Join(s.Dir, name), base.Add(time.Duration(i)*24*time.Hour), base.Add(time.Duration(i)*24*time.Hour))
	}
	manual := FileName("manual", "srv", base, true)
	s.Save(manual, []byte("y"))
	os.Chtimes(filepath.Join(s.Dir, manual), base, base)
	if err := s.Prune(2); err != nil {
		t.Fatal(err)
	}
	list, _ := s.List()
	auto := 0
	for _, e := range list {
		if e.Kind == "auto" {
			auto++
		}
	}
	if auto != 2 || len(list) != 3 {
		t.Fatalf("after prune: %+v", list)
	}
	if !strings.HasPrefix(list[0].Name, "auto-mein-server-20261005") {
		t.Fatalf("newest first: %s", list[0].Name)
	}
	if ValidName("../etc/passwd") || ValidName("x.sh") {
		t.Fatal("ValidName too lax")
	}
}

func TestAISettingsCountAsSecret(t *testing.T) {
	p := config.NewPaths(t.TempDir())
	write(t, p.SitesFile, `{"schema":1,"sites":[]}`)
	write(t, filepath.Join(p.Etc, "ai.json"), `{"apiKey":"sk-geheim"}`)
	var buf bytes.Buffer
	m, err := Create(p, &buf, Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Secrets {
		t.Fatal("ai.json nicht als Geheimnis markiert")
	}
}
