package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"caddyevolved/internal/releases"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"0.5.0", "0.4.1", true},
		{"0.5.0", "0.5.0", false},
		{"0.4.1", "0.5.0", false},
		{"0.10.0", "0.9.3", true},
		{"0.5.0", "0.5.0-dev", true}, // dev build of the same number is older
		{"0.5.0", "0.6.0-dev", false},
		{"0.5.0", "dev", true},
	}
	for _, c := range cases {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestIsDev(t *testing.T) {
	for v, want := range map[string]bool{"": true, "dev": true, "0.5.0-dev": true, "0.5.0": false} {
		if IsDev(v) != want {
			t.Errorf("IsDev(%q) != %v", v, want)
		}
	}
}

// TestApplyEndToEnd runs a whole update against a fake GitHub: release JSON,
// SHA256SUMS, archive; the new "binary" is a shell script answering version.
func TestApplyEndToEnd(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("release archives exist for linux/amd64 and linux/arm64 only")
	}
	script := []byte("#!/bin/sh\necho 'caddyEvolved 9.9.9 (test)'\n")
	name, _ := ArchiveName("9.9.9")
	var tgz bytes.Buffer
	gz := gzip.NewWriter(&tgz)
	tw := tar.NewWriter(gz)
	member := strings.TrimSuffix(name, ".tar.gz") + "/caddyevolved"
	tw.WriteHeader(&tar.Header{Name: member, Mode: 0o755, Size: int64(len(script)), Typeflag: tar.TypeReg})
	tw.Write(script)
	tw.Close()
	gz.Close()
	sum := sha256.Sum256(tgz.Bytes())
	sums := hex.EncodeToString(sum[:]) + "  " + name + "\n"

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/" + Repo + "/releases/latest":
			fmt.Fprintf(w, `{"tag_name":"v9.9.9","assets":[{"name":%q,"browser_download_url":%q},{"name":"SHA256SUMS","browser_download_url":%q}]}`,
				name, srv.URL+"/dl/"+name, srv.URL+"/dl/SHA256SUMS")
		case "/dl/" + name:
			w.Write(tgz.Bytes())
		case "/dl/SHA256SUMS":
			io.WriteString(w, sums)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := releases.GitHubAPI
	releases.GitHubAPI = srv.URL
	defer func() { releases.GitHubAPI = old }()

	bin := filepath.Join(t.TempDir(), "caddyevolved")
	os.WriteFile(bin, []byte("alt"), 0o755)
	got, err := Apply(context.Background(), "", bin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "9.9.9" {
		t.Fatalf("version = %q", got)
	}
	if data, _ := os.ReadFile(bin); !bytes.Equal(data, script) {
		t.Fatalf("binary not replaced: %q", data)
	}
	if data, _ := os.ReadFile(bin + ".prev"); string(data) != "alt" {
		t.Fatalf("previous binary not kept: %q", data)
	}

	// A wrong checksum must leave the installed binary alone.
	sums = strings.Repeat("0", 64) + "  " + name + "\n"
	os.WriteFile(bin, []byte("aktuell"), 0o755)
	if _, err := Apply(context.Background(), "", bin, nil); err == nil {
		t.Fatal("bad checksum accepted")
	}
	if data, _ := os.ReadFile(bin); string(data) != "aktuell" {
		t.Fatalf("binary touched after failed update: %q", data)
	}
}
