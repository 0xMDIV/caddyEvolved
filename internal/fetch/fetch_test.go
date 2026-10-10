package fetch

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDigest(t *testing.T) {
	const sha256Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const sha512Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	cases := []struct {
		name    string
		in      string
		wantAlg Algorithm
		wantHex string
		wantErr bool
	}{
		{name: "sha256 ohne Präfix", in: sha256Hex, wantAlg: SHA256, wantHex: sha256Hex},
		{name: "sha512 ohne Präfix", in: sha512Hex, wantAlg: SHA512, wantHex: sha512Hex},
		{name: "sha256 mit Präfix", in: "sha256:" + sha256Hex, wantAlg: SHA256, wantHex: sha256Hex},
		{name: "SHA512 mit Grossbuchstaben", in: "SHA512:" + strings.ToUpper(sha512Hex), wantAlg: SHA512, wantHex: sha512Hex},
		{name: "nur Hex gross", in: strings.ToUpper(sha256Hex), wantAlg: SHA256, wantHex: sha256Hex},
		{name: "leer", in: "", wantErr: true},
		{name: "kein hex", in: "sha256:zzzz", wantErr: true},
		{name: "unsupported alg", in: "md5:d41d8cd98f00b204e9800998ecf8427e", wantErr: true},
		{name: "laenge unbekannt", in: "abcdef", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			alg, hexPart, err := ParseDigest(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("erwartete Fehler, bekam %s/%s", alg, hexPart)
				}
				return
			}
			if err != nil {
				t.Fatalf("unerwarteter Fehler: %v", err)
			}
			if alg != c.wantAlg {
				t.Errorf("Algorithmus = %s, wollen %s", alg, c.wantAlg)
			}
			if hexPart != c.wantHex {
				t.Errorf("Hex = %q, wollen %q", hexPart, c.wantHex)
			}
		})
	}
}

// TestParseChecksumFileAlgorithms is the regression that matters: caddy publishes
// SHA-512 in caddy_<ver>_checksums.txt while other hosts publish SHA-256 for the
// same archive, and a hardcoded assumption rejected a perfectly good download.
func TestParseChecksumFileAlgorithms(t *testing.T) {
	const sha256Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const sha512Hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" +
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	manifest := []byte(
		"aa11  caddy_2.11.7_linux_amd64.deb\n" +
			sha256Hex + "  caddy_2.11.7_linux_amd64.tar.gz\n" +
			sha512Hex + "  caddy_2.11.7_windows_amd64.zip\n")

	got, err := ParseChecksumFile(manifest, "caddy_2.11.7_linux_amd64.tar.gz")
	if err != nil {
		t.Fatalf("ParseChecksumFile: %v", err)
	}
	if want := "sha256:" + sha256Hex; got != want {
		t.Errorf("digest = %q, wollen %q", got, want)
	}

	got, err = ParseChecksumFile(manifest, "caddy_2.11.7_windows_amd64.zip")
	if err != nil {
		t.Fatalf("ParseChecksumFile sha512: %v", err)
	}
	if want := "sha512:" + sha512Hex; got != want {
		t.Errorf("sha512-Digest = %q, wollen %q", got, want)
	}

	// A two-character field is not a digest; accepting it would let a truncated
	// or corrupt manifest pass as "verified".
	if _, err := ParseChecksumFile(manifest, "caddy_2.11.7_linux_amd64.deb"); err == nil {
		t.Error("2-Zeichen-Digest muss abbrechen")
	}
	if _, err := ParseChecksumFile(manifest, "missing.tar.gz"); err == nil {
		t.Error("fehlender Eintrag muss fehlschlagen")
	}
}

func TestToFileVerifiesBothAlgorithms(t *testing.T) {
	payload := []byte("caddyforge test payload")
	sum256 := "sha256:" + hex.EncodeToString(sha256Sum(payload))
	sum512 := "sha512:" + hex.EncodeToString(sha512Sum(payload))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer srv.Close()

	cases := []struct {
		name    string
		digest  string
		wantErr bool
	}{
		{name: "sha256 richtig", digest: sum256},
		{name: "sha512 richtig", digest: sum512},
		{name: "sha512 ohne Präfix", digest: strings.TrimPrefix(sum512, "sha512:")},
		{name: "ohne Prüfung", digest: ""},
		{name: "falscher Wert", digest: "sha256:" + strings.Repeat("f", 64), wantErr: true},
		{name: "Value eines anderen Algorithmus", digest: "sha256:" + strings.TrimPrefix(sum512, "sha512:")[:64], wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "out.bin")
			_, err := ToFile(context.Background(), srv.URL, dest, Options{Digest: c.digest})
			if c.wantErr {
				if err == nil {
					t.Fatalf("erwartete Prüffehler bei %q", c.digest)
				}
				return
			}
			if err != nil {
				t.Fatalf("unerwarteter Fehler: %v", err)
			}
			st, serr := os.Stat(dest)
			if serr != nil {
				t.Fatalf("Zieldatei fehlt: %v", serr)
			}
			if st.Size() != int64(len(payload)) {
				t.Errorf("Größe = %d, wollen %d", st.Size(), len(payload))
			}
		})
	}
}

// TestToFileLeavesNoPartialFile: a failed digest must never leave bytes on disk
// that a later step could install as a binary.
func TestToFileLeavesNoPartialFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("content"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "binary")
	_, err := ToFile(context.Background(), srv.URL, dest, Options{Digest: "sha256:" + hex.EncodeToString(sha256Sum([]byte("other")))})
	if err == nil {
		t.Fatal("erwartete Prüfung scheiterte nicht")
	}
	if _, serr := os.Stat(dest); serr == nil {
		t.Errorf("%s existiert trotz Digest-Fehler", dest)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Errorf("es blieben %d Dateien im Zielverzeichnis", len(entries))
	}
}

func TestExtractFileFromTarGzCreatesParent(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "test.tar.gz")
	writeTarGz(t, archive, map[string][]byte{
		"./caddy":     []byte("#!/bin/sh\necho caddy\n"),
		"LICENSE.txt": []byte("mit\n"),
	})

	// A staging prefix has no bin/ before the download; extraction must create it
	// instead of failing on a directory nobody was told to make first.
	dest := filepath.Join(dir, "usr", "local", "bin", "caddy")
	if err := ExtractFileFromTarGz(archive, "caddy", dest, 0o755); err != nil {
		t.Fatalf("ExtractFileFromTarGz: %v", err)
	}
	st, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if st.Mode().Perm()&0o111 == 0 {
		t.Errorf("Modus = %v, wollen ausführbar", st.Mode().Perm())
	}
}

func TestExtractFileFromTarGzMissingMember(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "test.tar.gz")
	writeTarGz(t, archive, map[string][]byte{"README.md": []byte("nur Doku")})

	err := ExtractFileFromTarGz(archive, "caddy", filepath.Join(dir, "caddy"), 0o755)
	if err == nil {
		t.Fatal("fehlendes Mitglied muss fehlschlagen")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Fehler = %q, wollen ein Nichtgefunden", err)
	}
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func sha512Sum(b []byte) []byte {
	h := sha512.Sum512(b)
	return h[:]
}

func writeTarGz(t *testing.T, path string, files map[string][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write header %s: %v", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("write body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
}
