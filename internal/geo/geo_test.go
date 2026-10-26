package geo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountryNoDB(t *testing.T) {
	r := New(func() (string, string) { return "", "" })
	if c := r.Country("1.1.1.1"); c != "" {
		t.Fatalf("Country = %q ohne Datenbank", c)
	}
	if n, org := r.ASN("1.1.1.1"); n != 0 || org != "" {
		t.Fatalf("ASN = %d %q ohne Datenbank", n, org)
	}
}

func TestCountryBadFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.mmdb")
	_ = os.WriteFile(p, []byte("kein mmdb"), 0o644)
	r := New(func() (string, string) { return p, p })
	if c := r.Country("1.1.1.1"); c != "" {
		t.Fatalf("Country = %q bei kaputter Datei", c)
	}
}

func TestCountryInvalidIP(t *testing.T) {
	r := New(func() (string, string) { return "", "" })
	if c := r.Country("nope"); c != "" {
		t.Fatalf("Country = %q für ungültige IP", c)
	}
}

// CEV_GEO_COUNTRY points at a real DB-IP country file for a manual check.
func TestCountryRealDB(t *testing.T) {
	p := os.Getenv("CEV_GEO_COUNTRY")
	if p == "" {
		t.Skip("CEV_GEO_COUNTRY nicht gesetzt")
	}
	r := New(func() (string, string) { return p, os.Getenv("CEV_GEO_ASN") })
	if c := r.Country("8.8.8.8"); c != "US" {
		t.Fatalf("8.8.8.8 → %q", c)
	}
	if c := r.Country("2a00:1450:4001:81b::200e"); c == "" {
		t.Fatal("IPv6 ohne Land")
	}
	if os.Getenv("CEV_GEO_ASN") != "" {
		if n, org := r.ASN("8.8.8.8"); n != 15169 || org == "" {
			t.Fatalf("ASN 8.8.8.8 → %d %q", n, org)
		}
	}
}
