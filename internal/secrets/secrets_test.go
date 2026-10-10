package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyAddsUpdatesAndRemoves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	s := New(path)

	changes, err := s.Apply(Apply{
		Wanted: map[string]string{"CF_API_TOKEN": "secret-value", "PLAIN": "open"},
		Header: "verwaltet von caddyforge",
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := changeKinds(changes); got != "CF_API_TOKEN:added,PLAIN:added" {
		t.Errorf("Änderungen = %q, wollen beide added", got)
	}

	changes, err = s.Apply(Apply{Wanted: map[string]string{"CF_API_TOKEN": "other", "NEU": "x"}})
	if err != nil {
		t.Fatalf("Apply 2: %v", err)
	}
	// Deselecting a provider must drop its token from the environment, not leave
	// it readable by the next process.
	if got := changeKinds(changes); got != "CF_API_TOKEN:updated,NEU:added,PLAIN:removed" {
		t.Errorf("Änderungen = %q", got)
	}

	got, err := s.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 2 || got["CF_API_TOKEN"] != "other" || got["NEU"] != "x" {
		t.Errorf("Inhalt = %v", got)
	}
}

func TestApplyQuotingRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	s := New(path)
	wanted := map[string]string{
		"SPACES":   "zwei worte",
		"DOLLAR":   "pass$word",
		"QUOTE":    `mit "cim` + `"`,
		"EMPTY":    "",
		"BACKTICK": "a`b",
		"HASH":     "a#b",
	}
	if _, err := s.Apply(Apply{Wanted: wanted}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, err := s.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	for k, want := range wanted {
		if got[k] != want {
			t.Errorf("%s = %q, wollen %q", k, got[k], want)
		}
	}
}

func TestApplyFileModeIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	if _, err := New(path).Apply(Apply{Wanted: map[string]string{"A": "1"}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("Modus = %v, wollen 0600 (die Datei enthält Token)", st.Mode().Perm())
	}
}

func TestReadIgnoresCommentsAndBlanks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	body := "# header\n\n  CF_API_TOKEN =  spaced  \n# commented=none\nOTHER=keep\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := New(path).Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Einträge = %d (%v), wollen 2", len(got), got)
	}
	if got["CF_API_TOKEN"] != "spaced" {
		t.Errorf("CF_API_TOKEN = %q, wollen getrimmt", got["CF_API_TOKEN"])
	}
}

func TestReadMissingFileIsEmpty(t *testing.T) {
	got, err := New(filepath.Join(t.TempDir(), "absent")).Read()
	if err != nil {
		t.Fatalf("Read eines fehlenden env: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got = %v, wollen leer", got)
	}
}

func changeKinds(changes []Change) string {
	parts := make([]string, 0, len(changes))
	for _, c := range changes {
		if c.Kind == "unchanged" {
			continue
		}
		parts = append(parts, c.Key+":"+c.Kind)
	}
	return strings.Join(parts, ",")
}
