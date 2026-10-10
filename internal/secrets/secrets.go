// Package secrets stores the module credentials caddy needs at run time.
//
// Values live in one EnvironmentFile that systemd feeds to the caddy process.
// The API never exposes the values, only key names and digests — a leaked
// state file must not contain anything an attacker can reuse.
package secrets

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Change describes one edited key without revealing either value.
type Change struct {
	Key      string
	Kind     string // "added" | "updated" | "removed" | "unchanged"
	HasValue bool
}

// Store is the env file.
type Store struct {
	path string
	mode os.FileMode
}

// New points at an env file path; mode defaults to 0600.
func New(path string) *Store { return &Store{path: path, mode: 0o600} }

// Read parses KEY=VALUE lines, ignoring comments and blanks.
func (s *Store) Read() (map[string]string, error) {
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = unquote(strings.TrimSpace(v))
	}
	return out, sc.Err()
}

// Apply groups the wanted keys with a comment header.
type Apply struct {
	Wanted map[string]string
	Header string
}

// Apply writes the wanted keys and returns a name-only change report. Keys
// absent from wanted are removed, so deselecting a provider really drops its
// token from the environment.
func (s *Store) Apply(a Apply) ([]Change, error) {
	current, err := s.Read()
	if err != nil {
		return nil, err
	}
	changes := report(current, a.Wanted)

	var b strings.Builder
	if a.Header != "" {
		for _, line := range strings.Split(strings.TrimSpace(a.Header), "\n") {
			fmt.Fprintf(&b, "# %s\n", line)
		}
	}
	keys := make([]string, 0, len(a.Wanted))
	for k := range a.Wanted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, quote(a.Wanted[k]))
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), s.mode); err != nil {
		return nil, err
	}
	if err := os.Chmod(tmp, s.mode); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return nil, err
	}
	return changes, nil
}

func report(old, want map[string]string) []Change {
	var out []Change
	for k, v := range want {
		switch prev, had := old[k]; {
		case !had:
			out = append(out, Change{Key: k, Kind: "added", HasValue: v != ""})
		case prev != v:
			out = append(out, Change{Key: k, Kind: "updated", HasValue: v != ""})
		default:
			out = append(out, Change{Key: k, Kind: "unchanged", HasValue: v != ""})
		}
	}
	for k := range old {
		if _, ok := want[k]; !ok {
			out = append(out, Change{Key: k, Kind: "removed"})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// Digest exposes a stable short fingerprint of a value so the UI can show
// "changed since last install" without storing plaintext.
func Digest(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:6])
}

func quote(v string) string {
	if v == "" {
		return `""`
	}
	if strings.ContainsAny(v, " \t\"'#$`") {
		return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
	}
	return v
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		inner := v[1 : len(v)-1]
		return strings.ReplaceAll(inner, `\"`, `"`)
	}
	return v
}
