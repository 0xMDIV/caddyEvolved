package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Store keeps archives on this host, under /var/lib/caddyevolved/backups.
// Automatic ones carry the prefix "auto-" and are pruned to Settings.Keep;
// manual ones and the safety copies taken before a restore stay until deleted.
type Store struct {
	Dir      string
	Settings string // settings file, /etc/caddyevolved/backup.json
}

// Settings drive the automatic backup.
type Settings struct {
	Daily bool `json:"daily"`
	Keep  int  `json:"keep"`
	Certs bool `json:"certs"`
}

// Entry is one stored archive.
type Entry struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
	Kind      string    `json:"kind"` // auto | manual | pre-restore
	Encrypted bool      `json:"encrypted"`
}

var reName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,120}\.(tar\.gz|cevbak)$`)

// ValidName refuses anything that could leave the backup directory.
func ValidName(name string) bool { return reName.MatchString(name) && !strings.Contains(name, "..") }

// FileName builds an archive name: <kind>-<host>-<timestamp>.<ext>.
func FileName(kind, host string, at time.Time, encrypted bool) string {
	host = regexp.MustCompile(`[^a-z0-9-]+`).ReplaceAllString(strings.ToLower(host), "-")
	if host == "" {
		host = "server"
	}
	ext := "tar.gz"
	if encrypted {
		ext = "cevbak"
	}
	return fmt.Sprintf("%s-%s-%s.%s", kind, host, at.UTC().Format("20060102-150405"), ext)
}

func kindOf(name string) string {
	switch {
	case strings.HasPrefix(name, "auto-"):
		return "auto"
	case strings.HasPrefix(name, "pre-restore-"):
		return "pre-restore"
	}
	return "manual"
}

// List returns stored archives, newest first.
func (s Store) List() ([]Entry, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range entries {
		if e.IsDir() || !ValidName(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Entry{Name: e.Name(), Size: info.Size(), CreatedAt: info.ModTime().UTC(), Kind: kindOf(e.Name()), Encrypted: strings.HasSuffix(e.Name(), ".cevbak")})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Save writes data as name (0600: archives contain credentials).
func (s Store) Save(name string, data []byte) error {
	if !ValidName(name) {
		return fmt.Errorf("ungültiger Name %q", name)
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(s.Dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.Dir, name))
}

// Read returns a stored archive.
func (s Store) Read(name string) ([]byte, error) {
	if !ValidName(name) {
		return nil, fmt.Errorf("ungültiger Name %q", name)
	}
	return os.ReadFile(filepath.Join(s.Dir, name))
}

// Delete removes a stored archive.
func (s Store) Delete(name string) error {
	if !ValidName(name) {
		return fmt.Errorf("ungültiger Name %q", name)
	}
	return os.Remove(filepath.Join(s.Dir, name))
}

// Prune keeps the newest keep automatic archives.
func (s Store) Prune(keep int) error {
	if keep < 1 {
		keep = 1
	}
	list, err := s.List()
	if err != nil {
		return err
	}
	n := 0
	for _, e := range list {
		if e.Kind != "auto" {
			continue
		}
		n++
		if n > keep {
			if err := s.Delete(e.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// LastAuto is the time of the newest automatic archive.
func (s Store) LastAuto() time.Time {
	list, _ := s.List()
	for _, e := range list {
		if e.Kind == "auto" {
			return e.CreatedAt
		}
	}
	return time.Time{}
}

// LoadSettings reads the settings; missing means daily off, keep 7.
func (s Store) LoadSettings() Settings {
	st := Settings{Keep: 7}
	if data, err := os.ReadFile(s.Settings); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	if st.Keep < 1 {
		st.Keep = 7
	}
	return st
}

// SaveSettings writes the settings.
func (s Store) SaveSettings(st Settings) error {
	if st.Keep < 1 || st.Keep > 365 {
		return errors.New("Anzahl zwischen 1 und 365")
	}
	data, _ := json.MarshalIndent(st, "", "  ")
	if err := os.MkdirAll(filepath.Dir(s.Settings), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.Settings, data, 0o600)
}
