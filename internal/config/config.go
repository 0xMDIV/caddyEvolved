// Package config holds the install layout and the persisted state file.
//
// Two path modes exist on purpose: the FHS layout used on a real LXC, and a
// --root prefix used for tests. Every filesystem access in caddyforge goes
// through Paths so the install engine stays runnable inside a temp dir.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Paths is the resolved filesystem layout.
type Paths struct {
	Root       string // "" for the live system, otherwise an install prefix
	Bin        string
	CaddyBin   string
	Etc        string // /etc/caddyforge
	CaddyEtc   string // /etc/caddy
	CaddyData  string // /var/lib/caddy
	StateDir   string // /var/lib/caddyforge
	LogDir     string // /var/log/caddy
	UnitsDir   string // /etc/systemd/system
	Caddyfile  string
	StateFile  string
	AuthFile   string // /etc/caddyforge/auth.json
	PIDFile    string // /var/lib/caddyforge/caddy.pid
	LogFile    string
	EventsFile string
	EnvFile    string
}

// NewPaths builds the layout. An empty root means absolute FHS paths.
func NewPaths(root string) Paths {
	if filepath.IsAbs(root) || root == "" {
		p := Paths{
			Root:       root,
			Bin:        join(root, "/usr/local/bin/caddyforge"),
			CaddyBin:   join(root, "/usr/local/bin/caddy"),
			Etc:        join(root, "/etc/caddyforge"),
			CaddyEtc:   join(root, "/etc/caddy"),
			CaddyData:  join(root, "/var/lib/caddy"),
			StateDir:   join(root, "/var/lib/caddyforge"),
			LogDir:     join(root, "/var/log/caddy"),
			UnitsDir:   join(root, "/etc/systemd/system"),
			Caddyfile:  join(root, "/etc/caddy/Caddyfile"),
			StateFile:  join(root, "/etc/caddyforge/state.json"),
			AuthFile:   join(root, "/etc/caddyforge/auth.json"),
			LogFile:    join(root, "/var/log/caddy/caddy.log"),
			EventsFile: join(root, "/var/lib/caddyforge/events.jsonl"),
			PIDFile:    join(root, "/var/lib/caddyforge/caddy.pid"),
			EnvFile:    join(root, "/etc/caddyforge/env"),
		}
		return p
	}
	// Relative prefixes are honoured as given; callers resolve them once.
	return NewPaths(mustAbs(root))
}

func join(root, abs string) string {
	if root == "" {
		return abs
	}
	return filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(abs, "/")))
}

func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return abs
}

// IsPrefixed reports whether the layout points at a staging root instead of
// the live system.
func (p Paths) IsPrefixed() bool { return p.Root != "" }

// EnsureDirs creates every directory the install needs, with the modes the
// caddy service expects. Ownership changes are skipped in prefix mode so the
// whole engine stays runnable as an unprivileged user inside a temp dir.
func (p Paths) EnsureDirs(owners map[string]int) error {
	for _, d := range []string{p.Etc, p.CaddyEtc, p.CaddyData, p.StateDir, p.LogDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}
	for _, d := range []string{p.Etc, p.StateDir} {
		if err := os.Chmod(d, 0o750); err != nil {
			return err
		}
	}
	if p.IsPrefixed() {
		return nil
	}
	for dir, uid := range owners {
		if dir == "" || uid == 0 {
			continue
		}
		if err := os.Chown(dir, uid, -1); err != nil {
			return fmt.Errorf("chown %s: %w", dir, err)
		}
	}
	return nil
}

// State is the durable record of what was installed.
type State struct {
	SchemaVersion int      `json:"schema"`
	Installed     bool     `json:"installed"`
	CaddyVersion  string   `json:"caddyVersion"`
	BinarySource  string   `json:"binarySource"`
	Variant       string   `json:"variant"`
	Enabled       []string `json:"enabledPlugins"`
	Email         string   `json:"email"`
	AdminBind     string   `json:"adminBind"`
	AdminPort     int      `json:"adminPort"`
	HTTPPort      int      `json:"httpPort"`
	HTTPSPort     int      `json:"httpsPort"`
	UIPort        int      `json:"uiPort"`
	UIBind        string   `json:"uiBind"`
	UIDirect      bool     `json:"uiDirect"`
	Managed       bool     `json:"managed"`
	DeployPath    string   `json:"deployPath"`
	UpdatedAt     string   `json:"updatedAt"`
}

// LoadState reads the state file; a missing file is an empty state.
func LoadState(path string) (State, error) {
	var s State
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// SaveState writes atomically with 0600 (the file lists plugin credentials by
// name even if never their values).
func SaveState(path string, s State) error {
	s.SchemaVersion = 1
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
