package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return data, err
}

func unmarshalJSON(data []byte, dst any) error {
	return json.Unmarshal(data, dst)
}

// writeFileJSON persists v atomically. Auth state that survives a crash must
// never be a half-written file, or logins break until someone edits by hand.
func writeFileJSON(path string, v any, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RevokeAll signs every session out, e.g. after a password reset from the CLI.
func (s *Store) RevokeAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeAll()
	return s.saveLocked()
}
