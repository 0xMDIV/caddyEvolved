package builder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// ActivateError carries whether the rollback after a failed swap worked, so
// the UI can say "old binary is running again" instead of a bare error.
type ActivateError struct {
	Err         error
	RolledBack  bool
	RollbackErr error
}

func (e *ActivateError) Error() string {
	msg := "Aktivierung fehlgeschlagen: " + e.Err.Error()
	switch {
	case e.RolledBack:
		msg += " – vorherige Binary wieder aktiv"
	case e.RollbackErr != nil:
		msg += " – ROLLBACK FEHLGESCHLAGEN: " + e.RollbackErr.Error()
	}
	return msg
}

func (e *ActivateError) Unwrap() error { return e.Err }

type previousMeta struct {
	BuildID string    `json:"buildId,omitempty"`
	SavedAt time.Time `json:"savedAt"`
	SHA256  string    `json:"sha256"`
}

// Activate installs a finished build as the live caddy binary.
//
// Order matters: the current binary is copied aside first, the new one is
// written next to the target and renamed over it (a running caddy keeps its
// old inode), then caddy restarts. If it is not healthy within the grace
// period, the saved binary goes back and caddy restarts again.
func (m *Manager) Activate(ctx context.Context, id string, h Hooks) (Build, error) {
	m.actMu.Lock()
	defer m.actMu.Unlock()

	b := m.snapshot(id)
	if b.ID == "" {
		return Build{}, fmt.Errorf("Build %s: %w", id, os.ErrNotExist)
	}
	if b.Status != StatusSucceeded {
		return b, fmt.Errorf("Build %s ist nicht erfolgreich (%s)", id, b.Status)
	}
	if !b.ValidateOK {
		return b, errors.New("die neue Binary lehnt das aktuelle Caddyfile ab – erst die Konfiguration anpassen, dann neu bauen")
	}
	src := m.binaryPath(id)
	if sum, err := fileSHA256(src); err != nil || sum != b.SHA256 {
		return b, fmt.Errorf("Build-Binary verändert oder fehlt (sha256 %s, erwartet %s)", sum, b.SHA256)
	}

	prevActive := m.ActiveID()
	hadPrevious := false
	if _, err := os.Stat(m.caddyBin); err == nil {
		if err := m.savePrevious(prevActive); err != nil {
			return b, fmt.Errorf("aktuelle Binary sichern: %w", err)
		}
		hadPrevious = true
	}
	if err := installBinary(src, m.caddyBin); err != nil {
		return b, fmt.Errorf("Binary installieren: %w", err)
	}

	if err := restartHealthy(ctx, h); err != nil {
		aerr := &ActivateError{Err: err}
		if hadPrevious {
			if rerr := m.restorePrevious(ctx, h); rerr != nil {
				aerr.RollbackErr = rerr
			} else {
				aerr.RolledBack = true
			}
		}
		return b, aerr
	}

	now := time.Now().UTC()
	m.mu.Lock()
	for _, other := range m.builds {
		if other.Active {
			other.Active = false
			m.saveLocked(other)
		}
	}
	cur := m.builds[id]
	cur.Active, cur.ActivatedAt = true, now
	m.saveLocked(cur)
	out := *cur
	m.mu.Unlock()
	return out, nil
}

// Rollback swaps the saved previous binary back in. The binary it replaces
// becomes the new "previous", so a second rollback undoes the first.
func (m *Manager) Rollback(ctx context.Context, h Hooks) error {
	m.actMu.Lock()
	defer m.actMu.Unlock()
	if !m.PreviousAvailable() {
		return errors.New("keine vorherige Binary gesichert")
	}
	meta := m.readPrevious()
	cur := m.ActiveID()
	swap := filepath.Join(m.buildsDir(), "previous", "caddy.swap")
	if err := copyFile(m.caddyBin, swap); err != nil {
		return err
	}
	if err := installBinary(m.previousBin(), m.caddyBin); err != nil {
		return err
	}
	if err := restartHealthy(ctx, h); err != nil {
		// Put the binary we just replaced back; it was running a moment ago.
		installBinary(swap, m.caddyBin)
		restartHealthy(ctx, h)
		os.Remove(swap)
		return fmt.Errorf("vorherige Binary startet nicht, aktuelle wiederhergestellt: %w", err)
	}
	os.Rename(swap, m.previousBin())
	sum, _ := fileSHA256(m.previousBin())
	m.writePrevious(previousMeta{BuildID: cur, SavedAt: time.Now().UTC(), SHA256: sum})

	m.mu.Lock()
	for _, b := range m.builds {
		want := b.ID == meta.BuildID
		if b.Active != want {
			b.Active = want
			if want {
				b.ActivatedAt = time.Now().UTC()
			}
			m.saveLocked(b)
		}
	}
	m.mu.Unlock()
	return nil
}

func (m *Manager) savePrevious(activeID string) error {
	if err := os.MkdirAll(filepath.Dir(m.previousBin()), 0o750); err != nil {
		return err
	}
	if err := copyFile(m.caddyBin, m.previousBin()); err != nil {
		return err
	}
	sum, _ := fileSHA256(m.previousBin())
	return m.writePrevious(previousMeta{BuildID: activeID, SavedAt: time.Now().UTC(), SHA256: sum})
}

func (m *Manager) restorePrevious(ctx context.Context, h Hooks) error {
	if err := installBinary(m.previousBin(), m.caddyBin); err != nil {
		return err
	}
	return restartHealthy(ctx, h)
}

func (m *Manager) readPrevious() previousMeta {
	var p previousMeta
	if data, err := os.ReadFile(m.previousMeta()); err == nil {
		json.Unmarshal(data, &p)
	}
	return p
}

func (m *Manager) writePrevious(p previousMeta) error {
	data, _ := json.MarshalIndent(p, "", "  ")
	return os.WriteFile(m.previousMeta(), data, 0o640)
}

// restartHealthy restarts caddy and waits for the admin API.
func restartHealthy(ctx context.Context, h Hooks) error {
	if h.Restart == nil {
		return nil
	}
	if err := h.Restart(ctx); err != nil {
		return fmt.Errorf("caddy neu starten: %w", err)
	}
	if h.Healthy == nil {
		return nil
	}
	deadline := time.Now().Add(20 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		if last = h.Healthy(ctx); last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("caddy nicht gesund nach Neustart: %w", last)
}

// installBinary writes src next to dst and renames it over dst, so the target
// path never holds a half-written file.
func installBinary(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".caddyevolved-new"
	if err := copyFile(src, tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}
