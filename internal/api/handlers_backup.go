package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"caddyevolved/internal/backup"
	"caddyevolved/internal/buildinfo"
	"caddyevolved/internal/events"
)

// Backups hold every credential caddyEvolved knows, so all endpoints here are
// for logged-in admins only, never for API tokens.

const maxBackupUpload = 256 << 20

var restoreMu sync.Mutex

func (s *Server) backupStore() backup.Store {
	return backup.Store{Dir: filepath.Join(s.Paths.StateDir, "backups"), Settings: filepath.Join(s.Paths.Etc, "backup.json")}
}

// createBackup writes an archive into the store and returns its entry.
func (s *Server) createBackup(kind string, o backup.Options) (backup.Entry, backup.Manifest, error) {
	o.Version = buildinfo.Version
	var buf bytes.Buffer
	m, err := backup.Create(s.Paths, &buf, o)
	if err != nil {
		return backup.Entry{}, m, err
	}
	host, _ := os.Hostname()
	name := backup.FileName(kind, host, m.CreatedAt, o.Passphrase != "")
	store := s.backupStore()
	if err := store.Save(name, buf.Bytes()); err != nil {
		return backup.Entry{}, m, err
	}
	return backup.Entry{Name: name, Size: int64(buf.Len()), CreatedAt: m.CreatedAt, Kind: kind, Encrypted: o.Passphrase != ""}, m, nil
}

func (s *Server) handleBackupList(w http.ResponseWriter, r *http.Request) {
	if !tokenAdmin(w, r) {
		return
	}
	store := s.backupStore()
	list, err := store.List()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup_list", errText(err))
		return
	}
	if list == nil {
		list = []backup.Entry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"backups": list, "settings": store.LoadSettings(), "dir": store.Dir, "lastAuto": store.LastAuto()})
}

func (s *Server) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	if !tokenAdmin(w, r) {
		return
	}
	var req struct {
		Certs      bool   `json:"certs"`
		Passphrase string `json:"passphrase"`
	}
	if r.ContentLength > 0 {
		if err := decode(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
			return
		}
	}
	if req.Passphrase != "" && len(req.Passphrase) < 8 {
		writeErr(w, http.StatusBadRequest, "weak_passphrase", "Passwort für das Backup: mindestens 8 Zeichen")
		return
	}
	e, m, err := s.createBackup("manual", backup.Options{Certs: req.Certs, Passphrase: req.Passphrase, Reason: "manuell"})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup_failed", errText(err))
		return
	}
	s.Events.Record(events.Event{Kind: events.KindConfig, Step: "backup", OK: true, Summary: "Backup " + e.Name + " erstellt"})
	writeJSON(w, http.StatusCreated, map[string]any{"backup": e, "manifest": m})
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	if !tokenAdmin(w, r) {
		return
	}
	name := r.PathValue("name")
	data, err := s.backupStore().Read(name)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", errText(err))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Write(data)
}

func (s *Server) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	if !tokenAdmin(w, r) {
		return
	}
	if err := s.backupStore().Delete(r.PathValue("name")); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", errText(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleBackupSettings(w http.ResponseWriter, r *http.Request) {
	if !tokenAdmin(w, r) {
		return
	}
	var st backup.Settings
	if err := decode(r, &st); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	if err := s.backupStore().SaveSettings(st); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_settings", errText(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": st})
}

// restoreSource reads the archive: a stored one (?name=) or the request body.
func (s *Server) restoreSource(r *http.Request) ([]byte, error) {
	if name := r.URL.Query().Get("name"); name != "" {
		return s.backupStore().Read(name)
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBackupUpload+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBackupUpload {
		return nil, errors.New("Datei zu groß (max. 256 MB)")
	}
	if len(data) == 0 {
		return nil, errors.New("keine Datei hochgeladen")
	}
	return data, nil
}

// handleRestorePreview shows what an archive contains without touching anything.
func (s *Server) handleRestorePreview(w http.ResponseWriter, r *http.Request) {
	if !tokenAdmin(w, r) {
		return
	}
	data, err := s.restoreSource(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_backup", errText(err))
		return
	}
	pass := r.Header.Get("X-Backup-Passphrase")
	m, names, err := backup.Inspect(data, pass)
	if errors.Is(err, backup.ErrPassphrase) {
		writeErr(w, http.StatusBadRequest, "passphrase", errText(err))
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_backup", errText(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"manifest": m, "files": names})
}

// handleRestore replaces the configuration with an archive. A safety backup
// of the current state comes first; if caddy rejects the restored config, that
// safety backup goes straight back.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if !tokenAdmin(w, r) {
		return
	}
	if !restoreMu.TryLock() {
		writeErr(w, http.StatusConflict, "restore_running", "Eine Wiederherstellung läuft bereits")
		return
	}
	defer restoreMu.Unlock()

	data, err := s.restoreSource(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_backup", errText(err))
		return
	}
	pass := r.Header.Get("X-Backup-Passphrase")
	certs := r.URL.Query().Get("certs") == "1"
	m, _, err := backup.Inspect(data, pass)
	if errors.Is(err, backup.ErrPassphrase) {
		writeErr(w, http.StatusBadRequest, "passphrase", errText(err))
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_backup", errText(err))
		return
	}

	safety, _, err := s.createBackup("pre-restore", backup.Options{Certs: certs && m.Certs, Reason: "vor Wiederherstellung"})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "safety_backup", "Sicherung des aktuellen Stands fehlgeschlagen, nichts geändert: "+errText(err))
		return
	}
	if _, err := backup.Restore(s.Paths, data, pass, backup.RestoreOptions{Certs: certs}); err != nil {
		s.rollbackRestore(safety.Name, certs)
		writeErr(w, http.StatusInternalServerError, "restore_failed", errText(err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	out, reloaded, err := s.commitConfig(ctx)
	if err != nil {
		s.rollbackRestore(safety.Name, certs)
		_, _, _ = s.commitConfig(ctx)
		writeErr(w, http.StatusUnprocessableEntity, "caddy_rejected", "Caddy lehnt die wiederhergestellte Konfiguration ab – alter Stand ist zurück: "+errText(err), outputLines(out, err)...)
		return
	}
	if certs && m.Certs && s.Systemd.Available(ctx) {
		// Caddy keeps certificates in memory; a restart loads the restored ones.
		_ = s.Systemd.Restart(ctx, "caddy.service")
	}
	s.Events.Record(events.Event{Kind: events.KindConfig, Step: "restore", OK: true,
		Summary: fmt.Sprintf("Konfiguration vom %s wiederhergestellt (Sicherung davor: %s)", m.CreatedAt.Format("02.01.2006 15:04"), safety.Name)})

	restart := s.Systemd.Available(ctx)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "manifest": m, "safety": safety.Name, "reloaded": reloaded, "restarting": restart})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	if restart {
		// Login, tokens and sites live in memory too: restart to load them.
		go func() {
			time.Sleep(700 * time.Millisecond)
			_ = exec.Command("systemctl", "--no-block", "restart", "caddyevolved.service").Run()
		}()
	}
}

func (s *Server) rollbackRestore(safety string, certs bool) {
	data, err := s.backupStore().Read(safety)
	if err == nil {
		_, err = backup.Restore(s.Paths, data, "", backup.RestoreOptions{Certs: certs})
	}
	s.Events.Record(events.Event{Kind: events.KindConfig, Step: "restore", OK: false, Summary: "Wiederherstellung zurückgerollt auf " + safety, Error: errText(err)})
}

// autoBackupLoop takes the daily automatic backup when enabled.
func (s *Server) autoBackupLoop(ctx context.Context) {
	tick := time.NewTicker(30 * time.Minute)
	defer tick.Stop()
	for {
		store := s.backupStore()
		st := store.LoadSettings()
		if st.Daily && time.Since(store.LastAuto()) > 23*time.Hour+30*time.Minute {
			e, _, err := s.createBackup("auto", backup.Options{Certs: st.Certs, Reason: "automatisch"})
			summary := "Automatisches Backup " + e.Name
			if err == nil {
				err = store.Prune(st.Keep)
			}
			s.Events.Record(events.Event{Kind: events.KindConfig, Step: "backup", OK: err == nil, Summary: summary, Error: errText(err)})
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
