package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"caddyevolved/internal/accesslog"
	"caddyevolved/internal/events"
	"caddyevolved/internal/sites"
)

// logSettings is the UI's view of the access log rotation; stored in
// /etc/caddyevolved/logging.json and rendered into every site's log block.
type logSettings struct {
	Rotate    bool `json:"rotate"`
	SizeMB    int  `json:"sizeMb"`
	Keep      int  `json:"keep"`
	KeepDays  int  `json:"keepDays"`
	Compress  bool `json:"compress"`
	LocalTime bool `json:"localTime"`
}

func (s *Server) loggingFile() string { return filepath.Join(s.Paths.Etc, "logging.json") }

func defaultLogSettings() logSettings {
	return logSettings{Rotate: true, SizeMB: 50, Keep: 5, Compress: true}
}

func (s *Server) loadLogSettings() logSettings {
	st := defaultLogSettings()
	if data, err := os.ReadFile(s.loggingFile()); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

func (ls logSettings) roll() sites.LogRoll {
	return sites.LogRoll{Disabled: !ls.Rotate, SizeMB: ls.SizeMB, Keep: ls.Keep, KeepDays: ls.KeepDays, Uncompressed: !ls.Compress, LocalTime: ls.LocalTime}
}

func (ls logSettings) validate() error {
	switch {
	case ls.SizeMB < 1 || ls.SizeMB > 10240:
		return errors.New("Dateigröße zwischen 1 und 10240 MB")
	case ls.Keep < 1 || ls.Keep > 1000:
		return errors.New("Anzahl Dateien zwischen 1 und 1000")
	case ls.KeepDays < 0 || ls.KeepDays > 3650:
		return errors.New("Aufbewahrung zwischen 0 (unbegrenzt) und 3650 Tagen")
	}
	return nil
}

// siteOptions is the rendering configuration for every site snippet.
func (s *Server) siteOptions() sites.Options {
	return sites.Options{AccessLog: s.Paths.AccessLog, Roll: s.loadLogSettings().roll()}
}

func (s *Server) handleLoggingGet(w http.ResponseWriter, r *http.Request) {
	files := accesslog.Files(s.Paths.AccessLog)
	var total int64
	for _, f := range files {
		total += f.Size
	}
	if files == nil {
		files = []accesslog.File{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings": s.loadLogSettings(), "path": s.Paths.AccessLog, "files": files, "totalBytes": total, "tags": accesslog.AllTags,
	})
}

// handleLoggingSave stores the rotation settings and rewrites every site
// snippet through the usual validate-and-reload transaction.
func (s *Server) handleLoggingSave(w http.ResponseWriter, r *http.Request) {
	var ls logSettings
	if err := decode(r, &ls); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	if err := ls.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_settings", errText(err))
		return
	}
	prev, _ := os.ReadFile(s.loggingFile())
	data, _ := json.MarshalIndent(ls, "", "  ")
	if err := os.WriteFile(s.loggingFile(), data, 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "write", errText(err))
		return
	}
	s.Sites.SetOptions(s.siteOptions())
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	var reloaded bool
	if err := s.Sites.Sync(ctx, s.siteCommit(&reloaded)); err != nil {
		// Back to the previous settings; the transaction already restored the snippets.
		if prev != nil {
			_ = os.WriteFile(s.loggingFile(), prev, 0o644)
		} else {
			_ = os.Remove(s.loggingFile())
		}
		s.Sites.SetOptions(s.siteOptions())
		s.siteError(w, r, err)
		return
	}
	s.Events.Record(events.Event{Kind: events.KindConfig, Step: "logging", OK: true, Summary: "Log-Rotation geändert"})
	writeJSON(w, http.StatusOK, map[string]any{"settings": ls, "reloaded": reloaded})
}

// handleAccessLog queries the access log, rotated files included.
func (s *Server) handleAccessLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := accesslog.Filter{
		Host: strings.ToLower(q.Get("host")), IP: q.Get("ip"), Method: q.Get("method"), Status: q.Get("status"),
		Path: q.Get("path"), Agent: q.Get("agent"), Text: q.Get("q"), Tag: q.Get("tag"),
	}
	if v, err := strconv.ParseFloat(q.Get("minMs"), 64); err == nil {
		f.MinMs = v
	}
	if d, err := time.ParseDuration(q.Get("since")); err == nil && d > 0 {
		f.From = time.Now().Add(-d)
	}
	if t, err := time.Parse(time.RFC3339, q.Get("from")); err == nil {
		f.From = t
	}
	if t, err := time.Parse(time.RFC3339, q.Get("to")); err == nil {
		f.To = t
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	res := accesslog.Query(s.Paths.AccessLog, f, limit, 0)
	writeJSON(w, http.StatusOK, res)
}
