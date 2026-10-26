package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"caddyevolved/internal/accesslog"
	"caddyevolved/internal/blocklists"
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
	// RedactParams are query parameters shortened in the log on top of the
	// built-in list (accesslog.DefaultRedactParams).
	RedactParams []string `json:"redactParams"`
	// LookupURL opens an IP in an external lookup service; {ip} is replaced.
	LookupURL string `json:"lookupUrl"`
}

const defaultLookupURL = "https://ipinfo.io/{ip}"

// validLookupURL accepts only http(s) links that carry the {ip} placeholder.
func validLookupURL(u string) error {
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return errors.New("Lookup-URL muss mit http:// oder https:// beginnen")
	}
	if !strings.Contains(u, "{ip}") {
		return errors.New("Lookup-URL braucht den Platzhalter {ip}")
	}
	return nil
}

var reParamName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,40}$`)

func (s *Server) loggingFile() string { return filepath.Join(s.Paths.Etc, "logging.json") }

func defaultLogSettings() logSettings {
	return logSettings{Rotate: true, SizeMB: 50, Keep: 5, Compress: true, LookupURL: defaultLookupURL}
}

func (s *Server) loadLogSettings() logSettings {
	st := defaultLogSettings()
	if data, err := os.ReadFile(s.loggingFile()); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

func (ls logSettings) roll() sites.LogRoll {
	return sites.LogRoll{Disabled: !ls.Rotate, SizeMB: ls.SizeMB, Keep: ls.Keep, KeepDays: ls.KeepDays, Uncompressed: !ls.Compress, LocalTime: ls.LocalTime, RedactParams: ls.RedactParams}
}

func (ls logSettings) validate() error {
	switch {
	case ls.SizeMB < 1 || ls.SizeMB > 10240:
		return errors.New("Dateigröße zwischen 1 und 10240 MB")
	case ls.Keep < 1 || ls.Keep > 1000:
		return errors.New("Anzahl Dateien zwischen 1 und 1000")
	case ls.KeepDays < 0 || ls.KeepDays > 3650:
		return errors.New("Aufbewahrung zwischen 0 (unbegrenzt) und 3650 Tagen")
	case len(ls.RedactParams) > 50:
		return errors.New("Höchstens 50 eigene Token-Parameter")
	}
	if err := validLookupURL(ls.LookupURL); err != nil {
		return err
	}
	for _, p := range ls.RedactParams {
		if !reParamName.MatchString(p) {
			return errors.New("Ungültiger Parametername: " + p)
		}
	}
	return nil
}

// siteOptions is the rendering configuration for every site snippet. It asks
// the running binary which optional modules it has, so features of a missing
// plugin are left out instead of breaking the config.
func (s *Server) siteOptions() sites.Options {
	g := s.loadGlobal()
	return sites.Options{
		AccessLog: s.Paths.AccessLog, Roll: s.loadLogSettings().roll(), GuardExtra: s.loadProtect().Extra,
		Global: g, Caps: s.caps(), StateDir: s.Paths.CaddyData,
		FirewallLists: blocklists.Load(s.listDir(), g.Firewall.Lists),
		GeoDB:         blocklists.GeoPath(s.geoDir(), blocklists.GeoCountry),
		ASNDB:         blocklists.GeoPath(s.geoDir(), blocklists.GeoASN),
		WAFLog:        s.wafLog(),
		AutoBanned:    s.autobanActive(g),
	}
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
	if ls.LookupURL == "" {
		ls.LookupURL = defaultLookupURL
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
	ips := make([]string, len(res.Entries))
	for i, e := range res.Entries {
		ips[i] = e.IP
	}
	writeJSON(w, http.StatusOK, struct {
		accesslog.Result
		Geo map[string]ipGeo `json:"ipGeo"`
	}{res, s.geoFor(ips)})
}
