package api

import (
	"net/http"
	"time"

	"caddyevolved/internal/accesslog"
	"caddyevolved/internal/sysstat"
)

// handleSystem reports host load and what caddy and caddyEvolved take of it:
// the newest sample, the last hour, disk usage and the size of the logs.
func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	if s.Sys == nil {
		writeErr(w, http.StatusServiceUnavailable, "no_sampler", "Systemwerte nicht verfügbar")
		return
	}
	hist := s.Sys.History()
	var cur sysstat.Sample
	if len(hist) > 0 {
		cur = hist[len(hist)-1]
	} else {
		var err error
		if cur, err = s.Sys.Sample(); err != nil {
			writeErr(w, http.StatusServiceUnavailable, "unsupported", errText(err))
			return
		}
	}
	var logBytes int64
	for _, f := range accesslog.Files(s.Paths.AccessLog) {
		logBytes += f.Size
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"current": cur, "history": hist, "interval": 5,
		"disks":    sysstat.Disks("/", s.Paths.StateDir, s.Paths.LogDir, s.Paths.CaddyData),
		"logBytes": logBytes, "at": time.Now().UTC(),
	})
}
