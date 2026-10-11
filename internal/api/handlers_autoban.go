package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"caddyevolved/internal/sites"
)

// The auto-ban (internal/autoban) watches the access log and keeps a list
// of banned addresses; here it is wired to the firewall file.

// autobanActive hands the current rules to the store and returns the bans
// to render. Never banned: the allowlist, trusted proxies and Cloudflare,
// whose addresses stand for every visitor behind it when the real-IP
// setting is missing.
func (s *Server) autobanActive(g sites.Global) []string {
	if s.Bans == nil {
		return nil
	}
	exempt := append([]string{}, g.Firewall.Allow...)
	exempt = append(exempt, g.RealIP.Proxies...)
	exempt = append(exempt, sites.CloudflareRanges...)
	s.Bans.Configure(g.Firewall, exempt)
	return s.Bans.Active()
}

// autobanLoop applies new and expired bans. Bans are collected for a few
// seconds, so a scanner burst costs one reload, not one per request.
func (s *Server) autobanLoop(ctx context.Context) {
	if s.Bans == nil {
		return
	}
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		s.Bans.Sweep()
		changed, added := s.Bans.TakeChanges()
		if !changed {
			continue
		}
		summary := "Auto-Bann: abgelaufene Sperren aufgehoben"
		if len(added) > 0 {
			summary = "Auto-Bann: " + strings.Join(added[:min(len(added), 5)], ", ")
			if len(added) > 5 {
				summary += fmt.Sprintf(" und %d weitere", len(added)-5)
			}
			summary += " gesperrt"
		}
		rctx, cancel := context.WithTimeout(ctx, time.Minute)
		s.resyncSites(rctx, summary)
		cancel()
	}
}

// handleAutobanClear lifts every ban.
func (s *Server) handleAutobanClear(w http.ResponseWriter, r *http.Request) {
	n := s.Bans.Clear()
	s.Bans.TakeChanges()
	s.resyncSites(r.Context(), fmt.Sprintf("Auto-Bann: alle %d Sperren aufgehoben", n))
	writeJSON(w, http.StatusOK, map[string]any{"cleared": n})
}
