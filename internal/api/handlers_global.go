package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"caddyevolved/internal/config"
	"caddyevolved/internal/events"
	"caddyevolved/internal/plugins"
	"caddyevolved/internal/secrets"
	"caddyevolved/internal/sites"
)

// Host-wide options (real client IPs, DynDNS, CrowdSec, Tailscale, cache) are
// stored in /etc/caddyevolved/global.json and rendered into the snippet the
// main Caddyfile imports in its global block (sites/global.go).

func (s *Server) globalFile() string { return filepath.Join(s.Paths.Etc, "global.json") }

func (s *Server) loadGlobal() sites.Global {
	var g sites.Global
	if data, err := os.ReadFile(s.globalFile()); err == nil {
		_ = json.Unmarshal(data, &g)
	}
	g.Normalize()
	return g
}

// caps asks the running caddy which optional modules it has.
func (s *Server) caps() sites.Caps {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	names, err := s.Caddy.ModuleNames(ctx, false)
	mods := map[string]bool{}
	if err == nil {
		for _, n := range names {
			mods[n] = true
		}
	}
	return sites.CapsFromModules(mods)
}

// resyncSites re-renders everything after a change outside the site list,
// e.g. a new binary with other modules.
func (s *Server) resyncSites(ctx context.Context, summary string) {
	s.Sites.SetOptions(s.siteOptions())
	if !s.Sites.NeedsSync() {
		return
	}
	var reloaded bool
	err := s.Sites.Sync(ctx, s.siteCommit(&reloaded))
	s.Events.Record(events.Event{Kind: events.KindConfig, Step: "sites-sync", OK: err == nil, Summary: summary, Error: errText(err)})
}

type dnsChoice struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Ready bool   `json:"ready"`
}

func (s *Server) handleGlobalGet(w http.ResponseWriter, r *http.Request) {
	st, _ := config.LoadState(s.Paths.StateFile)
	var dns []dnsChoice
	for _, p := range s.pluginStates(r.Context(), st) {
		if p.Category == plugins.CatDNS && p.Detected {
			dns = append(dns, dnsChoice{ID: p.ID, Name: p.Name, Ready: !hasMissing(p)})
		}
	}
	if dns == nil {
		dns = []dnsChoice{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"global": s.loadGlobal(), "caps": s.Sites.Options().Caps, "dnsProviders": dns, "file": s.Sites.GlobalFile(),
	})
}

func hasMissing(p PluginState) bool {
	for _, v := range p.CredentialState {
		if v == "missing" {
			return true
		}
	}
	return false
}

// handleGlobalSave stores the options and applies them through the
// validate-and-reload transaction; a rejected config restores the old file.
func (s *Server) handleGlobalSave(w http.ResponseWriter, r *http.Request) {
	var g sites.Global
	if err := decode(r, &g); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	g.Normalize()
	if err := g.Validate(); err != nil {
		s.siteError(w, r, err)
		return
	}
	if missing := s.missingCredentials(g); len(missing) > 0 {
		s.siteError(w, r, &sites.ValidationError{Problems: missing})
		return
	}
	prev, _ := os.ReadFile(s.globalFile())
	data, _ := json.MarshalIndent(g, "", "  ")
	if err := os.WriteFile(s.globalFile(), data, 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "write", errText(err))
		return
	}
	s.Sites.SetOptions(s.siteOptions())
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	var reloaded bool
	if err := s.Sites.Sync(ctx, s.siteCommit(&reloaded)); err != nil {
		if prev != nil {
			_ = os.WriteFile(s.globalFile(), prev, 0o644)
		} else {
			_ = os.Remove(s.globalFile())
		}
		s.Sites.SetOptions(s.siteOptions())
		s.siteError(w, r, err)
		return
	}
	s.Events.Record(events.Event{Kind: events.KindConfig, Step: "global", OK: true, Summary: "Globale Optionen geändert"})
	writeJSON(w, http.StatusOK, map[string]any{"global": g, "reloaded": reloaded, "caps": s.Sites.Options().Caps})
}

// missingCredentials names the keys a switched-on feature needs but the env
// file lacks. Caddy would refuse the config anyway, only in its own words.
func (s *Server) missingCredentials(g sites.Global) []string {
	env, err := secrets.New(s.Paths.EnvFile).Read()
	if err != nil {
		env = map[string]string{}
	}
	var out []string
	need := func(on bool, key, what string) {
		if on && env[key] == "" {
			out = append(out, what)
		}
	}
	need(g.CrowdSec.Enabled, "CROWDSEC_API_KEY", "CrowdSec: zuerst den Bouncer-API-Key in der CrowdSec-Karte speichern")
	need(g.Tailscale.Enabled, "TS_AUTHKEY", "Tailscale: zuerst den Auth-Key in der Tailscale-Karte speichern")
	if g.DynDNS.Enabled {
		if e, ok := plugins.ByID(g.DynDNS.Provider); ok {
			for _, v := range e.Env {
				need(v.Required, v.Name, "DynDNS: "+e.Name+" braucht noch „"+firstNonEmptyStr(v.Label, v.Name)+"“ – in der Karte des DNS-Anbieters speichern")
			}
		}
	}
	return out
}
