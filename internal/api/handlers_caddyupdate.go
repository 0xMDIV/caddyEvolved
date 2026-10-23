package api

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"caddyevolved/internal/builder"
	"caddyevolved/internal/config"
	"caddyevolved/internal/plugins"
)

// moduleLatestCache keeps proxy answers for a while: the update card and the
// sidebar ask on every page load, one request per compiled-in plugin.
type moduleLatestCache struct {
	mu      sync.Mutex
	entries map[string]moduleLatest
}

type moduleLatest struct {
	version string
	err     string
	at      time.Time
}

const moduleLatestTTL = 30 * time.Minute

// PluginVersion compares one compiled-in plugin with what a rebuild would get.
type PluginVersion struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Module    string `json:"module"`
	Installed string `json:"installed,omitempty"`
	Latest    string `json:"latest,omitempty"`
	Available bool   `json:"available"`
	// Pinned plugins carry an @version and stay on it in every rebuild.
	Pinned bool   `json:"pinned,omitempty"`
	Error  string `json:"error,omitempty"`
}

// CaddyUpdateInfo is the state behind the "Caddy & Plugins" update card.
type CaddyUpdateInfo struct {
	Installed      string          `json:"installed,omitempty"`
	Latest         string          `json:"latest,omitempty"`
	Available      bool            `json:"available"`
	Plugins        []PluginVersion `json:"plugins"`
	PluginUpdates  int             `json:"pluginUpdates"`
	CanBuild       bool            `json:"canBuild"`
	RunningBuildID string          `json:"runningBuildId,omitempty"`
	Error          string          `json:"error,omitempty"`
}

// handleCaddyUpdateCheck compares the installed caddy and its plugins with
// the newest releases. ?refresh=1 asks the module proxy again.
func (s *Server) handleCaddyUpdateCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.caddyUpdateInfo(r.Context(), r.URL.Query().Get("refresh") == "1"))
}

func (s *Server) caddyUpdateInfo(ctx context.Context, refresh bool) CaddyUpdateInfo {
	info := CaddyUpdateInfo{Plugins: []PluginVersion{}, CanBuild: s.Builder != nil}
	if s.Builder != nil {
		info.RunningBuildID = s.Builder.Running()
	}
	if v, err := s.Caddy.Version(ctx); err == nil {
		info.Installed = v
	}
	recent, err := s.recentVersions(ctx)
	if len(recent) > 0 {
		info.Latest = strings.TrimPrefix(recent[0], "v")
		if info.Installed != "" {
			c, ok := plugins.CompareVersions("v"+info.Latest, "v"+info.Installed)
			info.Available = ok && c > 0
		}
	} else if err != nil {
		info.Error = "GitHub nicht erreichbar: " + errText(err)
	}

	mods := s.installedModules(ctx)
	ids := s.pluginsInBinary(ctx)
	pv := make([]PluginVersion, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		path, pin, pinned := strings.Cut(id, "@")
		p := PluginVersion{ID: id, Name: path, Module: path, Pinned: pinned}
		if e, ok := plugins.ByID(path); ok {
			p.Name, p.Module = e.Name, e.Module
		}
		for _, m := range mods {
			if builder.HasPackage([]builder.Module{m}, p.Module) && m.Version != "" {
				p.Installed = m.Version
				break
			}
		}
		if pinned {
			p.Latest = pin
			pv[i] = p
			continue
		}
		wg.Add(1)
		go func(i int, p PluginVersion) {
			defer wg.Done()
			p.Latest, p.Error = s.moduleLatest(ctx, p.Module, refresh)
			if c, ok := plugins.CompareVersions(p.Latest, p.Installed); ok && c > 0 {
				p.Available = true
			}
			pv[i] = p
		}(i, p)
	}
	wg.Wait()
	for _, p := range pv {
		if p.Available {
			info.PluginUpdates++
		}
	}
	sort.SliceStable(pv, func(i, j int) bool { return strings.ToLower(pv[i].Name) < strings.ToLower(pv[j].Name) })
	info.Plugins = pv
	return info
}

func (s *Server) moduleLatest(ctx context.Context, path string, refresh bool) (string, string) {
	c := &s.latestMods
	c.mu.Lock()
	e, ok := c.entries[path]
	c.mu.Unlock()
	if ok && !refresh && time.Since(e.at) < moduleLatestTTL {
		return e.version, e.err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	v, err := plugins.LatestVersion(ctx, path)
	e = moduleLatest{version: v, at: time.Now()}
	if err != nil {
		e.err = errText(err)
	}
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]moduleLatest{}
	}
	c.entries[path] = e
	c.mu.Unlock()
	return e.version, e.err
}

// pluginsInBinary is the plugin list a rebuild must keep: what the active
// build (or the installer) selected, plus every catalog module the binary
// actually contains, so nothing silently drops out on an update.
func (s *Server) pluginsInBinary(ctx context.Context) []string {
	var ids []string
	seen := map[string]bool{}
	add := func(id string) {
		key, _, _ := strings.Cut(id, "@")
		if e, ok := plugins.ByID(key); ok {
			key = e.ID
		}
		if id == "" || seen[key] {
			return
		}
		seen[key] = true
		ids = append(ids, id)
	}
	if s.Builder != nil {
		if id := s.Builder.ActiveID(); id != "" {
			if b, _, err := s.Builder.Get(id); err == nil {
				for _, p := range b.Plugins {
					add(p)
				}
			}
		}
	}
	if st, err := config.LoadState(s.Paths.StateFile); err == nil {
		for _, p := range st.Enabled {
			add(p)
		}
	}
	mods := s.installedModules(ctx)
	for _, e := range plugins.All() {
		if builder.HasPackage(mods, e.Module) {
			add(e.ID)
		}
	}
	// Selections from a vanilla binary may name plugins that were never
	// compiled in; keep only what the binary really has.
	out := ids[:0]
	for _, id := range ids {
		path, _, _ := strings.Cut(id, "@")
		if e, ok := plugins.ByID(path); ok {
			path = e.Module
		}
		if builder.HasPackage(mods, path) {
			out = append(out, id)
		}
	}
	return out
}

// handleCaddyUpdateApply rebuilds caddy with the newest (or a given) version
// and the current plugins at their newest versions, and activates the result
// with the builder's health check and automatic rollback.
func (s *Server) handleCaddyUpdateApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CaddyVersion string `json:"caddyVersion"`
	}
	if r.ContentLength > 0 {
		if err := decode(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
			return
		}
	}
	ids := s.pluginsInBinary(r.Context())
	b, notes, err := s.startBuild(r.Context(), req.CaddyVersion, ids, true)
	if err != nil {
		s.failBuildStart(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"build": b, "notes": notes})
}
