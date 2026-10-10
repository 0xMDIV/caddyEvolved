package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"caddyforge/internal/caddyctl"
	"caddyforge/internal/config"
	"caddyforge/internal/events"
	"caddyforge/internal/plugins"
	"caddyforge/internal/secrets"
	"caddyforge/internal/sites"
)

// caddyWithEnv is a caddy client that sees the credential file, because
// validate provisions DNS modules and some refuse an empty token.
func (s *Server) caddyWithEnv() *caddyctl.Client {
	c := caddyctl.New(s.Paths.CaddyBin, s.Runner)
	if vars, err := secrets.New(s.Paths.EnvFile).Read(); err == nil {
		for k, v := range vars {
			c.Env = append(c.Env, k+"="+v)
		}
	}
	return c
}

// caddyRunning reports whether there is a live caddy to reload.
func (s *Server) caddyRunning(ctx context.Context) bool {
	return caddyctl.NewAdmin(caddyctl.AdminURL(s.stateAdminListen())).Sync(ctx) == nil
}

// commitConfig validates the Caddyfile on disk and reloads a running caddy.
// It reports whether a reload happened.
func (s *Server) commitConfig(ctx context.Context) (out string, reloaded bool, err error) {
	if !s.Caddy.Exists() {
		return "", false, errors.New("keine caddy-Binary installiert")
	}
	s.ensureAccessLog()
	out, err = s.caddyWithEnv().Validate(ctx, s.Paths.Caddyfile, "caddyfile")
	if err != nil {
		return out, false, err
	}
	if !s.caddyRunning(ctx) {
		return out, false, nil
	}
	if s.Systemd.Available(ctx) {
		err = s.Systemd.ReloadOrRestart(ctx, "caddy.service")
	} else {
		err = s.caddyWithEnv().Reload(ctx, s.Paths.Caddyfile)
	}
	if err != nil {
		return out, false, fmt.Errorf("reload: %w", err)
	}
	return out, true, nil
}

// siteCommit adapts commitConfig to the sites transaction and remembers
// whether caddy reloaded.
func (s *Server) siteCommit(reloaded *bool) sites.Commit {
	return func(ctx context.Context) (string, error) {
		out, r, err := s.commitConfig(ctx)
		*reloaded = r
		return out, err
	}
}

// siteError maps the sites package errors onto stable API codes.
func (s *Server) siteError(w http.ResponseWriter, r *http.Request, err error) {
	var verr *sites.ValidationError
	var cerr *sites.ErrInvalid
	switch {
	case errors.As(err, &verr):
		writeErr(w, http.StatusUnprocessableEntity, "invalid_site", "Eingaben prüfen", verr.Problems...)
	case errors.As(err, &cerr):
		writeErr(w, http.StatusUnprocessableEntity, "invalid_config", "caddy lehnt die Konfiguration ab – nichts geändert", outputLines(cerr.Output, cerr.Err)...)
	default:
		s.fail(w, r, err, 0)
	}
}

// outputLines turns caddy's output into what an operator needs to read.
// caddy logs JSON; info lines are noise next to a rejected config, so only
// warnings and errors survive, reduced to their message.
func outputLines(out string, err error) []string {
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(out+"\n"+errText(err)), "\n") {
		l = strings.TrimSpace(l)
		// cmdx prefixes stderr with "exit status 1: "; the JSON follows.
		if i := strings.Index(l, "{\""); i >= 0 {
			var rec struct {
				Level string `json:"level"`
				Msg   string `json:"msg"`
				Error string `json:"error"`
			}
			if json.Unmarshal([]byte(l[i:]), &rec) == nil && rec.Level != "" {
				if rec.Level == "info" || rec.Level == "debug" || strings.Contains(rec.Msg, "not formatted") {
					continue
				}
				msg := rec.Msg
				if rec.Error != "" {
					msg += ": " + rec.Error
				}
				l = rec.Level + ": " + msg
			}
		}
		if l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) > 40 {
		lines = lines[len(lines)-40:]
	}
	return lines
}

type dnsProviderInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Ready    bool   `json:"ready"`
	Detected bool   `json:"detected"`
}

func (s *Server) handleSitesList(w http.ResponseWriter, r *http.Request) {
	list, err := s.Sites.List()
	if err != nil {
		s.fail(w, r, err, 0)
		return
	}
	st, _ := config.LoadState(s.Paths.StateFile)
	var dns []dnsProviderInfo
	for _, p := range s.pluginStates(r.Context(), st) {
		if p.Category != plugins.CatDNS || !p.Detected {
			continue
		}
		dns = append(dns, dnsProviderInfo{ID: p.ID, Name: p.Name, Ready: p.Complete && credentialsSet(p), Detected: p.Detected})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sites": list, "importOk": s.Sites.ImportOK(), "sitesDir": s.Sites.Dir(), "dnsProviders": dns,
	})
}

// credentialsSet is true when every required variable has a value; Complete
// alone only covers plugins marked active.
func credentialsSet(p PluginState) bool {
	for _, v := range p.Env {
		if v.Required && p.CredentialState[v.Name] != "set" {
			return false
		}
	}
	return true
}

func (s *Server) handleSitePreview(w http.ResponseWriter, r *http.Request) {
	var site sites.Site
	if err := decode(r, &site); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	if site.ID == "" {
		site.ID = sites.Slug(strings.Join(site.Domains, " "))
	}
	site.Normalize()
	out := map[string]any{"caddyfile": s.Sites.PreviewFor(site)}
	if err := site.Validate(); err != nil {
		var verr *sites.ValidationError
		if errors.As(err, &verr) {
			out["problems"] = verr.Problems
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSiteCreate(w http.ResponseWriter, r *http.Request) {
	s.upsertSite(w, r, true)
}

func (s *Server) handleSiteUpdate(w http.ResponseWriter, r *http.Request) {
	s.upsertSite(w, r, false)
}

func (s *Server) upsertSite(w http.ResponseWriter, r *http.Request, create bool) {
	var site sites.Site
	if err := decode(r, &site); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	if !create {
		site.ID = r.PathValue("id")
	}
	var reloaded bool
	saved, err := s.Sites.Upsert(r.Context(), site, create, s.siteCommit(&reloaded))
	verb := "geändert"
	if create {
		verb = "angelegt"
	}
	s.recordSite(saved.ID, site.ID, verb, err)
	if err != nil {
		s.siteError(w, r, err)
		return
	}
	status := http.StatusOK
	if create {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"site": saved, "reloaded": reloaded})
}

func (s *Server) handleSiteDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var reloaded bool
	err := s.Sites.Delete(r.Context(), id, s.siteCommit(&reloaded))
	s.recordSite(id, id, "gelöscht", err)
	if err != nil {
		s.siteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "reloaded": reloaded})
}

func (s *Server) handleSiteEnabled(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	var reloaded bool
	site, err := s.Sites.SetEnabled(r.Context(), id, req.Enabled, s.siteCommit(&reloaded))
	verb := "deaktiviert"
	if req.Enabled {
		verb = "aktiviert"
	}
	s.recordSite(id, id, verb, err)
	if err != nil {
		s.siteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"site": site, "reloaded": reloaded})
}

func (s *Server) recordSite(id, fallback, verb string, err error) {
	if id == "" {
		id = fallback
	}
	s.Events.Record(events.Event{
		Kind: events.KindProxy, Step: "site", OK: err == nil,
		Summary: fmt.Sprintf("Site %s %s", id, verb), Error: errText(err),
		Meta: map[string]any{"site": id},
	})
}

// --- Caddyfile expert mode ---------------------------------------------------

func (s *Server) handleCaddyfileGet(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.Paths.Caddyfile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		s.fail(w, r, err, 0)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path": s.Paths.Caddyfile, "content": string(data), "sitesDir": s.Sites.Dir(),
		"importOk": sites.HasImport(string(data), s.Sites.ImportLine()), "importLine": s.Sites.ImportLine(),
	})
}

type contentRequest struct {
	Content string `json:"content"`
}

// validateContent checks text as if it were the Caddyfile. The probe file
// sits next to the real one so relative imports resolve the same way.
func (s *Server) validateContent(ctx context.Context, content string) (string, error) {
	if !s.Caddy.Exists() {
		return "", errors.New("keine caddy-Binary installiert")
	}
	probe := filepath.Join(filepath.Dir(s.Paths.Caddyfile), ".Caddyfile.caddyforge-check")
	if err := os.WriteFile(probe, []byte(content), 0o600); err != nil {
		return "", err
	}
	defer os.Remove(probe)
	return s.caddyWithEnv().Validate(ctx, probe, "caddyfile")
}

func (s *Server) handleCaddyfileValidate(w http.ResponseWriter, r *http.Request) {
	var req contentRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	out, err := s.validateContent(r.Context(), req.Content)
	writeJSON(w, http.StatusOK, map[string]any{"ok": err == nil, "output": strings.TrimSpace(strings.Join(outputLines(out, err), "\n"))})
}

func (s *Server) handleCaddyfileFmt(w http.ResponseWriter, r *http.Request) {
	var req contentRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	out, err := s.Caddy.Fmt(r.Context(), []byte(req.Content))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "fmt_failed", "caddy fmt fehlgeschlagen", outputLines("", err)...)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"content": string(out)})
}

// handleCaddyfileSave validates first, then swaps the file and reloads; a
// failed reload puts the previous file back.
func (s *Server) handleCaddyfileSave(w http.ResponseWriter, r *http.Request) {
	var req contentRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	ctx := r.Context()
	content := strings.ReplaceAll(req.Content, "\r\n", "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if out, err := s.validateContent(ctx, content); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "invalid_config", "caddy lehnt die Konfiguration ab – nichts gespeichert", outputLines(out, err)...)
		return
	}
	before, readErr := os.ReadFile(s.Paths.Caddyfile)
	if readErr == nil {
		backup := s.Paths.Caddyfile + ".caddyforge-prev"
		os.WriteFile(backup, before, 0o644)
	}
	tmp := s.Paths.Caddyfile + ".caddyforge-new"
	// Explicit chmod: the daemon's UMask=0077 would leave caddy unable to read.
	err := os.WriteFile(tmp, []byte(content), 0o644)
	if err == nil {
		err = os.Chmod(tmp, 0o644)
	}
	if err != nil {
		s.fail(w, r, err, 0)
		return
	}
	if err := os.Rename(tmp, s.Paths.Caddyfile); err != nil {
		s.fail(w, r, err, 0)
		return
	}
	out, reloaded, err := s.commitConfig(ctx)
	if err != nil {
		if readErr == nil {
			os.WriteFile(s.Paths.Caddyfile, before, 0o644)
			os.Chmod(s.Paths.Caddyfile, 0o644)
		}
		s.Events.Record(events.Event{Kind: events.KindConfig, Step: "caddyfile", OK: false, Summary: "Caddyfile nicht übernommen", Error: errText(err)})
		writeErr(w, http.StatusUnprocessableEntity, "invalid_config", "Reload fehlgeschlagen – vorheriges Caddyfile wiederhergestellt", outputLines(out, err)...)
		return
	}
	s.Events.Record(events.Event{Kind: events.KindConfig, Step: "caddyfile", OK: true, Summary: "Caddyfile gespeichert", Meta: map[string]any{"reloaded": reloaded}})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": strings.TrimSpace(out), "reloaded": reloaded, "savedAt": time.Now().UTC()})
}
