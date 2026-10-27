package api

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"caddyevolved/internal/cloudflare"
	"caddyevolved/internal/events"
	"caddyevolved/internal/probe"
	"caddyevolved/internal/secrets"
	"caddyevolved/internal/sites"
)

// Sites with the Cloudflare switch get their DNS record created on save.
// The token is either its own (settings card) or the one the Cloudflare DNS
// plugin already has in the env file.

func (s *Server) cloudflareFile() string { return filepath.Join(s.Paths.Etc, "cloudflare.json") }

// cloudflareConfig returns the stored settings and where the token comes
// from: "own", "plugin" or "" when there is none.
func (s *Server) cloudflareConfig() (cloudflare.Config, string) {
	c, _ := cloudflare.LoadConfig(s.cloudflareFile())
	if c.APIToken != "" {
		return c, "own"
	}
	if vars, err := secrets.New(s.Paths.EnvFile).Read(); err == nil && vars["CF_API_TOKEN"] != "" {
		c.APIToken, c.Email = vars["CF_API_TOKEN"], ""
		return c, "plugin"
	}
	return c, ""
}

func (s *Server) cloudflareClient(c cloudflare.Config) *cloudflare.Client {
	return cloudflare.New(c, s.cloudflareAPI)
}

func (s *Server) handleCloudflareGet(w http.ResponseWriter, r *http.Request) {
	stored, _ := cloudflare.LoadConfig(s.cloudflareFile())
	_, source := s.cloudflareConfig()
	out := stored.Public()
	out["source"] = source
	out["configured"] = source != ""
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCloudflareSave(w http.ResponseWriter, r *http.Request) {
	var in cloudflare.Config
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	in.Target = strings.TrimSpace(in.Target)
	in.Email = strings.TrimSpace(in.Email)
	in.APIToken = strings.TrimSpace(in.APIToken)
	// The UI never sees the token, so empty keeps it.
	if old, _ := cloudflare.LoadConfig(s.cloudflareFile()); in.APIToken == "" {
		in.APIToken = old.APIToken
	}
	if err := in.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_settings", errText(err))
		return
	}
	if err := cloudflare.SaveConfig(s.cloudflareFile(), in); err != nil {
		writeErr(w, http.StatusInternalServerError, "write", errText(err))
		return
	}
	s.handleCloudflareGet(w, r)
}

// handleCloudflareForget drops the own token; the plugin's stays untouched.
func (s *Server) handleCloudflareForget(w http.ResponseWriter, r *http.Request) {
	c, _ := cloudflare.LoadConfig(s.cloudflareFile())
	c.APIToken, c.Email = "", ""
	if err := cloudflare.SaveConfig(s.cloudflareFile(), c); err != nil {
		writeErr(w, http.StatusInternalServerError, "write", errText(err))
		return
	}
	s.handleCloudflareGet(w, r)
}

// handleCloudflareTest lists the zones the token sees and what new records
// would point at.
func (s *Server) handleCloudflareTest(w http.ResponseWriter, r *http.Request) {
	c, source := s.cloudflareConfig()
	if source == "" {
		writeErr(w, http.StatusBadRequest, "cf_unconfigured", "Erst einen API-Token speichern")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	zones, err := s.cloudflareClient(c).Zones(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "cf_failed", errText(err))
		return
	}
	names := make([]string, 0, len(zones))
	for _, z := range zones {
		names = append(names, z.Name)
	}
	target, terr := s.cloudflareTarget(ctx, c)
	writeJSON(w, http.StatusOK, map[string]any{
		"zones": names, "target": target, "type": cloudflare.RecordType(target), "targetError": errText(terr),
	})
}

// cloudflareTarget is the configured target or this host's public IPv4.
func (s *Server) cloudflareTarget(ctx context.Context, c cloudflare.Config) (string, error) {
	if c.Target != "" {
		return c.Target, nil
	}
	if s.publicIP != nil {
		return s.publicIP(ctx)
	}
	return probe.PublicIP(ctx)
}

// syncCloudflare creates the site's missing records. It never fails the
// save: the site is live either way, the result tells what DNS did.
func (s *Server) syncCloudflare(ctx context.Context, site sites.Site) []cloudflare.Result {
	if site.Cloudflare == nil || !site.Enabled || len(site.Domains) == 0 {
		return nil
	}
	c, source := s.cloudflareConfig()
	if source == "" {
		return []cloudflare.Result{{Action: "error", Message: "Kein Cloudflare-API-Token eingerichtet (Einstellungen → Cloudflare)"}}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
	defer cancel()
	target, err := s.cloudflareTarget(ctx, c)
	if err != nil {
		target = ""
	}
	res := s.cloudflareClient(c).Ensure(ctx, site.Domains, target, site.Cloudflare.Proxied)
	var changed, failed []string
	for _, r := range res {
		switch r.Action {
		case "created", "updated":
			changed = append(changed, fmt.Sprintf("%s %s → %s", r.Name, r.Type, r.Content))
		case "error":
			failed = append(failed, r.Name+": "+r.Message)
		}
	}
	if len(changed) > 0 || len(failed) > 0 {
		s.Events.Record(events.Event{
			Kind: events.KindProxy, Step: "cloudflare", OK: len(failed) == 0,
			Summary: fmt.Sprintf("Cloudflare-DNS für %s: %d geändert, %d Fehler", site.ID, len(changed), len(failed)),
			Error:   strings.Join(failed, "; "), Meta: map[string]any{"site": site.ID, "records": changed},
		})
	}
	return res
}
