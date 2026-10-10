package api

import (
	"context"
	"net/http"
	"strings"

	"caddyevolved/internal/builder"
	"caddyevolved/internal/config"
	"caddyevolved/internal/plugins"
	"caddyevolved/internal/secrets"
)

// PluginState is one catalog entry plus what we know about this host.
type PluginState struct {
	plugins.Entry
	// Detected means the module is compiled into the installed binary.
	Detected bool `json:"detected"`
	// Active means the operator selected it in the last install.
	Active bool `json:"active"`
	// CredentialState maps env var names to "set" | "missing" | "optional".
	CredentialState map[string]string `json:"credentialState,omitempty"`
	// Complete is false when an active module misses a required credential.
	Complete bool `json:"complete"`
}

// handlePlugins lists the catalog with host-specific state.
func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st, _ := config.LoadState(s.Paths.StateFile)
	writeJSON(w, http.StatusOK, map[string]any{
		"variant":      st.Variant,
		"binarySource": st.BinarySource,
		"plugins":      s.pluginStates(ctx, st),
		"categories":   []string{"dns", "auth", "storage", "infra", "observability", "unclassified"},
		"caddyVersion": st.CaddyVersion,
	})
}

// pluginStates merges catalog, binary and env file into one view.
func (s *Server) pluginStates(ctx context.Context, st config.State) []PluginState {
	env, err := secrets.New(s.Paths.EnvFile).Read()
	if err != nil {
		env = map[string]string{}
	}
	detected := s.detectedModules(ctx)
	mods := s.installedModules(ctx)
	selected := map[string]bool{}
	for _, id := range st.Enabled {
		selected[id] = true
	}

	out := make([]PluginState, 0, len(plugins.All()))
	for _, e := range plugins.All() {
		// The go module path is the reliable signal; the name map only
		// helps for free-form caddy-dns providers.
		ps := PluginState{Entry: e, Detected: builder.HasPackage(mods, e.Module) || detected[e.Module], Active: selected[e.ID]}
		if len(e.Env) == 0 {
			ps.Complete = true
			out = append(out, ps)
			continue
		}
		ps.CredentialState = map[string]string{}
		ps.Complete = true
		for _, v := range e.Env {
			switch {
			case env[v.Name] != "":
				ps.CredentialState[v.Name] = "set"
			case v.Required:
				ps.CredentialState[v.Name] = "missing"
				if ps.Active {
					ps.Complete = false
				}
			default:
				ps.CredentialState[v.Name] = "optional"
			}
		}
		out = append(out, ps)
	}
	return out
}

// detectedModules asks the installed binary what it actually contains. A
// missing binary is not an error here: the dashboard shows "not installed".
func (s *Server) detectedModules(ctx context.Context) map[string]bool {
	out := map[string]bool{}
	names, err := s.Caddy.ModuleNames(ctx, false)
	if err != nil {
		return out
	}
	for _, n := range names {
		out[n] = true
		if rest, ok := strings.CutPrefix(n, "dns.providers."); ok {
			out["github.com/caddy-dns/"+rest] = true
			out[rest] = true
		}
	}
	return out
}

// handlePluginDetect re-reads the binary and returns detected provider names.
func (s *Server) handlePluginDetect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	names, err := s.Caddy.ModuleNames(ctx, false)
	if err != nil {
		s.fail(w, r, err, http.StatusServiceUnavailable)
		return
	}
	known := map[string]bool{}
	for _, e := range plugins.All() {
		for _, n := range names {
			if n == e.Module || strings.HasSuffix(n, "."+e.ID) {
				known[e.ID] = true
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"modules":  names,
		"catalog":  known,
		"count":    len(names),
		"binary":   s.Paths.CaddyBin,
		"detected": len(known),
	})
}

// handlePluginCheck validates a free-form go module path against the proxy.
func (s *Server) handlePluginCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Module string `json:"module"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	res, err := plugins.ValidateModule(r.Context(), req.Module)
	if err != nil {
		writeErr(w, http.StatusOK, "invalid", errText(err), res.Hint)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handlePluginCredentials updates single env keys without accepting a whole
// file: there must be no API surface that can drop a line like PATH=…/malicious.
func (s *Server) handlePluginCredentials(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Set   map[string]string `json:"set,omitempty"`
		Unset []string          `json:"unset,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	if err := s.credentialsAllowed(req.Set, req.Unset); err != nil {
		writeErr(w, http.StatusBadRequest, "unknown_key", errText(err))
		return
	}
	before, err := secrets.New(s.Paths.EnvFile).Read()
	if err != nil {
		s.fail(w, r, err, 0)
		return
	}
	want := map[string]string{}
	for k, v := range before {
		want[k] = v
	}
	for k, v := range req.Set {
		if v == "" {
			delete(want, k)
			continue
		}
		want[k] = v
	}
	for _, k := range req.Unset {
		delete(want, k)
	}
	changes, err := secrets.New(s.Paths.EnvFile).Apply(secrets.Apply{
		Wanted: want,
		Header: "Verwaltet von caddyEvolved – Zugangsdaten für Caddy-Module.",
	})
	if err != nil {
		s.fail(w, r, err, 0)
		return
	}
	var names []string
	for _, c := range changes {
		if c.Kind != "unchanged" {
			names = append(names, c.Key+":"+c.Kind)
		}
	}
	recordCredentialEvent(s.Events, names)
	writeJSON(w, http.StatusOK, map[string]any{"changed": names, "reloadRecommended": len(names) > 0})
}
