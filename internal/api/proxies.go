package api

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"caddyevolved/internal/blocklists"
	"caddyevolved/internal/sites"
)

// proxyState is one trusted-proxy provider as the settings card shows it.
type proxyState struct {
	ID      string    `json:"id"`
	Label   string    `json:"label"`
	Ranges  int       `json:"ranges"`
	Builtin bool      `json:"builtin"` // no download yet, the built-in list is used
	Updated time.Time `json:"updated,omitzero"`
}

func (s *Server) proxyDir() string { return filepath.Join(s.Paths.StateDir, "firewall") }

func (s *Server) proxyInfo() []proxyState {
	out := make([]proxyState, 0, len(blocklists.ProxyProviders))
	for _, p := range blocklists.ProxyProviders {
		st := proxyState{ID: p.ID, Label: p.Label, Ranges: len(blocklists.ProxyRanges(s.proxyDir(), p.ID))}
		if fi, err := os.Stat(filepath.Join(s.proxyDir(), "proxy-"+p.ID+".txt")); err == nil {
			st.Updated = fi.ModTime()
		} else {
			st.Builtin = len(p.Builtin) > 0
		}
		out = append(out, st)
	}
	return out
}

// proxyRanges are the ranges of the switched-on providers for rendering.
func (s *Server) proxyRanges(g sites.Global) map[string][]string {
	out := map[string][]string{}
	for _, p := range blocklists.ProxyProviders {
		if g.RealIP.Has(p.ID) {
			out[p.ID] = blocklists.ProxyRanges(s.proxyDir(), p.ID)
		}
	}
	return out
}

// proxyExempt lists every trusted provider range: they must never be
// auto-banned, a proxy address stands for many visitors.
func (s *Server) proxyExempt(g sites.Global) []string {
	var out []string
	for _, r := range s.proxyRanges(g) {
		out = append(out, r...)
	}
	return out
}

// ensureProxyRanges downloads the lists of the switched-on providers; with
// force=false only those never downloaded. A provider left without any range
// is an error, otherwise its setting would silently do nothing.
func (s *Server) ensureProxyRanges(ctx context.Context, g sites.Global, force bool) error {
	var errs []error
	for _, p := range blocklists.ProxyProviders {
		if !g.RealIP.Has(p.ID) {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.proxyDir(), "proxy-"+p.ID+".txt")); err == nil && !force {
			continue
		}
		if _, err := blocklists.UpdateProxy(ctx, s.proxyDir(), p.ID); err != nil && len(blocklists.ProxyRanges(s.proxyDir(), p.ID)) == 0 {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
