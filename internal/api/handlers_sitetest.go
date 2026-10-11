package api

import (
	"context"
	"net/http"
	"time"

	"caddyevolved/internal/certs"
	"caddyevolved/internal/config"
	"caddyevolved/internal/platform"
	"caddyevolved/internal/probe"
)

// probeEnv collects what a site test needs: ports from the state file, the
// public IP, caddy's certificates and recent ACME errors.
func (s *Server) probeEnv(ctx context.Context, extern bool) probe.Env {
	st, _ := config.LoadState(s.Paths.StateFile)
	env := probe.Env{HTTPPort: st.HTTPPort, HTTPSPort: st.HTTPSPort, LANIP: platform.PrimaryIP(), Extern: extern}
	if env.HTTPPort == 0 {
		env.HTTPPort = 80
	}
	if env.HTTPSPort == 0 {
		env.HTTPSPort = 443
	}
	env.PublicIP, _ = probe.PublicIP(ctx)
	env.Certs, _ = certs.List(s.Paths.CaddyStorage)
	env.ACMEErrors = probe.RecentACMEErrors(ctx)
	return env
}

// handleSiteTest calls one site the way a visitor would. extern=true adds
// checks from the internet through check-host.net.
func (s *Server) handleSiteTest(w http.ResponseWriter, r *http.Request) {
	site, err := s.Sites.Get(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", errText(err))
		return
	}
	var req struct {
		Extern bool `json:"extern"`
	}
	if r.ContentLength > 0 {
		if err := decode(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	env := s.probeEnv(ctx, req.Extern)
	findings := probe.Site(ctx, site, env)
	fails, warns := 0, 0
	for _, f := range findings {
		switch f.Level {
		case probe.Fail:
			fails++
		case probe.Warn:
			warns++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"findings": findings, "failures": fails, "warnings": warns,
		"publicIp": env.PublicIP, "lanIp": env.LANIP, "extern": req.Extern, "testedAt": time.Now().UTC(),
	})
}

// handleSiteCertificate shows, per domain, the certificate caddy stored and
// the chain it actually presents.
func (s *Server) handleSiteCertificate(w http.ResponseWriter, r *http.Request) {
	site, err := s.Sites.Get(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", errText(err))
		return
	}
	st, _ := config.LoadState(s.Paths.StateFile)
	port := st.HTTPSPort
	if port == 0 {
		port = 443
	}
	stored, _ := certs.List(s.Paths.CaddyStorage)
	type domainCert struct {
		Domain    string           `json:"domain"`
		Stored    *certs.Cert      `json:"stored,omitempty"`
		Chain     []probe.CertInfo `json:"chain,omitempty"`
		Trusted   bool             `json:"trusted"`
		VerifyErr string           `json:"verifyError,omitempty"`
		Error     string           `json:"error,omitempty"`
	}
	var out []domainCert
	for _, dom := range site.Domains {
		host, ok := probe.Host(dom)
		if !ok {
			continue
		}
		dc := domainCert{Domain: host}
		if c, found := probe.CoveringCert(stored, host); found {
			dc.Stored = &c
		}
		if site.TLS != "off" {
			chain, trusted, verr, err := probe.Presented(r.Context(), host, port)
			dc.Chain, dc.Trusted, dc.VerifyErr = chain, trusted, verr
			if err != nil {
				dc.Error = err.Error()
			}
		}
		out = append(out, dc)
	}
	writeJSON(w, http.StatusOK, map[string]any{"site": site.ID, "tls": site.TLS, "domains": out})
}
