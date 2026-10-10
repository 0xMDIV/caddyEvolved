// Package api serves the WebUI: JSON over HTTP plus SSE streams.
//
// The daemon binds 0.0.0.0 by default, so every route except login and the
// version probe is behind a session, and every mutation is behind the
// custom-header check that a cross-site form post cannot set.
package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"caddyforge/internal/auth"
	"caddyforge/internal/caddyctl"
	"caddyforge/internal/cmdx"
	"caddyforge/internal/config"
	"caddyforge/internal/events"
	"caddyforge/internal/forge"
	"caddyforge/internal/supervisor"
	"caddyforge/internal/systemd"
	"caddyforge/internal/webui"
)

// Server holds the daemon's dependencies.
type Server struct {
	Paths    config.Paths
	Runner   cmdx.Runner
	Auth     *auth.Store
	Events   *events.Log
	Systemd  *systemd.Service
	Sup      *supervisor.Manager
	Caddy    *caddyctl.Client
	Forge    *forge.Client
	Bind     string
	Port     int
	Insecure bool

	runs *runs

	mux *http.ServeMux
	srv *http.Server
}

// New wires routes. The caller supplies an already-loaded store and log.
func New(s *Server) *Server {
	if s.Runner == nil {
		s.Runner = cmdx.ExecRunner{}
	}
	if s.Bind == "" {
		s.Bind = "0.0.0.0"
	}
	if s.Port == 0 {
		s.Port = 8484
	}
	if s.Caddy == nil {
		s.Caddy = caddyctl.New(s.Paths.CaddyBin, s.Runner)
	}
	if s.Sup == nil {
		s.Sup = supervisor.New(s.Paths.CaddyBin, s.Paths.Caddyfile, s.Paths.EnvFile, s.Paths.LogFile, s.Paths.PIDFile)
	}
	if s.Systemd == nil {
		s.Systemd = systemd.New(s.Runner, s.Paths.UnitsDir)
	}
	if s.Forge == nil {
		s.Forge = forge.New()
	}
	if s.runs == nil {
		s.runs = newRuns()
	}
	s.mux = s.routes()
	return s
}

// Handler exposes the router for tests and for embedding behind caddy.
func (s *Server) Handler() http.Handler { return s.middleware(s.mux) }

// ListenAndServe starts the UI. A routable bind without --insecure-dev gets
// TLS with a self-signed certificate, because login over plaintext HTTP on a
// LAN is credential leakage we should refuse rather than warn about.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr := net.JoinHostPort(s.Bind, fmt.Sprint(s.Port))
	s.srv = &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}

	if !s.Insecure && routable(s.Bind) {
		certPEM, keyPEM, err := s.ensureCert()
		if err != nil {
			return err
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("TLS-Schlüssel: %w", err)
		}
		s.srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		fmt.Fprintf(os.Stderr, "caddyforge: https://%s  (selbstsigniertes Zertifikat, Datei %s)\n", addr, s.certFile())
		if err := s.srv.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	if err := s.srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

// routes maps every endpoint. Go 1.22 method+pattern matching keeps this flat.
func (s *Server) routes() *http.ServeMux {
	m := http.NewServeMux()

	m.HandleFunc("GET /api/version", s.handleVersion)
	m.HandleFunc("POST /api/login", s.handleLogin)

	m.HandleFunc("GET /api/status", s.auth(s.handleStatus))
	m.HandleFunc("GET /api/state", s.auth(s.handleState))
	m.HandleFunc("POST /api/state/apply", s.auth(s.handleApplyState))

	m.HandleFunc("GET /api/plugins", s.auth(s.handlePlugins))
	m.HandleFunc("GET /api/plugins/detect", s.auth(s.handlePluginDetect))
	m.HandleFunc("POST /api/plugins/check", s.auth(s.handlePluginCheck))
	m.HandleFunc("POST /api/plugins/credentials", s.auth(s.handlePluginCredentials))

	m.HandleFunc("GET /api/install/plan", s.auth(s.handleInstallPlan))
	m.HandleFunc("POST /api/install/apply", s.auth(s.handleInstallApply))
	m.HandleFunc("GET /api/install/runs", s.auth(s.handleRuns))
	m.HandleFunc("POST /api/install/abort", s.auth(s.handleRunAbort))

	m.HandleFunc("GET /api/events", s.auth(s.handleEvents))
	m.HandleFunc("GET /api/events/stream", s.auth(s.handleEventStream))
	m.HandleFunc("GET /api/logs", s.auth(s.handleLogs))

	m.HandleFunc("POST /api/service/{action}", s.auth(s.handleService))

	m.HandleFunc("POST /api/logout", s.auth(s.handleLogout))
	m.HandleFunc("GET /api/session", s.auth(s.handleSession))
	m.HandleFunc("POST /api/password", s.auth(s.handleChangePassword))
	m.HandleFunc("GET /api/host", s.auth(s.handleHostStatus))
	m.HandleFunc("POST /api/cert", s.auth(s.handleCert))

	// Everything else is the SPA.
	m.Handle("/", webui.Handler())
	return m
}
