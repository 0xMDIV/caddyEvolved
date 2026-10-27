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
	"path/filepath"
	"time"

	"caddyevolved/internal/ai"
	"caddyevolved/internal/aiaudit"
	"caddyevolved/internal/analytics"
	"caddyevolved/internal/auth"
	"caddyevolved/internal/autoban"
	"caddyevolved/internal/builder"
	"caddyevolved/internal/caddyctl"
	"caddyevolved/internal/cmdx"
	"caddyevolved/internal/config"
	"caddyevolved/internal/events"
	"caddyevolved/internal/geo"
	"caddyevolved/internal/sites"
	"caddyevolved/internal/supervisor"
	"caddyevolved/internal/sysstat"
	"caddyevolved/internal/systemd"
	"caddyevolved/internal/webui"
)

// Server holds the daemon's dependencies.
type Server struct {
	Paths   config.Paths
	Runner  cmdx.Runner
	Auth    *auth.Store
	Events  *events.Log
	Systemd *systemd.Service
	Sup     *supervisor.Manager
	Caddy   *caddyctl.Client
	Builder *builder.Manager
	Sites   *sites.Manager
	// Analytics is nil when request statistics are off (tests).
	Analytics *analytics.Store
	// Bans is the auto-ban; nil (tests) disables it.
	Bans *autoban.Store
	Geo  *geo.Resolver
	// AIAudit is the append-only protocol of the AI chat.
	AIAudit *aiaudit.Log
	// AIChats keeps the conversations of the AI chat.
	AIChats *ai.Store

	aiProvider func(ai.Config) (ai.Provider, error) // tests swap the model
	// Tests point Cloudflare at a fake and skip the public IP lookup.
	cloudflareAPI string
	publicIP      func(context.Context) (string, error)
	// Sys samples host and process load; nil disables the system page.
	Sys      *sysstat.Sampler
	Bind     string
	Port     int
	Insecure bool

	runs       *runs
	versions   versionCache
	modules    moduleCache
	update     updateState
	latestMods moduleLatestCache

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
	if s.Sites == nil {
		s.Sites = sites.New(s.Paths.SitesFile, s.Paths.SitesDir, s.Paths.Caddyfile)
	}
	if s.Builder == nil {
		b, err := builder.New(builder.Config{
			Dir: s.Paths.StateDir, CaddyBin: s.Paths.CaddyBin,
			Caddyfile: s.Paths.Caddyfile, EnvFile: s.Paths.EnvFile,
		})
		if err != nil {
			// Builds are unavailable, everything else still works; the
			// handlers answer 503 instead of the daemon refusing to start.
			fmt.Fprintf(os.Stderr, "caddyevolved: Builder nicht verfügbar: %v\n", err)
		}
		s.Builder = b
	}
	if s.Sys == nil {
		s.Sys = sysstat.New(720, nil) // one hour at 5 s
	}
	if s.AIAudit == nil && s.Paths.StateDir != "" {
		if l, err := aiaudit.Open(s.Paths.StateDir); err == nil {
			s.AIAudit = l
		} else {
			fmt.Fprintf(os.Stderr, "caddyevolved: KI-Protokoll: %v\n", err)
		}
	}
	if s.AIChats == nil {
		s.AIChats = ai.NewStore(filepath.Join(s.Paths.StateDir, "ai-chats"), time.Now())
	}
	if s.Geo == nil {
		s.Geo = s.newGeo()
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
		fmt.Fprintf(os.Stderr, "caddyevolved: https://%s  (selbstsigniertes Zertifikat, Datei %s)\n", addr, s.certFile())
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
	m.HandleFunc("GET /api/logs/access", s.auth(s.handleAccessLog))
	m.HandleFunc("GET /api/logging", s.auth(s.handleLoggingGet))
	m.HandleFunc("GET /api/system", s.auth(s.handleSystem))

	m.HandleFunc("GET /api/tools", s.auth(s.handleToolsInfo))
	m.HandleFunc("GET /api/tools/cidr", s.auth(s.handleToolCIDR))
	m.HandleFunc("GET /api/tools/dns", s.auth(s.handleToolDNS))
	m.HandleFunc("POST /api/tools/ping", s.auth(s.handleToolPing))
	m.HandleFunc("POST /api/tools/traceroute", s.auth(s.handleToolTraceroute))
	m.HandleFunc("POST /api/tools/ports", s.auth(s.handleToolPorts))
	m.HandleFunc("POST /api/tools/hosts", s.auth(s.handleToolHosts))
	m.HandleFunc("POST /api/tools/mdns", s.auth(s.handleToolMDNS))
	m.HandleFunc("PUT /api/logging", s.auth(s.handleLoggingSave))
	m.HandleFunc("GET /api/protect", s.auth(s.handleProtectGet))
	m.HandleFunc("GET /api/protect/check", s.auth(s.handleProtectCheck))
	m.HandleFunc("PUT /api/protect", s.auth(s.handleProtectSave))
	m.HandleFunc("GET /api/global", s.auth(s.handleGlobalGet))
	m.HandleFunc("PUT /api/global", s.auth(s.handleGlobalSave))
	m.HandleFunc("GET /api/firewall", s.auth(s.handleFirewallGet))
	m.HandleFunc("PUT /api/firewall", s.auth(s.handleFirewallSave))
	m.HandleFunc("POST /api/firewall/quick", s.auth(s.handleFirewallQuick))
	m.HandleFunc("POST /api/firewall/refresh", s.auth(s.handleFirewallRefresh))
	m.HandleFunc("POST /api/firewall/lists/test", s.auth(s.handleFirewallListTest))
	m.HandleFunc("GET /api/firewall/log", s.auth(s.handleFirewallLog))
	m.HandleFunc("POST /api/firewall/bans/clear", s.auth(s.handleAutobanClear))

	m.HandleFunc("POST /api/service/{action}", s.auth(s.handleService))

	m.HandleFunc("POST /api/logout", s.auth(s.handleLogout))
	m.HandleFunc("GET /api/session", s.auth(s.handleSession))
	m.HandleFunc("POST /api/password", s.auth(s.handleChangePassword))
	m.HandleFunc("GET /api/host", s.auth(s.handleHostStatus))
	m.HandleFunc("POST /api/cert", s.auth(s.handleCert))

	m.HandleFunc("GET /api/build/toolchain", s.auth(s.needBuilder(s.handleBuildToolchain)))
	m.HandleFunc("GET /api/build/versions", s.auth(s.handleBuildVersions))
	m.HandleFunc("GET /api/builds", s.auth(s.needBuilder(s.handleBuildList)))
	m.HandleFunc("POST /api/builds", s.auth(s.needBuilder(s.handleBuildStart)))
	m.HandleFunc("POST /api/builds/rollback", s.auth(s.needBuilder(s.handleBuildRollback)))
	m.HandleFunc("GET /api/builds/{id}", s.auth(s.needBuilder(s.handleBuildGet)))
	m.HandleFunc("GET /api/builds/{id}/stream", s.auth(s.needBuilder(s.handleBuildStream)))
	m.HandleFunc("POST /api/builds/{id}/cancel", s.auth(s.needBuilder(s.handleBuildCancel)))
	m.HandleFunc("POST /api/builds/{id}/activate", s.auth(s.needBuilder(s.handleBuildActivate)))
	m.HandleFunc("DELETE /api/builds/{id}", s.auth(s.needBuilder(s.handleBuildDelete)))

	m.HandleFunc("GET /api/sites", s.auth(s.handleSitesList))
	m.HandleFunc("POST /api/sites/preview", s.auth(s.handleSitePreview))
	m.HandleFunc("POST /api/sites", s.auth(s.handleSiteCreate))
	m.HandleFunc("PUT /api/sites/{id}", s.auth(s.handleSiteUpdate))
	m.HandleFunc("DELETE /api/sites/{id}", s.auth(s.handleSiteDelete))
	m.HandleFunc("POST /api/sites/{id}/enabled", s.auth(s.handleSiteEnabled))
	m.HandleFunc("POST /api/sites/{id}/test", s.auth(s.handleSiteTest))
	m.HandleFunc("GET /api/sites/{id}/certificate", s.auth(s.handleSiteCertificate))

	m.HandleFunc("GET /api/caddyfile", s.auth(s.handleCaddyfileGet))
	m.HandleFunc("PUT /api/caddyfile", s.auth(s.handleCaddyfileSave))
	m.HandleFunc("POST /api/caddyfile/validate", s.auth(s.handleCaddyfileValidate))
	m.HandleFunc("POST /api/caddyfile/fmt", s.auth(s.handleCaddyfileFmt))

	m.HandleFunc("GET /api/access-lists", s.auth(s.handleACLList))
	m.HandleFunc("POST /api/access-lists", s.auth(s.handleACLCreate))
	m.HandleFunc("PUT /api/access-lists/{id}", s.auth(s.handleACLUpdate))
	m.HandleFunc("DELETE /api/access-lists/{id}", s.auth(s.handleACLDelete))

	m.HandleFunc("GET /api/certificates", s.auth(s.handleCertificates))
	m.HandleFunc("GET /api/certificates/root.crt", s.auth(s.handleRootCA))

	m.HandleFunc("GET /api/nav", s.auth(s.handleNav))

	m.HandleFunc("GET /api/analytics", s.auth(s.handleAnalytics))
	m.HandleFunc("GET /api/analytics/recent", s.auth(s.handleAnalyticsRecent))
	m.HandleFunc("GET /api/audit", s.auth(s.handleAudit))
	m.HandleFunc("GET /api/ai/audit", s.auth(s.handleAIAudit))
	m.HandleFunc("GET /api/ai/audit/export", s.auth(s.handleAIAuditExport))
	m.HandleFunc("GET /api/cloudflare", s.auth(s.handleCloudflareGet))
	m.HandleFunc("PUT /api/cloudflare", s.auth(s.browserOnly(s.handleCloudflareSave)))
	m.HandleFunc("DELETE /api/cloudflare/token", s.auth(s.browserOnly(s.handleCloudflareForget)))
	m.HandleFunc("POST /api/cloudflare/test", s.auth(s.handleCloudflareTest))
	m.HandleFunc("GET /api/ai/settings", s.auth(s.handleAISettingsGet))
	m.HandleFunc("PUT /api/ai/settings", s.auth(s.browserOnly(s.handleAISettingsSave)))
	m.HandleFunc("POST /api/ai/test", s.auth(s.browserOnly(s.handleAITest)))
	m.HandleFunc("GET /api/ai/models", s.auth(s.browserOnly(s.handleAIModels)))
	m.HandleFunc("GET /api/ai/chats", s.auth(s.browserOnly(s.handleAIChatList)))
	m.HandleFunc("POST /api/ai/chats", s.auth(s.browserOnly(s.handleAIChatCreate)))
	m.HandleFunc("GET /api/ai/chats/{id}", s.auth(s.browserOnly(s.handleAIChatGet)))
	m.HandleFunc("DELETE /api/ai/chats/{id}", s.auth(s.browserOnly(s.handleAIChatDelete)))
	m.HandleFunc("POST /api/ai/chats/{id}/messages", s.auth(s.browserOnly(s.handleAIChatMessage)))
	m.HandleFunc("POST /api/ai/chats/{id}/proposals/{pid}", s.auth(s.browserOnly(s.handleAIProposal)))

	m.HandleFunc("POST /api/import/preview", s.auth(s.handleImportPreview))
	m.HandleFunc("POST /api/import/apply", s.auth(s.handleImportApply))

	m.HandleFunc("GET /api/tokens", s.auth(s.handleTokenList))
	m.HandleFunc("POST /api/tokens", s.auth(s.handleTokenCreate))
	m.HandleFunc("DELETE /api/tokens/{id}", s.auth(s.handleTokenRevoke))
	m.HandleFunc("GET /api/mcp/info", s.auth(s.handleMCPInfo))
	m.HandleFunc("GET /api/ui.crt", s.auth(s.handleUICert))

	m.HandleFunc("GET /api/update", s.auth(s.handleUpdateCheck))
	m.HandleFunc("POST /api/update", s.auth(s.handleUpdateApply))
	m.HandleFunc("GET /api/update/caddy", s.auth(s.handleCaddyUpdateCheck))
	m.HandleFunc("POST /api/update/caddy", s.auth(s.needBuilder(s.handleCaddyUpdateApply)))

	m.HandleFunc("GET /api/backups", s.auth(s.handleBackupList))
	m.HandleFunc("POST /api/backups", s.auth(s.handleBackupCreate))
	m.HandleFunc("PUT /api/backups/settings", s.auth(s.handleBackupSettings))
	m.HandleFunc("GET /api/backups/{name}", s.auth(s.handleBackupDownload))
	m.HandleFunc("DELETE /api/backups/{name}", s.auth(s.handleBackupDelete))
	m.HandleFunc("POST /api/restore/preview", s.auth(s.handleRestorePreview))
	m.HandleFunc("POST /api/restore", s.auth(s.handleRestore))

	// MCP authenticates itself (bearer only) and answers JSON-RPC.
	m.HandleFunc("/mcp", s.handleMCP)

	// Everything else is the SPA.
	m.Handle("/", webui.Handler())
	return m
}

// needBuilder answers 503 when the build directory could not be prepared.
func (s *Server) needBuilder(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Builder == nil {
			writeErr(w, http.StatusServiceUnavailable, "no_builder", "Builder nicht verfügbar – Rechte auf "+s.Paths.StateDir+" prüfen")
			return
		}
		next(w, r)
	}
}
