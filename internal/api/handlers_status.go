package api

import (
	"net/http"
	"time"

	"caddyevolved/internal/caddyctl"
	"caddyevolved/internal/config"
	"caddyevolved/internal/events"
	"caddyevolved/internal/platform"
)

// StatusResponse is the single screen payload. It is deliberately chatty: one
// request paints the dashboard, and a partially unavailable subsystem shows up
// in Warnings instead of turning the endpoint into a 500.
type StatusResponse struct {
	Installed     bool                 `json:"installed"`
	CaddyVersion  string               `json:"caddyVersion,omitempty"`
	Variant       string               `json:"variant,omitempty"`
	AdminURL      string               `json:"adminUrl,omitempty"`
	AdminReach    bool                 `json:"adminReachable"`
	AdminError    string               `json:"adminError,omitempty"`
	ServiceState  string               `json:"serviceState,omitempty"`
	ServiceActive bool                 `json:"serviceActive"`
	MainPID       string               `json:"mainPid,omitempty"`
	Listening     bool                 `json:"listening"`
	UI            UIStatus             `json:"ui"`
	Host          HostStatus           `json:"host"`
	Ports         []platform.PortState `json:"ports"`
	Enabled       []PluginState        `json:"enabledPlugins"`
	LastEvent     *events.Event        `json:"lastEvent,omitempty"`
	UpdatedAt     string               `json:"updatedAt,omitempty"`
	Warnings      []string             `json:"warnings,omitempty"`
}

// UIStatus describes how the operator reaches this daemon.
type UIStatus struct {
	Bind       string `json:"bind"`
	Port       int    `json:"port"`
	TLS        bool   `json:"tls"`
	SelfSigned bool   `json:"selfSigned"`
	AuthSet    bool   `json:"authConfigured"`
	Sessions   int    `json:"sessions"`
}

// HostStatus is the container/OS facts the dashboard shows in its header.
type HostStatus struct {
	Distro    string `json:"distro,omitempty"`
	DistroVer string `json:"distroVersion,omitempty"`
	Init      string `json:"init"`
	Virt      string `json:"virt,omitempty"`
	UnprivLXC bool   `json:"unprivilegedLxc"`
	CanBind   bool   `json:"canBindLowPorts"`
	Hostname  string `json:"hostname,omitempty"`
}

// handleStatus aggregates caddy, systemd and our own state.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resp := StatusResponse{
		UI:       UIStatus{Bind: s.Bind, Port: s.Port, TLS: !s.Insecure, SelfSigned: !s.Insecure, AuthSet: s.Auth.HasPassword(), Sessions: len(s.Auth.ListSessions())},
		AdminURL: caddyctl.AdminURL(s.stateAdminListen()),
	}
	host := platform.Detect(ctx)
	resp.Host = HostStatus{
		Distro: host.Distro, DistroVer: host.DistroVer, Init: host.Init.String(),
		Virt: host.Virt, UnprivLXC: host.UnprivilegedLXC(), CanBind: host.CanBind,
		Hostname: host.Hostname,
	}

	st, err := config.LoadState(s.Paths.StateFile)
	if err != nil {
		resp.Warnings = append(resp.Warnings, "Zustand nicht lesbar: "+errText(err))
	} else {
		resp.Installed = st.Installed
		resp.CaddyVersion = st.CaddyVersion
		resp.Variant = st.Variant
		resp.UpdatedAt = st.UpdatedAt
		resp.Ports = platform.CheckPorts(ctx, st.HTTPPort, st.HTTPSPort, st.AdminPort)
	}

	// Service state: systemd if we have it, otherwise our own supervisor.
	if s.Systemd.Available(ctx) {
		summary, active, err := s.Systemd.Status(ctx, "caddy.service")
		if err != nil {
			resp.Warnings = append(resp.Warnings, "caddy.service: "+errText(err))
		} else {
			resp.ServiceState = summary
			resp.ServiceActive = active == "active/running" || active == "active/ready"
		}
	} else if pid, running := s.Sup.PID(); running {
		resp.ServiceActive = true
		resp.MainPID = itoa(pid)
		resp.ServiceState = "gestartet ohne systemd (supervisor)"
	}

	if err := caddyctl.NewAdmin(resp.AdminURL).Sync(ctx); err != nil {
		resp.AdminError = errText(err)
	} else {
		resp.AdminReach = true
		resp.Listening = true
	}

	if v, err := s.Caddy.Version(ctx); err == nil {
		resp.CaddyVersion = v
	}

	resp.Enabled = s.pluginStates(ctx, st)
	if last, ok := s.Events.Latest(); ok {
		resp.LastEvent = &last
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) stateAdminListen() string {
	st, err := config.LoadState(s.Paths.StateFile)
	if err != nil || st.AdminPort == 0 {
		return "localhost:2019"
	}
	return "localhost:" + itoa(st.AdminPort)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// nowUTC is the timestamp helper for handlers that report freshness.
func nowUTC() string { return time.Now().UTC().Format(time.RFC3339) }
