package cli

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"caddyevolved/internal/buildinfo"
	"caddyevolved/internal/caddyctl"
	"caddyevolved/internal/config"
	"caddyevolved/internal/platform"
	"caddyevolved/internal/plugins"
)

// statusView is everything `status` reports, assembled once so the text and the
// JSON output cannot disagree with each other.
type statusView struct {
	Version       string               `json:"version"`
	Commit        string               `json:"commit,omitempty"`
	Root          string               `json:"root"`
	Host          platform.Info        `json:"host"`
	Installed     bool                 `json:"installed"`
	CaddyVersion  string               `json:"caddyVersion,omitempty"`
	BinarySource  string               `json:"binarySource,omitempty"`
	Variant       string               `json:"variant,omitempty"`
	CaddyBin      string               `json:"caddyBin,omitempty"`
	BinaryError   string               `json:"binaryError,omitempty"`
	Enabled       []string             `json:"enabledPlugins,omitempty"`
	Modules       []moduleState        `json:"modules,omitempty"`
	Service       serviceState         `json:"service"`
	DaemonService *serviceState        `json:"daemonService,omitempty"`
	Admin         endpointState        `json:"admin"`
	UI            endpointState        `json:"ui"`
	Ports         []platform.PortState `json:"ports,omitempty"`
	StateFile     string               `json:"stateFile"`
	UpdatedAt     string               `json:"updatedAt,omitempty"`
	Email         string               `json:"email,omitempty"`
	Managed       bool                 `json:"managed"`
	Problems      []string             `json:"problems,omitempty"`
}

// serviceState is one unit as this host reports it.
type serviceState struct {
	Managed string `json:"managed"` // systemd | supervisor
	Active  string `json:"active,omitempty"`
	Summary string `json:"summary,omitempty"`
	PID     int    `json:"pid,omitempty"`
	Problem string `json:"problem,omitempty"`
}

// endpointState is one reachable-or-not HTTP endpoint.
type endpointState struct {
	URL     string `json:"url,omitempty"`
	Reach   string `json:"reachable"`
	Problem string `json:"problem,omitempty"`
}

// moduleState is one catalogue entry checked against the binary on disk.
type moduleState struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Detail  string `json:"detail,omitempty"`
}

func cmdStatus(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", envDefault("CADDYEVOLVED_ROOT", ""), "Installation in diesem Baum prüfen")
	jsonOut := fs.Bool("json", false, "JSON ausgeben")
	showPorts := fs.Bool("ports", true, "Belegung der Ports anzeigen")
	if err := fs.Parse(args); err != nil {
		return err
	}

	view, err := collectStatus(ctx, *root, *showPorts)
	if err != nil {
		return err
	}
	if *jsonOut {
		return encode(stdout, view)
	}
	printStatus(stdout, view)
	if len(view.Problems) > 0 {
		// A human still gets the answer in the exit code, not only in prose.
		return fmt.Errorf("%d Problem(e): %s", len(view.Problems), strings.Join(view.Problems, "; "))
	}
	return nil
}

func collectStatus(ctx context.Context, root string, showPorts bool) (statusView, error) {
	l := newLayout(ctx, root)
	v := statusView{
		Version:   buildinfo.Version,
		Commit:    buildinfo.Commit,
		Root:      displayRoot(l.paths.Root),
		Host:      l.host,
		StateFile: l.paths.StateFile,
	}
	st, err := l.state()
	if err != nil {
		return v, fmt.Errorf("state %s: %w", l.paths.StateFile, err)
	}
	v.Installed = st.Installed
	v.CaddyVersion = st.CaddyVersion
	v.BinarySource = st.BinarySource
	v.Variant = st.Variant
	v.Enabled = st.Enabled
	v.Email = st.Email
	v.Managed = st.Managed
	v.UpdatedAt = st.UpdatedAt

	useSystemd := l.hasSystemd(ctx)

	// The binary on disk answers for itself; state.json may predate a manual swap.
	bin, findErr := caddyctl.Find(l.paths.CaddyBin)
	v.CaddyBin = bin
	if findErr != nil {
		v.BinaryError = findErr.Error()
		if v.Installed {
			v.Problems = append(v.Problems, findErr.Error())
		}
	} else {
		c := caddyctl.New(bin, l.runner)
		if ver, verr := c.Version(ctx); verr != nil {
			v.BinaryError = verr.Error()
			v.Problems = append(v.Problems, "caddy-Binary nicht lauffähig: "+verr.Error())
		} else {
			v.CaddyVersion = ver
		}
		v.Modules = checkModules(ctx, c, st.Enabled)
		for _, m := range v.Modules {
			if !m.Present && m.ID != "" {
				v.Problems = append(v.Problems, fmt.Sprintf("Modul %s: %s", m.ID, orDefault(m.Detail, "fehlt in der Binary")))
			}
		}
	}

	v.Service = collectService(ctx, l, useSystemd)
	if useSystemd {
		fs := collectUnit(ctx, l, "caddyevolved.service")
		v.DaemonService = &fs
		if fs.Problem != "" {
			v.Problems = append(v.Problems, fs.Problem)
		}
	} else if v.Installed && l.host.Init != platform.InitSystemd {
		// Only a host without an init is a problem; a staging prefix skips
		// systemd on purpose and must not be reported as broken.
		v.Problems = append(v.Problems, "kein systemd: caddy mit `caddyevolved start`, WebUI mit `caddyevolved serve`")
	}

	if v.Installed {
		v.Admin = checkAdmin(ctx, l.adminURL(st))
		v.UI = checkUI(ctx, st)
		if v.Admin.Reach == "nein" {
			v.Problems = append(v.Problems, "Admin-API "+v.Admin.URL+": "+orDefault(v.Admin.Problem, "nicht erreichbar"))
		}
	} else {
		v.Admin = endpointState{Reach: "nicht installiert"}
		v.UI = endpointState{Reach: "nicht installiert"}
	}

	if showPorts && v.Installed {
		v.Ports = platform.CheckPorts(ctx, st.HTTPPort, st.HTTPSPort, st.AdminPort, st.UIPort)
	}
	return v, nil
}

// collectService reports caddy's liveness through whichever supervisor this host
// actually has.
func collectService(ctx context.Context, l *layout, useSystemd bool) serviceState {
	if useSystemd {
		return collectUnit(ctx, l, "caddy.service")
	}
	pid, running := l.manager().Running()
	s := serviceState{Managed: "supervisor", Active: "stopped", PID: pid}
	if running {
		s.Active = "running"
	} else if l.paths.IsPrefixed() {
		s.Problem = "Prefix-Installation: läuft nur, wenn `caddyevolved start` es gestartet hat"
	} else {
		s.Problem = "caddy läuft nicht (kein systemd)"
	}
	return s
}

func collectUnit(ctx context.Context, l *layout, unit string) serviceState {
	summary, active, err := l.units().Status(ctx, unit)
	s := serviceState{Managed: "systemd", Active: active, Summary: summary}
	switch {
	case err != nil:
		s.Problem = unit + ": " + err.Error()
	case !strings.HasPrefix(active, "active"):
		s.Problem = unit + " ist " + active
	}
	return s
}

func checkAdmin(ctx context.Context, url string) endpointState {
	e := endpointState{URL: url}
	if err := caddyctl.NewAdmin(url).Sync(ctx); err != nil {
		e.Reach = "nein"
		e.Problem = err.Error()
		return e
	}
	e.Reach = "ja"
	return e
}

// checkUI probes the daemon's own version endpoint. The self-signed certificate
// makes verification impossible here, which is why the answer is "antwortet" and
// not "vertrauenswürdig".
func checkUI(ctx context.Context, st config.State) endpointState {
	if st.UIPort == 0 {
		return endpointState{Reach: "unbekannt"}
	}
	host := "127.0.0.1"
	if bind := strings.TrimSpace(st.UIBind); bind != "" && bind != "0.0.0.0" && bind != "::" {
		host = bind
	}
	url := "https://" + net.JoinHostPort(host, fmt.Sprint(st.UIPort))
	e := endpointState{URL: url + "/api/version"}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if ok, err := probeUI(probeCtx, url); ok {
		e.Reach = "antwortet"
		return e
	} else if err != nil {
		e.Problem = err.Error()
	}
	e.Reach = "nein"
	return e
}

// probeUI tries TLS first and plain HTTP second, because --insecure-dev is a
// legitimate way to run the daemon on loopback.
func probeUI(ctx context.Context, base string) (bool, error) {
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		url := strings.Replace(base, "https://", scheme+"://", 1)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/api/version", nil)
		if err != nil {
			return false, err
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 500 {
			return true, nil
		}
		lastErr = fmt.Errorf("HTTP %s", resp.Status)
	}
	return false, lastErr
}

// checkModules verifies the enabled plugins really are compiled into the binary
// on disk, because "downloaded vanilla caddy by accident" otherwise surfaces as
// a missing tls directive minutes later.
func checkModules(ctx context.Context, c *caddyctl.Client, ids []string) []moduleState {
	var out []moduleState
	for _, id := range ids {
		e, ok := plugins.ByID(id)
		if !ok {
			out = append(out, moduleState{ID: id, Name: id, Detail: "nicht im Katalog"})
			continue
		}
		var has bool
		var err error
		if name := providerName(e.Registr); name != "" {
			has, err = c.HasModule(ctx, name)
		} else {
			// Other plugins register module names the catalog does not know;
			// their go module path is what list-modules --packages reports.
			has, err = c.HasPackage(ctx, e.Module)
		}
		m := moduleState{ID: e.ID, Name: e.Name, Present: has}
		if err != nil {
			m.Detail = err.Error()
		} else if !has {
			m.Detail = "fehlt in der Binary"
		}
		out = append(out, m)
	}
	return out
}

func printStatus(w io.Writer, v statusView) {
	fmt.Fprintf(w, "caddyEvolved %s (%s) · Root %s\n", v.Version, orDefault(v.Commit, "unknown"), v.Root)
	fmt.Fprintf(w, "Host       %s %s · init %s · Virtualisierung %s · uid %d\n",
		v.Host.Distro, v.Host.DistroVer, v.Host.Init, orDefault(v.Host.Virt, "unknown"), v.Host.UID)
	fmt.Fprintf(w, "State      %s\n", v.StateFile)
	if !v.Installed {
		fmt.Fprintf(w, "\nInstallation: nicht installiert – `caddyevolved install` ausführen\n")
		return
	}
	fmt.Fprintf(w, "\nInstallation: vorhanden · caddy %s · Quelle %s · Variante %s\n",
		orDefault(v.CaddyVersion, "unbekannt"), orDefault(v.BinarySource, "?"), orDefault(v.Variant, "?"))
	fmt.Fprintf(w, "Binary     %s%s\n", orDefault(v.CaddyBin, "nicht gefunden"), indentLine(v.BinaryError))
	fmt.Fprintf(w, "Dienst     %s: %s%s\n", v.Service.Managed, orDefault(v.Service.Active, "?"), indentLine(orDefault(v.Service.Summary, v.Service.Problem)))
	if v.DaemonService != nil {
		fmt.Fprintf(w, "UI-Dienst  %s: %s%s\n", v.DaemonService.Managed, orDefault(v.DaemonService.Active, "?"), indentLine(orDefault(v.DaemonService.Problem, "")))
	}
	fmt.Fprintf(w, "Admin-API  %s: %s%s\n", orDefault(v.Admin.URL, "-"), v.Admin.Reach, indentLine(v.Admin.Problem))
	fmt.Fprintf(w, "WebUI      %s: %s%s\n", orDefault(v.UI.URL, "-"), v.UI.Reach, indentLine(v.UI.Problem))
	fmt.Fprintf(w, "ACME       Konto %s · Caddyfile verwaltet %v · Stand %s\n",
		orDefault(v.Email, "-"), v.Managed, orDefault(v.UpdatedAt, "-"))

	if len(v.Modules) > 0 {
		fmt.Fprintln(w, "\nModule:")
		for _, m := range v.Modules {
			state := "in der Binary"
			if m.Detail != "" {
				state = m.Detail
			}
			fmt.Fprintf(w, "  %-20s %-26s %s\n", m.ID, m.Name, state)
		}
	}
	if len(v.Ports) > 0 {
		fmt.Fprintln(w, "\nPorts:")
		for _, p := range v.Ports {
			line := fmt.Sprintf("  %-6d %s", p.Port, "frei")
			if !p.Free {
				line = fmt.Sprintf("  %-6d belegt von %s", p.Port, orDefault(p.UsedBy, "?"))
			}
			if p.Own {
				line += " (caddyEvolved selbst)"
			}
			fmt.Fprintln(w, line)
		}
	}
	if len(v.Problems) > 0 {
		fmt.Fprintln(w, "\nProbleme:")
		for _, p := range v.Problems {
			fmt.Fprintln(w, "  - "+p)
		}
	}
}

func indentLine(s string) string {
	if s == "" {
		return ""
	}
	return "\n           " + s
}

// providerName turns the catalogue's "dns.provider cloudflare" into the module
// suffix `caddy list-modules` reports.
func providerName(registr string) string {
	rest, ok := strings.CutPrefix(registr, "dns.provider ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(rest)
}
