package install

import (
	"context"
	"fmt"
	"strings"
	"time"

	"caddyevolved/internal/caddyctl"
	"caddyevolved/internal/platform"
	"caddyevolved/internal/supervisor"
	"caddyevolved/internal/systemd"
)

// stepEnableStart brings both services up and proves caddy answers.
func (p *Plan) stepEnableStart(ctx context.Context, s *Step) error {
	if p.opts.DryRun {
		if p.paths.IsPrefixed() || p.host.Init != platform.InitSystemd {
			return skip(s, StatusPlanned, "caddy würde direkt gestartet (ohne systemd)")
		}
		return skip(s, StatusPlanned, "systemctl enable --now caddy caddyevolved")
	}
	if p.host.Init != platform.InitSystemd || p.paths.IsPrefixed() {
		// No systemd, or a staging tree we must not hand to the host's init:
		// start caddy as a detached child we can still control.
		if err := p.startDetached(ctx); err != nil {
			return err
		}
		s.Reason = "direkt gestartet (pid " + fmt.Sprint(p.resolved.pid) + ")"
		p.resolved.started = true
		return nil
	}

	svc := systemd.New(p.runner, p.paths.UnitsDir)
	for _, name := range []string{"caddy.service", "caddyevolved.service"} {
		if err := svc.Enable(ctx, name); err != nil {
			return fmt.Errorf("enable %s: %w", name, err)
		}
	}
	if err := svc.Start(ctx, "caddy.service"); err != nil {
		return fmt.Errorf("start caddy: %w", p.unitError(ctx, svc, "caddy.service", err))
	}
	p.resolved.started = true
	// The UI service is ours; failing to start it must not undo a good caddy.
	if err := svc.Start(ctx, "caddyevolved.service"); err != nil {
		s.Reason = "caddy läuft, caddyEvolved-UI nicht: " + err.Error()
		p.opts.Logf("WARN  caddyevolved.service: %v", err)
	}
	return nil
}

// unitError pulls the last journal lines so a failed start explains itself.
func (p *Plan) unitError(ctx context.Context, svc *systemd.Service, unit string, cause error) error {
	logs, err := svc.Journal(ctx, unit, 20)
	if err != nil || strings.TrimSpace(logs) == "" {
		return cause
	}
	return fmt.Errorf("%w\n%s", cause, indent(lastLines(logs, 8)))
}

// stepVerify checks the running system, not just the files we wrote.
func (p *Plan) stepVerify(ctx context.Context, s *Step) error {
	if p.opts.DryRun || !p.resolved.started {
		return skip(s, StatusPlanned, "nach dem Start ausführen")
	}

	c := caddyctl.New(p.paths.CaddyBin, p.runner)
	if _, err := c.Validate(ctx, p.paths.Caddyfile, "caddyfile"); err != nil {
		return err
	}

	admin := caddyctl.NewAdmin(caddyctl.AdminURL(p.adminListen()))
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := admin.Sync(ctx); err == nil {
			lastErr = nil
			break
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf("admin-API auf %s nicht erreichbar: %w", p.adminListen(), lastErr)
	}
	p.resolved.adminOK = true

	if p.host.Init == platform.InitSystemd && !p.paths.IsPrefixed() {
		svc := systemd.New(p.runner, p.paths.UnitsDir)
		summary, active, err := svc.Status(ctx, "caddy.service")
		if err != nil {
			return err
		}
		if !strings.HasPrefix(active, "active") {
			return fmt.Errorf("caddy.service ist %s", active)
		}
		s.Reason = summary
	}
	return nil
}

// stepReport composes the final summary for terminal and UI.
func (p *Plan) stepReport(ctx context.Context, s *Step) error {
	a := p.opts.Answers
	var b strings.Builder
	fmt.Fprintf(&b, "caddy %s  Quelle %s  (%s)\n", p.resolved.caddyVersion, a.BinarySource, p.resolved.binaryURL)
	if len(a.Plugins) > 0 {
		fmt.Fprintf(&b, "Module: %s\n", strings.Join(a.Plugins, ", "))
	}
	fmt.Fprintf(&b, "Caddyfile: %s\n", p.paths.Caddyfile)
	fmt.Fprintf(&b, "Admin-API: %s\n", caddyctl.AdminURL(p.adminListen()))
	if !a.UIBehindProxy {
		fmt.Fprintf(&b, "WebUI: http://%s:%d  (Login: caddyevolved token)\n", displayHost(a.UIBind), a.UIPort)
	} else {
		fmt.Fprintf(&b, "WebUI: hinter caddy auf https://%s/caddyevolved\n", a.SiteDomain)
	}
	if p.resolved.slowDownload {
		b.WriteString("Hinweis: benannter Build wurde auf caddyserver.com kompiliert.\n")
	}
	p.resolved.summary = b.String()
	s.Reason = "siehe Zusammenfassung"
	return nil
}

func (p *Plan) adminListen() string {
	if p.opts.Answers.AdminPort == 0 {
		return "localhost:2019"
	}
	return fmt.Sprintf("localhost:%d", p.opts.Answers.AdminPort)
}

// displayHost keeps 0.0.0.0 from appearing as a clickable URL.
func displayHost(bind string) string {
	switch bind {
	case "", "0.0.0.0", "::":
		return "<host-ip>"
	default:
		return bind
	}
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "      " + l
	}
	return strings.Join(lines, "\n")
}

func lastLines(s string, n int) string {
	all := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(all) <= n {
		return s
	}
	return strings.Join(all[len(all)-n:], "\n")
}

// startDetached runs caddy without systemd (prefix installs, odd images).
func (p *Plan) startDetached(ctx context.Context) error {
	pid, err := p.caddyManager().Start(ctx)
	if err != nil {
		return err
	}
	p.resolved.pid = pid
	return nil
}

// caddyManager is the non-systemd process manager for this layout.
func (p *Plan) caddyManager() *supervisor.Manager {
	if p.sup == nil {
		p.sup = supervisor.New(p.paths.CaddyBin, p.paths.Caddyfile, p.paths.EnvFile, p.paths.LogFile, p.paths.PIDFile)
	}
	return p.sup
}
