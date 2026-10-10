package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"caddyforge/internal/auth"
	"caddyforge/internal/platform"
)

// stepUIAuth guarantees the daemon can log anybody in.
//
// Without a stored password every request would be rejected forever, so first
// install generates one and the report prints it exactly once.
func (p *Plan) stepUIAuth(ctx context.Context, s *Step) error {
	store, err := auth.LoadStore(p.paths.AuthFile)
	if err != nil {
		return fmt.Errorf("Auth-Store: %w", err)
	}
	if store.HasPassword() {
		p.resolved.authExisting = true
		return skip(s, StatusSkipped, "UI-Passwort bereits gesetzt")
	}
	if p.opts.DryRun {
		// Generating a password here would print one that was never stored, and
		// an operator would write it down for nothing.
		return skip(s, StatusPlanned, "UI-Zugang würde eingerichtet (Passwort entsteht erst im echten Lauf)")
	}
	password := p.opts.UIPassword
	if password == "" {
		password, err = auth.GeneratePassword()
		if err != nil {
			return err
		}
		p.resolved.generatedPassword = password
	}
	if err := store.SetPassword(password); err != nil {
		if errors.Is(err, auth.ErrWeakPassword) {
			return fmt.Errorf("%w – vorgeschlagen: %s", err, auth.GeneratePasswordHint())
		}
		return err
	}
	if p.opts.PasswordOut != "" {
		if err := os.WriteFile(p.opts.PasswordOut, []byte(password+"\n"), 0o600); err != nil {
			return fmt.Errorf("Passwort-Datei: %w", err)
		}
		s.Reason = "Passwort additionally in " + p.opts.PasswordOut
	}
	return nil
}

// Warnings collects the non-fatal notes the UI should show next to a plan.
func (p *Plan) Warnings() []string {
	var out []string
	if p.resolved.slowDownload {
		out = append(out, "Modulauswahl wird auf caddyserver.com kompiliert (1–3 Minuten)")
	}
	if p.resolved.authExisting {
		out = append(out, "UI-Passwort existiert bereits – es wird nicht ersetzt")
	}
	if p.host.Init != platform.InitSystemd {
		out = append(out, "Kein systemd: caddy mit `caddyforge start`, die WebUI mit `caddyforge serve` laufen lassen")
	}
	if !p.host.CanBind && !p.host.IsRoot {
		out = append(out, "Ports <1024 nur mit CAP_NET_BIND_SERVICE in der Unit")
	}
	if p.opts.DryRun {
		out = append(out, "Trockendurchlauf: es wurden keine Änderungen geschrieben")
	}
	for _, st := range p.Steps {
		if st.Status == StatusSkipped && st.Reason != "" && !strings.Contains(st.Reason, "Prefix") {
			out = append(out, st.Name+": "+st.Reason)
		}
	}
	return out
}
