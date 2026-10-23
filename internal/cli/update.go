package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"caddyevolved/internal/buildinfo"
	"caddyevolved/internal/platform"
	"caddyevolved/internal/selfupdate"
	"caddyevolved/internal/tui"
)

// cmdUpdate replaces caddyevolved itself with the newest (or a given) release
// and restarts the WebUI service. Caddy, sites and settings stay untouched.
func cmdUpdate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	checkOnly := fs.Bool("check", false, "nur prüfen, ob ein Update da ist")
	version := fs.String("version", "", "bestimmte Version installieren, z. B. 0.5.0 (auch ältere)")
	root := fs.String("root", envDefault("CADDYEVOLVED_ROOT", ""), "Installation in diesem Baum")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := tui.PaintFor(stdout)
	l := newLayout(ctx, *root)

	info, err := selfupdate.Check(ctx, buildinfo.Version)
	if err != nil {
		return fmt.Errorf("Update-Prüfung: %w", err)
	}
	fmt.Fprintf(stdout, "Installiert  %s\nNeuestes     %s\n", info.Current, p.Bold(info.Latest))
	if *version == "" && !info.Available {
		fmt.Fprintln(stdout, p.Green("✔ caddyEvolved ist aktuell."))
		return nil
	}
	if *checkOnly {
		fmt.Fprintln(stdout, p.Yellow("Update verfügbar: ")+"sudo caddyevolved update")
		fmt.Fprintln(stdout, p.Dim("Änderungen: "+info.NotesURL))
		return nil
	}
	if platform.InContainer() {
		return errors.New("im Docker-Container kommt ein Update als neues Image: docker compose pull && docker compose up -d")
	}
	if os.Geteuid() != 0 && !l.paths.IsPrefixed() {
		return errors.New("Update braucht root: sudo caddyevolved update")
	}

	got, err := selfupdate.Apply(ctx, *version, l.paths.Bin, func(s string) { fmt.Fprintln(stdout, p.Dim("  "+s)) })
	if err != nil {
		return err
	}

	restarted := false
	if l.hasSystemd(ctx) {
		if err := l.units().Restart(ctx, "caddyevolved.service"); err != nil {
			fmt.Fprintln(stderr, "Warnung: Dienst nicht neu gestartet: "+err.Error()+" – systemctl restart caddyevolved")
		} else {
			restarted = true
		}
	}
	msg := "WebUI im Browser neu laden."
	if !restarted {
		msg = "WebUI-Dienst neu starten (systemctl restart caddyevolved), dann im Browser neu laden."
	}
	tui.Done(stdout, "caddyEvolved "+got+" ist installiert", []tui.Row{{Label: "Vorher", Value: info.Current}, {Label: "Jetzt", Value: got}},
		msg, "Caddy, Sites und Einstellungen sind unverändert – Caddy und Plugins aktualisiert die WebUI unter Einstellungen → Caddy & Plugins. Alte Binary: "+l.paths.Bin+".prev")
	return nil
}
