package cli

import (
	"context"
	"flag"
	"fmt"
	"io"

	"caddyforge/internal/caddyctl"
)

// action is one of the service verbs sharing this implementation.
type action struct {
	name   string
	verb   string
	notice string
}

var (
	actStart   = action{name: "start", verb: "starten", notice: "caddy wird gestartet"}
	actStop    = action{name: "stop", verb: "anhalten", notice: "caddy wird angehalten"}
	actRestart = action{name: "restart", verb: "neu starten", notice: "caddy startet durch (kurzer Ausfall)"}
	actReload  = action{name: "reload", verb: "neu laden", notice: "Caddyfile wird ohne Unterbrechung neu geladen"}
)

func cmdStart(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return serviceAction(ctx, args, stdout, stderr, actStart)
}

func cmdStop(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return serviceAction(ctx, args, stdout, stderr, actStop)
}

func cmdRestart(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return serviceAction(ctx, args, stdout, stderr, actRestart)
}

func cmdReload(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return serviceAction(ctx, args, stdout, stderr, actReload)
}

// serviceAction drives caddy through systemd when the host has it and through
// the built-in supervisor otherwise. Both paths must reach the same outcome,
// otherwise a prefix test would validate a code path production never takes.
func serviceAction(ctx context.Context, args []string, stdout, stderr io.Writer, a action) error {
	fs := flag.NewFlagSet(a.name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", envDefault("CADDYFORGE_ROOT", ""), "Installation in diesem Baum verwalten")
	force := fs.Bool("force", false, "systemd umgehen und den Supervisor benutzen")
	if err := fs.Parse(args); err != nil {
		return err
	}

	l := newLayout(ctx, *root)
	useSystemd := !*force && l.hasSystemd(ctx)

	if a.name == "reload" {
		// A reload of a broken Caddyfile is the one mistake that must not reach
		// a running proxy, so validate first and refuse on failure.
		out, err := l.caddy().Validate(ctx, l.paths.Caddyfile, "caddyfile")
		if err != nil {
			fmt.Fprint(stderr, out)
			return fmt.Errorf("Caddyfile ungültig – reload verweigert: %w", err)
		}
	}

	if useSystemd {
		return systemdAction(ctx, l, stdout, a)
	}
	return supervisedAction(ctx, l, stdout, a)
}

func systemdAction(ctx context.Context, l *layout, stdout io.Writer, a action) error {
	svc := l.units()
	var err error
	switch a.name {
	case "start":
		err = svc.Start(ctx, "caddy.service")
	case "stop":
		err = svc.Stop(ctx, "caddy.service")
	case "restart":
		err = svc.Restart(ctx, "caddy.service")
	case "reload":
		err = svc.ReloadOrRestart(ctx, "caddy.service")
	}
	if err != nil {
		return fmt.Errorf("%s: %w", a.verb, err)
	}
	// systemctl start blocks until the unit's job is through, so this status is
	// already the settled one.
	summary, active, _ := svc.Status(ctx, "caddy.service")
	fmt.Fprintf(stdout, "%s: %s (%s)\n", a.notice, active, summary)
	return nil
}

func supervisedAction(ctx context.Context, l *layout, stdout io.Writer, a action) error {
	m := l.manager()
	switch a.name {
	case "start":
		pid, err := m.Start(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s: pid %d (ohne systemd, Protokoll %s)\n", a.notice, pid, l.paths.LogFile)
		return nil
	case "stop":
		if err := m.Stop(ctx); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s: beendet\n", a.notice)
		return nil
	case "restart":
		if err := m.Stop(ctx); err != nil {
			return err
		}
		pid, err := m.Start(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s: pid %d\n", a.notice, pid)
		return nil
	case "reload":
		if err := l.caddy().Reload(ctx, l.paths.Caddyfile); err != nil {
			return fmt.Errorf("%s: %w", a.verb, err)
		}
		fmt.Fprintf(stdout, "%s: über die Admin-API von caddy\n", a.notice)
		return nil
	}
	return nil
}

func cmdValidate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", envDefault("CADDYFORGE_ROOT", ""), "Installation in diesem Baum verwalten")
	file := fs.String("file", "", "diese Datei prüfen (Standard: das installierte Caddyfile)")
	adapter := fs.String("adapter", "caddyfile", "Syntax der Datei (caddyfile|json)")
	jsonOut := fs.Bool("json", false, "Ergebnis als JSON ausgeben")
	if err := fs.Parse(args); err != nil {
		return err
	}

	l := newLayout(ctx, *root)
	target := *file
	if target == "" {
		target = l.paths.Caddyfile
	}
	bin, err := caddyctl.Find(l.paths.CaddyBin)
	if err != nil {
		return err
	}
	out, verr := caddyctl.New(bin, l.runner).Validate(ctx, target, *adapter)
	if *jsonOut {
		return encode(stdout, map[string]any{
			"file": target, "binary": bin, "adapter": *adapter,
			"valid": verr == nil, "output": out, "error": errString(verr),
		})
	}
	if out != "" {
		fmt.Fprint(stdout, out)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			fmt.Fprintln(stdout)
		}
	}
	if verr != nil {
		return verr
	}
	fmt.Fprintf(stdout, "%s ist gültig (%s)\n", target, bin)
	return nil
}
