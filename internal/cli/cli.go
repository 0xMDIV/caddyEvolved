// Package cli implements the caddyforge command line.
//
// Every command has a machine-readable sibling path (--json or the HTTP API),
// because the installer is expected to be driven by the WebUI as often as by a
// human with a shell.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"caddyforge/internal/buildinfo"
)

// version is what the version command prints.
func version() string { return buildinfo.String() }

// commandTable maps a name to its handler.
//
// A function rather than a package var: cmdCommands prints this table, so a
// variable initialiser that references it would be an initialisation cycle.
func commandTable() map[string]command {
	return map[string]command{
		"install":   {run: cmdInstall, usage: "caddyforge install [--unattended answers.json] [--prefix DIR] [--root DIR] [--dry-run] [--force] [--yes] [--plugin ID ...] [--env KEY=VALUE ...] [--variant official|bundle|custom] [--caddy-version V] [--email ADDR] [--http-port N --https-port N --admin-port N] [--ui-port N --ui-bind ADDR --ui-behind-proxy] [--managed] [--domain D --target URL] [--ui-password PW] [--password-file F] [--json]", summary: "Caddy + WebUI einrichten (interaktiv oder unbeaufsichtigt)"},
		"serve":     {run: cmdServe, usage: "caddyforge serve [--bind 0.0.0.0] [--port 8484] [--insecure-dev] [--root DIR]", summary: "WebUI und Verwaltungsdaemon starten (systemd-Dienst)"},
		"status":    {run: cmdStatus, usage: "caddyforge status [--json] [--ports=false] [--root DIR]", summary: "Installations-, Dienst- und Modulstatus anzeigen"},
		"start":     {run: cmdStart, usage: "caddyforge start [--root DIR] [--force]", summary: "caddy starten"},
		"stop":      {run: cmdStop, usage: "caddyforge stop [--root DIR] [--force]", summary: "caddy anhalten"},
		"restart":   {run: cmdRestart, usage: "caddyforge restart [--root DIR] [--force]", summary: "caddy neu starten"},
		"reload":    {run: cmdReload, usage: "caddyforge reload [--root DIR] [--force]", summary: "Caddyfile prüfen und ohne Unterbrechung neu laden"},
		"validate":  {run: cmdValidate, usage: "caddyforge validate [--file PATH] [--adapter caddyfile|json] [--json] [--root DIR]", summary: "Caddyfile prüfen, ohne etwas zu ändern"},
		"logs":      {run: cmdLogs, usage: "caddyforge logs [--lines N] [--follow] [--unit caddy|caddyforge] [--root DIR]", summary: "Protokoll anzeigen"},
		"proxy":     {run: cmdProxy, usage: "caddyforge proxy add|list|remove [--root DIR] ...", summary: "Reverse-Proxy-Sites verwalten (geplant für M5)"},
		"token":     {run: cmdToken, usage: "caddyforge token [--ttl HOURS] [--json] [--root DIR]", summary: "Einmaliges Anmeldetoken für die WebUI erzeugen"},
		"passwd":    {run: cmdPasswd, usage: "caddyforge passwd [--generate] [--password-file F] [--root DIR]", summary: "UI-Passwort setzen und alle Sitzungen abmelden"},
		"do":        {run: cmdDo, usage: "caddyforge do GET /api/status | POST /api/state '{}' [--token T] [--port N] [--root DIR]", summary: "HTTP-Aufruf gegen die eigene API (Token aus der Umgebung)"},
		"uninstall": {run: cmdUninstall, usage: "caddyforge uninstall --yes [--keep-config] [--root DIR]", summary: "Dienste entfernen, optionale Daten löschen (geplant für M7)"},
		"version":   {run: cmdVersion, usage: "caddyforge version [--json] [--root DIR]", summary: "Version von caddyforge und caddy anzeigen"},
		"commands":  {run: cmdCommands, usage: "caddyforge commands --json", summary: "Befehle und Flags maschinenlesbar ausgeben"},
	}
}

type command struct {
	run     func(ctx context.Context, args []string, stdout, stderr io.Writer) error
	usage   string
	summary string
}

// Run executes one command and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(args) == 0 {
		printUsage(stdout)
		return 0
	}
	switch args[0] {
	case "-h", "--help", "help":
		if len(args) > 1 {
			return usageFor(args[1], stdout, stderr)
		}
		printUsage(stdout)
		return 0
	}
	cmd, ok := commandTable()[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "bekannter Befehl ist %q\n", args[0])
		printUsage(stderr)
		return 2
	}
	// Serve must survive a SIGTERM cleanly (systemd stop); everything else may
	// be interrupted by the user without a graceful plan.
	err := cmd.run(ctx, args[1:], stdout, stderr)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, context.DeadlineExceeded):
		fmt.Fprintln(stderr, "Zeitüberschreitung")
		return 124
	default:
		fmt.Fprintln(stderr, "Fehler: "+err.Error())
		return 1
	}
}

func usageFor(name string, stdout, stderr io.Writer) int {
	cmd, ok := commandTable()[name]
	if !ok {
		fmt.Fprintf(stderr, "bekannter Befehl ist %q\n", name)
		return 2
	}
	fmt.Fprintf(stdout, "%s\n\n%s\n", cmd.summary, cmd.usage)
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "caddyforge – Caddy Installer und WebUI  (%s)\n\nBefehle:\n", buildinfo.Version)
	table := commandTable()
	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "  %-11s %s\n", name, table[name].summary)
	}
	fmt.Fprintf(w, "\nDetails: caddyforge help <befehl>\n")
}

func cmdCommands(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("commands", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "JSON ausgeben")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*jsonOut {
		printUsage(stdout)
		return nil
	}
	table := commandTable()
	type entry struct {
		Name    string `json:"name"`
		Usage   string `json:"usage"`
		Summary string `json:"summary"`
	}
	out := make([]entry, 0, len(table))
	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, entry{Name: name, Usage: table[name].usage, Summary: table[name].summary})
	}
	data, err := json.MarshalIndent(map[string]any{"version": buildinfo.Version, "commands": out}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, string(data))
	return nil
}

func cmdVersion(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "JSON ausgeben")
	root := fs.String("root", envDefault("CADDYFORGE_ROOT", ""), "Installationswurzel")
	if err := fs.Parse(args); err != nil {
		return err
	}
	info := map[string]any{
		"forge": buildinfo.Version, "commit": buildinfo.Commit, "date": buildinfo.Date,
		"root": displayRoot(*root),
	}
	if v, err := caddyVersion(ctx, *root); err == nil {
		info["caddy"] = v
	} else {
		info["caddy"] = "nicht installiert"
		info["caddyError"] = err.Error()
	}
	if *jsonOut {
		return encode(stdout, info)
	}
	fmt.Fprintf(stdout, "caddyforge %s (%s)\n", buildinfo.Version, buildinfo.Commit)
	fmt.Fprintf(stdout, "caddy      %v\n", info["caddy"])
	return nil
}

// encode writes indented JSON with a trailing newline.
func encode(w io.Writer, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", data)
	return err
}

func envDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func displayRoot(root string) string {
	if strings.TrimSpace(root) == "" {
		return "/ (Live-System)"
	}
	return root
}
