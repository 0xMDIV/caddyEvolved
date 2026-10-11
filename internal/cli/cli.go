// Package cli implements the caddyevolved command line.
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

	"caddyevolved/internal/buildinfo"
	"caddyevolved/internal/tui"
)

// version is what the version command prints.
func version() string { return buildinfo.String() }

// commandTable maps a name to its handler.
//
// A function rather than a package var: cmdCommands prints this table, so a
// variable initialiser that references it would be an initialisation cycle.
func commandTable() map[string]command {
	return map[string]command{
		"install":   {run: cmdInstall, usage: "caddyevolved install [--unattended answers.json] [--prefix DIR] [--root DIR] [--dry-run] [--force] [--yes] [--plugin ID ...] [--env KEY=VALUE ...] [--variant official|bundle|custom] [--caddy-version V] [--email ADDR] [--http-port N --https-port N --admin-port N] [--ui-port N --ui-bind ADDR --ui-behind-proxy] [--managed] [--domain D --target URL] [--ui-password PW] [--password-file F] [--json]", summary: "Caddy + WebUI einrichten (interaktiv oder unbeaufsichtigt)"},
		"container": {run: cmdContainer, usage: "caddyevolved container", summary: "Einstiegspunkt des Docker-Images: einrichten, caddy überwachen, WebUI starten"},
		"serve":     {run: cmdServe, usage: "caddyevolved serve [--bind 0.0.0.0] [--port 8484] [--insecure-dev] [--root DIR]", summary: "WebUI und Verwaltungsdaemon starten (systemd-Dienst)"},
		"status":    {run: cmdStatus, usage: "caddyevolved status [--json] [--ports=false] [--root DIR]", summary: "Installations-, Dienst- und Modulstatus anzeigen"},
		"start":     {run: cmdStart, usage: "caddyevolved start [--root DIR] [--force]", summary: "caddy starten"},
		"stop":      {run: cmdStop, usage: "caddyevolved stop [--root DIR] [--force]", summary: "caddy anhalten"},
		"restart":   {run: cmdRestart, usage: "caddyevolved restart [--root DIR] [--force]", summary: "caddy neu starten"},
		"reload":    {run: cmdReload, usage: "caddyevolved reload [--root DIR] [--force]", summary: "Caddyfile prüfen und ohne Unterbrechung neu laden"},
		"validate":  {run: cmdValidate, usage: "caddyevolved validate [--file PATH] [--adapter caddyfile|json] [--json] [--root DIR]", summary: "Caddyfile prüfen, ohne etwas zu ändern"},
		"logs":      {run: cmdLogs, usage: "caddyevolved logs [--lines N] [--follow] [--unit caddy|caddyevolved] [--root DIR]", summary: "Protokoll anzeigen"},
		"proxy":     {run: cmdProxy, usage: "caddyevolved proxy add|list|remove [--root DIR] ...", summary: "Reverse-Proxy-Sites verwalten (geplant für M5)"},
		"token":     {run: cmdToken, usage: "caddyevolved token [--ttl HOURS] [--json] [--root DIR]", summary: "Einmaliges Anmeldetoken für die WebUI erzeugen"},
		"passwd":    {run: cmdPasswd, usage: "caddyevolved passwd [--generate] [--password-file F] [--root DIR]", summary: "UI-Passwort setzen und alle Sitzungen abmelden"},
		"do":        {run: cmdDo, usage: "caddyevolved do GET /api/status | POST /api/state '{}' [--token T] [--port N] [--root DIR]", summary: "HTTP-Aufruf gegen die eigene API (Token aus der Umgebung)"},
		"uninstall": {run: cmdUninstall, usage: "caddyevolved uninstall --yes [--keep-config] [--root DIR]", summary: "Dienste entfernen, optionale Daten löschen (geplant für M7)"},
		"version":   {run: cmdVersion, usage: "caddyevolved version [--json] [--root DIR]", summary: "Version von caddyEvolved und caddy anzeigen"},
		"update":    {run: cmdUpdate, usage: "caddyevolved update [--check] [--version V] [--root DIR]", summary: "caddyEvolved selbst auf das neueste Release aktualisieren"},
		"backup":    {run: cmdBackup, usage: "caddyevolved backup [--certs] [--encrypt] [--passphrase-file F] [--out DATEI] [--root DIR]", summary: "Konfiguration sichern (Sites, Access Lists, Zugangsdaten, optional Zertifikate)"},
		"restore":   {run: cmdRestore, usage: "caddyevolved restore [--certs] [--passphrase-file F] [--yes] DATEI", summary: "Konfiguration aus einem Backup wiederherstellen (aktueller Stand wird vorher gesichert)"},
		"doctor":    {run: cmdDoctor, usage: "caddyevolved doctor [--extern] [--json] [--root DIR]", summary: "Ports, Firewall, Weiterleitung, DNS und Zertifikate prüfen – mit Lösungshinweisen"},
		"commands":  {run: cmdCommands, usage: "caddyevolved commands --json", summary: "Befehle und Flags maschinenlesbar ausgeben"},
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
	case errors.Is(err, tui.ErrAborted):
		// The UI already said so on screen.
		return 130
	case errors.Is(err, context.Canceled):
		fmt.Fprintln(stderr, "Abgebrochen.")
		return 130
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
	fmt.Fprintf(w, "caddyEvolved – Caddy Installer und WebUI  (%s)\n\nBefehle:\n", buildinfo.Version)
	table := commandTable()
	names := make([]string, 0, len(table))
	for name := range table {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(w, "  %-11s %s\n", name, table[name].summary)
	}
	fmt.Fprintf(w, "\nDetails: caddyevolved help <befehl>\n")
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
	root := fs.String("root", envDefault("CADDYEVOLVED_ROOT", ""), "Installationswurzel")
	if err := fs.Parse(args); err != nil {
		return err
	}
	info := map[string]any{
		"version": buildinfo.Version, "commit": buildinfo.Commit, "date": buildinfo.Date,
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
	fmt.Fprintf(stdout, "caddyevolved %s (%s)\n", buildinfo.Version, buildinfo.Commit)
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
