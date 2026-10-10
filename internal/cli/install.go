package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"caddyevolved/internal/config"
	"caddyevolved/internal/install"
)

// installFlags is the parsed command line of `caddyevolved install`.
type installFlags struct {
	set        *flag.FlagSet
	unattended string
	root       string
	prefix     string
	dryRun     bool
	force      bool
	variant    string
	version    string
	plugins    stringList
	env        stringList
	email      string
	httpPort   int
	httpsPort  int
	adminPort  int
	uiPort     int
	uiBind     string
	managed    bool
	domain     string
	target     string
	behind     bool
	uiPassword string
	passwordIn string
	jsonOut    bool
	yes        bool
}

func parseInstallFlags(args []string, stderr io.Writer) (*installFlags, error) {
	f := &installFlags{}
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	f.set = fs
	fs.StringVar(&f.unattended, "unattended", "", "answers.json ohne Rückfragen verwenden")
	fs.StringVar(&f.root, "root", envDefault("CADDYEVOLVED_ROOT", ""), "Konfiguration/Daten dieses Baums verwenden")
	fs.StringVar(&f.prefix, "prefix", "", "alles unter dieses Staging-Präfix schreiben (ohne root)")
	fs.BoolVar(&f.dryRun, "dry-run", false, "nur planen und prüfen, nichts schreiben")
	fs.BoolVar(&f.force, "force", false, "bestehende Units, Ports und Dateien übernehmen")
	fs.StringVar(&f.variant, "variant", "", "official|bundle|custom")
	fs.StringVar(&f.version, "caddy-version", "", "caddy-Version, leer = aktuellste")
	fs.Var(&f.plugins, "plugin", "Modul-ID aus dem Katalog (wiederholbar, Kommata erlaubt)")
	fs.Var(&f.env, "env", "KEY=VALUE für Modul-Zugangsdaten (wiederholbar)")
	fs.StringVar(&f.email, "email", "", "E-Mail für das ACME-Konto")
	fs.IntVar(&f.httpPort, "http-port", 0, "HTTP-Port (0 = Standard 80)")
	fs.IntVar(&f.httpsPort, "https-port", 0, "HTTPS-Port (0 = Standard 443)")
	fs.IntVar(&f.adminPort, "admin-port", 0, "Admin-Port auf localhost (0 = Standard 2019)")
	fs.IntVar(&f.uiPort, "ui-port", 0, "Port der WebUI (0 = Standard 8484)")
	fs.StringVar(&f.uiBind, "ui-bind", "", "Bind-Adresse der WebUI (0 = Standard 0.0.0.0)")
	fs.BoolVar(&f.managed, "managed", false, "Caddyfile vollständig durch caddyEvolved verwalten")
	fs.StringVar(&f.domain, "domain", "", "Domain der ersten Site")
	fs.StringVar(&f.target, "target", "", "Ziel-URL der ersten Site")
	fs.BoolVar(&f.behind, "ui-behind-proxy", false, "WebUI hinter caddy statt auf eigenem Port")
	fs.StringVar(&f.uiPassword, "ui-password", "", "UI-Passwort setzen statt eines erzeugen")
	fs.StringVar(&f.passwordIn, "password-file", "", "generiertes UI-Passwort zusätzlich hierhin schreiben")
	fs.BoolVar(&f.jsonOut, "json", false, "Ergebnis als JSON ausgeben")
	fs.BoolVar(&f.yes, "yes", false, "Rückfrage vor dem Schreiben überspringen")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("install kennt keine Positionsargumente, bekam %q", strings.Join(fs.Args(), " "))
	}
	return f, nil
}

func cmdInstall(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	f, err := parseInstallFlags(args, stderr)
	if err != nil {
		return err
	}
	l := newLayout(ctx, firstNonEmpty(f.prefix, f.root))

	answers, err := f.collectAnswers(ctx, l, stdout)
	if err != nil {
		return err
	}
	answers.Defaults()
	if err := answers.Validate(); err != nil {
		return err
	}

	logf := func(format string, a ...any) { fmt.Fprintf(stdout, format+"\n", a...) }
	if f.jsonOut {
		logf = func(string, ...any) {}
	}
	opts := install.Options{
		Answers:     answers,
		Root:        l.paths.Root,
		DryRun:      f.dryRun,
		Unattended:  f.unattended != "",
		Runner:      l.runner,
		Logf:        logf,
		Proxy:       os.Getenv("HTTPS_PROXY"),
		UIPassword:  f.uiPassword,
		PasswordOut: f.passwordIn,
	}
	plan, err := install.NewPlan(ctx, opts)
	if err != nil {
		return err
	}

	if !f.dryRun && !f.jsonOut {
		printIntent(stdout, answers, l.paths)
		if !f.yes && !newPrompt(stdout).confirm("Jetzt installieren?", true) {
			data, _ := json.MarshalIndent(answers, "", "  ")
			fmt.Fprintf(stdout, "Abgebrochen. Dieselben Antworten unbeaufsichtigt:\n  caddyevolved install --unattended antworten.json\n%s\n", data)
			return nil
		}
	}

	runErr := plan.Run(ctx)
	if f.jsonOut {
		if encErr := encode(stdout, map[string]any{
			"answers":  answers,
			"steps":    plan.StepsCopy(),
			"warnings": plan.Warnings(),
			"dryRun":   f.dryRun,
			"error":    errString(runErr),
		}); encErr != nil {
			return encErr
		}
	} else {
		fmt.Fprintln(stdout)
		plan.Report(stdout)
		if pw := plan.GeneratedPassword(); pw != "" && !f.dryRun {
			fmt.Fprintf(stdout, "\nUI-Passwort (einmalig, nicht wiederholbar): %s\n", pw)
		}
	}
	if runErr != nil {
		if !f.dryRun && !f.jsonOut {
			fmt.Fprintln(stdout, "\nWiederhole denselben Befehl, um bei dem fehlgeschlagenen Schritt fortzusetzen.")
		}
		return runErr
	}
	return nil
}

// collectAnswers reads --unattended or runs the wizard, then applies flag
// overrides so `install --unattended a.json --force` behaves as written.
func (f *installFlags) collectAnswers(ctx context.Context, l *layout, stdout io.Writer) (install.Answers, error) {
	var a install.Answers
	if f.unattended != "" {
		data, err := os.ReadFile(f.unattended)
		if err != nil {
			return a, fmt.Errorf("answers-Datei: %w", err)
		}
		if err := json.Unmarshal(data, &a); err != nil {
			return a, fmt.Errorf("%s: %w", f.unattended, err)
		}
	} else {
		if f.dryRun {
			fmt.Fprintln(stdout, "Trockendurchlauf: es wird nichts geschrieben und kein Passwort gesetzt.")
		}
		w := newWizard(ctx, stdout, l.host)
		res, werr := w.run()
		if werr != nil {
			return a, werr
		}
		a = res
	}
	f.override(&a)
	return a, nil
}

// override lets explicit flags win over the file or the wizard.
func (f *installFlags) override(a *install.Answers) {
	if a.Credentials == nil {
		a.Credentials = map[string]string{}
	}
	if ids := splitIDs(f.plugins); len(ids) > 0 {
		a.Plugins = ids
	}
	if v, err := parseEnvPairs(f.env); err == nil {
		for k, val := range v {
			a.Credentials[k] = val
		}
	}
	if f.variant != "" {
		a.BinarySource = f.variant
	}
	if f.version != "" {
		a.CaddyVersion = strings.TrimPrefix(f.version, "v")
	}
	if f.email != "" {
		a.Email = f.email
	}
	if f.httpPort > 0 {
		a.HTTPPort = f.httpPort
	}
	if f.httpsPort > 0 {
		a.HTTPSPort = f.httpsPort
	}
	if f.adminPort > 0 {
		a.AdminPort = f.adminPort
	}
	if f.uiPort > 0 {
		a.UIPort = f.uiPort
	}
	if f.uiBind != "" {
		a.UIBind = f.uiBind
	}
	if f.managed {
		a.Managed = true
	}
	if f.behind {
		a.UIBehindProxy = true
	}
	if f.domain != "" {
		a.SiteDomain = f.domain
	}
	if f.target != "" {
		a.SiteTarget = f.target
	}
	if f.force {
		a.Force = true
	}
}

// printIntent states what is about to change on this machine. A wizard that
// silently rewrites /etc/caddy is the failure mode this exists to prevent.
func printIntent(w io.Writer, a install.Answers, p config.Paths) {
	target := "Live-System"
	if p.IsPrefixed() {
		target = "Präfix " + p.Root
	}
	fmt.Fprintf(w, "\nInstallation auf %s:\n", target)
	fmt.Fprintf(w, "  caddy   %s aus Quelle %q\n", orDefault(a.CaddyVersion, "aktuellste"), a.BinarySource)
	if len(a.Plugins) > 0 {
		fmt.Fprintf(w, "  Module  %s\n", strings.Join(a.Plugins, ", "))
	}
	fmt.Fprintf(w, "  Ports   http %d https %d admin %d webui %d (bind %s)\n",
		a.HTTPPort, a.HTTPSPort, a.AdminPort, a.UIPort, a.UIBind)
	if a.SiteDomain != "" {
		fmt.Fprintf(w, "  Site    %s -> %s\n", a.SiteDomain, a.SiteTarget)
	}
	fmt.Fprintf(w, "  managed %v · force %v\n", a.Managed, a.Force)
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
