package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"caddyevolved/internal/config"
	"caddyevolved/internal/install"
	"caddyevolved/internal/tui"
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

	answers, confirmed, err := f.collectAnswers(ctx, l, stdout)
	if errors.Is(err, errDeclined) {
		return nil
	}
	if err != nil {
		return err
	}
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

	if !f.dryRun && !f.jsonOut && !confirmed {
		printIntent(stdout, answers, l.paths)
		if !f.yes && !newPrompt(stdout).confirm("Jetzt installieren?", true) {
			printDeclined(stdout, answers)
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
		pw := plan.GeneratedPassword()
		switch {
		case f.dryRun:
		case runErr == nil:
			printLogin(stdout, answers, pw, f.uiPassword != "")
		case pw != "":
			// Failed later on, but the password is set already – it must not be lost.
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

// errDeclined means the user said no on the summary; nothing was changed.
var errDeclined = errors.New("nicht bestätigt")

// collectAnswers reads --unattended or runs the wizard, then applies flag
// overrides so `install --unattended a.json --force` behaves as written.
// confirmed reports that the wizard already showed the summary and got a yes.
func (f *installFlags) collectAnswers(ctx context.Context, l *layout, stdout io.Writer) (install.Answers, bool, error) {
	var a install.Answers
	if f.unattended != "" {
		data, err := os.ReadFile(f.unattended)
		if err != nil {
			return a, false, fmt.Errorf("answers-Datei: %w", err)
		}
		if err := json.Unmarshal(data, &a); err != nil {
			return a, false, fmt.Errorf("%s: %w", f.unattended, err)
		}
		f.override(&a)
		a.Defaults()
		return a, false, nil
	}

	// The terminal UI stays open through the summary and is closed before the
	// plan runs, so step output and Ctrl+C behave normally again.
	ui := openUI(ctx, stdout)
	defer ui.Close()
	w := newWizard(ctx, ui, l.host, f.dryRun)
	a, err := w.run()
	if err != nil {
		return a, false, err
	}
	f.override(&a)
	a.Defaults()
	if f.dryRun || f.jsonOut || f.yes {
		return a, true, nil
	}
	ok, err := w.summary(a)
	if err != nil {
		return a, false, err
	}
	if !ok {
		printDeclined(ui.Out(), a)
		return a, false, errDeclined
	}
	return a, true, nil
}

// printLogin ends a successful install with where and how to log in.
func printLogin(w io.Writer, a install.Answers, generated string, given bool) {
	rows := []tui.Row{{Label: "WebUI", Value: install.UIURL(a)}}
	notes := []string{}
	switch {
	case generated != "":
		rows = append(rows, tui.Row{Label: "Passwort", Value: generated})
		notes = append(notes, "Das Passwort wird nur dieses eine Mal angezeigt – jetzt notieren.",
			"Ändern: in der WebUI unter Einstellungen oder mit „caddyevolved passwd“.")
	case given:
		rows = append(rows, tui.Row{Label: "Passwort", Value: "das mit --ui-password gesetzte"})
	default:
		rows = append(rows, tui.Row{Label: "Passwort", Value: "unverändert (bestehende Installation)"})
		notes = append(notes, "Vergessen? „caddyevolved passwd --generate“ setzt ein neues.")
	}
	if a.UIBehindProxy {
		rows[0].Value = "https://" + a.SiteDomain + "/caddyevolved"
	} else {
		notes = append(notes, "Der Browser warnt einmal vor dem selbstsignierten Zertifikat – bestätigen.")
	}
	tui.Done(w, "caddyEvolved ist installiert – melde dich jetzt an", rows, notes...)
}

// openUI uses the arrow-key interface on a terminal and numbered prompts
// everywhere else.
func openUI(ctx context.Context, stdout io.Writer) tui.UI {
	if out, ok := stdout.(*os.File); ok {
		return tui.New(ctx, os.Stdin, out)
	}
	return tui.NewPlain(ctx, os.Stdin, stdout)
}

// printDeclined offers the answers for an unattended rerun. Credentials are
// left out: they would otherwise end up in the scrollback.
func printDeclined(w io.Writer, a install.Answers) {
	if len(a.Credentials) > 0 {
		masked := map[string]string{}
		for k := range a.Credentials {
			masked[k] = "<eintragen>"
		}
		a.Credentials = masked
	}
	data, _ := json.MarshalIndent(a, "", "  ")
	fmt.Fprintf(w, "Nicht installiert. Dieselben Antworten unbeaufsichtigt:\n  caddyevolved install --unattended antworten.json\n%s\n", data)
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
