// Package install turns a set of answers into a running caddy + caddyforge.
//
// Everything happens through named, idempotent steps so a rerun is safe, a
// failure says exactly where it stopped, and --dry-run can walk the whole plan
// without writing to the system.
package install

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"caddyforge/internal/cmdx"
	"caddyforge/internal/config"
	"caddyforge/internal/platform"
	"caddyforge/internal/plugins"
	"caddyforge/internal/supervisor"
)

// Answers is the complete configuration of an install, from wizard or JSON.
type Answers struct {
	BinarySource string            `json:"binarySource"` // official | bundle | custom
	CaddyVersion string            `json:"caddyVersion,omitempty"`
	Plugins      []string          `json:"plugins,omitempty"`
	Credentials  map[string]string `json:"credentials,omitempty"`
	Email        string            `json:"email"`
	HTTPPort     int               `json:"httpPort"`
	HTTPSPort    int               `json:"httpsPort"`
	AdminPort    int               `json:"adminPort"`
	UIPort       int               `json:"uiPort"`
	UIBind       string            `json:"uiBind"`
	// UIBehindProxy puts the UI behind a caddy site block instead of letting
	// caddyforge listen on its own port.
	UIBehindProxy bool `json:"uiBehindProxy,omitempty"`
	Managed       bool `json:"managed"`
	SiteDomain   string            `json:"siteDomain,omitempty"`
	SiteTarget   string            `json:"siteTarget,omitempty"`
	Force        bool              `json:"force,omitempty"`
}

// Defaults fills in what the wizard left alone.
func (a *Answers) Defaults() {
	if a.BinarySource == "" {
		a.BinarySource = "official"
	}
	if a.HTTPPort == 0 {
		a.HTTPPort = 80
	}
	if a.HTTPSPort == 0 {
		a.HTTPSPort = 443
	}
	if a.AdminPort == 0 {
		a.AdminPort = 2019
	}
	if a.UIPort == 0 {
		a.UIPort = 8484
	}
	if a.UIBind == "" {
		a.UIBind = "0.0.0.0"
	}
	if a.Credentials == nil {
		a.Credentials = map[string]string{}
	}
}

// Validate checks the answers before any step runs, because "80 is taken" is a
// better error before we create a user than after we downloaded 40 MB.
func (a Answers) Validate() error {
	var problems []string
	switch a.BinarySource {
	case "official", "bundle", "custom":
	default:
		problems = append(problems, fmt.Sprintf("unknown binary source %q", a.BinarySource))
	}
	if a.HTTPPort < 1 || a.HTTPPort > 65534 {
		problems = append(problems, "httpPort out of range")
	}
	if a.HTTPSPort < 1 || a.HTTPSPort > 65534 {
		problems = append(problems, "httpsPort out of range")
	}
	if a.AdminPort < 1 || a.AdminPort > 65534 {
		problems = append(problems, "adminPort out of range")
	}
	if a.UIPort < 1 || a.UIPort > 65534 {
		problems = append(problems, "uiPort out of range")
	}
	if a.HTTPPort == a.AdminPort || a.HTTPPort == a.UIPort || a.HTTPSPort == a.AdminPort || a.HTTPSPort == a.UIPort || a.AdminPort == a.UIPort {
		problems = append(problems, "ports must be distinct")
	}
	if a.AdminPort == 2019 && a.HTTPPort == 2019 {
		problems = append(problems, "2019 is caddy's admin port")
	}
	if a.Managed && a.Email == "" {
		problems = append(problems, "managed HTTPS needs an email for the ACME account")
	}
	if (a.SiteDomain == "") != (a.SiteTarget == "") {
		problems = append(problems, "siteDomain and siteTarget come in pairs")
	}
	if a.SiteTarget != "" && !strings.HasPrefix(a.SiteTarget, "http://") && !strings.HasPrefix(a.SiteTarget, "https://") && !strings.HasPrefix(a.SiteTarget, "unix://") {
		problems = append(problems, "siteTarget must be an http(s):// or unix:// URL")
	}

	res, err := plugins.Resolve(a.Plugins)
	if err != nil {
		problems = append(problems, err.Error())
	} else if res.Variant == "custom" && a.BinarySource != "custom" {
		problems = append(problems, fmt.Sprintf("selection %v needs a custom build; set binarySource to \"custom\"", append(res.Missing, res.Untracked...)))
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New("answers: " + strings.Join(problems, "; "))
	}
	return nil
}

// Options wraps Answers with execution concerns.
type Options struct {
	Answers
	Root       string
	Prefix     string
	DryRun     bool
	Unattended bool
	Runner     cmdx.Runner
	Logf       func(format string, args ...any)
	Proxy      string
	// UIPassword seeds the first-run login; empty generates one.
	UIPassword string
	// PasswordOut optionally writes the generated password to a file (0600).
	PasswordOut string

	Progress func(Step)
}

// Status is a step outcome.
type Status string

const (
	StatusPending Status = "pending"
	StatusRunning Status = "running"
	StatusOK      Status = "ok"
	StatusSkipped Status = "skipped"
	StatusFailed  Status = "failed"
	StatusPlanned Status = "planned" // dry-run: would run
)

// Step is one unit of work.
type Step struct {
	Name     string        `json:"name"`
	Title    string        `json:"title"`
	Status   Status        `json:"status"`
	Reason   string        `json:"reason,omitempty"` // skip reason or error
	Duration time.Duration `json:"durationNs,omitempty"`
}

// Plan is an ordered step list plus the mutable run context.
type Plan struct {
	Steps []*Step

	opts    Options
	paths   config.Paths
	host    platform.Info
	runner  cmdx.Runner
	sup     *supervisor.Manager
	resolved resolvedState
}

type resolvedState struct {
	caddyVersion string
	binaryURL    string
	binarySHA    string
	foundBinary  string
	modules      []string
	slowDownload bool
	caddyUserUID int
	caddyUserGID int
	pid          int
	started      bool
	adminOK      bool
	authExisting bool
	generatedPassword string
	summary      string
}

// NewPlan builds the run context and ordered steps for opts.
func NewPlan(ctx context.Context, opts Options) (*Plan, error) {
	opts.Answers.Defaults()
	if opts.Runner == nil {
		opts.Runner = cmdx.ExecRunner{}
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	root := opts.Root
	if opts.Prefix != "" {
		root = opts.Prefix
	}
	p := &Plan{
		opts:   opts,
		paths:  config.NewPaths(root),
		host:   platform.Detect(ctx),
		runner: opts.Runner,
	}
	p.Steps = []*Step{
		{Name: "preflight", Title: "Host prüfen", },
		{Name: "system-user", Title: "Dienst-Benutzer anlegen"},
		{Name: "directories", Title: "Verzeichnisse anlegen"},
		{Name: "credentials", Title: "Modul-Zugangsdaten schreiben"},
		{Name: "binary", Title: "Caddy-Binary installieren"},
		{Name: "caddyfile", Title: "Caddyfile schreiben"},
		{Name: "ui-auth", Title: "UI-Zugang einrichten"},
		{Name: "forge-config", Title: "caddyforge-Konfiguration schreiben"},
		{Name: "systemd-units", Title: "Systemd-Units installieren"},
		{Name: "enable-start", Title: "Dienste starten"},
		{Name: "verify", Title: "Gesundheit prüfen"},
		{Name: "report", Title: "Zusammenfassung"},
	}
	for _, s := range p.Steps {
		s.Status = StatusPending
	}
	return p, nil
}

// Run executes the plan. A failed step stops the run; earlier steps stay
// applied because each one is idempotent, so the same command resumes.
func (p *Plan) Run(ctx context.Context) error {
	fns := map[string]func(context.Context, *Step) error{
		"preflight":      p.stepPreflight,
		"system-user":    p.stepSystemUser,
		"directories":    p.stepDirectories,
		"credentials":    p.stepCredentials,
		"binary":         p.stepBinary,
		"caddyfile":      p.stepCaddyfile,
		"ui-auth":        p.stepUIAuth,
		"forge-config":   p.stepForgeConfig,
		"systemd-units":  p.stepUnits,
		"enable-start":   p.stepEnableStart,
		"verify":         p.stepVerify,
		"report":         p.stepReport,
	}
	var failed error
	for _, s := range p.Steps {
		if ctx.Err() != nil {
			s.Status, s.Reason = StatusFailed, "abgebrochen"
			return ctx.Err()
		}
		fn, ok := fns[s.Name]
		if !ok {
			s.Status, s.Reason = StatusFailed, "interne Fehler: Schritt nicht implementiert"
			failed = fmt.Errorf("step %s: not implemented", s.Name)
			break
		}
		s.Status = StatusRunning
		if p.opts.Progress != nil {
			p.opts.Progress(*s)
		}
		started := time.Now()
		err := fn(ctx, s)
		s.Duration = time.Since(started)
		switch {
		case err != nil && !errors.Is(err, errSkip):
			s.Status = StatusFailed
			s.Reason = err.Error()
			failed = fmt.Errorf("%s: %w", s.Title, err)
		case errors.Is(err, errSkip):
			if s.Status == StatusRunning {
				s.Status = StatusSkipped
			}
		case s.Status == StatusRunning:
			s.Status = StatusOK
		}
		p.opts.Logf("%-16s %s %s", s.Name, s.Status, s.Reason)
		if p.opts.Progress != nil {
			p.opts.Progress(*s)
		}
		if failed != nil {
			break
		}
	}
	return failed
}

// errSkip marks a step as intentionally skipped.
var errSkip = errors.New("skip")

// Steps returns a copy of the step list for reports and the API.
func (p *Plan) StepsCopy() []Step {
	out := make([]Step, 0, len(p.Steps))
	for _, s := range p.Steps {
		out = append(out, *s)
	}
	return out
}

// Report renders the run for the terminal.
func (p *Plan) Report(w io.Writer) {
	for _, s := range p.Steps {
		line := fmt.Sprintf("%-4s %-18s %s", statusMark(s.Status), s.Name, s.Title)
		if s.Reason != "" {
			line += "  — " + s.Reason
		}
		fmt.Fprintln(w, line)
	}
	if p.resolved.summary != "" {
		fmt.Fprintln(w, "\n"+p.resolved.summary)
	}
}

func statusMark(s Status) string {
	switch s {
	case StatusOK:
		return "[ok]"
	case StatusSkipped:
		return "[--]"
	case StatusFailed:
		return "[xx]"
	case StatusPlanned:
		return "[plan]"
	default:
		return "[..]"
	}
}
