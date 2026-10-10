package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"caddyforge/internal/caddyctl"
	"caddyforge/internal/cmdx"
	"caddyforge/internal/config"
	"caddyforge/internal/platform"
	"caddyforge/internal/supervisor"
	"caddyforge/internal/systemd"
)

// layout is everything a command needs once --root/--prefix is known: the
// filesystem model, a runner for external tools and the host probe.
type layout struct {
	paths  config.Paths
	runner cmdx.Runner
	host   platform.Info
}

func newLayout(ctx context.Context, root string) *layout {
	return &layout{
		paths:  config.NewPaths(root),
		runner: cmdx.ExecRunner{},
		host:   platform.Detect(ctx),
	}
}

// state loads the persisted install record. An absent file is not an error:
// every command still has to answer "not installed" instead of failing.
func (l *layout) state() (config.State, error) {
	return config.LoadState(l.paths.StateFile)
}

func (l *layout) units() *systemd.Service {
	return systemd.New(l.runner, l.paths.UnitsDir)
}

// hasSystemd is the branch every service command takes. Three conditions must
// agree: the host has an init, systemctl reaches its bus, and we are not looking
// at a staging prefix — a --root tree is started by our supervisor, and driving
// the host's units from it would control the wrong caddy.
func (l *layout) hasSystemd(ctx context.Context) bool {
	if l.paths.IsPrefixed() {
		return false
	}
	if l.host.Init != platform.InitSystemd {
		return false
	}
	return l.units().Available(ctx)
}

func (l *layout) caddy() *caddyctl.Client {
	return caddyctl.New(l.paths.CaddyBin, l.runner)
}

func (l *layout) manager() *supervisor.Manager {
	return supervisor.New(l.paths.CaddyBin, l.paths.Caddyfile, l.paths.EnvFile, l.paths.LogFile, l.paths.PIDFile)
}

// adminURL is the caddy admin endpoint recorded at install time.
func (l *layout) adminURL(st config.State) string {
	port := st.AdminPort
	if port == 0 {
		port = 2019
	}
	return caddyctl.AdminURL(fmt.Sprintf("localhost:%d", port))
}

// caddyVersion asks the installed binary (or PATH) what it is.
func caddyVersion(ctx context.Context, root string) (string, error) {
	l := newLayout(ctx, root)
	bin, err := caddyctl.Find(l.paths.CaddyBin)
	if err != nil {
		return "", err
	}
	return caddyctl.New(bin, l.runner).Version(ctx)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// stringList collects a repeatable flag (--plugin, --env).
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	*s = append(*s, v)
	return nil
}

// parseEnvPairs turns --env KEY=VALUE occurrences into a map.
func parseEnvPairs(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("--env erwartet KEY=VALUE, bekommen %q", p)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, nil
}

// partitionFlags pulls flag arguments out of a list that also carries
// positionals, so `do GET /api/x --port 8585` works. Go's flag package stops at
// the first positional and would otherwise ignore everything after it.
// valueFlags names the flags that consume the following argument.
func partitionFlags(args []string, valueFlags map[string]bool) (flags, positionals []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			// Everything after the separator is positional, dashes and all.
			return flags, append(positionals, args[i+1:]...)
		case !strings.HasPrefix(a, "-"):
			positionals = append(positionals, a)
		case strings.Contains(a, "="):
			flags = append(flags, a)
		default:
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if valueFlags[name] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		}
	}
	return flags, positionals
}

// splitIDs accepts both a repeated --plugin and one comma-separated value.
func splitIDs(values []string) []string {
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if s := strings.TrimSpace(part); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// prompt is the wizard's terminal input. There is no hidden-input path in the
// standard library, so secret values are read visibly and the wizard says so.
type prompt struct {
	sc  *bufio.Scanner
	out io.Writer
}

func newPrompt(out io.Writer) *prompt {
	return &prompt{sc: bufio.NewScanner(os.Stdin), out: out}
}

func (p *prompt) ask(label, def string) string {
	if def != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(p.out, "%s: ", label)
	}
	if !p.sc.Scan() {
		return def
	}
	v := strings.TrimSpace(p.sc.Text())
	if v == "" {
		return def
	}
	return v
}

func (p *prompt) confirm(label string, def bool) bool {
	suffix := "j/N"
	if def {
		suffix = "J/n"
	}
	fmt.Fprintf(p.out, "%s [%s]: ", label, suffix)
	if !p.sc.Scan() {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(p.sc.Text())) {
	case "":
		return def
	case "j", "ja", "y", "yes":
		return true
	case "n", "nein", "no":
		return false
	default:
		return def
	}
}

func (p *prompt) integer(label string, def int) int {
	for {
		v := p.ask(label, strconv.Itoa(def))
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
		fmt.Fprintf(p.out, "  bitte eine Zahl eingeben (%v)\n", err)
	}
}
