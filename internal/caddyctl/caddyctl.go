// Package caddyctl talks to the caddy binary on disk.
package caddyctl

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"caddyevolved/internal/cmdx"
)

// Client runs subcommands of one caddy binary.
type Client struct {
	bin    string
	runner cmdx.Runner
	// Env feeds the credential file values a module may need even offline.
	Env []string
}

// New uses the binary at bin.
func New(bin string, runner cmdx.Runner) *Client {
	if runner == nil {
		runner = cmdx.ExecRunner{}
	}
	return &Client{bin: bin, runner: runner}
}

// Find locates caddy: explicit path, PATH, then the usual install dirs.
func Find(path string) (string, error) {
	candidates := []string{}
	if path != "" {
		candidates = append(candidates, path)
	}
	if p, err := exec.LookPath("caddy"); err == nil {
		candidates = append(candidates, p)
	}
	candidates = append(candidates, "/usr/local/bin/caddy", "/usr/bin/caddy", "/opt/caddyevolved/bin/caddy")
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
		if c == path {
			break
		}
	}
	return "", fmt.Errorf("caddy binary not found (looked in %s)", strings.Join(candidates[:min(3, len(candidates))], ", "))
}

func min(a, b int) int {
	if b < a {
		return b
	}
	return a
}

// Exists reports whether the configured binary is present and executable.
func (c *Client) Exists() bool {
	st, err := os.Stat(c.bin)
	return err == nil && !st.IsDir() && st.Mode().Perm()&0o111 != 0
}

// versionField matches the first version-shaped token of `caddy --version`.
//
// The output format is not stable across releases: 2.11 prints
// "v2.11.7 h1:<digest>" while older builds printed "Caddy version v2.11.7" and a
// custom build appends "+unknown". Matching the field instead of assuming a
// prefix is the only parser that survives all three.
var versionField = regexp.MustCompile(`^v?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[0-9A-Za-z.]+)?)`)

// Version returns the short version string, e.g. "2.11.7".
func (c *Client) Version(ctx context.Context) (string, error) {
	out, err := c.run(ctx, "--version")
	if err != nil {
		return "", err
	}
	for _, field := range strings.Fields(string(out)) {
		base, _, _ := strings.Cut(field, "+")
		if m := versionField.FindStringSubmatch(base); m != nil {
			return m[1], nil
		}
	}
	return "", fmt.Errorf("caddy --version: keine Version in %q", strings.TrimSpace(string(out)))
}

// ModuleNames lists compiled-in module identifiers ("standard" or "nonstandard"
// scopes) with optional versions.
func (c *Client) ModuleNames(ctx context.Context, standard bool) ([]string, error) {
	args := []string{"list-modules"}
	if !standard {
		args = append(args, "--skip-standard")
	}
	out, err := c.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	// Module lines start in column 0; the trailing summary ("  Standard
	// modules: 120") is indented and must not be mistaken for a module.
	var names []string
	for _, line := range strings.Split(out, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if f := strings.Fields(line); len(f) > 0 {
			names = append(names, f[0])
		}
	}
	return names, nil
}

// HasModule reports whether a provider name is compiled in. DNS providers are
// registered as "dns.providers.<name>", so a suffix match is the contract.
func (c *Client) HasModule(ctx context.Context, name string) (bool, error) {
	if _, err := os.Stat(c.bin); err != nil {
		return false, fmt.Errorf("caddy binary at %s: %w", c.bin, err)
	}
	out, err := c.run(ctx, "list-modules", "--versions")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(out, "\n") {
		field := strings.Fields(line)
		if len(field) == 0 {
			continue
		}
		if field[0] == name || strings.HasSuffix(field[0], "."+name) {
			return true, nil
		}
	}
	return false, nil
}

// HasPackage reports whether any compiled-in module comes from the go module
// path. It covers plugins whose module names are not predictable from the
// catalog (WAF, rate limit, ...); a package line may name a sub-package.
func (c *Client) HasPackage(ctx context.Context, path string) (bool, error) {
	if _, err := os.Stat(c.bin); err != nil {
		return false, fmt.Errorf("caddy binary at %s: %w", c.bin, err)
	}
	out, err := c.run(ctx, "list-modules", "--packages", "--skip-standard")
	if err != nil {
		return false, err
	}
	path = strings.TrimSuffix(path, "/")
	for _, line := range strings.Split(out, "\n") {
		for _, f := range strings.Fields(line) {
			if f == path || strings.HasPrefix(f, path+"/") || strings.Contains(f, "/") && strings.HasPrefix(path, f+"/") {
				return true, nil
			}
		}
	}
	return false, nil
}

// Validate runs "caddy validate" over configPath and returns the process
// output. The adapter names the config syntax, not the file extension.
func (c *Client) Validate(ctx context.Context, configPath, adapter string) (string, error) {
	if adapter == "" {
		adapter = "caddyfile"
	}
	// validate provisions every module, and the local CA writes a root
	// certificate to $XDG_DATA_HOME/caddy. Run as root inside the hardened
	// daemon that is a read-only /root; pointed at caddy's own data dir it
	// would leave root-owned files the service user cannot read. A scratch
	// directory keeps both away.
	env := append([]string(nil), c.Env...)
	if scratch, err := os.MkdirTemp("", "caddyevolved-validate-"); err == nil {
		defer os.RemoveAll(scratch)
		env = append(env, ScratchEnv(scratch)...)
	}
	outb, err := c.runner.Output(ctx, cmdx.Cmd{Name: c.bin, Args: []string{"validate", "--config", configPath, "--adapter", adapter}, Env: env})
	out := string(outb)
	if err != nil {
		return out, fmt.Errorf("validate: %w", err)
	}
	return out, nil
}

// HashPassword returns a bcrypt hash for basic_auth. The plaintext goes in on
// stdin, never in argv, where any local user could read it from /proc.
func (c *Client) HashPassword(ctx context.Context, plaintext string) (string, error) {
	out, err := c.runner.Output(ctx, cmdx.Cmd{
		Name:  c.bin,
		Args:  []string{"hash-password", "--algorithm", "bcrypt"},
		Stdin: []byte(plaintext + "\n"),
	})
	if err != nil {
		return "", fmt.Errorf("hash-password: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return "", fmt.Errorf("hash-password: keine Ausgabe")
	}
	return fields[len(fields)-1], nil
}

// ScratchEnv points caddy's data and config storage into dir.
func ScratchEnv(dir string) []string {
	return []string{
		"HOME=" + dir,
		"XDG_DATA_HOME=" + filepath.Join(dir, "data"),
		"XDG_CONFIG_HOME=" + filepath.Join(dir, "config"),
	}
}

// Fmt formats Caddyfile content through "caddy fmt --stdin".
func (c *Client) Fmt(ctx context.Context, content []byte) ([]byte, error) {
	return c.runner.Output(ctx, cmdx.Cmd{
		Name:  c.bin,
		Args:  []string{"fmt", "--stdin"},
		Stdin: content,
		Env:   c.Env,
	})
}

// Reload asks a running caddy to re-read its config with zero downtime.
func (c *Client) Reload(ctx context.Context, configPath string) error {
	_, err := c.run(ctx, "reload", "--config", configPath, "--force")
	return err
}

// StartArgs are the argv for the systemd ExecStart line.
func StartArgs(configPath string) []string {
	return []string{"run", "--config", configPath}
}

// AdminEndpoint is the parsed admin listen address from a global options block.
func AdminEndpoint(globalOpts string) string {
	for _, line := range strings.Split(globalOpts, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "admin "); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

// AdminURL normalises an admin listen address into a base URL.
func AdminURL(listen string) string {
	if listen == "" {
		listen = "localhost:2019"
	}
	host, port, ok := strings.Cut(listen, ":")
	if !ok {
		host, port = listen, "2019"
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	if p, err := strconv.Atoi(port); err == nil && p == 0 {
		return "http://" + host // admin disabled
	}
	return "http://" + host + ":" + port
}

// PIDFile reads a pid file written by our fallback supervisor.
func PIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("%s: not a pid: %w", path, err)
	}
	return n, nil
}

// WritePIDFile stores a pid.
func WritePIDFile(path string, pid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0o644)
}

func (c *Client) run(ctx context.Context, args ...string) (string, error) {
	out, err := c.runner.Output(ctx, cmdx.Cmd{Name: c.bin, Args: args, Env: c.Env})
	return string(out), err
}

// JSON is a small helper for endpoints that return one document.
func JSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
