package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"caddyevolved/internal/caddyctl"
	"caddyevolved/internal/cmdx"
	"caddyevolved/internal/config"
	"caddyevolved/internal/fetch"
	"caddyevolved/internal/plugins"
	"caddyevolved/internal/releases"
	"caddyevolved/internal/secrets"
	"caddyevolved/internal/sites"
)

// isMissingUser recognises getent's "key not found" exit code (2).
func isMissingUser(err error) bool {
	var ee *exec.ExitError
	return errors.As(err, &ee) && ee.ExitCode() == 2
}

// stepSystemUser creates the caddy service account. In prefix mode there is
// no system to add a user to, so the step is skipped rather than faked.
func (p *Plan) stepSystemUser(ctx context.Context, s *Step) error {
	if p.paths.IsPrefixed() {
		return skip(s, StatusSkipped, "Prefix-Installation: kein System-User angelegt")
	}
	out, err := p.runner.Output(ctx, cmdx.Cmd{Name: "getent", Args: []string{"passwd", "caddy"}})
	if len(strings.TrimSpace(string(out))) > 0 {
		p.noteUser("caddy", "existiert bereits")
		return skip(s, StatusSkipped, "Benutzer caddy vorhanden")
	}
	if err != nil && !isMissingUser(err) {
		// getent exits non-zero when the key is unknown; other failures
		// (no nss, odd systems) must not be mistaken for "absent".
		return fmt.Errorf("getent passwd caddy: %w", err)
	}
	if p.opts.DryRun {
		return skip(s, StatusPlanned, "Benutzer caddy würde angelegt (groupadd/useradd --system)")
	}

	commands := []cmdx.Cmd{
		{Name: "groupadd", Args: []string{"--system", "caddy"}},
		{Name: "useradd", Args: []string{
			"--system", "--gid", "caddy", "--home-dir", "/var/lib/caddy",
			"--shell", "/usr/sbin/nologin", "--no-create-home", "caddy",
		}},
	}
	for _, c := range commands {
		if _, err := p.runner.Output(ctx, c); err != nil {
			return fmt.Errorf("%s: %w", c.Line(), err)
		}
	}
	p.noteUser("caddy", "angelegt")
	return nil
}

func (p *Plan) noteUser(name, what string) { p.opts.Logf("user %-8s %s", name, what) }

// stepDirectories creates and permission-sets every tree we write into.
func (p *Plan) stepDirectories(ctx context.Context, s *Step) error {
	if p.opts.DryRun {
		return skip(s, StatusPlanned, "Verzeichnisse würden angelegt: "+p.paths.Etc)
	}
	owners := map[string]int{}
	if !p.paths.IsPrefixed() {
		if u, err := user.Lookup("caddy"); err == nil {
			uid, _ := strconv.Atoi(u.Uid)
			gid, _ := strconv.Atoi(u.Gid)
			p.resolved.caddyUserUID, p.resolved.caddyUserGID = uid, gid
			owners[p.paths.CaddyData] = uid
			owners[p.paths.CaddyEtc] = uid
		}
	}
	if err := p.paths.EnsureDirs(owners); err != nil {
		return err
	}
	// The log file must exist before the first rotate, and be caddy-readable.
	if err := os.MkdirAll(filepath.Dir(p.paths.LogFile), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(p.paths.LogFile); os.IsNotExist(err) {
		f, err := os.OpenFile(p.paths.LogFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
		if err != nil {
			return err
		}
		f.Close()
	}
	return nil
}

// stepCredentials writes the EnvironmentFile that feeds module tokens.
func (p *Plan) stepCredentials(ctx context.Context, s *Step) error {
	a := p.opts.Answers
	want := map[string]string{}
	var unknown []string
	for _, id := range a.Plugins {
		e, ok := plugins.ByID(id)
		if !ok {
			unknown = append(unknown, id)
			continue
		}
		for _, v := range e.Env {
			val, given := a.Credentials[v.Name]
			if !given || val == "" {
				if v.Required {
					return fmt.Errorf("fehlende Zugangsdaten: %s für %s (%s)", v.Name, e.Name, v.Label)
				}
				continue
			}
			want[v.Name] = val
		}
	}
	if len(unknown) > 0 {
		// Free-form module paths are allowed, but then we cannot know their
		// variables: pass any credential the operator named explicitly.
		for k, v := range a.Credentials {
			if v != "" {
				want[k] = v
			}
		}
	}
	if p.opts.DryRun {
		keys := make([]string, 0, len(want))
		for k := range want {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return skip(s, StatusPlanned, fmt.Sprintf("%s würde schreiben: %s", p.paths.EnvFile, strings.Join(keys, ",")))
	}
	if len(want) == 0 {
		// Still write an empty file: the unit references it, and an absent
		// EnvironmentFile is a failed service start, not a warning.
		s.Reason = "keine Modul-Zugangsdaten nötig"
	}
	store := secrets.New(p.paths.EnvFile)
	header := []string{
		"Verwaltet von caddyEvolved – Änderungen über die WebUI oder `caddyevolved secrets set`.",
		"Rechte 0600, nur der caddy-Prozess liest diese Datei.",
	}
	changes, err := store.Apply(secrets.Apply{
		Wanted: want,
		Header: strings.Join(header, "\n"),
	})
	if err != nil {
		return err
	}
	var touched []string
	for _, c := range changes {
		if c.Kind != "unchanged" {
			touched = append(touched, c.Key+":"+c.Kind)
		}
	}
	if len(touched) > 0 {
		p.opts.Logf("env: %s", strings.Join(touched, ", "))
	}
	return nil
}

// stepBinary installs caddy and the caddyevolved service binary.
func (p *Plan) stepBinary(ctx context.Context, s *Step) error {
	// A caddy that is already there needs no release lookup: the GitHub API
	// is rate limited and may be unreachable (fresh container, air gap).
	if p.resolved.foundBinary != "" && !p.opts.Force && !p.opts.DryRun && len(p.opts.Answers.Plugins) == 0 {
		return skip(s, StatusSkipped, fmt.Sprintf("caddy %s bereits installiert: %s", p.resolved.caddyVersion, p.resolved.foundBinary))
	}
	if err := p.resolveBinary(ctx); err != nil {
		return err
	}
	if p.opts.DryRun {
		return skip(s, StatusPlanned, p.resolved.binaryURL)
	}

	dst := p.paths.CaddyBin
	if p.resolved.foundBinary != "" && !p.opts.Force && p.resolved.modules == nil {
		return skip(s, StatusSkipped, fmt.Sprintf("caddy %s bereits installiert: %s", p.resolved.caddyVersion, p.resolved.foundBinary))
	}

	if p.resolved.slowDownload {
		p.opts.Logf("Achtung: benannter Build wird auf caddyserver.com kompiliert – 1 bis 3 Minuten")
	}
	archive := filepath.Join(os.TempDir(), "caddyevolved-download.tar.gz")
	defer os.Remove(archive)

	var last int64
	_, err := fetch.ToFile(ctx, p.resolved.binaryURL, archive, fetch.Options{
		Digest: p.resolved.binarySHA,
		Progress: func(n int64) {
			if n/mb >= last/mb {
				return
			}
			last = n
			p.opts.Logf("download %.0f MB", float64(n)/mb)
		},
	})
	if err != nil {
		return fmt.Errorf("Download %s: %w", p.resolved.binaryURL, err)
	}
	if err := fetch.ExtractFileFromTarGz(archive, "caddy", dst, 0o755); err != nil {
		return err
	}

	c := caddyctl.New(dst, p.runner)
	v, err := c.Version(ctx)
	if err != nil {
		return fmt.Errorf("installierte binary nicht lauffähig: %w", err)
	}
	if !releases.VersionAtLeast(v, p.resolved.caddyVersion) && v != p.resolved.caddyVersion {
		return fmt.Errorf("caddy %s installiert, erwartet >= %s", v, p.resolved.caddyVersion)
	}
	p.resolved.caddyVersion = v

	// Verify each requested provider really ended up in the binary. This is the
	// check that distinguishes "downloaded a vanilla build by accident".
	for _, id := range p.opts.Answers.Plugins {
		e, ok := plugins.ByID(id)
		if !ok {
			continue
		}
		name := providerName(e.Registr)
		if name == "" {
			continue
		}
		has, err := c.HasModule(ctx, name)
		if err != nil {
			return err
		}
		if !has {
			return fmt.Errorf("Modul %s (%s) fehlt in der Binary – Build unvollständig", e.Name, name)
		}
	}
	if err := p.selfInstall(); err != nil {
		return err
	}
	s.Reason = fmt.Sprintf("caddy %s -> %s", v, dst)
	return nil
}

// stepCaddyfile writes the initial configuration, backing up anything present.
func (p *Plan) stepCaddyfile(ctx context.Context, s *Step) error {
	content, err := p.renderCaddyfile()
	if err != nil {
		return err
	}
	if p.opts.DryRun {
		return skip(s, StatusPlanned, p.paths.Caddyfile)
	}

	existing, err := os.ReadFile(p.paths.Caddyfile)
	if err == nil && string(existing) == content {
		return skip(s, StatusSkipped, "Caddyfile unverändert")
	}

	// Validate what we are about to install, not what is on disk: on a first
	// install the target does not exist yet, and on a rerun the old file may be
	// perfectly valid while the new one is broken.
	// The first site goes into the snippet directory the new file imports, so
	// the validation below covers it as well.
	if site, ok := p.initialSite(); ok {
		if err := sites.WriteInitial(p.paths.SitesFile, p.paths.SitesDir, site); err != nil {
			return fmt.Errorf("erste Site: %w", err)
		}
	} else if err := os.MkdirAll(p.paths.SitesDir, 0o755); err != nil {
		return err
	}
	// 0644: caddy runs as its own user and must read the file.
	tmp := p.paths.Caddyfile + ".caddyevolved-new"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := caddyctl.New(p.paths.CaddyBin, p.runner).Validate(ctx, tmp, "caddyfile"); err != nil {
		return err
	}

	if err == nil && !p.opts.Force {
		backup := p.paths.Caddyfile + ".caddyevolved-backup-" + time.Now().Format("20060102-150405")
		if err := os.WriteFile(backup, existing, 0o640); err != nil {
			return err
		}
		s.Reason = "vorhandenes Caddyfile gesichert: " + filepath.Base(backup)
	}
	return os.Rename(tmp, p.paths.Caddyfile)
}

// stepDaemonConfig persists the state file the daemon and UI read.
func (p *Plan) stepDaemonConfig(ctx context.Context, s *Step) error {
	st, err := config.LoadState(p.paths.StateFile)
	if err != nil {
		return err
	}
	a := p.opts.Answers
	st.Installed = !p.opts.DryRun
	st.CaddyVersion = p.resolved.caddyVersion
	st.BinarySource = a.BinarySource
	st.Enabled = append([]string(nil), a.Plugins...)
	st.Email = a.Email
	st.AdminPort = a.AdminPort
	st.HTTPPort = a.HTTPPort
	st.HTTPSPort = a.HTTPSPort
	st.UIPort = a.UIPort
	st.UIBind = a.UIBind
	st.Managed = a.Managed
	st.Variant = variantOf(a.BinarySource, a.Plugins)
	st.DeployPath = p.paths.Root
	st.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if p.opts.DryRun {
		return skip(s, StatusPlanned, p.paths.StateFile)
	}
	return config.SaveState(p.paths.StateFile, st)
}

func variantOf(source string, ids []string) string {
	switch source {
	case "custom":
		return "custom"
	case "bundle":
		return "bundle"
	default:
		if len(ids) == 0 {
			return "caddy"
		}
		return "standard"
	}
}

// providerName extracts the lego DNS provider name from a Registers string.
func providerName(registers string) string {
	rest, ok := strings.CutPrefix(registers, "dns.provider ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(rest)
}

const mb = 1 << 20
