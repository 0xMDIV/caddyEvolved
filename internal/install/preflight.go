package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"caddyforge/internal/caddyctl"
	"caddyforge/internal/fetch"
	"caddyforge/internal/platform"
	"caddyforge/internal/plugins"
	"caddyforge/internal/releases"
)

// skip marks a step without failing the plan; the plan honours our status.
func skip(s *Step, status Status, reason string) error {
	s.Status = status
	s.Reason = reason
	return errSkip
}

func (p *Plan) stepPreflight(ctx context.Context, s *Step) error {
	var problems []string

	if !p.paths.IsPrefixed() && !p.host.IsRoot {
		problems = append(problems, "Installation braucht root (oder --prefix für eine staging-installation)")
	}
	if p.host.GOOS != "linux" && !p.paths.IsPrefixed() {
		problems = append(problems, fmt.Sprintf("Zielsystem ist %s, unterstützt ist linux", p.host.GOOS))
	}
	if p.host.Init != platform.InitSystemd && !p.paths.IsPrefixed() {
		problems = append(problems, "systemd nicht erreichbar – im LXC Start-Modus \"systemd\" (init=/sbin/boot) prüfen")
	}

	ports := []int{p.opts.Answers.HTTPPort, p.opts.Answers.HTTPSPort, p.opts.Answers.AdminPort}
	if !p.opts.Answers.UIBehindProxy {
		ports = append(ports, p.opts.Answers.UIPort)
	}
	for _, st := range platform.CheckPorts(ctx, ports...) {
		switch {
		case st.Free:
		case st.Own && !p.opts.Force:
			problems = append(problems, fmt.Sprintf("Port %d belegt von %s – mit --force übernimmt caddyforge den bestehenden Dienst", st.Port, st.UsedBy))
		case st.UsedBy != "":
			problems = append(problems, fmt.Sprintf("Port %d belegt von %s", st.Port, st.UsedBy))
		default:
			problems = append(problems, fmt.Sprintf("Port %d ist belegt", st.Port))
		}
	}
	if !p.host.CanBind && !p.host.IsRoot && (p.opts.Answers.HTTPPort < 1024 || p.opts.Answers.HTTPSPort < 1024) {
		s.Reason = fmt.Sprintf("Ports <1024: als uid %d nur über CAP_NET_BIND_SERVICE in der Unit möglich", p.host.UID)
	}

	// An existing caddy is fine, but we report what we found before touching it.
	if bin, err := caddyctl.Find(p.paths.CaddyBin); err == nil {
		if v, err := caddyctl.New(bin, p.runner).Version(ctx); err == nil {
			p.resolved.caddyVersion = v
			p.resolved.foundBinary = bin
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	if p.resolved.caddyVersion == "" {
		v := strings.TrimPrefix(p.opts.Answers.CaddyVersion, "v")
		if v == "" {
			rel, err := releases.Latest(ctx, "caddyserver/caddy")
			if err != nil {
				return fmt.Errorf("aktuelle caddy-Version ermitteln: %w", err)
			}
			v = rel.Version
		}
		p.resolved.caddyVersion = v
	}
	if p.resolved.foundBinary != "" {
		s.Reason = fmt.Sprintf("caddy %s gefunden: %s", p.resolved.caddyVersion, p.resolved.foundBinary)
	}
	if p.opts.DryRun {
		return skip(s, StatusPlanned, "Trockendurchlauf: "+(s.Reason+"Host geprüft"))
	}
	return nil
}

// resolveBinary decides what gets installed and from where.
func (p *Plan) resolveBinary(ctx context.Context) error {
	a := p.opts.Answers
	res, err := plugins.Resolve(a.Plugins)
	if err != nil {
		return err
	}
	p.resolved.modules = res.Modules

	goos, goarch := releases.Detect()
	switch a.BinarySource {
	case releases.SourceOfficial:
		if len(res.Modules) > 0 {
			return fmt.Errorf("Quelle %q kann keine Module einbinden – diese Auswahl benötigt \"custom\"", a.BinarySource)
		}
		name, err := releases.ArchiveName(p.resolved.caddyVersion, goos, goarch, releases.SourceOfficial)
		if err != nil {
			return err
		}
		p.resolved.binaryURL = fmt.Sprintf("%s/caddyserver/caddy/releases/download/v%s/%s",
			releases.ReleaseBase, p.resolved.caddyVersion, name)
	case releases.SourceBundle:
		return fmt.Errorf("vorgebaute Bundle-Varianten liefert der forge-Builder (M3/M8) – bis dahin \"official\" oder \"custom\"")
	case releases.SourceCustom:
		if len(res.Modules) == 0 {
			return fmt.Errorf("Quelle \"custom\" braucht mindestens ein Modul")
		}
		u, err := releases.CustomURL(p.resolved.caddyVersion, res.Modules, goos, goarch)
		if err != nil {
			return err
		}
		p.resolved.binaryURL = u
		p.resolved.slowDownload = true
	default:
		return fmt.Errorf("unbekannte Quelle %q", a.BinarySource)
	}
	return p.resolveChecksum(ctx)
}

// resolveChecksum pins the digest we will verify the download against.
func (p *Plan) resolveChecksum(ctx context.Context) error {
	switch p.opts.Answers.BinarySource {
	case releases.SourceOfficial:
		rel, err := releases.ByTag(ctx, "caddyserver/caddy", "v"+p.resolved.caddyVersion)
		if err != nil {
			return err
		}
		manifest, err := rel.DownloadChecksums(ctx)
		if err != nil {
			return err
		}
		goos, goarch := releases.Detect()
		name, err := releases.ArchiveName(p.resolved.caddyVersion, goos, goarch, releases.SourceOfficial)
		if err != nil {
			return err
		}
		sha, err := fetch.ParseChecksumFile(manifest, name)
		if err != nil {
			return err
		}
		p.resolved.binarySHA = sha
		return nil
	default:
		// Custom builds from caddyserver.com ship without a manifest; we record
		// the digest we saw and verify it on the next rerun.
		return nil
	}
}

// selfInstall copies the running binary to the target path so the unit has a
// stable location and an upgrade replaces a known file.
func (p *Plan) selfInstall() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("eigener Pfad: %w", err)
	}
	if sameFile(exe, p.paths.Bin) {
		return nil
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	tmp := p.paths.Bin + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, p.paths.Bin)
}

func sameFile(a, b string) bool {
	sa, ea := os.Stat(a)
	sb, eb := os.Stat(b)
	if ea != nil || eb != nil {
		return false
	}
	return os.SameFile(sa, sb)
}
