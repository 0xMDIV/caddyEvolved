package install

import (
	"bytes"
	"context"
	_ "embed"
	"strings"
	"text/template"

	"caddyforge/internal/platform"
	"caddyforge/internal/systemd"
)

//go:embed templates/caddy.service.tmpl
var caddyUnitTmpl string

//go:embed templates/caddyforge.service.tmpl
var forgeUnitTmpl string

// unitData feeds the service templates.
type unitData struct {
	CaddyBin    string
	ForgeBin    string
	Caddyfile   string
	EnvFile     string
	AdminPort   int
	HTTPPort    int
	HTTPSPort   int
	UIPort      int
	UIBind      string
	User        string
	Group       string
	StateDir    string
	LogFile     string
	BindLowPort bool
	PIDFile     string
}

func (p *Plan) unitValues() unitData {
	a := p.opts.Answers
	bin := p.paths.CaddyBin
	if p.resolved.foundBinary != "" && !p.opts.Force {
		bin = p.resolved.foundBinary
	}
	return unitData{
		CaddyBin:    bin,
		ForgeBin:    p.paths.Bin,
		Caddyfile:   p.paths.Caddyfile,
		EnvFile:     p.paths.EnvFile,
		AdminPort:   a.AdminPort,
		HTTPPort:    a.HTTPPort,
		HTTPSPort:   a.HTTPSPort,
		UIPort:      a.UIPort,
		UIBind:      a.UIBind,
		User:        "caddy",
		Group:       "caddy",
		StateDir:    p.paths.CaddyData,
		LogFile:     p.paths.LogFile,
		BindLowPort: a.HTTPPort < 1024 || a.HTTPSPort < 1024,
		PIDFile:     p.paths.PIDFile,
	}
}

// stepUnits installs both service files.
func (p *Plan) stepUnits(ctx context.Context, s *Step) error {
	if p.host.Init != platform.InitSystemd {
		return skip(s, StatusSkipped, "kein systemd – Dienste mit `caddyforge start` und `caddyforge serve` laufen lassen")
	}
	units, err := p.renderUnits()
	if err != nil {
		return err
	}
	if p.opts.DryRun {
		return skip(s, StatusPlanned, strings.Join(unitNames(units), ", "))
	}
	svc := systemd.New(p.runner, p.paths.UnitsDir)
	if p.paths.IsPrefixed() {
		// The staging tree gets the files only: pointing the host's systemd at a
		// test layout would start a second caddy on the real ports.
		for _, u := range units {
			if err := svc.Write(u); err != nil {
				return err
			}
		}
		s.Reason = "nur geschrieben (Prefix): " + strings.Join(unitNames(units), ", ")
		return nil
	}
	for _, u := range units {
		if err := svc.InstallUnit(ctx, u); err != nil {
			return err
		}
	}
	s.Reason = "installiert: " + strings.Join(unitNames(units), ", ")
	return nil
}

func unitNames(units []systemd.Unit) []string {
	out := make([]string, 0, len(units))
	for _, u := range units {
		out = append(out, u.Name)
	}
	return out
}

func (p *Plan) renderUnits() ([]systemd.Unit, error) {
	v := p.unitValues()
	caddyBody, err := renderUnit("caddy.service.tmpl", caddyUnitTmpl, v)
	if err != nil {
		return nil, err
	}
	forgeBody, err := renderUnit("caddyforge.service.tmpl", forgeUnitTmpl, v)
	if err != nil {
		return nil, err
	}
	return []systemd.Unit{
		{Name: "caddy.service", Body: caddyBody},
		{Name: "caddyforge.service", Body: forgeBody},
	}, nil
}

func renderUnit(name, tmpl string, v unitData) (string, error) {
	t, err := template.New(name).Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := t.Execute(&out, v); err != nil {
		return "", err
	}
	return out.String(), nil
}
