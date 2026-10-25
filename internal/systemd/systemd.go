// Package systemd manages service units through systemctl.
package systemd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"caddyevolved/internal/cmdx"
)

// Unit is a rendered service file.
type Unit struct {
	Name string
	Body string
}

// Service exposes the operations the installer and daemon need.
type Service struct {
	runner cmdx.Runner
	units  string
}

// New builds a Service writing units into unitsDir (normally
// /etc/systemd/system, or the staging prefix during a --root install).
func New(runner cmdx.Runner, unitsDir string) *Service {
	return &Service{runner: runner, units: unitsDir}
}

// Available reports whether systemctl can talk to a running systemd.
func (s *Service) Available(ctx context.Context) bool {
	out, err := s.runner.Output(ctx, cmdx.Cmd{Name: "systemctl", Args: []string{"is-system-running"}})
	if err != nil {
		return false
	}
	state := strings.TrimSpace(string(out))
	return state == "running" || state == "degraded" || state == "starting"
}

// InstallUnit writes the unit, reloads systemd and re-reads dependencies.
func (s *Service) InstallUnit(ctx context.Context, u Unit) error {
	if err := s.Write(u); err != nil {
		return err
	}
	return s.DaemonReload(ctx)
}

// Write places a unit file without touching systemctl. Staging trees need this:
// a --prefix install must not make the live systemd read files that belong to a
// test layout, and a non-root caller could not reload it anyway.
func (s *Service) Write(u Unit) error {
	if err := os.MkdirAll(s.units, 0o755); err != nil {
		return err
	}
	path := filepath.Join(s.units, u.Name)
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(u.Body), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RemoveUnit deletes a unit file if present, then reloads.
func (s *Service) RemoveUnit(ctx context.Context, name string) error {
	path := filepath.Join(s.units, name)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return s.DaemonReload(ctx)
}

func (s *Service) DaemonReload(ctx context.Context) error {
	return s.runner.Run(ctx, cmdx.Cmd{Name: "systemctl", Args: []string{"daemon-reload"}})
}

func (s *Service) Enable(ctx context.Context, name string) error {
	return s.runner.Run(ctx, cmdx.Cmd{Name: "systemctl", Args: []string{"enable", name}})
}

func (s *Service) Disable(ctx context.Context, name string) error {
	return s.runner.Run(ctx, cmdx.Cmd{Name: "systemctl", Args: []string{"disable", "--now", name}})
}

func (s *Service) Start(ctx context.Context, name string) error {
	return s.runner.Run(ctx, cmdx.Cmd{Name: "systemctl", Args: []string{"start", name}})
}

func (s *Service) Stop(ctx context.Context, name string) error {
	return s.runner.Run(ctx, cmdx.Cmd{Name: "systemctl", Args: []string{"stop", name}})
}

func (s *Service) Restart(ctx context.Context, name string) error {
	return s.runner.Run(ctx, cmdx.Cmd{Name: "systemctl", Args: []string{"restart", name}})
}

func (s *Service) Reload(ctx context.Context, name string) error {
	return s.runner.Run(ctx, cmdx.Cmd{Name: "systemctl", Args: []string{"reload", name}})
}

// ReloadOrRestart falls back where a unit has no ExecReload.
func (s *Service) ReloadOrRestart(ctx context.Context, name string) error {
	if err := s.Reload(ctx, name); err != nil {
		return s.Restart(ctx, name)
	}
	return nil
}

// Status returns the summary line and active state for a unit.
func (s *Service) Status(ctx context.Context, name string) (summary string, active string, err error) {
	out, err := s.runner.Output(ctx, cmdx.Cmd{Name: "systemctl", Args: []string{"show", name, "--no-pager", "--property=ActiveState,SubState,MainPID,ExecMainStartTimestamp,Description,UnitFileState"}})
	if err != nil {
		return "", "", err
	}
	props := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			props[k] = v
		}
	}
	active = props["ActiveState"]
	if props["SubState"] != "" {
		active += "/" + props["SubState"]
	}
	summary = fmt.Sprintf("%s (%s) pid=%s enabled=%s", props["Description"], active, props["MainPID"], props["UnitFileState"])
	return summary, active, nil
}

// IsActive is the boolean form used by health checks.
func (s *Service) IsActive(ctx context.Context, name string) bool {
	return s.runner.Run(ctx, cmdx.Cmd{Name: "systemctl", Args: []string{"is-active", "--quiet", name}}) == nil
}

// Journal returns the last lines of a unit's log. --no-pager keeps it stable
// for capture, and the count guard stops a huge output from reaching the UI.
func (s *Service) Journal(ctx context.Context, unit string, lines int) (string, error) {
	if lines <= 0 || lines > 1000 {
		lines = 50
	}
	out, err := s.runner.Output(ctx, cmdx.Cmd{
		Name: "journalctl",
		Args: []string{"--no-pager", "--lines", strconv.Itoa(lines), "-u", unit},
	})
	return string(out), err
}
