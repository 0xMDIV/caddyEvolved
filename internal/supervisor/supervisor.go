// Package supervisor starts and watches caddy when systemd is not available.
//
// This path exists for --prefix staging installs, containers without systemd,
// and images where a unit file cannot be installed.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"caddyevolved/internal/caddyctl"
)

// Manager owns one supervised caddy process.
type Manager struct {
	bin      string
	config   string
	envFile  string
	logPath  string
	pidFile  string
	adminURL string

	cmd  *exec.Cmd
	done chan error
}

// New prepares a manager. envFile is passed to caddy as extra environment so
// module credentials work in the no-systemd path too.
func New(bin, config, envFile, logPath, pidFile string) *Manager {
	return &Manager{bin: bin, config: config, envFile: envFile, logPath: logPath, pidFile: pidFile}
}

// SetAdminURL points health checks at the admin endpoint of this layout.
func (m *Manager) SetAdminURL(u string) { m.adminURL = u }

// Start launches caddy in a new session so a ctrl-c on the installer does not
// leave an orphan holding ports 80/443.
func (m *Manager) Start(ctx context.Context) (int, error) {
	if pid, running := m.PID(); running {
		return pid, nil
	}
	if err := os.MkdirAll(filepath.Dir(m.logPath), 0o755); err != nil {
		return 0, err
	}
	logFile, err := os.OpenFile(m.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(m.bin, caddyctl.StartArgs(m.config)...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = "/"
	if env, err := m.environment(); err == nil {
		cmd.Env = env
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return 0, fmt.Errorf("start %s: %w", m.bin, err)
	}
	// The child outlives us; close our copy of the fd so log rotation works.
	logFile.Close()

	if err := caddyctl.WritePIDFile(m.pidFile, cmd.Process.Pid); err != nil {
		return cmd.Process.Pid, err
	}
	m.cmd = cmd
	m.done = make(chan error, 1)
	go func() { m.done <- cmd.Wait() }()
	return cmd.Process.Pid, nil
}

// environment merges the process environment with the module credential file,
// which systemd would otherwise inject via EnvironmentFile.
func (m *Manager) environment() ([]string, error) {
	env := os.Environ()
	if m.envFile == "" {
		return env, nil
	}
	f, err := os.Open(m.envFile)
	if os.IsNotExist(err) {
		return env, nil
	}
	if err != nil {
		return env, err
	}
	defer f.Close()
	lines, err := readEnvLines(f)
	if err != nil {
		return env, err
	}
	return append(env, lines...), nil
}

// PID returns the recorded pid and whether that process is alive.
func (m *Manager) PID() (int, bool) {
	pid, err := caddyctl.PIDFile(m.pidFile)
	if err != nil || pid <= 1 {
		return 0, false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return pid, false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return pid, false
	}
	return pid, true
}

// Stop terminates the supervised process, escalating to SIGKILL.
func (m *Manager) Stop(ctx context.Context) error {
	pid, running := m.PID()
	if !running {
		os.Remove(m.pidFile)
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("SIGTERM %d: %w", pid, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, alive := m.PID(); !alive {
			os.Remove(m.pidFile)
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err := proc.Kill(); err != nil {
		return fmt.Errorf("SIGKILL %d: %w", pid, err)
	}
	os.Remove(m.pidFile)
	return nil
}

// Running reports the supervised pid and liveness for the dashboard.
func (m *Manager) Running() (pid int, running bool) { return m.PID() }
