//go:build unix

package builder

import (
	"os/exec"
	"syscall"
	"time"
)

// prepareCmd puts the child into its own process group so a cancel kills the
// whole go toolchain tree (compile, link, vcs helpers), not just xcaddy.
func prepareCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 10 * time.Second
}
