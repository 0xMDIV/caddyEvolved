//go:build !unix

package builder

import (
	"os/exec"
	"time"
)

func prepareCmd(cmd *exec.Cmd) { cmd.WaitDelay = 10 * time.Second }
