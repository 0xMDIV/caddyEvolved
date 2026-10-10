package platform

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
)

const (
	runtimeGOOS   = runtime.GOOS
	runtimeGOARCH = runtime.GOARCH
)

func probe(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(b.Bytes())), nil
}
