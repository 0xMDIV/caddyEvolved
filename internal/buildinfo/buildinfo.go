// Package buildinfo carries version metadata injected at link time.
package buildinfo

import (
	"fmt"
	"runtime"
)

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String is the human one-liner; Long includes the toolchain.
func String() string {
	return fmt.Sprintf("caddyevolved %s (%s) %s/%s go%s", Version, Commit, runtime.GOOS, runtime.GOARCH, runtime.Version()[2:])
}
