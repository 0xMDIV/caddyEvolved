//go:build unix

package api

import (
	"os"
	"syscall"
)

func fileOwner(st os.FileInfo) (int, bool) {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid), true
	}
	return 0, false
}
