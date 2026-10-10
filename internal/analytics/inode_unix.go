//go:build unix

package analytics

import (
	"os"
	"syscall"
)

func inodeOf(f *os.File) uint64 {
	st, err := f.Stat()
	if err != nil {
		return 0
	}
	return inodeOfInfo(st)
}

func inodeOfInfo(st os.FileInfo) uint64 {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return uint64(s.Ino)
	}
	return 0
}
