//go:build !unix

package api

import "os"

func fileOwner(os.FileInfo) (int, bool) { return 0, false }
