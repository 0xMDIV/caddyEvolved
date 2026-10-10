//go:build !unix

package analytics

import "os"

func inodeOf(*os.File) uint64        { return 0 }
func inodeOfInfo(os.FileInfo) uint64 { return 0 }
