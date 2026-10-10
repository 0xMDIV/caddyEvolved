package fetch

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// ExtractFileFromTarGz pulls a single member out of a .tar.gz into dest with
// the given mode. Members escaping the destination ("../" tricks) are refused.
func ExtractFileFromTarGz(archivePath, member, dest string, mode os.FileMode) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip %s: %w", archivePath, err)
	}
	defer gz.Close()

	want := strings.TrimPrefix(member, "./")
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar %s: %w", archivePath, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if path.Base(hdr.Name) != want && path.Clean(hdr.Name) != want {
			continue
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		// Bound the member size: a tar bomb declares 0 and streams forever.
		n, err := io.Copy(out, io.LimitReader(tr, MaxSize))
		if err == nil && n == 0 {
			err = fmt.Errorf("%s: member %q is empty", archivePath, hdr.Name)
		}
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(dest)
			return err
		}
		return os.Chmod(dest, mode)
	}
	return fmt.Errorf("%s: member %q not found", archivePath, member)
}
