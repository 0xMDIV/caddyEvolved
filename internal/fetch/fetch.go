// Package fetch downloads files with integrity checks and atomic installs.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaxSize guards against a truncated or hostile archive filling the disk.
const MaxSize = 512 << 20

// Options controls one download.
type Options struct {
	// SHA256 is the expected hex digest; empty skips verification.
	SHA256 string
	// UserAgent identifies us to release hosts.
	UserAgent string
	Timeout   time.Duration
	// Progress receives bytes transferred so far.
	Progress func(n int64)
}

// ErrChecksum means the downloaded bytes did not match the published digest.
var ErrChecksum = errors.New("checksum mismatch")

// DefaultUserAgent is set from buildinfo at init to keep this package leaf-free.
var DefaultUserAgent = "caddyforge"

// ToFile downloads url into dest. A temporary file plus rename keeps a
// half-written binary from ever being the one systemd starts.
func ToFile(ctx context.Context, url, dest string, o Options) (int64, error) {
	if o.Timeout == 0 {
		o.Timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	ua := o.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	req.Header.Set("User-Agent", ua)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET %s: %s", url, resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".fetch-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())

	hasher := sha256.New()
	var written int64
	buf := make([]byte, 64*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if written += int64(n); written > MaxSize {
				tmp.Close()
				return written, fmt.Errorf("%s: exceeds %d bytes", url, MaxSize)
			}
			if _, werr := tmp.Write(buf[:n]); werr != nil {
				tmp.Close()
				return written, werr
			}
			hasher.Write(buf[:n])
			if o.Progress != nil {
				o.Progress(written)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			tmp.Close()
			return written, fmt.Errorf("read %s: %w", url, rerr)
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return written, err
	}
	tmp.Close()

	if o.SHA256 != "" {
		got := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(got, strings.TrimSpace(o.SHA256)) {
			return written, fmt.Errorf("%w: %s want %s got %s", ErrChecksum, url, o.SHA256, got)
		}
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return written, err
	}
	return written, os.Rename(tmp.Name(), dest)
}

// DigestFile returns the hex sha256 of a file on disk.
func DigestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ParseChecksumFile reads a "<hash>  <name>" manifest and returns the digest
// for name. GitHub release checksums files use exactly this format.
func ParseChecksumFile(manifest []byte, name string) (string, error) {
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.HasSuffix(fields[1], name) || fields[1] == name {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %s", name)
}
