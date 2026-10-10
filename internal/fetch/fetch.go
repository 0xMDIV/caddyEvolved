// Package fetch downloads files with integrity checks and atomic installs.
package fetch

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
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
	// Digest is the expected digest, either prefixed ("sha256:<hex>",
	// "sha512:<hex>") or bare hex whose length names the algorithm. Empty skips
	// verification, which is only acceptable for sources that publish none.
	Digest string
	// UserAgent identifies us to release hosts.
	UserAgent string
	Timeout   time.Duration
	// Progress receives bytes transferred so far.
	Progress func(n int64)
}

// ErrChecksum means the downloaded bytes did not match the published digest.
var ErrChecksum = errors.New("checksum mismatch")

// Algorithm names the hash a digest was written in.
type Algorithm string

const (
	SHA256 Algorithm = "sha256"
	SHA512 Algorithm = "sha512"
)

// ParseDigest normalises a digest as published by a release host. Caddy ships
// SHA-512 in caddy_<ver>_checksums.txt while its per-file JSON and our own build
// service use SHA-256, so guessing one of the two would fail every install that
// crossed the boundary — the length decides instead.
func ParseDigest(digest string) (Algorithm, string, error) {
	digest = strings.TrimSpace(digest)
	if digest == "" {
		return "", "", errors.New("digest ist leer")
	}
	alg, hexPart, hasPrefix := strings.Cut(digest, ":")
	alg = strings.ToLower(strings.TrimSpace(alg))
	if !hasPrefix {
		hexPart = digest
		switch len(hexPart) {
		case 64:
			alg = string(SHA256)
		case 128:
			alg = string(SHA512)
		default:
			return "", "", fmt.Errorf("digest %q: weder sha256 (64) noch sha512 (128) Zeichen", digest)
		}
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return "", "", fmt.Errorf("digest %q: %w", digest, err)
	}
	switch Algorithm(alg) {
	case SHA256, SHA512:
		return Algorithm(alg), strings.ToLower(hexPart), nil
	default:
		return "", "", fmt.Errorf("Digest-Algorithmus %q nicht unterstützt (nur sha256, sha512)", alg)
	}
}

// DefaultUserAgent is set from buildinfo at init to keep this package leaf-free.
var DefaultUserAgent = "caddyevolved"

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

	sum256 := sha256.New()
	sum512 := sha512.New()
	hasher := io.MultiWriter(sum256, sum512)
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

	if o.Digest != "" {
		alg, want, perr := ParseDigest(o.Digest)
		if perr != nil {
			return written, fmt.Errorf("%s: %w", url, perr)
		}
		var got string
		switch alg {
		case SHA512:
			got = hex.EncodeToString(sum512.Sum(nil))
		default:
			got = hex.EncodeToString(sum256.Sum(nil))
		}
		if !strings.EqualFold(got, want) {
			return written, fmt.Errorf("%w (%s): %s want %s got %s", ErrChecksum, alg, url, want, got)
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

// ParseChecksumFile reads a "<hash>  <name>" manifest and returns the digest for
// name, prefixed with its algorithm.
//
// The algorithm is read from the line, never assumed: caddy_<ver>_checksums.txt
// publishes SHA-512 while other release hosts publish SHA-256 for the same
// archive, and a hardcoded guess rejects a perfectly good download.
func ParseChecksumFile(manifest []byte, name string) (string, error) {
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.HasSuffix(fields[1], name) || fields[1] == name {
			alg, hexPart, err := ParseDigest(fields[0])
			if err != nil {
				return "", fmt.Errorf("%s: %w", name, err)
			}
			return string(alg) + ":" + hexPart, nil
		}
	}
	return "", fmt.Errorf("no checksum entry for %s", name)
}
