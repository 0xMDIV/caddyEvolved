// Package selfupdate replaces the caddyevolved binary with a published
// release: same archive, same SHA256SUMS check as install.sh, atomic swap with
// the previous binary kept next to it. Restarting the service is the caller's
// job, because the daemon and the CLI do that differently.
package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"caddyevolved/internal/fetch"
	"caddyevolved/internal/releases"
)

// Repo is where releases are published.
const Repo = "0xMDIV/caddyEvolved"

// Info compares the running version with the newest release.
type Info struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest"`
	Available bool      `json:"available"`
	Dev       bool      `json:"dev"`
	NotesURL  string    `json:"notesUrl"`
	CheckedAt time.Time `json:"checkedAt"`
}

// IsDev reports a build that did not come from a release tag.
func IsDev(v string) bool { return v == "" || v == "dev" || strings.Contains(v, "-") }

// Newer reports whether release version a is newer than the running b. A dev
// build counts as older than the release with the same number.
func Newer(a, b string) bool {
	base := strings.SplitN(b, "-", 2)[0]
	if a == base {
		return IsDev(b)
	}
	return releases.VersionAtLeast(a, base)
}

// Check asks GitHub for the newest release.
func Check(ctx context.Context, current string) (Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	rel, err := releases.Latest(ctx, Repo)
	if err != nil {
		return Info{Current: current, Dev: IsDev(current)}, err
	}
	return Info{
		Current:   current,
		Latest:    rel.Version,
		Available: Newer(rel.Version, current),
		Dev:       IsDev(current),
		NotesURL:  "https://github.com/" + Repo + "/releases/tag/" + rel.Tag,
		CheckedAt: time.Now().UTC(),
	}, nil
}

// ArchiveName is the release asset for this machine.
func ArchiveName(version string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("Updates gibt es nur für Linux, nicht für %s", runtime.GOOS)
	}
	switch runtime.GOARCH {
	case "amd64", "arm64":
	default:
		return "", fmt.Errorf("für %s gibt es kein Release-Archiv", runtime.GOARCH)
	}
	return fmt.Sprintf("caddyevolved_%s_linux_%s.tar.gz", version, runtime.GOARCH), nil
}

// Apply downloads version ("" = newest), verifies it against SHA256SUMS,
// checks the new binary starts, and swaps it in for bin. The old binary stays
// as bin.prev. It returns the installed version.
func Apply(ctx context.Context, version, bin string, logf func(string)) (string, error) {
	if logf == nil {
		logf = func(string) {}
	}
	var rel releases.Release
	var err error
	if version == "" {
		rel, err = releases.Latest(ctx, Repo)
	} else {
		rel, err = releases.ByTag(ctx, Repo, "v"+strings.TrimPrefix(version, "v"))
	}
	if err != nil {
		return "", fmt.Errorf("Release abrufen: %w", err)
	}
	name, err := ArchiveName(rel.Version)
	if err != nil {
		return "", err
	}
	archiveURL, err := rel.URL(name)
	if err != nil {
		return "", err
	}
	sumsURL, err := rel.URL("SHA256SUMS")
	if err != nil {
		return "", errors.New("das Release veröffentlicht keine SHA256SUMS – Update abgelehnt")
	}

	// Download into a temp dir; only the final copy lands next to bin, so the
	// rename that swaps it in stays on one filesystem.
	tmp, err := os.MkdirTemp("", "caddyevolved-update-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	logf("Prüfsummen laden")
	sumsPath := filepath.Join(tmp, "SHA256SUMS")
	if _, err := fetch.ToFile(ctx, sumsURL, sumsPath, fetch.Options{Timeout: time.Minute}); err != nil {
		return "", err
	}
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return "", err
	}
	digest, err := fetch.ParseChecksumFile(sums, name)
	if err != nil {
		return "", err
	}

	logf("caddyevolved " + rel.Version + " laden")
	archive := filepath.Join(tmp, name)
	if _, err := fetch.ToFile(ctx, archiveURL, archive, fetch.Options{Digest: digest, Timeout: 5 * time.Minute}); err != nil {
		return "", err
	}
	logf("Prüfsumme ok")

	staged := filepath.Join(tmp, "caddyevolved")
	if err := fetch.ExtractFileFromTarGz(archive, "caddyevolved", staged, 0o755); err != nil {
		return "", err
	}
	// The new binary has to start before it replaces a working one.
	out, err := exec.CommandContext(ctx, staged, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(out), rel.Version) {
		return "", fmt.Errorf("neue Binary startet nicht sauber: %v %s", err, strings.TrimSpace(string(out)))
	}

	// Keep the previous binary for a manual rollback, then swap atomically.
	prev := bin + ".prev"
	_ = os.Remove(prev)
	if err := os.Link(bin, prev); err != nil {
		logf("Hinweis: alte Binary nicht gesichert (" + err.Error() + ")")
	}
	next := bin + ".new"
	if err := copyFile(staged, next, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(next, bin); err != nil {
		os.Remove(next)
		return "", fmt.Errorf("Binary tauschen: %w", err)
	}
	logf("installiert: " + bin)
	return rel.Version, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, mode); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}
