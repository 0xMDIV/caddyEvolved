package builder

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"caddyevolved/internal/fetch"
)

// GoDownloads is the official release index; tests point it elsewhere.
var GoDownloads = "https://go.dev/dl/"

// XcaddyModule is what `go install` fetches for the build driver.
var XcaddyModule = "github.com/caddyserver/xcaddy/cmd/xcaddy@latest"

// ToolchainInfo is what the UI shows before the first build.
type ToolchainInfo struct {
	Go         Tool  `json:"go"`
	Xcaddy     Tool  `json:"xcaddy"`
	CacheBytes int64 `json:"cacheBytes"`
}

// Tool is one installed program.
type Tool struct {
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	Path      string `json:"path,omitempty"`
}

func (m *Manager) goRoot() string    { return filepath.Join(m.dir, "toolchain", "go") }
func (m *Manager) goBin() string     { return filepath.Join(m.goRoot(), "bin", "go") }
func (m *Manager) toolBin() string   { return filepath.Join(m.dir, "toolchain", "bin") }
func (m *Manager) xcaddyBin() string { return filepath.Join(m.toolBin(), "xcaddy") }
func (m *Manager) goPath() string    { return filepath.Join(m.dir, "gopath") }
func (m *Manager) goCache() string   { return filepath.Join(m.dir, "gocache") }
func (m *Manager) tmpDir() string    { return filepath.Join(m.dir, "tmp") }

// buildEnv is the environment of every go/xcaddy child. Everything lives under
// the state directory: the daemon runs with ProtectHome and PrivateTmp, and a
// module cache in /tmp would be thrown away on every restart.
func (m *Manager) buildEnv() []string {
	path := m.goRoot() + "/bin:" + m.toolBin() + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	return []string{
		"PATH=" + path,
		"HOME=" + m.dir,
		"GOPATH=" + m.goPath(),
		"GOCACHE=" + m.goCache(),
		"GOMODCACHE=" + filepath.Join(m.goPath(), "pkg", "mod"),
		"GOENV=off",
		"GOTELEMETRY=off",
		"TMPDIR=" + m.tmpDir(),
		"CGO_ENABLED=0",
		"XCADDY_SETCAP=0",
		"XCADDY_SUDO=0",
		"LANG=C.UTF-8",
	}
}

// Toolchain reports what is installed without changing anything.
func (m *Manager) Toolchain(ctx context.Context) ToolchainInfo {
	var info ToolchainInfo
	if out, err := m.output(ctx, m.goBin(), "version"); err == nil {
		info.Go = Tool{Installed: true, Path: m.goBin(), Version: goVersionField(out)}
	}
	if out, err := m.output(ctx, m.xcaddyBin(), "version"); err == nil {
		info.Xcaddy = Tool{Installed: true, Path: m.xcaddyBin(), Version: strings.TrimSpace(out)}
	}
	info.CacheBytes = dirSize(m.goCache()) + dirSize(m.goPath())
	return info
}

func (m *Manager) output(ctx context.Context, bin string, args ...string) (string, error) {
	if _, err := os.Stat(bin); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = m.buildEnv()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// goVersionField turns "go version go1.27.1 linux/amd64" into "go1.27.1".
func goVersionField(s string) string {
	for _, f := range strings.Fields(s) {
		if strings.HasPrefix(f, "go1") {
			return f
		}
	}
	return strings.TrimSpace(s)
}

// ensureGo installs the newest stable Go into the state directory when none
// is there. The archive is verified against the SHA-256 that go.dev publishes
// in the same index, so a tampered mirror cannot hand us a compiler.
func (m *Manager) ensureGo(ctx context.Context, log func(string)) error {
	if _, err := os.Stat(m.goBin()); err == nil {
		return nil
	}
	log("Go-Toolchain fehlt – lade die aktuelle stabile Version von go.dev")
	file, version, err := latestGo(ctx, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	archive := filepath.Join(m.tmpDir(), file.Filename)
	log(fmt.Sprintf("Lade %s (%d MB, sha256 %s…)", file.Filename, file.Size>>20, file.SHA256[:12]))
	if _, err := fetch.ToFile(ctx, GoDownloads+file.Filename, archive, fetch.Options{Digest: "sha256:" + file.SHA256, Timeout: 15 * time.Minute}); err != nil {
		return fmt.Errorf("Go-Download: %w", err)
	}
	defer os.Remove(archive)
	log("Digest geprüft, entpacke " + version)

	staging := m.goRoot() + ".new"
	os.RemoveAll(staging)
	if err := extractTarGz(archive, staging, "go/"); err != nil {
		os.RemoveAll(staging)
		return fmt.Errorf("Go entpacken: %w", err)
	}
	os.RemoveAll(m.goRoot())
	if err := os.Rename(staging, m.goRoot()); err != nil {
		return err
	}
	log("Go " + version + " installiert unter " + m.goRoot())
	return nil
}

// ensureXcaddy installs the build driver with the toolchain we just ensured.
func (m *Manager) ensureXcaddy(ctx context.Context, log func(string)) error {
	if _, err := os.Stat(m.xcaddyBin()); err == nil {
		return nil
	}
	log("xcaddy fehlt – go install " + XcaddyModule)
	cmd := exec.CommandContext(ctx, m.goBin(), "install", XcaddyModule)
	cmd.Env = append(m.buildEnv(), "GOBIN="+m.toolBin())
	if err := m.stream(cmd, log); err != nil {
		return fmt.Errorf("xcaddy installieren: %w", err)
	}
	return nil
}

type goFile struct {
	Filename string `json:"filename"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Kind     string `json:"kind"`
}

type goRelease struct {
	Version string   `json:"version"`
	Stable  bool     `json:"stable"`
	Files   []goFile `json:"files"`
}

// latestGo picks the first stable release's archive for this platform. The
// index is ordered newest first.
func latestGo(ctx context.Context, goos, goarch string) (goFile, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, GoDownloads+"?mode=json", nil)
	if err != nil {
		return goFile{}, "", err
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return goFile{}, "", fmt.Errorf("go.dev erreichen: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return goFile{}, "", fmt.Errorf("go.dev: %s", resp.Status)
	}
	var rels []goRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&rels); err != nil {
		return goFile{}, "", fmt.Errorf("go.dev-Index: %w", err)
	}
	for _, r := range rels {
		if !r.Stable {
			continue
		}
		for _, f := range r.Files {
			if f.OS == goos && f.Arch == goarch && f.Kind == "archive" && strings.HasSuffix(f.Filename, ".tar.gz") {
				if len(f.SHA256) != 64 {
					return goFile{}, "", fmt.Errorf("go.dev nennt für %s keinen SHA-256", f.Filename)
				}
				return f, r.Version, nil
			}
		}
	}
	return goFile{}, "", fmt.Errorf("keine stabile Go-Version für %s/%s gefunden", goos, goarch)
}

// extractTarGz unpacks every regular file and directory below stripPrefix into
// dest. Links are skipped (the Go archive ships none we need) and any member
// that would land outside dest is refused.
func extractTarGz(archive, dest, stripPrefix string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	root, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name, ok := strings.CutPrefix(hdr.Name, stripPrefix)
		if !ok || name == "" {
			continue
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
			return fmt.Errorf("Archiv-Eintrag außerhalb des Ziels: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o755|0o644)
			if err != nil {
				return err
			}
			_, err = io.Copy(out, io.LimitReader(tr, fetch.MaxSize))
			if cerr := out.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		}
	}
}

func dirSize(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}
