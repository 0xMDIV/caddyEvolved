// Package releases resolves and downloads caddy binaries.
//
// Three sources, in the order an installer should try them:
//  1. official GitHub release (vanilla caddy, checksums published)
//  2. a caddyevolved bundle variant (prebuilt with curated modules)
//  3. caddyserver.com/api/download, which compiles a custom build
//     server-side and is slow (measured ~114 s) — last resort
package releases

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Source names accepted by the installer.
const (
	SourceOfficial = "official"
	SourceBundle   = "bundle"
	SourceCustom   = "custom"
)

// GitHubAPI and ReleaseBase exist so tests and mirrors can point elsewhere.
var (
	GitHubAPI   = "https://api.github.com"
	ReleaseBase = "https://github.com"
	CustomBase  = "https://caddyserver.com/api/download"
)

// httpc avoids the per-request allocations of http.DefaultClient timeouts we
// do want, so set one explicitly.
var httpc = &http.Client{Timeout: 10 * time.Minute}

// Release is the subset of a GitHub release we care about.
type Release struct {
	Tag         string
	Version     string
	Assets      map[string]string // name -> download url
	ChecksumURL string
}

// asset is one GitHub release attachment.
type asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Latest asks GitHub for the newest caddy release.
func Latest(ctx context.Context, repo string) (Release, error) {
	var raw struct {
		TagName string  `json:"tag_name"`
		Assets  []asset `json:"assets"`
	}
	u := fmt.Sprintf("%s/repos/%s/releases/latest", GitHubAPI, repo)
	if err := getJSON(ctx, u, &raw); err != nil {
		return Release{}, fmt.Errorf("latest release of %s: %w", repo, err)
	}
	return build(raw.TagName, raw.Assets), nil
}

// Recent lists the newest stable release tags, newest first.
func Recent(ctx context.Context, repo string, n int) ([]string, error) {
	var raw []struct {
		TagName    string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	u := fmt.Sprintf("%s/repos/%s/releases?per_page=%d", GitHubAPI, repo, n*2)
	if err := getJSON(ctx, u, &raw); err != nil {
		return nil, fmt.Errorf("releases of %s: %w", repo, err)
	}
	var out []string
	for _, r := range raw {
		if r.Draft || r.Prerelease {
			continue
		}
		out = append(out, r.TagName)
		if len(out) == n {
			break
		}
	}
	return out, nil
}

// ByTag resolves a specific version tag, e.g. "v2.11.7".
func ByTag(ctx context.Context, repo, tag string) (Release, error) {
	var raw struct {
		TagName string  `json:"tag_name"`
		Assets  []asset `json:"assets"`
	}
	u := fmt.Sprintf("%s/repos/%s/releases/tags/%s", GitHubAPI, repo, tag)
	if err := getJSON(ctx, u, &raw); err != nil {
		return Release{}, err
	}
	return build(raw.TagName, raw.Assets), nil
}

func build(tag string, assets []asset) Release {
	r := Release{Tag: tag, Version: strings.TrimPrefix(tag, "v"), Assets: map[string]string{}}
	for _, a := range assets {
		r.Assets[a.Name] = a.BrowserDownloadURL
		if strings.HasSuffix(a.Name, "_checksums.txt") {
			r.ChecksumURL = a.BrowserDownloadURL
		}
	}
	return r
}

// ArchiveName is the release asset for an os/arch pair.
//
// caddy publishes linux_armv5/6/7 rather than Go's arm/v5 naming, and "mac"
// instead of "darwin". An unknown variant is an error, not a silent 404 on a
// half-downloaded archive.
func ArchiveName(version, goos, goarch, variant string) (string, error) {
	osName := goos
	if goos == "darwin" {
		osName = "mac"
	}
	arch := goarch
	if goarch == "arm" {
		arch = "armv7"
	}
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	switch variant {
	case "", SourceOfficial:
		return "caddy_" + version + "_" + osName + "_" + arch + ext, nil
	case SourceBundle:
		return "caddyevolved-caddy_" + version + "_" + osName + "_" + arch + ext, nil
	default:
		return "", fmt.Errorf("unknown binary source %q", variant)
	}
}

// AssetNames lists available assets for a release, filtered to tarballs.
func (r Release) AssetNames() []string {
	out := make([]string, 0, len(r.Assets))
	for name := range r.Assets {
		out = append(out, name)
	}
	return out
}

// HasAsset reports whether a name is present.
func (r Release) HasAsset(name string) bool {
	_, ok := r.Assets[name]
	return ok
}

// URL returns the download url for an asset.
func (r Release) URL(name string) (string, error) {
	u, ok := r.Assets[name]
	if !ok {
		return "", fmt.Errorf("release %s has no asset %s (has %d assets)", r.Tag, name, len(r.Assets))
	}
	return u, nil
}

// DownloadChecksums fetches the checksum manifest for a release.
func (r Release) DownloadChecksums(ctx context.Context) ([]byte, error) {
	if r.ChecksumURL == "" {
		return nil, fmt.Errorf("release %s publishes no checksums", r.Tag)
	}
	return raw(ctx, r.ChecksumURL)
}

// CustomURL builds the caddyserver.com download endpoint for a module set.
// Warning: the server compiles this on request (measured ~114 s).
func CustomURL(caddyVersion string, modules []string, goos, goarch string) (string, error) {
	q := url.Values{}
	q.Set("os", goos)
	q.Set("arch", archParam(goos, goarch))
	if caddyVersion != "" {
		q.Set("v", caddyVersion)
	}
	q.Set("p", "github.com/caddyserver/caddy/v2")
	for _, m := range modules {
		q.Add("p", m)
	}
	return CustomBase + "?" + q.Encode(), nil
}

func archParam(goos, goarch string) string {
	if goarch == "arm" {
		return "armv8" // caddyserver's endpoint expects arm variants it names itself
	}
	return goarch
}

// Detect returns the runtime's os/arch pair.
func Detect() (string, string) { return runtime.GOOS, runtime.GOARCH }

// VersionAtLeast compares "2.11.7" style versions.
func VersionAtLeast(v, min string) bool {
	pa, ar := parts(v), parts(min)
	for i := 0; i < 3; i++ {
		if pa[i] != ar[i] {
			return pa[i] > ar[i]
		}
	}
	return true
}

func parts(v string) [3]int {
	var out [3]int
	for i, p := range strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3) {
		if i > 2 {
			break
		}
		digits := regexp.MustCompile(`^\d+`).FindString(p)
		n, _ := strconv.Atoi(digits)
		out[i] = n
	}
	return out
}

func getJSON(ctx context.Context, u string, dst any) error {
	body, err := raw(ctx, u)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}

func raw(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "caddyevolved")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return body, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return body, nil
}
