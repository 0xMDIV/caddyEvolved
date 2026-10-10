// Package forge is the client for the caddyforge build service.
//
// The service compiles custom caddy variants (xcaddy is slow and memory
// hungry, so it does not belong on an LXC). A build is async: POST returns a
// job id, the UI polls until downloadReady, and the installer verifies the
// digest before swapping the binary.
package forge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Defaults can be overridden per call or by environment for staging.
var (
	Base      = "https://api.caddyforge.dev/v1"
	Release   = "https://github.com/caddyforge/caddyforge/releases/download"
	TokenEnv  = "CADDYFORGE_TOKEN"
	Endpoint  = "endpoint" // env override for the base URL
)

// Status of a build job.
type Status string

const (
	StatusQueued         Status = "queued"
	StatusBuilding       Status = "building"
	StatusReady          Status = "ready"
	StatusDownloadReady  Status = "downloadReady"
	StatusFailed         Status = "failed"
	StatusCancelled      Status = "cancelled"
)

// Terminated reports whether polling can stop.
func (s Status) Terminated() bool {
	return s == StatusReady || s == StatusDownloadReady || s == StatusFailed || s == StatusCancelled
}

// BuildSpec is the request body.
type BuildSpec struct {
	CaddyVersion string   `json:"caddyVersion,omitempty"`
	Modules      []string `json:"modules"`
	GOOS         string   `json:"goos,omitempty"`
	GOARCH       string   `json:"goarch,omitempty"`
	// Note is echoed back in the job list; use it to name the variant.
	Note string `json:"note,omitempty"`
}

// Job is one build as the service reports it.
type Job struct {
	ID            string   `json:"id"`
	Status        Status   `json:"status"`
	Percent       int      `json:"percent"`
	Stage         string   `json:"stage,omitempty"`
	QueuePos      int      `json:"queuePos,omitempty"`
	ETASeconds    int      `json:"etaSeconds,omitempty"`
	LogTail       []string `json:"logTail,omitempty"`
	Version       string   `json:"version,omitempty"`
	AssetName     string   `json:"assetName,omitempty"`
	Digest        string   `json:"digest,omitempty"`
	Signed        bool     `json:"signed,omitempty"`
	DownloadURL   string   `json:"downloadUrl,omitempty"`
	Error         string   `json:"error,omitempty"`
	CreatedAt     string   `json:"createdAt,omitempty"`
	CompletedAt   string   `json:"completedAt,omitempty"`
}

// Variant is a prebuilt release line (slim/standard/full).
type Variant struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Modules     []string `json:"modules"`
	AssetName   string   `json:"assetName"`
	Digest        string `json:"digest"`
	DownloadURL   string `json:"downloadUrl"`
	Signed        bool   `json:"signed"`
	CaddyVersion  string `json:"caddyVersion"`
}

// Client talks to the service. Token is optional for public endpoints.
type Client struct {
	Base   string
	Token  string
	Proxy  string
	HTTP   *http.Client
}

// New builds a client from environment overrides.
func New() *Client {
	base := Base
	if v := os.Getenv("CADDYFORGE_API"); v != "" {
		base = strings.TrimRight(v, "/")
	}
	return &Client{
		Base:  base,
		Token: os.Getenv(TokenEnv),
		HTTP:  &http.Client{Timeout: 60 * time.Second},
	}
}

// Submit starts a build and returns its job id.
func (c *Client) Submit(ctx context.Context, spec BuildSpec) (Job, error) {
	if len(spec.Modules) == 0 {
		return Job{}, errors.New("forge: build ohne Modulliste ist sinnlos")
	}
	var out Job
	err := c.request(ctx, http.MethodPost, "/builds", spec, &out)
	return out, err
}

// Get fetches one job.
func (c *Client) Get(ctx context.Context, id string) (Job, error) {
	var out Job
	err := c.request(ctx, http.MethodGet, "/builds/"+url.PathEscape(id), nil, &out)
	return out, err
}

// List returns recent jobs of this caller.
func (c *Client) List(ctx context.Context) ([]Job, error) {
	var out struct {
		Jobs []Job `json:"jobs"`
	}
	err := c.request(ctx, http.MethodGet, "/builds", nil, &out)
	return out.Jobs, err
}

// Cancel aborts a queued or running job.
func (c *Client) Cancel(ctx context.Context, id string) error {
	return c.request(ctx, http.MethodPost, "/builds/"+url.PathEscape(id)+"/cancel", nil, nil)
}

// Variants lists prebuilt bundle variants.
func (c *Client) Variants(ctx context.Context) ([]Variant, error) {
	var out struct {
		Variants []Variant `json:"variants"`
	}
	err := c.request(ctx, http.MethodGet, "/variants", nil, &out)
	return out.Variants, err
}

// Download writes the job artifact to dest and verifies its digest. An
// unexpected digest is an error: a half-trusted binary must never reach disk.
func (c *Client) Download(ctx context.Context, job Job, dest string) error {
	if job.DownloadURL == "" {
		return fmt.Errorf("forge: job %s hat keine downloadUrl (status %s)", job.ID, job.Status)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, job.DownloadURL, nil)
	if err != nil {
		return err
	}
	c.authorize(req)
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("forge download: %s", resp.Status)
	}
	tmp := dest + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hasher), io.LimitReader(resp.Body, 512<<20))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	digest := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if job.Digest != "" && !strings.EqualFold(job.Digest, digest) {
		os.Remove(tmp)
		return fmt.Errorf("forge download: Digest abweichend (will %s, hat %s, %d bytes)", job.Digest, digest, n)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// Wait polls a job until it terminates or ctx ends. onProgress sees every
// state change so the UI can render percent and log tail.
func (c *Client) Wait(ctx context.Context, id string, interval time.Duration, onProgress func(Job)) (Job, error) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	var last Job
	for {
		job, err := c.Get(ctx, id)
		if err != nil {
			return last, err
		}
		if job.Status != last.Status || job.Percent != last.Percent {
			last = job
			if onProgress != nil {
				onProgress(job)
			}
		}
		if job.Status.Terminated() {
			if job.Status == StatusFailed {
				return job, fmt.Errorf("forge build fehlgeschlagen: %s", job.Error)
			}
			return job, nil
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(interval):
		}
	}
}

func (c *Client) request(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.authorize(req)

	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("forge %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(raw)))
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (c *Client) authorize(req *http.Request) {
	req.Header.Set("User-Agent", "caddyforge")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}
