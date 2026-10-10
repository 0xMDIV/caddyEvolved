package caddyctl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Admin is a client for caddy's configuration API (default localhost:2019).
// It is read-mostly: the Caddyfile on disk stays the source of truth, the API
// gives us runtime state and a zero-downtime reload path.
type Admin struct {
	base string
	http *http.Client
}

// NewAdmin points at a base URL such as "http://127.0.0.1:2019".
func NewAdmin(base string) *Admin {
	return &Admin{
		base: strings.TrimRight(base, "/"),
		http: &http.Client{Timeout: 10 * time.Second},
	}
}

// Config is the live JSON config; nil when caddy runs a Caddyfile only.
func (a *Admin) Config(ctx context.Context) (json.RawMessage, error) {
	return a.get(ctx, "/config/")
}

// Revisions lists the config revision history kept in memory.
func (a *Admin) Revisions(ctx context.Context) (json.RawMessage, error) {
	return a.get(ctx, "/config/revisions")
}

// Certificates returns the managed TLS certificates as reported by the API.
func (a *Admin) Certificates(ctx context.Context) ([]Certificate, error) {
	raw, err := a.get(ctx, "/pki/certificates/local")
	if err != nil {
		return nil, err
	}
	var docs []struct {
		SANs        []string `json:"sans"`
		IssuerKey   string   `json:"issuer_key"`
		NotBefore   time.Time `json:"not_before"`
		NotAfter    time.Time `json:"not_after"`
	}
	if err := json.Unmarshal(raw, &docs); err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}
	out := make([]Certificate, 0, len(docs))
	for _, d := range docs {
		out = append(out, Certificate{
			SANs:        d.SANs,
			Issuer:      d.IssuerKey,
			NotBefore:   d.NotBefore,
			NotAfter:    d.NotAfter,
			ExpiresInDays: int(time.Until(d.NotAfter).Hours() / 24),
		})
	}
	return out, nil
}

// Certificate is one TLS cert as the API exposes it.
type Certificate struct {
	SANs          []string  `json:"sans"`
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"notBefore"`
	NotAfter      time.Time `json:"notAfter"`
	ExpiresInDays int       `json:"expiresInDays"`
}

// Restart triggers a graceful process restart through the API.
func (a *Admin) Restart(ctx context.Context) error {
	_, err := a.do(ctx, http.MethodPost, "/restart", nil)
	return err
}

// LoadConfig replaces the live config via POST /load. Used for reloads that
// must not touch the Caddyfile (API-managed installs).
func (a *Admin) LoadConfig(ctx context.Context, config json.RawMessage) error {
	_, err := a.do(ctx, http.MethodPost, "/load", config)
	return err
}

// Sync reports whether caddy is answering on the admin endpoint.
func (a *Admin) Sync(ctx context.Context) error {
	_, err := a.get(ctx, "/")
	return err
}

func (a *Admin) get(ctx context.Context, path string) (json.RawMessage, error) {
	return a.do(ctx, http.MethodGet, path, nil)
}

func (a *Admin) do(ctx context.Context, method, path string, body []byte) (json.RawMessage, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return raw, fmt.Errorf("admin %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}
