// Package cloudflare creates the DNS record a new site needs.
//
// Only what is missing is added: a name that already has an A, AAAA or
// CNAME record keeps its target, only the proxy flag follows the site. A
// record we create carries a comment so it can be told apart in the
// Cloudflare dashboard.
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"caddyevolved/internal/accesslog"
)

// APIBase is the Cloudflare v4 API.
const APIBase = "https://api.cloudflare.com/client/v4"

// Comment marks records created by caddyEvolved.
const Comment = "angelegt von caddyEvolved"

// Config is stored in /etc/caddyevolved/cloudflare.json, readable by the
// daemon only.
type Config struct {
	// APIToken is a scoped token (Zone:Read, DNS:Edit) or, with Email, the
	// Global API Key.
	APIToken string `json:"apiToken,omitempty"`
	Email    string `json:"email,omitempty"`
	// Target is what new records point at: an IPv4 (A), IPv6 (AAAA) or a
	// host name (CNAME). Empty means this host's public IPv4.
	Target string `json:"target,omitempty"`
	// Proxied is the default for new sites (orange cloud).
	Proxied bool `json:"proxied"`
}

// Public is the configuration as the UI sees it: the token only as a hint.
func (c Config) Public() map[string]any {
	hint := ""
	if c.APIToken != "" {
		hint = accesslog.RedactValue(c.APIToken)
	}
	return map[string]any{"keyHint": hint, "email": c.Email, "target": c.Target, "proxied": c.Proxied}
}

// Validate checks a configuration before it is stored.
func (c Config) Validate() error {
	t := strings.TrimSpace(c.Target)
	if t == "" || net.ParseIP(t) != nil {
		return nil
	}
	if strings.ContainsAny(t, "/: ") || !strings.Contains(t, ".") {
		return errors.New("Ziel: IPv4, IPv6 oder Hostname ohne http:// und Port")
	}
	return nil
}

// LoadConfig reads the settings; a missing file is an empty configuration.
func LoadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(data, &c)
}

// SaveConfig writes the settings with mode 0600.
func SaveConfig(path string, c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RecordType is the type a record pointing at target gets.
func RecordType(target string) string {
	ip := net.ParseIP(target)
	switch {
	case ip == nil:
		return "CNAME"
	case ip.To4() != nil:
		return "A"
	default:
		return "AAAA"
	}
}

// HostName reduces a site address to the DNS name, or "" when it has none
// worth a public record (":8080", IPs, "nas.lan" without a zone is left to
// the zone lookup).
func HostName(addr string) string {
	a := strings.TrimSpace(strings.ToLower(addr))
	if i := strings.Index(a, "://"); i >= 0 {
		a = a[i+3:]
	}
	a, _, _ = strings.Cut(a, "/")
	if h, _, err := net.SplitHostPort(a); err == nil {
		a = h
	}
	a = strings.TrimSuffix(a, ".")
	if a == "" || net.ParseIP(strings.Trim(a, "[]")) != nil || !strings.Contains(a, ".") || a == "localhost" {
		return ""
	}
	return a
}

// Zone is a Cloudflare zone.
type Zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Record is a DNS record.
type Record struct {
	ID        string `json:"id,omitempty"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Content   string `json:"content"`
	Proxied   bool   `json:"proxied"`
	Proxiable bool   `json:"proxiable,omitempty"`
	TTL       int    `json:"ttl,omitempty"`
	Comment   string `json:"comment,omitempty"`
}

// Result is what happened to one name.
type Result struct {
	Name    string `json:"name"`
	Action  string `json:"action"` // created | updated | exists | skipped | error
	Zone    string `json:"zone,omitempty"`
	Type    string `json:"type,omitempty"`
	Content string `json:"content,omitempty"`
	Proxied bool   `json:"proxied"`
	Message string `json:"message,omitempty"`
}

// Client talks to the API.
type Client struct {
	cfg  Config
	base string
	http *http.Client
}

// New returns a client; base "" is the public API.
func New(c Config, base string) *Client {
	if base == "" {
		base = APIBase
	}
	return &Client{cfg: c, base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 20 * time.Second}}
}

type envelope struct {
	Success bool            `json:"success"`
	Errors  []apiError      `json:"errors"`
	Result  json.RawMessage `json:"result"`
	Info    struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) (envelope, error) {
	var env envelope
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return env, err
		}
		rd = strings.NewReader(string(data))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return env, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.Email != "" {
		req.Header.Set("X-Auth-Email", c.cfg.Email)
		req.Header.Set("X-Auth-Key", c.cfg.APIToken)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return env, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return env, err
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return env, fmt.Errorf("Cloudflare: HTTP %d, unerwartete Antwort", resp.StatusCode)
	}
	if !env.Success {
		var msgs []string
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%s (%d)", e.Message, e.Code))
		}
		if len(msgs) == 0 {
			msgs = append(msgs, fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
		return env, errors.New("Cloudflare: " + strings.Join(msgs, "; "))
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return env, fmt.Errorf("Cloudflare: %w", err)
		}
	}
	return env, nil
}

// Zones lists every zone the credentials can see.
func (c *Client) Zones(ctx context.Context) ([]Zone, error) {
	var all []Zone
	for page := 1; page <= 50; page++ {
		var zs []Zone
		env, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/zones?per_page=50&page=%d", page), nil, &zs)
		if err != nil {
			return nil, err
		}
		all = append(all, zs...)
		if env.Info.TotalPages <= page {
			break
		}
	}
	return all, nil
}

// ZoneFor picks the zone a name belongs to: the longest matching suffix,
// so sub.example.com wins over example.com when both are zones.
func ZoneFor(zones []Zone, name string) (Zone, bool) {
	var best Zone
	for _, z := range zones {
		zn := strings.ToLower(z.Name)
		if (name == zn || strings.HasSuffix(name, "."+zn)) && len(zn) > len(best.Name) {
			best = Zone{ID: z.ID, Name: zn}
		}
	}
	return best, best.ID != ""
}

// Ensure makes every name resolve via Cloudflare: missing records are
// created towards target, existing ones only get the proxy flag adjusted.
func (c *Client) Ensure(ctx context.Context, names []string, target string, proxied bool) []Result {
	var out []Result
	var zones []Zone
	var zerr error
	loaded := false
	seen := map[string]bool{}
	for _, raw := range names {
		name := HostName(raw)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if !loaded {
			zones, zerr = c.Zones(ctx)
			loaded = true
		}
		if zerr != nil {
			out = append(out, Result{Name: name, Action: "error", Message: zerr.Error()})
			continue
		}
		out = append(out, c.ensureOne(ctx, zones, name, target, proxied))
	}
	return out
}

func (c *Client) ensureOne(ctx context.Context, zones []Zone, name, target string, proxied bool) Result {
	r := Result{Name: name, Proxied: proxied}
	z, ok := ZoneFor(zones, name)
	if !ok {
		r.Action, r.Message = "skipped", "keine passende Zone in diesem Cloudflare-Konto"
		return r
	}
	r.Zone = z.Name
	var recs []Record
	if _, err := c.do(ctx, http.MethodGet, "/zones/"+z.ID+"/dns_records?per_page=100&name="+url.QueryEscape(name), nil, &recs); err != nil {
		r.Action, r.Message = "error", err.Error()
		return r
	}
	for _, rec := range recs {
		if rec.Type != "A" && rec.Type != "AAAA" && rec.Type != "CNAME" {
			continue
		}
		r.Type, r.Content, r.Proxied = rec.Type, rec.Content, rec.Proxied
		if rec.Proxied == proxied || (proxied && !rec.Proxiable) {
			if r.Action == "" {
				r.Action = "exists"
			}
			if proxied && !rec.Proxiable {
				r.Message = "Eintrag lässt sich nicht über Cloudflare leiten"
			}
			continue
		}
		patch := map[string]any{"proxied": proxied}
		if _, err := c.do(ctx, http.MethodPatch, "/zones/"+z.ID+"/dns_records/"+rec.ID, patch, nil); err != nil {
			r.Action, r.Message = "error", err.Error()
			return r
		}
		r.Action, r.Proxied = "updated", proxied
	}
	if r.Action != "" {
		return r
	}
	if target == "" {
		r.Action, r.Message = "error", "kein Ziel: öffentliche IP nicht ermittelbar, bitte in den Einstellungen eintragen"
		return r
	}
	rec := Record{Type: RecordType(target), Name: name, Content: target, Proxied: proxied, TTL: 1, Comment: Comment}
	var created Record
	if _, err := c.do(ctx, http.MethodPost, "/zones/"+z.ID+"/dns_records", rec, &created); err != nil {
		r.Action, r.Message = "error", err.Error()
		return r
	}
	r.Action, r.Type, r.Content, r.Proxied = "created", rec.Type, rec.Content, created.Proxied
	return r
}
