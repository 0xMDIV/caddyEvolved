package plugins

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ProxyBase is the Go module proxy used to validate free-form module paths.
var ProxyBase = "https://proxy.golang.org"

// modulePathPattern accepts the shapes xcaddy understands: domain, path,
// optional /vN major suffix and an optional @version.
var modulePathPattern = regexp.MustCompile(`^[a-zA-Z0-9.\-_]+(/[a-zA-Z0-9.\-_]+)*(/v[0-9]+)?(@[a-zA-Z0-9.\-_+]+)?$`)

// ModuleCheck is the result of validating one operator-supplied module path.
type ModuleCheck struct {
	Module    string   `json:"module"`
	Path      string   `json:"cleanPath"`
	Version   string   `json:"version,omitempty"`
	Exists    bool     `json:"exists"`
	Known     bool     `json:"inCatalog"`
	Suffix    string   `json:"providerSuffix,omitempty"`
	Env       []EnvVar `json:"env,omitempty"`
	Categories  []string `json:"categories,omitempty"`
	Hint      string   `json:"hint,omitempty"`
	Warning   string   `json:"warning,omitempty"`
}

// ValidateModule normalises a path, checks it against the Go module proxy and
// reports what the catalog already knows about it.
//
// The proxy check matters: "github.com/caddy-dns/cloduflare" fails the build
// only after xcaddy has resolved half the dependency graph, which is minutes
// of the operator's time and a confusing error surface.
func ValidateModule(ctx context.Context, raw string) (ModuleCheck, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ModuleCheck{}, fmt.Errorf("modulpfad ist leer")
	}
	if !modulePathPattern.MatchString(raw) {
		return ModuleCheck{}, fmt.Errorf("keine gültige Go-Modulpfad: %s", raw)
	}
	path, version, _ := strings.Cut(raw, "@")
	check := ModuleCheck{Module: raw, Path: path, Version: version}

	for _, e := range entries {
		if strings.EqualFold(e.Module, path) {
			check.Known = true
			check.Env = e.Env
			check.Categories = append(check.Categories, string(e.Category))
			check.Suffix = providerSuffix(e)
			break
		}
	}

	if strings.HasPrefix(path, "github.com/caddy-dns/") {
		check.Suffix = strings.TrimPrefix(path, "github.com/caddy-dns/")
	}
	if strings.Contains(path, "caddy-storage-") {
		check.Categories = append(check.Categories, string(CatStorage))
	}

	httpc := &http.Client{Timeout: 12 * time.Second}
	u := ProxyBase + "/" + strings.ToLower(path) + "/@latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return check, err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return check, fmt.Errorf("Proxy nicht erreichbar: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusOK {
		var v struct {
			Version string `json:"Version"`
		}
		if err := json.Unmarshal(body, &v); err == nil {
			check.Exists = true
			if check.Version == "" {
				check.Version = v.Version
			}
			check.Hint = "im Go-Modul-Proxy gefunden: " + v.Version
			if !check.Known {
				check.Warning = "nicht im kuratierten Katalog – bitte Build-Variant wählen und Funktion selbst prüfen"
			}
			return check, nil
		}
	}
	if resp.StatusCode == http.StatusNotFound {
		return check, fmt.Errorf("Modul %s existiert nicht im Go-Modul-Proxy (HTTP 404)", path)
	}
	return check, fmt.Errorf("Modul %s: Proxy antwortete %s", path, resp.Status)
}

// providerSuffix is the short name used in Caddyfile tls blocks.
func providerSuffix(e Entry) string {
	if rest, ok := strings.CutPrefix(e.Module, "github.com/caddy-dns/"); ok {
		return rest
	}
	return ""
}
