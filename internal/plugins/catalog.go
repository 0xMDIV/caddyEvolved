// Package plugins holds the curated Caddy module catalog.
//
// Modules are compiled into the caddy binary, so the catalog drives three
// things: which variant satisfies a selection, which environment variables the
// operator has to provide, and which directives the proxy wizard may offer.
package plugins

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed catalog.json
var catalogJSON []byte

// Category groups catalog entries in the UI.
type Category string

const (
	CatDNS          Category = "dns"
	CatAuth         Category = "auth"
	CatStorage      Category = "storage"
	CatInfra        Category = "infra"
	CatCert         Category = "cert"
	CatObserv       Category = "observability"
	CatUnclassified Category = "unclassified"
)

// EnvVar is one credential a module reads from the environment.
type EnvVar struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Help     string `json:"help,omitempty"`
	Required bool   `json:"required"`
	Secret   bool   `json:"secret"`
	// Positional means the module expects the value as an argument in the
	// Caddyfile (`dns netcup {env.X}`) instead of reading the variable itself.
	// Only lego-backed providers like cloudflare truly fall back to env.
	Positional bool `json:"positional,omitempty"`
	// OptName is the config key inside an options block, for providers that
	// take a block rather than a positional argument.
	OptName string `json:"opt,omitempty"`
}

// Entry is a single Caddy module.
type Entry struct {
	ID       string   `json:"id"`
	Module   string   `json:"module"` // go import path, exact and verbatim
	Name     string   `json:"name"`
	Category Category `json:"category"`
	Subcat   string   `json:"subcat,omitempty"`
	Registr  string   `json:"registers,omitempty"`
	Env      []EnvVar `json:"env,omitempty"`
	Docs     string   `json:"docs,omitempty"`
	// InStandard marks a module that is inside the shipped standard bundle.
	InStandard bool `json:"standard"`
	// Deprecated modules are listed but never auto-selected and warn in the UI.
	Deprecated bool `json:"deprecated,omitempty"`
	// VersionSuffix is a build trap we must not silently drop: the unsuffixed
	// path of hetzner or caddy-docker-proxy resolves to an old major version.
	VersionSuffix bool `json:"versionSuffix,omitempty"`
	// License is the SPDX id GitHub reports; empty means "none detected",
	// which is a redistribution problem for a bundled binary, not a detail.
	License string `json:"license,omitempty"`
	// LicenseRisk carries what to tell the operator about the licence.
	LicenseRisk string `json:"licenseRisk,omitempty"`
	// Conflicts names module ids that cannot be ticked together, e.g. a
	// config-generating module versus our Caddyfile-as-source-of-truth model.
	Conflicts []string `json:"conflicts,omitempty"`
	// Requires pairs a module that must be built alongside this one.
	Requires []string `json:"requires,omitempty"`
	// CaddyMin is the highest caddy version this module's go.mod demands.
	CaddyMin string `json:"caddyMin,omitempty"`
	Note     string `json:"note,omitempty"`
	// UI is the sidebar page the WebUI shows while the module is compiled in.
	UI *UIPage `json:"ui,omitempty"`
}

// UIPage describes a plugin's own page in the WebUI.
type UIPage struct {
	Page  string `json:"page"`  // route key, e.g. "waf"
	Label string `json:"label"` // sidebar text
	Icon  string `json:"icon,omitempty"`
}

type catalogFile struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

var entries []Entry

func init() {
	var f catalogFile
	if err := json.Unmarshal(catalogJSON, &f); err != nil {
		panic("plugins/catalog.json: " + err.Error())
	}
	seen := map[string]bool{}
	for _, e := range f.Entries {
		if seen[e.Module] {
			panic("duplicate module in catalog: " + e.Module)
		}
		seen[e.Module] = true
		entries = append(entries, e)
	}
}

// All returns every catalog entry sorted by category then name.
func All() []Entry {
	out := append([]Entry(nil), entries...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// ByID looks up one entry.
func ByID(id string) (Entry, bool) {
	for _, e := range entries {
		if e.ID == id || strings.EqualFold(e.Module, id) {
			return e, true
		}
	}
	return Entry{}, false
}

// InCategory filters by category.
func InCategory(c Category) []Entry {
	var out []Entry
	for _, e := range entries {
		if e.Category == c {
			out = append(out, e)
		}
	}
	return out
}

// Resolution is the outcome of matching a selection against the variants.
type Resolution struct {
	Variant   string
	Modules   []string
	Missing   []string // requested but not in the chosen variant
	Untracked []string // free-form go paths the catalog does not know
	// CaddyfileManaged is false when a selected module generates its own
	// configuration (caddy-docker-proxy), which our Caddyfile editing model
	// must not fight over.
	CaddyfileManaged bool
	// Notes carries warnings the UI shows next to the selection.
	Notes []string
}

// Resolve maps selected ids onto a binary variant.
//
// "standard" needs no build because every entry it contains is already
// compiled in; anything outside it must be built on demand, which is why
// custom selections are always routed to the build queue.
func Resolve(ids []string) (Resolution, error) {
	var r Resolution
	r.CaddyfileManaged = true
	standard := map[string]bool{}
	for _, e := range entries {
		if e.InStandard {
			standard[e.ID] = true
		}
	}

	add := func(module string) {
		if !contains(r.Modules, module) {
			r.Modules = append(r.Modules, module)
		}
	}

	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		e, ok := ByID(id)
		if !ok {
			if !looksLikeModulePath(id) {
				return r, fmt.Errorf("unknown plugin %q: not in the catalog and not a go module path", id)
			}
			r.Untracked = append(r.Untracked, id)
			add(id)
			continue
		}
		if e.Deprecated {
			return r, fmt.Errorf("plugin %q is deprecated: %s", id, e.Note)
		}
		add(e.Module)

		for _, dep := range e.Requires {
			d, ok := ByID(dep)
			if !ok {
				return r, fmt.Errorf("plugin %q requires %q, which the catalog does not know", e.ID, dep)
			}
			add(d.Module)
			r.Notes = append(r.Notes, fmt.Sprintf("%s automatisch mitgebaut, weil %s es benötigt", d.Name, e.Name))
		}
		for _, c := range e.Conflicts {
			if c == "caddyfile-managed" {
				r.CaddyfileManaged = false
				r.Notes = append(r.Notes, fmt.Sprintf("%s erzeugt die Konfiguration selbst – der Caddyfile-Editor von caddyevolved wird dadurch wirkungslos", e.Name))
				continue
			}
			// Two modules registering the same caddy module id make the
			// binary panic at start, so the pair is refused before a build.
			if contains(ids, c) {
				other := c
				if o, ok := ByID(c); ok {
					other = o.Name
				}
				return r, fmt.Errorf("%s und %s können nicht zusammen gebaut werden (gleiche Caddy-Modul-ID)", e.Name, other)
			}
		}
		if !standard[e.ID] {
			r.Missing = append(r.Missing, e.ID)
		}
	}
	if len(r.Missing) > 0 || len(r.Untracked) > 0 {
		r.Variant = "custom"
		return r, nil
	}
	if len(r.Modules) == 0 {
		r.Variant = "caddy"
		return r, nil
	}
	r.Variant = "standard"
	return r, nil
}

func contains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}

func looksLikeModulePath(s string) bool {
	if !strings.Contains(s, "/") {
		return false
	}
	head, _ := strings.CutPrefix(s, "github.com/")
	return strings.Contains(head, "/")
}
