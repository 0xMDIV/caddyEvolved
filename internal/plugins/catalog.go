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
	CatDNS        Category = "dns"
	CatAuth       Category = "auth"
	CatStorage    Category = "storage"
	CatInfra      Category = "infra"
	CatObserv     Category = "observability"
	CatUnclassified Category = "unclassified"
)

// EnvVar is one credential a module reads from the environment.
type EnvVar struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Help     string `json:"help,omitempty"`
	Required bool   `json:"required"`
	Secret   bool   `json:"secret"`
}

// Entry is a single Caddy module.
type Entry struct {
	ID      string   `json:"id"`
	Module  string   `json:"module"` // go import path, exact
	Name    string   `json:"name"`
	Category Category `json:"category"`
	Subcat  string   `json:"subcat,omitempty"`
	Registr string   `json:"registers,omitempty"`
	Env     []EnvVar `json:"env,omitempty"`
	Docs    string   `json:"docs,omitempty"`
	// InStandard marks a module that is inside the shipped standard bundle.
	InStandard bool `json:"standard"`
	// Deprecated modules are listed but never auto-selected and warn in the UI.
	Deprecated bool   `json:"deprecated,omitempty"`
	Note       string `json:"note,omitempty"`
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
}

// Resolve maps selected ids onto a binary variant.
//
// "standard" needs no build because every entry it contains is already
// compiled in; anything outside it must be built on demand, which is why
// custom selections are always routed to the build queue.
func Resolve(ids []string) (Resolution, error) {
	var r Resolution
	standard := map[string]bool{}
	for _, e := range entries {
		if e.InStandard {
			standard[e.ID] = true
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
			r.Modules = append(r.Modules, id)
			continue
		}
		if e.Deprecated {
			return r, fmt.Errorf("plugin %q is deprecated: %s", id, e.Note)
		}
		r.Modules = append(r.Modules, e.Module)
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

func looksLikeModulePath(s string) bool {
	if !strings.Contains(s, "/") {
		return false
	}
	head, _ := strings.CutPrefix(s, "github.com/")
	return strings.Contains(head, "/")
}
