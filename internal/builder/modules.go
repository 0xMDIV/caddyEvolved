package builder

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// Module is one non-standard module as `caddy list-modules` reports it.
type Module struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
	Package string `json:"package,omitempty"`
}

// ListModules asks a caddy binary for its non-standard modules with versions
// and go module paths.
func ListModules(ctx context.Context, bin string) ([]Module, error) {
	out, err := exec.CommandContext(ctx, bin, "list-modules", "--packages", "--versions", "--skip-standard").Output()
	if err != nil {
		return nil, fmt.Errorf("%s list-modules: %w", bin, err)
	}
	return ParseModules(string(out)), nil
}

// ParseModules reads the list-modules output. Module lines start in column 0
// ("dns.providers.cloudflare v0.2.1 github.com/caddy-dns/cloudflare"); the
// summary at the end is indented and skipped.
func ParseModules(out string) []Module {
	var mods []Module
	for _, line := range strings.Split(out, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		f := strings.Fields(line)
		if len(f) == 0 || !strings.Contains(f[0], ".") && len(f) == 1 {
			continue
		}
		m := Module{ID: f[0]}
		for _, x := range f[1:] {
			switch {
			case strings.Contains(x, "/"):
				if m.Package == "" {
					m.Package = x
				}
			case strings.HasPrefix(x, "v") || strings.HasPrefix(x, "("):
				if m.Version == "" {
					m.Version = x
				}
			}
		}
		mods = append(mods, m)
	}
	return mods
}

// HasPackage reports whether any module comes from the go module path. A
// module path may register several caddy modules, and a package line may name
// a sub-package of it, so a prefix match is the contract.
func HasPackage(mods []Module, path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, m := range mods {
		if m.Package == path || strings.HasPrefix(m.Package, path+"/") || strings.HasPrefix(path, m.Package+"/") && m.Package != "" {
			return true
		}
	}
	return false
}
