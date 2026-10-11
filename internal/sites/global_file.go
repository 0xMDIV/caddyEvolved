package sites

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// GlobalFile is where the global snippet lives, next to the main Caddyfile.
func (m *Manager) GlobalFile() string {
	return filepath.Join(filepath.Dir(m.caddyfile), "caddyevolved-global.caddy")
}

// globalImportLine is what ensureGlobalImport puts into the global block.
func (m *Manager) globalImportLine() string { return "import " + filepath.ToSlash(m.GlobalFile()) }

// writeGlobal renders the snippet. It always exists – even empty – because the
// Caddyfile imports it by name and caddy refuses a missing import.
func (m *Manager) writeGlobal() error {
	return writeAtomic(m.GlobalFile(), []byte(RenderGlobal(m.opt)), 0o644)
}

// ensureGlobalImport puts the import into the Caddyfile's global options
// block, creating that block when the file has none.
func (m *Manager) ensureGlobalImport() error {
	data, err := os.ReadFile(m.caddyfile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	out, changed := withGlobalImport(string(data), m.globalImportLine())
	if !changed {
		return nil
	}
	return writeAtomic(m.caddyfile, []byte(out), 0o644)
}

// withGlobalImport returns content with line inside its global options block.
func withGlobalImport(content, line string) (string, bool) {
	lines := strings.Split(content, "\n")
	for _, l := range lines {
		if strings.TrimSpace(l) == line {
			return content, false
		}
	}
	// The global block is a bare "{" before any site address.
	start := -1
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if t == "{" {
			start = i
		}
		break
	}
	entry := "\t# Von caddyEvolved verwaltete globale Optionen (WebUI)\n\t" + line
	if start < 0 {
		return "{\n" + entry + "\n}\n\n" + content, true
	}
	depth := 0
	for i := start; i < len(lines); i++ {
		depth += strings.Count(stripComment(lines[i]), "{") - strings.Count(stripComment(lines[i]), "}")
		if depth == 0 {
			out := append([]string{}, lines[:i]...)
			out = append(out, entry)
			out = append(out, lines[i:]...)
			return strings.Join(out, "\n"), true
		}
	}
	// Unbalanced file: leave it alone, caddy validation will name the problem.
	return content, false
}

func stripComment(l string) string {
	if i := strings.Index(l, "#"); i >= 0 {
		return l[:i]
	}
	return l
}
