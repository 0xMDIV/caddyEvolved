package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"caddyevolved/internal/install"
	"caddyevolved/internal/platform"
	"caddyevolved/internal/plugins"
	"caddyevolved/internal/releases"
)

// wizard collects an install.Answers interactively.
//
// It asks in the order the answers actually depend on each other: the plugin
// selection decides which credentials are asked for, and the certificate mode
// decides whether an email is mandatory at all.
type wizard struct {
	p    *prompt
	host platform.Info
	ctx  context.Context
}

func newWizard(ctx context.Context, out io.Writer, host platform.Info) *wizard {
	return &wizard{p: newPrompt(out), host: host, ctx: ctx}
}

func (w *wizard) run() (install.Answers, error) {
	var a install.Answers
	fmt.Fprintf(w.p.out, "Host: %s %s · init %s · Virtualisierung %q · uid %d\n",
		w.host.Distro, w.host.DistroVer, w.host.Init, orNone(w.host.Virt), w.host.UID)
	if w.host.Init != platform.InitSystemd {
		fmt.Fprintln(w.p.out, "Hinweis: ohne systemd starten die Dienste über `caddyevolved start` statt über Units.")
	}

	a.BinarySource = w.askSource()
	a.CaddyVersion = w.askVersion()
	a.Plugins = w.askPlugins(a.BinarySource)
	a.Credentials = w.askCredentials(a.Plugins)
	a.HTTPPort, a.HTTPSPort, a.AdminPort = w.askPorts()
	a.Email = strings.TrimSpace(w.p.ask("E-Mail für Zertifikate (ACME-Konto)", "hostmaster@example.org"))
	a.UIPort = w.p.integer("Port der WebUI", 8484)
	a.UIBind = strings.TrimSpace(w.p.ask("Bind-Adresse der WebUI", "0.0.0.0"))
	a.Managed = w.p.confirm("Caddyfile vollständig durch caddyEvolved verwalten?", true)
	a.SiteDomain, a.SiteTarget = w.askSite()
	a.Force = w.p.confirm("Bestehende Dateien/Dienste notfalls übernehmen?", false)
	return a, a.Validate()
}

func (w *wizard) askSource() string {
	fmt.Fprintln(w.p.out, `Quelle der Caddy-Binary:
  official  offizielles Caddy-Archiv, keine Zusatzmodule
  bundle    vorgebaute Variante mit den üblichen Modulen
  custom    eigener Build mit den gewählten Modulen`)
	for {
		v := strings.ToLower(strings.TrimSpace(w.p.ask("Quelle", "official")))
		switch v {
		case "official", "bundle", "custom":
			return v
		default:
			fmt.Fprintln(w.p.out, "  official, bundle oder custom")
		}
	}
}

func (w *wizard) askVersion() string {
	def := ""
	if rel, err := releases.Latest(w.ctx, "caddyserver/caddy"); err == nil {
		def = rel.Version
	} else {
		fmt.Fprintf(w.p.out, "aktuelle caddy-Version nicht ermittelbar (%v) – leer lassen und später nachfragen\n", err)
	}
	return strings.TrimPrefix(strings.TrimSpace(w.p.ask("Caddy-Version", def)), "v")
}

// askPlugins lists the catalog numbered and accepts numbers or ids.
func (w *wizard) askPlugins(source string) []string {
	fmt.Fprintln(w.p.out, "\nModule aus dem Katalog:")
	w.printCatalog()
	if source == "official" {
		fmt.Fprintln(w.p.out, "Achtung: binarySource official bindet keine Module ein – für eine Auswahl bitte \"custom\" wählen.")
	}
	seen := map[string]bool{}
	var out []string
	for {
		v := strings.TrimSpace(w.p.ask("Module hinzufügen (Nummern oder IDs, leer für fertig)", ""))
		if v == "" {
			break
		}
		for _, tok := range strings.Split(v, ",") {
			id := w.resolveEntry(strings.TrimSpace(tok))
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// printCatalog renders the numbered list that resolveEntry's numbers refer to.
func (w *wizard) printCatalog() {
	rows := w.catalogEntries()
	var cat plugins.Category
	for i, e := range rows {
		if e.Category != cat {
			cat = e.Category
			fmt.Fprintf(w.p.out, "  -- %s --\n", cat)
		}
		std := ""
		if e.InStandard {
			std = " (standard)"
		}
		need := ""
		if len(e.Env) > 0 {
			need = " Zugangsdaten"
		}
		fmt.Fprintf(w.p.out, "  %3d) %-20s %s%s%s\n", i+1, e.ID, e.Name, std, need)
	}
}

// resolveEntry maps a catalogue number or an id/module path onto a catalogue id.
func (w *wizard) resolveEntry(tok string) string {
	if tok == "" {
		return ""
	}
	if n, err := strconv.Atoi(tok); err == nil {
		rows := w.catalogEntries()
		if n < 1 || n > len(rows) {
			fmt.Fprintf(w.p.out, "  keine Nummer %d\n", n)
			return ""
		}
		return rows[n-1].ID
	}
	if _, ok := plugins.ByID(tok); ok {
		return tok
	}
	// Free-form module paths stay as typed; Resolve validates them against the proxy.
	if strings.Contains(tok, "/") {
		return tok
	}
	fmt.Fprintf(w.p.out, "  %q ist nicht im Katalog (oder veraltet)\n", tok)
	return ""
}

// catalogEntries is the single ordering behind both the numbered listing and the
// number lookup, so the two can never drift apart.
func (w *wizard) catalogEntries() []plugins.Entry {
	all := plugins.All()
	rows := make([]plugins.Entry, 0, len(all))
	for _, e := range all {
		if e.Deprecated {
			continue
		}
		rows = append(rows, e)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].ID < rows[j].ID
	})
	return rows
}

// askCredentials walks the env vars the selected modules need.
func (w *wizard) askCredentials(ids []string) map[string]string {
	out := map[string]string{}
	for _, id := range ids {
		e, ok := plugins.ByID(id)
		if !ok || len(e.Env) == 0 {
			if len(e.Env) == 0 && ok {
				fmt.Fprintf(w.p.out, "\n%s: keine Zugangsdaten nötig\n", e.Name)
			}
			continue
		}
		fmt.Fprintf(w.p.out, "\n%s – Zugangsdaten (Eingabe ist sichtbar, Tippen auf dem Handy also ungünstig):\n", e.Name)
		for _, v := range e.Env {
			help := v.Label
			if v.Help != "" {
				help += " – " + v.Help
			}
			if v.Required {
				help += " (pflicht)"
			}
			val := strings.TrimSpace(w.p.ask(help, ""))
			if val == "" && v.Required {
				fmt.Fprintf(w.p.out, "  %s fehlt – die Zertifikatsausstellung wird später scheitern\n", v.Name)
			}
			if val != "" {
				out[v.Name] = val
			}
		}
	}
	return out
}

func (w *wizard) askPorts() (int, int, int) {
	fmt.Fprintln(w.p.out, "\nPorts – im unprivilegierten LXC braucht Caddy CAP_NET_BIND_SERVICE dafür in der Unit.")
	httpPort := w.p.integer("HTTP-Port", 80)
	httpsPort := w.p.integer("HTTPS-Port", 443)
	adminPort := w.p.integer("Admin-Port (nur localhost)", 2019)
	return httpPort, httpsPort, adminPort
}

func (w *wizard) askSite() (string, string) {
	domain := strings.TrimSpace(w.p.ask("Domain für die erste Site (leer = keine)", ""))
	if domain == "" {
		return "", ""
	}
	target := strings.TrimSpace(w.p.ask("Ziel-URL dieser Site (http://localhost:8080)", "http://localhost:8080"))
	return domain, target
}

func orNone(s string) string {
	if s == "" {
		return "keine/unknown"
	}
	return s
}
