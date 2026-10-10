package install

import (
	"fmt"
	"strings"

	"caddyforge/internal/plugins"
)

// renderCaddyfile builds the initial configuration from the answers.
//
// Block order is deliberate: global options, then the first site. Anything the
// operator adds later stays untouched by a rerun.
func (p *Plan) renderCaddyfile() (string, error) {
	a := p.opts.Answers
	var b strings.Builder

	b.WriteString("# Caddyfile – verwaltet von caddyforge\n")
	b.WriteString("# Prüfen: caddy validate --config <Pfad> --adapter caddyfile\n")
	b.WriteString("# Reload: systemctl reload caddy\n\n")

	b.WriteString("{\n")
	fmt.Fprintf(&b, "\tadmin localhost:%d\n", a.AdminPort)
	if a.Managed {
		fmt.Fprintf(&b, "\temail %s\n", a.Email)
	}
	if len(a.Plugins) > 0 {
		b.WriteString("\t# aktivierte Module:\n")
		for _, id := range a.Plugins {
			name := id
			if e, ok := plugins.ByID(id); ok {
				name = e.Name
			}
			fmt.Fprintf(&b, "\t#   - %s\n", name)
		}
	}
	b.WriteString("}\n\n")

	if a.SiteDomain != "" {
		b.WriteString(p.siteBlock(a))
		return b.String(), nil
	}

	b.WriteString("# Noch kein Site angelegt. Beispiel:\n")
	b.WriteString("#   caddyforge proxy add api.example.com http://127.0.0.1:8080\n")
	b.WriteString(`:2015 {
	# Platzhalter-Dienst, damit caddy mit leerer Konfiguration startet
	respond "caddyforge: noch kein Site konfiguriert"
}
`)
	return b.String(), nil
}

// siteBlock renders one reverse-proxy site with the right tls stanza.
func (p *Plan) siteBlock(a Answers) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s {\n", a.SiteDomain)

	provider := dnsProviderName(a.Plugins)
	switch {
	case provider != "":
		b.WriteString("\ttls {\n\t\tissuer acme {\n")
		fmt.Fprintf(&b, "\t\t\tdns %s\n", provider)
		b.WriteString("\t\t}\n\t}\n")
	case a.Managed:
		fmt.Fprintf(&b, "\ttls %s\n", a.Email)
	default:
		b.WriteString("\ttls internal\n")
	}

	fmt.Fprintf(&b, "\treverse_proxy %s\n", a.SiteTarget)
	b.WriteString("}\n")
	return b.String()
}

// dnsProviderName returns the lego provider name of the first DNS module, e.g.
// "cloudflare" for github.com/caddy-dns/cloudflare.
func dnsProviderName(ids []string) string {
	for _, id := range ids {
		module := id
		if e, ok := plugins.ByID(id); ok {
			module = e.Module
		}
		if rest, ok := strings.CutPrefix(module, "github.com/caddy-dns/"); ok {
			return rest
		}
	}
	return ""
}
