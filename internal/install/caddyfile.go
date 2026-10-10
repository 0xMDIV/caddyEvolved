package install

import (
	"fmt"
	"path/filepath"
	"strings"

	"caddyforge/internal/plugins"
	"caddyforge/internal/sites"
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
	// Non-default listen ports have to reach caddy itself; the systemd unit does
	// not bind anything, so without these global options the answer would be lost.
	if a.HTTPSPort != 0 && a.HTTPSPort != 443 {
		fmt.Fprintf(&b, "\thttps_port %d\n", a.HTTPSPort)
	}
	if a.HTTPPort != 0 && a.HTTPPort != 80 {
		fmt.Fprintf(&b, "\thttp_port %d\n", a.HTTPPort)
	}
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

	// Sites live in one snippet each, managed by the WebUI; the first one from
	// the answers is written there too (see initialSite).
	b.WriteString("# Sites aus der caddyforge-WebUI (eine Datei pro Site)\n")
	b.WriteString("import " + filepath.ToSlash(p.paths.SitesDir) + "/*.caddy\n")
	if a.SiteDomain != "" {
		if _, ok := p.initialSite(); !ok {
			// A free-form DNS module has no structured form; keep it inline.
			b.WriteString("\n" + p.siteBlock(a))
		}
		return b.String(), nil
	}

	b.WriteString("\n# Noch keine Site angelegt – in der WebUI unter \"Sites\" hinzufügen.\n")
	b.WriteString(`:2015 {
	# Platzhalter-Dienst, damit caddy mit leerer Konfiguration startet
	respond "caddyforge: noch keine Site konfiguriert"
}
`)
	return b.String(), nil
}

// initialSite turns the install answers into a managed site. ok is false
// when the selection cannot be expressed structurally.
func (p *Plan) initialSite() (sites.Site, bool) {
	a := p.opts.Answers
	if a.SiteDomain == "" {
		return sites.Site{}, false
	}
	site := sites.Site{
		Domains:   []string{a.SiteDomain},
		Upstreams: []string{a.SiteTarget},
		Mode:      sites.ModeProxy,
		TLS:       sites.TLSAuto,
		Enabled:   true,
	}
	site.ID = sites.Slug(a.SiteDomain)
	if e, ok := dnsProvider(a.Plugins); ok {
		if _, known := plugins.ByID(e.ID); !known {
			return sites.Site{}, false
		}
		site.TLS, site.DNSProvider = sites.TLSDNS, e.ID
	} else if !a.Managed {
		site.TLS = sites.TLSInternal
	}
	site.Normalize()
	if site.Validate() != nil {
		return sites.Site{}, false
	}
	return site, true
}

// siteBlock renders one reverse-proxy site with the right tls stanza.
func (p *Plan) siteBlock(a Answers) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s {\n", a.SiteDomain)

	if e, ok := dnsProvider(a.Plugins); ok {
		b.WriteString(dnsBlock(e))
	} else if a.Managed {
		fmt.Fprintf(&b, "\ttls %s\n", a.Email)
	} else {
		b.WriteString("\ttls internal\n")
	}

	fmt.Fprintf(&b, "\treverse_proxy %s\n", a.SiteTarget)
	b.WriteString("}\n")
	return b.String()
}

// dnsProvider returns the first DNS-01 module of the selection.
func dnsProvider(ids []string) (plugins.Entry, bool) { return plugins.DNSProvider(ids) }

// dnsBlock renders the tls stanza that hands credentials to the provider.
func dnsBlock(e plugins.Entry) string { return plugins.DNSTLSBlock(e) }
