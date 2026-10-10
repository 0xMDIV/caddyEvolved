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
func dnsProvider(ids []string) (plugins.Entry, bool) {
	for _, id := range ids {
		if e, ok := plugins.ByID(id); ok && e.Category == plugins.CatDNS {
			return e, true
		}
		// A free-form path still counts if it lives in caddy-dns.
		if rest, ok := strings.CutPrefix(id, "github.com/caddy-dns/"); ok {
			return plugins.Entry{
				ID:     id,
				Module: id,
				Name:   rest,
				Env:    []plugins.EnvVar{{Name: providerTokenVar(rest), Required: true, Secret: true, Positional: true}},
			}, true
		}
	}
	return plugins.Entry{}, false
}

// dnsBlock renders the tls stanza that hands credentials to the provider.
//
// Most caddy-dns modules do not read the environment on their own – they take
// the value as an argument or option, and the READMEs only *name* a variable
// that the user is expected to interpolate. Writing bare `dns netcup` would
// therefore produce a config that validates and then fails certificate issuance
// minutes later, so every credential is interpolated explicitly here.
func dnsBlock(e plugins.Entry) string {
	var positional, named []plugins.EnvVar
	for _, v := range e.Env {
		if v.Positional {
			positional = append(positional, v)
			continue
		}
		named = append(named, v)
	}

	name := e.ID
	if rest, ok := strings.CutPrefix(e.Module, "github.com/caddy-dns/"); ok {
		name = strings.TrimSuffix(rest, "/v2")
	}
	if len(named) == 0 && len(positional) > 0 {
		if len(positional) == 1 {
			return fmt.Sprintf("\ttls {\n\t\tissuer acme {\n\t\t\tdns %s {env.%s}\n\t\t}\n\t}\n", name, positional[0].Name)
		}
		args := make([]string, 0, len(positional))
		for _, v := range positional {
			args = append(args, "{env."+v.Name+"}")
		}
		return fmt.Sprintf("\ttls {\n\t\tissuer acme {\n\t\t\tdns %s %s\n\t\t}\n\t}\n", name, strings.Join(args, " "))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\ttls {\n\t\tissuer acme {\n\t\t\tdns %s {\n", name)
	for _, v := range positional {
		// Positional values cannot live inside the options block; they are
		// emitted as arguments instead (see providerTokenVar ordering).
		fmt.Fprintf(&b, "\t\t\t\t%s {env.%s}\n", v.OptName, v.Name)
	}
	for _, v := range named {
		opt := v.OptName
		if opt == "" {
			opt = strings.ToLower(strings.TrimSuffix(v.Name, "_TOKEN"))
		}
		if !v.Required {
			fmt.Fprintf(&b, "\t\t\t\t# %s {env.%s}\n", opt, v.Name)
			continue
		}
		fmt.Fprintf(&b, "\t\t\t\t%s {env.%s}\n", opt, v.Name)
	}
	b.WriteString("\t\t\t}\n\t\t}\n\t}\n")
	return b.String()
}

// providerTokenVar is the variable name caddyforge writes for an unknown
// caddy-dns provider, derived from the repo slug.
func providerTokenVar(slug string) string {
	up := strings.ToUpper(strings.ReplaceAll(slug, "-", "_"))
	for _, suffix := range []string{"_API_TOKEN", "_API_KEY", "_TOKEN", "_AUTH_API_TOKEN"} {
		if strings.HasSuffix(up, suffix) {
			return up
		}
	}
	return up + "_API_TOKEN"
}
