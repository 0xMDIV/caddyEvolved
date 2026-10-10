package plugins

import (
	"fmt"
	"strings"
)

// DNSProvider returns the first DNS-01 module of the selection.
func DNSProvider(ids []string) (Entry, bool) {
	for _, id := range ids {
		if e, ok := ByID(id); ok && e.Category == CatDNS {
			return e, true
		}
		// A free-form path still counts if it lives in caddy-dns.
		if rest, ok := strings.CutPrefix(id, "github.com/caddy-dns/"); ok {
			return Entry{
				ID:     id,
				Module: id,
				Name:   rest,
				Env:    []EnvVar{{Name: providerTokenVar(rest), Required: true, Secret: true, Positional: true}},
			}, true
		}
	}
	return Entry{}, false
}

// DNSTLSBlock renders the tls stanza that hands credentials to the provider.
//
// Most caddy-dns modules do not read the environment on their own – they take
// the value as an argument or option, and the READMEs only *name* a variable
// that the user is expected to interpolate. Writing bare `dns netcup` would
// therefore produce a config that validates and then fails certificate issuance
// minutes later, so every credential is interpolated explicitly here.
func DNSTLSBlock(e Entry) string {
	name := DNSName(e)
	var positional, named []EnvVar
	for _, v := range e.Env {
		if v.Positional {
			positional = append(positional, v)
			continue
		}
		named = append(named, v)
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

// providerTokenVar is the variable name caddyevolved writes for an unknown
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

// DNSName is the provider argument of the `dns` directive for an entry.
func DNSName(e Entry) string {
	// The registered name wins: all-inkl lives at caddy-dns/all-inkl but
	// registers as "allinkl".
	if _, after, ok := strings.Cut(e.Registr, "dns.provider "); ok && strings.TrimSpace(after) != "" {
		return strings.TrimSpace(after)
	}
	if rest, ok := strings.CutPrefix(e.Module, "github.com/caddy-dns/"); ok {
		return strings.TrimSuffix(rest, "/v2")
	}
	return e.ID
}
