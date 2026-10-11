package sites

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"caddyevolved/internal/blocklists"
)

// Firewall are host-wide rules every site applies before anything else:
// blocked addresses, public blocklists, countries and networks (ASN). The
// allowlist bypasses all of it, including WAF, bot filter, rate limit and
// CrowdSec. Site access lists and the sensitive-file guard still apply.
type Firewall struct {
	Enabled bool `json:"enabled"`
	// Allow are trusted addresses (whitelist), Block refused ones (blacklist).
	Allow []string `json:"allow,omitempty"`
	Block []string `json:"block,omitempty"`
	// Lists are public blocklists by catalog id (blocklists.Catalog).
	Lists []string `json:"lists,omitempty"`
	// Countries are ISO codes. With AllowCountries set, only those pass;
	// private addresses always pass, the plugin would see them as unknown.
	BlockCountries []string `json:"blockCountries,omitempty"`
	AllowCountries []string `json:"allowCountries,omitempty"`
	// BlockASN are network operators, e.g. 14061 for DigitalOcean.
	BlockASN []int `json:"blockAsn,omitempty"`
	// Drop closes the connection instead of answering 403.
	Drop bool `json:"drop"`
}

// Normalize trims, upper-cases and sorts, so the rendered file stays stable.
func (f *Firewall) Normalize() {
	f.Allow = cleanList(f.Allow)
	f.Block = cleanList(f.Block)
	f.Lists = cleanList(f.Lists)
	f.BlockCountries = upper(cleanList(f.BlockCountries))
	f.AllowCountries = upper(cleanList(f.AllowCountries))
	slices.Sort(f.Lists)
	f.Lists = slices.Compact(f.Lists)
	slices.Sort(f.BlockCountries)
	f.BlockCountries = slices.Compact(f.BlockCountries)
	slices.Sort(f.AllowCountries)
	f.AllowCountries = slices.Compact(f.AllowCountries)
	slices.Sort(f.BlockASN)
	f.BlockASN = slices.Compact(f.BlockASN)
}

func (f Firewall) validate() []string {
	var problems []string
	for _, r := range f.Allow {
		if !validRange(r) {
			problems = append(problems, fmt.Sprintf("Firewall-Freigabe %q: IP-Adresse oder Bereich wie 192.168.0.0/16", r))
		}
	}
	for _, r := range f.Block {
		if r == "private_ranges" || !validRange(r) {
			problems = append(problems, fmt.Sprintf("Firewall-Sperre %q: IP-Adresse oder Bereich wie 203.0.113.0/24", r))
		}
	}
	for _, id := range f.Lists {
		if _, ok := blocklists.ByID(id); !ok {
			problems = append(problems, fmt.Sprintf("Firewall: unbekannte Sperrliste %q", id))
		}
	}
	for _, c := range append(append([]string{}, f.BlockCountries...), f.AllowCountries...) {
		if !reCountry.MatchString(c) {
			problems = append(problems, fmt.Sprintf("Firewall: Ländercode %q ungültig (zwei Buchstaben, z. B. CN)", c))
		}
	}
	if len(f.BlockCountries) > 0 && len(f.AllowCountries) > 0 {
		problems = append(problems, "Firewall: Länder entweder sperren oder nur bestimmte erlauben, nicht beides")
	}
	for _, a := range f.BlockASN {
		if a < 1 || a > 4294967295 {
			problems = append(problems, fmt.Sprintf("Firewall: ASN %d ungültig", a))
		}
	}
	return problems
}

// UsesGeo / UsesASN report which database the rules need.
func (f Firewall) UsesGeo() bool { return f.Enabled && len(f.BlockCountries)+len(f.AllowCountries) > 0 }
func (f Firewall) UsesASN() bool { return f.Enabled && len(f.BlockASN) > 0 }

// firewallOn reports whether the site imports the firewall rules.
func (s Site) firewallOn(opt Options) bool {
	return opt.Global.Firewall.Enabled && !s.NoFirewall && opt.FirewallPath != ""
}

// trusted reports whether the site wraps its filters in an allowlist check.
func (s Site) trusted(opt Options) bool {
	return s.firewallOn(opt) && len(opt.Global.Firewall.Allow) > 0
}

// FirewallFile is the rule file every protected site imports in its route.
func (m *Manager) FirewallFile() string {
	return filepath.Join(filepath.Dir(m.caddyfile), "caddyevolved-firewall.caddy")
}

func (m *Manager) writeFirewall() error {
	return writeAtomic(m.FirewallFile(), []byte(RenderFirewall(m.opt)), 0o644)
}

func (m *Manager) firewallCurrent() bool {
	data, err := os.ReadFile(m.FirewallFile())
	return err == nil && string(data) == RenderFirewall(m.opt)
}

// RenderFirewall produces the rule file, already indented for a route block.
// Each rule tags the access log entry (cev_block), so Analytics can say why
// a request was refused.
func RenderFirewall(o Options) string {
	f := o.Global.Firewall
	var b strings.Builder
	b.WriteString("# Firewall – verwaltet von caddyEvolved (WebUI → Firewall). Wird überschrieben.\n")
	if !f.Enabled {
		return b.String()
	}
	deny := func(matcher, reason string) {
		fmt.Fprintf(&b, "\t\tlog_append %s cev_block %s\n", matcher, reason)
		if f.Drop {
			fmt.Fprintf(&b, "\t\tabort %s\n", matcher)
		} else {
			fmt.Fprintf(&b, "\t\trespond %s \"Zugriff verweigert\" 403\n", matcher)
		}
	}
	exempt := func(withPrivate bool) {
		ranges := append([]string{}, f.Allow...)
		if withPrivate {
			ranges = append([]string{"private_ranges"}, ranges...)
		}
		if len(ranges) > 0 {
			writeIPLines(&b, "\t\t\tnot client_ip", ranges)
		}
	}

	var blocked []string
	blocked = append(blocked, f.Block...)
	for _, id := range f.Lists {
		blocked = append(blocked, o.FirewallLists[id]...)
	}
	if len(blocked) > 0 {
		b.WriteString("\t\t@cev_fw_ip {\n")
		writeIPLines(&b, "\t\t\tclient_ip", blocked)
		exempt(false)
		b.WriteString("\t\t}\n")
		deny("@cev_fw_ip", "firewall-ip")
	}
	if f.UsesGeo() && o.Caps.Geo && o.GeoDB != "" {
		b.WriteString("\t\t@cev_fw_geo {\n")
		exempt(true)
		fmt.Fprintf(&b, "\t\t\tnot maxmind_geolocation {\n\t\t\t\tdb_path %s\n", filepath.ToSlash(o.GeoDB))
		if len(f.AllowCountries) > 0 {
			fmt.Fprintf(&b, "\t\t\t\tallow_countries %s\n", strings.Join(f.AllowCountries, " "))
		} else {
			fmt.Fprintf(&b, "\t\t\t\tdeny_countries %s\n", strings.Join(f.BlockCountries, " "))
		}
		b.WriteString("\t\t\t}\n\t\t}\n")
		deny("@cev_fw_geo", "firewall-land")
	}
	if f.UsesASN() && o.Caps.Geo && o.ASNDB != "" {
		asns := make([]string, 0, len(f.BlockASN))
		for _, a := range f.BlockASN {
			asns = append(asns, fmt.Sprint(a))
		}
		b.WriteString("\t\t@cev_fw_asn {\n")
		exempt(true)
		fmt.Fprintf(&b, "\t\t\tnot maxmind_geolocation {\n\t\t\t\tdb_path %s\n\t\t\t\tdeny_asn %s\n\t\t\t}\n\t\t}\n",
			filepath.ToSlash(o.ASNDB), strings.Join(asns, " "))
		deny("@cev_fw_asn", "firewall-asn")
	}
	return b.String()
}

// writeIPLines splits long lists; caddy merges repeated client_ip lines.
func writeIPLines(b *strings.Builder, prefix string, ranges []string) {
	for i := 0; i < len(ranges); i += 40 {
		fmt.Fprintf(b, "%s %s\n", prefix, strings.Join(ranges[i:min(i+40, len(ranges))], " "))
	}
}
