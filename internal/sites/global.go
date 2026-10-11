package sites

import (
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"caddyevolved/internal/plugins"
)

// Global holds the host-wide options caddyEvolved manages. They are rendered
// into one snippet that the main Caddyfile imports inside its global options
// block, so the operator's own global options stay untouched.
type Global struct {
	RealIP    RealIP    `json:"realIp"`
	DynDNS    DynDNS    `json:"dynDns"`
	CrowdSec  CrowdSec  `json:"crowdsec"`
	Tailscale Tailscale `json:"tailscale"`
	Cache     Cache     `json:"cache"`
}

// RealIP makes caddy trust proxies in front of it, so access lists, rate
// limits and logs see the visitor instead of the proxy.
type RealIP struct {
	Cloudflare bool     `json:"cloudflare"`
	Proxies    []string `json:"proxies,omitempty"` // further proxies, IPs or CIDRs
}

// DynDNS keeps DNS records pointed at this host's public IP (caddy-dynamicdns).
type DynDNS struct {
	Enabled  bool        `json:"enabled"`
	Provider string      `json:"provider,omitempty"` // catalog id of a DNS plugin
	Domains  []DynDomain `json:"domains,omitempty"`
	Interval string      `json:"interval,omitempty"`
	IPv6     bool        `json:"ipv6"`
}

// DynDomain is one zone and the records in it; "@" is the zone itself.
type DynDomain struct {
	Zone  string   `json:"zone"`
	Names []string `json:"names"`
}

// CrowdSec connects to a CrowdSec Local API; the bouncer then runs on every
// site that does not opt out.
type CrowdSec struct {
	Enabled   bool   `json:"enabled"`
	APIURL    string `json:"apiUrl,omitempty"`
	AppSecURL string `json:"appsecUrl,omitempty"`
}

// Tailscale lets sites listen on the tailnet only (caddy-tailscale).
type Tailscale struct {
	Enabled   bool `json:"enabled"`
	Ephemeral bool `json:"ephemeral"`
}

// Cache is the Souin HTTP cache; sites switch it on individually.
type Cache struct {
	Enabled bool   `json:"enabled"`
	TTL     string `json:"ttl,omitempty"`
}

// Caps are the optional modules in the running caddy binary. Nothing is
// rendered for a module that is missing: caddy would reject the whole config.
type Caps struct {
	CloudflareIP bool            `json:"cloudflareIp"`
	DynDNS       bool            `json:"dynDns"`
	CrowdSec     bool            `json:"crowdsec"`
	AppSec       bool            `json:"appsec"`
	Tailscale    bool            `json:"tailscale"`
	Cache        bool            `json:"cache"`
	Brotli       bool            `json:"brotli"`
	WebDAV       bool            `json:"webdav"`
	DNS          map[string]bool `json:"dns"` // provider names, e.g. "cloudflare"
}

// CapsFromModules reads the module IDs `caddy list-modules` prints.
func CapsFromModules(mods map[string]bool) Caps {
	c := Caps{
		CloudflareIP: mods["http.ip_sources.cloudflare"],
		DynDNS:       mods["dynamic_dns"],
		CrowdSec:     mods["http.handlers.crowdsec"],
		AppSec:       mods["http.handlers.appsec"],
		Tailscale:    mods["tailscale"],
		Cache:        mods["http.handlers.cache"],
		Brotli:       mods["http.encoders.br"],
		WebDAV:       mods["http.handlers.webdav"],
		DNS:          map[string]bool{},
	}
	for m := range mods {
		if name, ok := strings.CutPrefix(m, "dns.providers."); ok {
			c.DNS[name] = true
		}
	}
	return c
}

// CloudflareRanges are Cloudflare's published proxy ranges
// (cloudflare.com/ips-v4, ips-v6). The cloudflare-ip plugin fetches them live.
var CloudflareRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
	"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
	"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
	"2a06:98c0::/29", "2c0f:f248::/32",
}

var (
	reZone     = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	reRecord   = regexp.MustCompile(`^(@|\*|[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?)*)$`)
	reDuration = regexp.MustCompile(`^[0-9]{1,5}(s|m|h)$`)
)

// Normalize trims input and fills defaults.
func (g *Global) Normalize() {
	g.RealIP.Proxies = cleanList(g.RealIP.Proxies)
	d := &g.DynDNS
	d.Provider = strings.TrimSpace(d.Provider)
	var doms []DynDomain
	for _, z := range d.Domains {
		z.Zone = strings.Trim(strings.ToLower(strings.TrimSpace(z.Zone)), ".")
		var names []string
		for _, n := range z.Names {
			n = strings.Trim(strings.ToLower(strings.TrimSpace(n)), ".")
			if n != "" {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			names = []string{"@"}
		}
		z.Names = names
		if z.Zone != "" {
			doms = append(doms, z)
		}
	}
	d.Domains = doms
	if d.Interval == "" {
		d.Interval = "5m"
	}
	g.CrowdSec.APIURL = strings.TrimSpace(g.CrowdSec.APIURL)
	if g.CrowdSec.APIURL == "" {
		g.CrowdSec.APIURL = "http://127.0.0.1:8080"
	}
	g.CrowdSec.AppSecURL = strings.TrimSpace(g.CrowdSec.AppSecURL)
	if g.Cache.TTL == "" {
		g.Cache.TTL = "120s"
	}
}

// Validate reports every problem, worded for the UI.
func (g Global) Validate() error {
	var problems []string
	for _, p := range g.RealIP.Proxies {
		if _, err := netip.ParsePrefix(p); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(p); err == nil {
			continue
		}
		problems = append(problems, fmt.Sprintf("Proxy %q: IP-Adresse oder Bereich wie 10.0.0.0/8", p))
	}
	if d := g.DynDNS; d.Enabled {
		if e, ok := plugins.ByID(d.Provider); !ok || e.Category != plugins.CatDNS {
			problems = append(problems, "DynDNS: DNS-Anbieter wählen")
		}
		if len(d.Domains) == 0 {
			problems = append(problems, "DynDNS: mindestens eine Domain")
		}
		for _, z := range d.Domains {
			if !reZone.MatchString(z.Zone) {
				problems = append(problems, fmt.Sprintf("DynDNS: Zone %q – z. B. example.com", z.Zone))
			}
			for _, n := range z.Names {
				if !reRecord.MatchString(n) {
					problems = append(problems, fmt.Sprintf("DynDNS: Eintrag %q – @ für die Domain selbst, sonst z. B. www", n))
				}
			}
		}
		if !reDuration.MatchString(d.Interval) {
			problems = append(problems, "DynDNS: Intervall wie 5m oder 1h")
		}
	}
	if c := g.CrowdSec; c.Enabled {
		for _, u := range []string{c.APIURL, c.AppSecURL} {
			if u == "" {
				continue
			}
			if p, err := url.Parse(u); err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
				problems = append(problems, fmt.Sprintf("CrowdSec: %q ist keine URL wie http://127.0.0.1:8080", u))
			}
		}
	}
	if g.Cache.Enabled && !reDuration.MatchString(g.Cache.TTL) {
		problems = append(problems, "Cache: Dauer wie 120s oder 10m")
	}
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

// crowdsecOn reports whether sites get the bouncer.
func (o Options) crowdsecOn() bool { return o.Caps.CrowdSec && o.Global.CrowdSec.Enabled }

// tailscaleOn reports whether sites may bind to the tailnet.
func (o Options) tailscaleOn() bool { return o.Caps.Tailscale && o.Global.Tailscale.Enabled }

// cacheOn reports whether sites may use the cache directive.
func (o Options) cacheOn() bool { return o.Caps.Cache && o.Global.Cache.Enabled }

// RenderGlobal produces the snippet imported into the global options block.
func RenderGlobal(o Options) string {
	g, c := o.Global, o.Caps
	var b strings.Builder
	b.WriteString("# Globale Optionen – verwaltet von caddyEvolved (WebUI → Plugins & Einstellungen).\n")
	b.WriteString("# Wird überschrieben; eigene globale Optionen gehören direkt in die Caddyfile.\n")

	if g.RealIP.Cloudflare || len(g.RealIP.Proxies) > 0 {
		b.WriteString("servers {\n")
		switch {
		case g.RealIP.Cloudflare && len(g.RealIP.Proxies) == 0 && c.CloudflareIP:
			b.WriteString("\ttrusted_proxies cloudflare {\n\t\tinterval 12h\n\t\ttimeout 15s\n\t}\n")
		default:
			var ranges []string
			if g.RealIP.Cloudflare {
				ranges = append(ranges, CloudflareRanges...)
			}
			ranges = append(ranges, g.RealIP.Proxies...)
			fmt.Fprintf(&b, "\ttrusted_proxies static %s\n", strings.Join(ranges, " "))
		}
		if g.RealIP.Cloudflare {
			// Cloudflare names the visitor in its own header; X-Forwarded-For
			// stays as fallback for the other proxies.
			b.WriteString("\tclient_ip_headers Cf-Connecting-Ip X-Forwarded-For\n")
		}
		b.WriteString("}\n")
	}

	if d := g.DynDNS; d.Enabled && c.DynDNS && len(d.Domains) > 0 {
		if e, ok := plugins.ByID(d.Provider); ok && c.DNS[plugins.DNSName(e)] {
			b.WriteString("dynamic_dns {\n")
			fmt.Fprintf(&b, "\tprovider %s\n", plugins.DNSProviderSpec(e, "\t"))
			b.WriteString("\tdomains {\n")
			for _, z := range d.Domains {
				fmt.Fprintf(&b, "\t\t%s %s\n", z.Zone, strings.Join(z.Names, " "))
			}
			b.WriteString("\t}\n")
			fmt.Fprintf(&b, "\tcheck_interval %s\n", d.Interval)
			if d.IPv6 {
				b.WriteString("\tversions ipv4 ipv6\n")
			} else {
				b.WriteString("\tversions ipv4\n")
			}
			b.WriteString("}\n")
		}
	}

	if o.crowdsecOn() {
		b.WriteString("crowdsec {\n")
		fmt.Fprintf(&b, "\tapi_url %s\n", g.CrowdSec.APIURL)
		b.WriteString("\tapi_key {env.CROWDSEC_API_KEY}\n")
		b.WriteString("\tticker_interval 15s\n")
		if g.CrowdSec.AppSecURL != "" && c.AppSec {
			fmt.Fprintf(&b, "\tappsec_url %s\n", g.CrowdSec.AppSecURL)
		}
		b.WriteString("}\n")
	}

	if o.tailscaleOn() {
		b.WriteString("tailscale {\n\tauth_key {env.TS_AUTHKEY}\n")
		if o.StateDir != "" {
			fmt.Fprintf(&b, "\tstate_dir %s\n", filepath.ToSlash(filepath.Join(o.StateDir, "tailscale")))
		}
		if g.Tailscale.Ephemeral {
			b.WriteString("\tephemeral true\n")
		}
		b.WriteString("}\n")
	}

	if o.cacheOn() {
		fmt.Fprintf(&b, "cache {\n\tttl %s\n}\n", g.Cache.TTL)
	}
	return b.String()
}
