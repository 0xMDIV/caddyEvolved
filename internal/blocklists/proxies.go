package blocklists

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ProxyProvider is a CDN or proxy service whose published address ranges
// caddy may trust, so the visitor's IP is read from the provider's header.
type ProxyProvider struct {
	ID, Label string
	// URLs publish the ranges; Parse reads one response (default: every IP
	// or CIDR in the body, which covers plain lists and JSON arrays).
	URLs  []string
	Parse func([]byte) []string
	// Header names the visitor; empty means X-Forwarded-For.
	Header string
	// Builtin is used while nothing was downloaded yet.
	Builtin []string
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

// ProxyProviders in the order the UI lists them and headers are tried.
var ProxyProviders = []ProxyProvider{
	{
		ID: "cloudflare", Label: "Cloudflare",
		URLs:    []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"},
		Header:  "Cf-Connecting-Ip",
		Builtin: CloudflareRanges,
	},
	{
		ID: "fastly", Label: "Fastly",
		URLs:   []string{"https://api.fastly.com/public-ip-list"},
		Header: "Fastly-Client-Ip",
		Builtin: []string{
			"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24",
			"104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17", "151.101.0.0/16",
			"157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
			"172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
			"2a04:4e40::/32", "2a04:4e42::/31", "2a04:4e44::/32",
		},
	},
	{
		// Bunny publishes single edge servers (several hundred); no builtin.
		ID: "bunny", Label: "Bunny CDN",
		URLs: []string{"https://bunnycdn.com/api/system/edgeserverlist/plain", "https://bunnycdn.com/api/system/edgeserverlist/ipv6"},
	},
	{
		ID: "cloudfront", Label: "AWS CloudFront",
		URLs:  []string{"https://ip-ranges.amazonaws.com/ip-ranges.json"},
		Parse: parseCloudFront,
	},
}

// ProxyByID finds a provider.
func ProxyByID(id string) (ProxyProvider, bool) {
	for _, p := range ProxyProviders {
		if p.ID == id {
			return p, true
		}
	}
	return ProxyProvider{}, false
}

var reAddrToken = regexp.MustCompile(`[0-9A-Fa-f:.]+(?:/[0-9]{1,3})?`)

// parseRanges picks every valid IP or CIDR out of a response.
func parseRanges(body []byte) []string {
	var out []string
	for _, tok := range reAddrToken.FindAllString(string(body), -1) {
		if !strings.ContainsAny(tok, ".:") {
			continue
		}
		if p, err := netip.ParsePrefix(tok); err == nil {
			out = append(out, p.String())
		} else if a, err := netip.ParseAddr(tok); err == nil {
			out = append(out, a.String())
		}
	}
	return out
}

// parseCloudFront keeps the CLOUDFRONT entries of AWS's ip-ranges.json.
func parseCloudFront(body []byte) []string {
	var doc struct {
		Prefixes []struct {
			IP      string `json:"ip_prefix"`
			Service string `json:"service"`
		} `json:"prefixes"`
		IPv6 []struct {
			IP      string `json:"ipv6_prefix"`
			Service string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	var out []string
	for _, p := range doc.Prefixes {
		if p.Service == "CLOUDFRONT" {
			out = append(out, p.IP)
		}
	}
	for _, p := range doc.IPv6 {
		if p.Service == "CLOUDFRONT" {
			out = append(out, p.IP)
		}
	}
	return parseRanges([]byte(strings.Join(out, "\n")))
}

func proxyFile(dir, id string) string { return filepath.Join(dir, "proxy-"+id+".txt") }

func proxyCache(dir, id string) []string {
	data, err := os.ReadFile(proxyFile(dir, id))
	if err != nil {
		return nil
	}
	return strings.Fields(string(data))
}

// ProxyRanges returns the downloaded ranges of a provider, else its builtin
// list; nil for an unknown provider.
func ProxyRanges(dir, id string) []string {
	p, ok := ProxyByID(id)
	if !ok {
		return nil
	}
	if r := proxyCache(dir, id); len(r) > 0 {
		return r
	}
	return append([]string{}, p.Builtin...)
}

// UpdateProxy downloads a provider's ranges. A response without any valid
// range keeps the old file, so an outage cannot drop the trust silently.
func UpdateProxy(ctx context.Context, dir, id string) (int, error) {
	p, ok := ProxyByID(id)
	if !ok {
		return 0, errors.New("unbekannter Proxy-Anbieter " + id)
	}
	return updateProxy(ctx, dir, p)
}

func updateProxy(ctx context.Context, dir string, p ProxyProvider) (int, error) {
	parse := p.Parse
	if parse == nil {
		parse = parseRanges
	}
	var all []string
	for _, u := range p.URLs {
		data, err := get(ctx, u, 8<<20)
		if err != nil {
			return 0, err
		}
		all = append(all, parse(data)...)
	}
	if len(all) == 0 {
		return 0, errors.New(p.Label + ": keine Adressbereiche in der Antwort")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	return len(all), writeAtomic(proxyFile(dir, p.ID), []byte(strings.Join(all, "\n")+"\n"))
}
