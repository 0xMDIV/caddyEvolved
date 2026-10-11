package api

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"caddyevolved/internal/certs"
	"caddyevolved/internal/platform"
	"caddyevolved/internal/probe"
	"caddyevolved/internal/sites"
)

// pendingCert is a domain caddy should hold a certificate for but does not.
type pendingCert struct {
	Site        string `json:"site"`
	Domain      string `json:"domain"`
	TLS         string `json:"tls"`
	DNSProvider string `json:"dnsProvider,omitempty"`
	Cloudflare  bool   `json:"cloudflare"`
	Error       string `json:"error,omitempty"`
	Hint        string `json:"hint"`
}

// pendingCerts lists the domains of enabled sites with automatic HTTPS that
// have no certificate in storage yet, with the last ACME error and the step
// that most likely fixes it.
func pendingCerts(ctx context.Context, have []certs.Cert, siteList []sites.Site) []pendingCert {
	var names []string
	for _, c := range have {
		names = append(names, c.Domains...)
	}
	var out []pendingCert
	for _, st := range siteList {
		if !st.Enabled || (st.TLS != sites.TLSAuto && st.TLS != sites.TLSDNS) {
			continue
		}
		for _, d := range st.Domains {
			host := certHost(d)
			if host == "" || siteCovers(sites.Site{Domains: []string{host}}, names) {
				continue
			}
			out = append(out, pendingCert{Site: st.ID, Domain: host, TLS: st.TLS, DNSProvider: st.DNSProvider})
		}
	}
	if len(out) == 0 {
		return []pendingCert{}
	}

	errs := probe.RecentACMEErrors(ctx)
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := range out {
		wg.Add(1)
		go func(p *pendingCert) {
			defer wg.Done()
			ips, err := net.DefaultResolver.LookupHost(lookupCtx, strings.TrimPrefix(p.Domain, "*."))
			if err != nil || len(ips) == 0 {
				return
			}
			p.Cloudflare = true
			for _, ip := range ips {
				if !probe.IsCloudflare(ip) {
					p.Cloudflare = false
				}
			}
		}(&out[i])
	}
	wg.Wait()

	lan := platform.PrimaryIP()
	for i := range out {
		p := &out[i]
		p.Error = errs[p.Domain]
		switch {
		case p.Error != "":
			p.Hint = probe.ACMEHint(p.Error, p.Cloudflare && p.TLS == sites.TLSAuto, lan)
		case p.Cloudflare && p.TLS == sites.TLSAuto:
			p.Hint = "Die Domain läuft über den Cloudflare-Proxy. Am zuverlässigsten ist dann die DNS-Challenge mit dem Cloudflare-Plugin."
		default:
			p.Hint = "Caddy holt das Zertifikat kurz nach dem Anlegen der Site. Kommt nach ein paar Minuten keins, zeigt Sites → Testen den Grund."
		}
	}
	return out
}

// certHost strips a port and skips names no public CA issues for.
func certHost(d string) string {
	host := strings.ToLower(strings.TrimSpace(d))
	if strings.HasPrefix(host, ":") || strings.HasPrefix(host, "http://") {
		return ""
	}
	host = strings.TrimPrefix(host, "https://")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host == "" || host == "localhost" || net.ParseIP(host) != nil {
		return ""
	}
	return host
}
