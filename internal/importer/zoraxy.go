package importer

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"caddyforge/internal/sites"
)

// Zoraxy stores one JSON file per rule; its structs carry no json tags, so
// the keys are the Go field names (src/mod/dynamicproxy/typedef.go).
type zoraxyUpstream struct {
	OriginIpOrDomain    string
	RequireTLS          bool
	SkipCertValidations bool
}

type zoraxyVdir struct {
	MatchingPath        string
	Domain              string
	RequireTLS          bool
	SkipCertValidations bool
	Disabled            bool
}

type zoraxyEndpoint struct {
	ProxyType              int
	RootOrMatchingDomain   string
	MatchingDomainAlias    []string
	ActiveOrigins          []zoraxyUpstream
	Disabled               bool
	VirtualDirectories     []zoraxyVdir
	AccessFilterUUID       string
	RequireRateLimit       bool
	RateLimit              int64
	BlockAICrawlers        bool
	AuthenticationProvider *struct {
		AuthMethod           int
		BasicAuthCredentials []struct {
			Username     string
			PasswordHash string
		}
		ForwardAuthURL string
	}
	HeaderRewriteRules *struct {
		RequestHostOverwrite string
	}
}

type zoraxyAccess struct {
	ID                             string
	Name                           string
	BlacklistEnabled               bool
	WhitelistEnabled               bool
	WhitelistAllowLocalAndLoopback bool
	WhiteListCountryCode           map[string]string
	WhiteListIP                    map[string]string
	BlackListContryCode            map[string]string // sic, the real key
	BlackListIP                    map[string]string
}

type zoraxyRedirect struct {
	Enabled          *bool
	RedirectURL      string
	TargetURL        string
	ForwardChildpath bool
	StatusCode       int
}

func importZoraxy(res *Result, files []plainFile) {
	accessByID := map[string]int{}
	var endpoints []struct {
		src string
		ep  zoraxyEndpoint
	}
	for _, f := range files {
		var probe map[string]json.RawMessage
		if json.Unmarshal(f.Data, &probe) != nil {
			if strings.HasSuffix(f.Name, ".config") || strings.HasSuffix(f.Name, ".json") {
				res.warn("%s: kein JSON, übersprungen", f.Name)
			}
			continue
		}
		switch {
		case probe["RootOrMatchingDomain"] != nil:
			var ep zoraxyEndpoint
			if err := json.Unmarshal(f.Data, &ep); err != nil {
				res.warn("%s: %v", f.Name, err)
				continue
			}
			endpoints = append(endpoints, struct {
				src string
				ep  zoraxyEndpoint
			}{f.Name, ep})
		case probe["BlacklistEnabled"] != nil || probe["WhitelistEnabled"] != nil:
			var a zoraxyAccess
			if err := json.Unmarshal(f.Data, &a); err != nil {
				res.warn("%s: %v", f.Name, err)
				continue
			}
			if acl, ok := zoraxyACL(a, res, f.Name); ok {
				accessByID[a.ID] = len(res.AccessLists)
				res.AccessLists = append(res.AccessLists, acl)
			}
		case probe["RedirectURL"] != nil:
			var rd zoraxyRedirect
			if err := json.Unmarshal(f.Data, &rd); err != nil {
				res.warn("%s: %v", f.Name, err)
				continue
			}
			if c, ok := zoraxyRedirectSite(rd, f.Name); ok {
				res.Sites = append(res.Sites, c)
			} else {
				res.warn("%s: Weiterleitung %s → %s enthält einen Pfad und wurde nicht übernommen", f.Name, rd.RedirectURL, rd.TargetURL)
			}
		case probe["ProxyTargetAddr"] != nil:
			res.warn("%s: Stream-Proxy (TCP/UDP) übersprungen – dafür braucht caddy das Plugin caddy-l4", f.Name)
		}
	}
	for _, e := range endpoints {
		res.Sites = append(res.Sites, zoraxySite(e.ep, e.src, accessByID, res))
	}
	if len(res.Sites) == 0 && len(res.AccessLists) == 0 {
		res.warn("keine Zoraxy-Regeln gefunden – erwartet werden conf/proxy/*.config (oder das Backup-ZIP aus Zoraxy)")
	}
}

func zoraxySite(ep zoraxyEndpoint, src string, accessByID map[string]int, res *Result) Candidate {
	c := Candidate{Source: src}
	if ep.ProxyType == 0 || ep.RootOrMatchingDomain == "/" {
		c.Warnings = append(c.Warnings, "Zoraxy-Root-Regel (Standard-Site): Domain bitte selbst eintragen")
	}
	s := sites.Site{
		Mode:    sites.ModeProxy,
		TLS:     sites.TLSAuto,
		Enabled: !ep.Disabled,
		Domains: append([]string{ep.RootOrMatchingDomain}, ep.MatchingDomainAlias...),
	}
	if ep.RootOrMatchingDomain == "/" {
		s.Domains = ep.MatchingDomainAlias
	}
	for _, o := range ep.ActiveOrigins {
		up, _, p := upstreamFromURL(o.OriginIpOrDomain)
		if o.RequireTLS && !strings.HasPrefix(up, "https://") {
			up = "https://" + up
		}
		if o.SkipCertValidations {
			s.UpstreamInsecure = true
		}
		if p != "" {
			c.Warnings = append(c.Warnings, "Upstream-Pfad "+p+" nicht übernommen (reverse_proxy leitet den Pfad unverändert weiter)")
		}
		s.Upstreams = append(s.Upstreams, up)
	}
	if len(ep.ActiveOrigins) > 1 {
		s.LBPolicy = "round_robin"
	}
	var extra []string
	for _, v := range ep.VirtualDirectories {
		if v.Disabled {
			continue
		}
		up, _, _ := upstreamFromURL(v.Domain)
		if v.RequireTLS && !strings.HasPrefix(up, "https://") {
			up = "https://" + up
		}
		p := strings.TrimSuffix(v.MatchingPath, "/")
		if p == "" || strings.ContainsAny(p+up, " {}\"\n") {
			c.Warnings = append(c.Warnings, "virtuelles Verzeichnis "+v.MatchingPath+" übersprungen")
			continue
		}
		extra = append(extra, fmt.Sprintf("handle_path %s/* {\n\treverse_proxy %s\n}", p, up))
	}
	if len(extra) > 0 {
		s.Extra = strings.Join(extra, "\n")
		c.Warnings = append(c.Warnings, "virtuelle Verzeichnisse als handle_path im Zusatzfeld übernommen")
	}
	if h := ep.HeaderRewriteRules; h != nil && h.RequestHostOverwrite != "" {
		c.Warnings = append(c.Warnings, "Host-Header-Überschreibung ("+h.RequestHostOverwrite+") nicht übernommen")
	}
	if ap := ep.AuthenticationProvider; ap != nil {
		switch ap.AuthMethod {
		case 1:
			c.Warnings = append(c.Warnings, fmt.Sprintf("Basic Auth mit %d Benutzer(n): Zoraxy-Hashes sind nicht übertragbar – Benutzer in einer Access List neu anlegen", len(ap.BasicAuthCredentials)))
		case 2:
			c.Warnings = append(c.Warnings, "Forward-Auth ("+ap.ForwardAuthURL+") nicht übernommen – im Zusatzfeld mit forward_auth nachbauen")
		case 3, 4:
			c.Warnings = append(c.Warnings, "OAuth2/ZorxAuth nicht übernommen – mit dem Plugin caddy-security nachbauen")
		}
	}
	if id := ep.AccessFilterUUID; id != "" && id != "default" {
		if _, ok := accessByID[id]; ok {
			s.AccessList = sites.Slug(res.AccessLists[accessByID[id]].AccessList.Name)
			res.AccessLists[accessByID[id]].AccessList.ID = s.AccessList
		} else {
			c.Warnings = append(c.Warnings, "Access Rule "+id+" nicht in den hochgeladenen Dateien (conf/access/"+id+".json)")
		}
	}
	if ep.RequireRateLimit {
		s.RateLimit = &sites.RateLimit{Enabled: true, Events: int(ep.RateLimit), Window: "1s"}
		c.Warnings = append(c.Warnings, "Rate Limit übernommen – braucht das Plugin caddy-ratelimit")
	}
	if ep.BlockAICrawlers {
		s.Defender = &sites.Defender{Enabled: true}
		c.Warnings = append(c.Warnings, "KI-Crawler-Sperre übernommen – braucht das Plugin caddy-defender")
	}
	c.Site = s
	return c
}

func zoraxyACL(a zoraxyAccess, res *Result, src string) (ACLCandidate, bool) {
	if a.ID == "default" && !a.WhitelistEnabled && !a.BlacklistEnabled {
		return ACLCandidate{}, false
	}
	c := ACLCandidate{Source: src}
	acl := sites.AccessList{Name: firstNonEmpty(a.Name, a.ID)}
	if a.WhitelistEnabled {
		acl.Allow = keys(a.WhiteListIP)
		if a.WhitelistAllowLocalAndLoopback {
			acl.Allow = append(acl.Allow, "private_ranges")
		}
		acl.AllowCountries = upperKeys(a.WhiteListCountryCode)
	}
	if a.BlacklistEnabled {
		acl.Deny = keys(a.BlackListIP)
		acl.DenyCountries = upperKeys(a.BlackListContryCode)
	}
	if len(acl.AllowCountries)+len(acl.DenyCountries) > 0 {
		acl.GeoDB = "/var/lib/caddyforge/GeoLite2-Country.mmdb"
		c.Warnings = append(c.Warnings, "Länderregeln brauchen das Plugin maxmind-geolocation und die GeoLite2-Datenbank unter "+acl.GeoDB)
	}
	if len(acl.Allow)+len(acl.Deny)+len(acl.AllowCountries)+len(acl.DenyCountries) == 0 {
		res.warn("%s: Access Rule %s ist leer und wurde übersprungen", src, acl.Name)
		return c, false
	}
	c.AccessList = acl
	return c, true
}

func zoraxyRedirectSite(rd zoraxyRedirect, src string) (Candidate, bool) {
	if rd.Enabled != nil && !*rd.Enabled {
		return Candidate{}, false
	}
	from := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(rd.RedirectURL, "https://"), "http://"), "/")
	if strings.Contains(from, "/") {
		return Candidate{}, false
	}
	to := rd.TargetURL
	if !strings.Contains(to, "://") {
		to = "https://" + to
	}
	if u, err := url.Parse(to); err != nil || (u.Path != "" && u.Path != "/") {
		return Candidate{}, false
	}
	c := Candidate{Source: src, Site: sites.Site{
		Domains: []string{from}, Mode: sites.ModeRedirect, RedirectTo: strings.TrimSuffix(to, "/"), TLS: sites.TLSAuto, Enabled: true,
	}}
	if !rd.ForwardChildpath {
		c.Warnings = append(c.Warnings, "Zoraxy leitete ohne Pfad weiter; caddyforge hängt den Pfad an")
	}
	return c, true
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, strings.TrimSpace(k))
	}
	sort.Strings(out)
	return out
}

func upperKeys(m map[string]string) []string {
	out := keys(m)
	for i := range out {
		out[i] = strings.ToUpper(out[i])
	}
	return out
}
