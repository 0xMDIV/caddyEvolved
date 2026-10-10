package importer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"caddyforge/internal/sites"
)

// Nginx Proxy Manager keeps its hosts in SQLite. Two exports are accepted,
// both JSON arrays of rows:
//
//   - the REST API: GET /api/nginx/proxy-hosts?expand=access_list
//     (and /api/nginx/redirection-hosts)
//   - sqlite3 -json /data/database.sqlite "select * from proxy_host where is_deleted=0"
//
// The sqlite form stores domain_names and locations as JSON strings and
// booleans as 0/1, so fields are decoded leniently.
type npmRow struct {
	ID                json.RawMessage `json:"id"`
	DomainNames       json.RawMessage `json:"domain_names"`
	ForwardScheme     string          `json:"forward_scheme"`
	ForwardHost       string          `json:"forward_host"`
	ForwardPort       json.RawMessage `json:"forward_port"`
	ForwardDomainName string          `json:"forward_domain_name"` // redirection hosts
	PreservePath      json.RawMessage `json:"preserve_path"`
	Enabled           json.RawMessage `json:"enabled"`
	IsDeleted         json.RawMessage `json:"is_deleted"`
	BlockExploits     json.RawMessage `json:"block_exploits"`
	CachingEnabled    json.RawMessage `json:"caching_enabled"`
	AdvancedConfig    string          `json:"advanced_config"`
	Locations         json.RawMessage `json:"locations"`
	AccessListID      json.RawMessage `json:"access_list_id"`
	CertificateID     json.RawMessage `json:"certificate_id"`
	SSLForced         json.RawMessage `json:"ssl_forced"`
	AccessList        *npmAccessList  `json:"access_list"`
	IncomingPort      json.RawMessage `json:"incoming_port"` // streams
}

type npmAccessList struct {
	ID      json.RawMessage `json:"id"`
	Name    string          `json:"name"`
	Items   []npmAuthItem   `json:"items"`
	Clients []npmClient     `json:"clients"`
}

type npmAuthItem struct {
	Username string `json:"username"`
}

type npmClient struct {
	Address   string `json:"address"`
	Directive string `json:"directive"`
}

type npmLocation struct {
	Path          string          `json:"path"`
	ForwardScheme string          `json:"forward_scheme"`
	ForwardHost   string          `json:"forward_host"`
	ForwardPort   json.RawMessage `json:"forward_port"`
}

func importNPM(res *Result, files []plainFile) error {
	aclByID := map[string]string{}
	for _, f := range files {
		var rows []npmRow
		if err := json.Unmarshal(f.Data, &rows); err != nil {
			return fmt.Errorf("%s: erwartet wird ein JSON-Array (NPM-API oder sqlite3 -json): %w", f.Name, err)
		}
		for i, r := range rows {
			src := fmt.Sprintf("%s #%d", f.Name, i+1)
			if truthy(r.IsDeleted) {
				continue
			}
			if len(r.IncomingPort) > 0 && string(r.IncomingPort) != "null" {
				res.warn("%s: Stream (TCP/UDP) übersprungen – dafür braucht caddy das Plugin caddy-l4", src)
				continue
			}
			res.Sites = append(res.Sites, npmSite(res, r, src, aclByID))
		}
	}
	if len(res.Sites) == 0 {
		res.warn("keine Hosts gefunden")
	}
	return nil
}

func npmSite(res *Result, r npmRow, src string, aclByID map[string]string) Candidate {
	c := Candidate{Source: src}
	s := sites.Site{Mode: sites.ModeProxy, TLS: sites.TLSAuto, Enabled: r.Enabled == nil || truthy(r.Enabled)}
	s.Domains = stringList(r.DomainNames)

	if r.ForwardDomainName != "" {
		// A redirection host.
		scheme := r.ForwardScheme
		if scheme == "" || scheme == "auto" || scheme == "$scheme" {
			scheme = "https"
		}
		s.Mode = sites.ModeRedirect
		s.RedirectTo = scheme + "://" + strings.TrimSuffix(r.ForwardDomainName, "/")
		if len(r.PreservePath) > 0 && !truthy(r.PreservePath) {
			c.Warnings = append(c.Warnings, "NPM leitete ohne Pfad weiter; caddyforge hängt den Pfad an")
		}
	} else {
		host := r.ForwardHost
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			host = "[" + host + "]" // IPv6
		}
		up := host + ":" + rawString(r.ForwardPort)
		if r.ForwardScheme == "https" {
			up = "https://" + up
		}
		s.Upstreams = []string{up}
	}
	if !truthy(r.CertificateID) {
		// NPM served it over plain HTTP; caddy would obtain a certificate.
		c.Warnings = append(c.Warnings, "in NPM ohne Zertifikat – caddy holt automatisch eins; für reines HTTP TLS auf „aus“ stellen")
	}
	if strings.TrimSpace(r.AdvancedConfig) != "" {
		c.Warnings = append(c.Warnings, "nginx-Advanced-Config nicht übernommen:\n"+strings.TrimSpace(r.AdvancedConfig))
	}
	if truthy(r.BlockExploits) {
		c.Warnings = append(c.Warnings, "„Block Common Exploits“ war an – Gegenstück ist die WAF (Plugin coraza)")
	}
	if truthy(r.CachingEnabled) {
		c.Warnings = append(c.Warnings, "Caching war an – Gegenstück ist das Plugin souin-cache")
	}
	var extra []string
	for _, l := range locations(r.Locations) {
		up := l.ForwardHost + ":" + rawString(l.ForwardPort)
		if l.ForwardScheme == "https" {
			up = "https://" + up
		}
		p := strings.TrimSuffix(l.Path, "/")
		if p == "" || strings.ContainsAny(p+up, " {}\"\n") {
			c.Warnings = append(c.Warnings, "Location "+l.Path+" übersprungen")
			continue
		}
		extra = append(extra, fmt.Sprintf("handle_path %s/* {\n\treverse_proxy %s\n}", p, up))
	}
	if len(extra) > 0 {
		s.Extra = strings.Join(extra, "\n")
		c.Warnings = append(c.Warnings, "Custom Locations als handle_path im Zusatzfeld übernommen")
	}
	if a := r.AccessList; a != nil {
		key := rawString(a.ID)
		id, ok := aclByID[key]
		if !ok {
			id = npmACL(res, a)
			aclByID[key] = id
		}
		s.AccessList = id
	} else if truthy(r.AccessListID) {
		c.Warnings = append(c.Warnings, "Access List "+rawString(r.AccessListID)+" nur als ID vorhanden – mit ?expand=access_list exportieren oder neu anlegen")
	}
	c.Site = s
	return c
}

func npmACL(res *Result, a *npmAccessList) string {
	c := ACLCandidate{Source: "access list " + a.Name}
	acl := sites.AccessList{ID: sites.Slug(a.Name), Name: a.Name}
	for _, cl := range a.Clients {
		addr := strings.TrimSpace(cl.Address)
		if addr == "" || addr == "all" {
			continue
		}
		if cl.Directive == "deny" {
			acl.Deny = append(acl.Deny, addr)
		} else {
			acl.Allow = append(acl.Allow, addr)
		}
	}
	if len(a.Items) > 0 {
		c.Warnings = append(c.Warnings, fmt.Sprintf("%d Benutzer: NPM gibt keine Passwörter heraus – in caddyforge neu setzen", len(a.Items)))
	}
	if len(acl.Allow)+len(acl.Deny) == 0 {
		res.warn("Access List %s: nur Benutzer – nach dem Import Benutzer mit Passwort anlegen und der Site zuweisen", a.Name)
		return ""
	}
	c.AccessList = acl
	res.AccessLists = append(res.AccessLists, c)
	return acl.ID
}

// stringList accepts ["a","b"] or the sqlite form "[\"a\",\"b\"]".
func stringList(raw json.RawMessage) []string {
	var v []string
	if json.Unmarshal(raw, &v) == nil {
		return v
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if json.Unmarshal([]byte(s), &v) == nil {
			return v
		}
		return []string{s}
	}
	return nil
}

func locations(raw json.RawMessage) []npmLocation {
	var v []npmLocation
	if json.Unmarshal(raw, &v) == nil {
		return v
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		json.Unmarshal([]byte(s), &v)
	}
	return v
}

// truthy reads true/false, 1/0, "1"/"0" alike.
func truthy(raw json.RawMessage) bool {
	switch strings.Trim(strings.TrimSpace(string(raw)), `"`) {
	case "", "null", "0", "false":
		return false
	}
	return true
}

func rawString(raw json.RawMessage) string {
	t := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if t == "null" {
		return ""
	}
	if n, err := strconv.ParseFloat(t, 64); err == nil {
		return strconv.Itoa(int(n))
	}
	return t
}
