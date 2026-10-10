package importer

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"caddyforge/internal/sites"
)

// Traefik v3 dynamic configuration (file provider), the subset that maps
// onto caddyforge sites.
type tkDynamic struct {
	HTTP tkHTTP `yaml:"http" toml:"http"`
}

type tkHTTP struct {
	Routers           map[string]*tkRouter     `yaml:"routers" toml:"routers"`
	Services          map[string]*tkService    `yaml:"services" toml:"services"`
	Middlewares       map[string]*tkMiddleware `yaml:"middlewares" toml:"middlewares"`
	ServersTransports map[string]*struct {
		InsecureSkipVerify bool `yaml:"insecureSkipVerify" toml:"insecureSkipVerify"`
	} `yaml:"serversTransports" toml:"serversTransports"`
}

type tkRouter struct {
	Rule        string   `yaml:"rule" toml:"rule"`
	EntryPoints []string `yaml:"entryPoints" toml:"entryPoints"`
	Service     string   `yaml:"service" toml:"service"`
	Middlewares []string `yaml:"middlewares" toml:"middlewares"`
	TLS         *struct {
		CertResolver string `yaml:"certResolver" toml:"certResolver"`
	} `yaml:"tls" toml:"tls"`
}

type tkServer struct {
	URL string `yaml:"url" toml:"url"`
}

type tkService struct {
	LoadBalancer *struct {
		Servers          []tkServer `yaml:"servers" toml:"servers"`
		ServersTransport string     `yaml:"serversTransport" toml:"serversTransport"`
	} `yaml:"loadBalancer" toml:"loadBalancer"`
}

type tkIPList struct {
	SourceRange []string `yaml:"sourceRange" toml:"sourceRange"`
}

type tkMiddleware struct {
	BasicAuth *struct {
		Users []string `yaml:"users" toml:"users"`
	} `yaml:"basicAuth" toml:"basicAuth"`
	IPAllowList    *tkIPList `yaml:"ipAllowList" toml:"ipAllowList"`
	IPWhiteList    *tkIPList `yaml:"ipWhiteList" toml:"ipWhiteList"`
	Compress       *struct{} `yaml:"compress" toml:"compress"`
	RedirectScheme *struct{} `yaml:"redirectScheme" toml:"redirectScheme"`
	Headers        *struct{} `yaml:"headers" toml:"headers"`
	StripPrefix    *struct{} `yaml:"stripPrefix" toml:"stripPrefix"`
	RateLimit      *struct{} `yaml:"rateLimit" toml:"rateLimit"`
	ForwardAuth    *struct {
		Address string `yaml:"address" toml:"address"`
	} `yaml:"forwardAuth" toml:"forwardAuth"`
}

var (
	reHostMatcher = regexp.MustCompile("Host\\(([^)]*)\\)")
	reBacktick    = regexp.MustCompile("[`\"]([^`\"]+)[`\"]")
	reRuleRest    = regexp.MustCompile(`[\s()|&!]+`)
)

func importTraefik(res *Result, files []plainFile) error {
	merged := tkDynamic{HTTP: tkHTTP{
		Routers: map[string]*tkRouter{}, Services: map[string]*tkService{}, Middlewares: map[string]*tkMiddleware{},
	}}
	merged.HTTP.ServersTransports = map[string]*struct {
		InsecureSkipVerify bool `yaml:"insecureSkipVerify" toml:"insecureSkipVerify"`
	}{}
	composeHosts := map[string]string{} // service name -> compose service, for warnings
	for _, f := range files {
		lower := strings.ToLower(f.Name)
		var d tkDynamic
		trimmed := strings.TrimSpace(string(f.Data))
		looksTOML := strings.HasPrefix(trimmed, "[http") || strings.HasPrefix(trimmed, "[[http")
		switch {
		case strings.HasSuffix(lower, ".toml") || looksTOML:
			if _, err := toml.Decode(string(f.Data), &d); err != nil {
				return fmt.Errorf("%s: %w", f.Name, err)
			}
		default:
			var probe map[string]any
			if err := yaml.Unmarshal(f.Data, &probe); err != nil {
				return fmt.Errorf("%s: kein gültiges YAML: %w", f.Name, err)
			}
			if _, ok := probe["services"]; ok && probe["http"] == nil {
				dd, hosts, err := composeLabels(f.Data)
				if err != nil {
					return fmt.Errorf("%s: %w", f.Name, err)
				}
				d = dd
				for k, v := range hosts {
					composeHosts[k] = v
				}
				break
			}
			if err := yaml.Unmarshal(f.Data, &d); err != nil {
				return fmt.Errorf("%s: %w", f.Name, err)
			}
		}
		mergeDynamic(&merged, d)
	}
	if len(merged.HTTP.Routers) == 0 {
		res.warn("keine HTTP-Router gefunden – erwartet wird eine dynamische Traefik-Konfiguration (http.routers) oder eine docker-compose.yml mit traefik-Labels")
		return nil
	}

	names := make([]string, 0, len(merged.HTTP.Routers))
	for n := range merged.HTTP.Routers {
		names = append(names, n)
	}
	sort.Strings(names)
	aclByMW := map[string]string{}
	for _, name := range names {
		rt := merged.HTTP.Routers[name]
		c := Candidate{Source: "router " + name}
		s := sites.Site{ID: sites.Slug(name), Mode: sites.ModeProxy, TLS: sites.TLSAuto, Enabled: true}

		for _, m := range reHostMatcher.FindAllStringSubmatch(rt.Rule, -1) {
			for _, h := range reBacktick.FindAllStringSubmatch(m[1], -1) {
				s.Domains = append(s.Domains, h[1])
			}
		}
		if rest := reRuleRest.ReplaceAllString(reHostMatcher.ReplaceAllString(rt.Rule, ""), ""); rest != "" {
			c.Warnings = append(c.Warnings, "Regel enthält mehr als Host(): "+rt.Rule+" – nur die Hosts wurden übernommen")
		}
		if len(s.Domains) == 0 {
			c.Warnings = append(c.Warnings, "keine Host()-Regel – Domain bitte eintragen")
		}
		if rt.TLS == nil && onlyWeb(rt.EntryPoints) {
			s.TLS = sites.TLSOff
			c.Warnings = append(c.Warnings, "Router ohne TLS – als HTTP-Site übernommen; für HTTPS TLS auf automatisch stellen")
		}

		svc := merged.HTTP.Services[stripProvider(rt.Service)]
		switch {
		case svc == nil || svc.LoadBalancer == nil:
			c.Warnings = append(c.Warnings, "Service "+rt.Service+" nicht gefunden – Ziel bitte eintragen")
		default:
			for _, srv := range svc.LoadBalancer.Servers {
				up, _, p := upstreamFromURL(srv.URL)
				if p != "" {
					c.Warnings = append(c.Warnings, "Pfad "+p+" im Ziel "+srv.URL+" nicht übernommen")
				}
				s.Upstreams = append(s.Upstreams, up)
				host := up
				if i := strings.Index(host, "://"); i >= 0 {
					host = host[i+3:]
				}
				if cs, ok := composeHosts[strings.Split(host, ":")[0]]; ok {
					c.Warnings = append(c.Warnings, "Ziel "+up+" ist der Docker-Service "+cs+" – caddy auf dem LXC kennt diesen Namen nicht, bitte IP:Port eintragen")
				}
			}
			if len(s.Upstreams) > 1 {
				s.LBPolicy = "round_robin"
			}
			if t := merged.HTTP.ServersTransports[stripProvider(svc.LoadBalancer.ServersTransport)]; t != nil && t.InsecureSkipVerify {
				s.UpstreamInsecure = true
			}
		}

		for _, mwName := range rt.Middlewares {
			key := stripProvider(mwName)
			mw := merged.HTTP.Middlewares[key]
			if mw == nil {
				c.Warnings = append(c.Warnings, "Middleware "+mwName+" nicht gefunden")
				continue
			}
			switch {
			case mw.Compress != nil:
				s.Compress = true
			case mw.RedirectScheme != nil:
				// caddy redirects to https on its own
			case mw.BasicAuth != nil || mw.IPAllowList != nil || mw.IPWhiteList != nil:
				id, ok := aclByMW[key]
				if !ok {
					id = traefikACL(res, key, mw)
					aclByMW[key] = id
				}
				if id == "" {
					continue
				}
				if s.AccessList != "" && s.AccessList != id {
					c.Warnings = append(c.Warnings, "mehrere Zugriffs-Middlewares – nur "+s.AccessList+" übernommen")
					continue
				}
				s.AccessList = id
			case mw.ForwardAuth != nil:
				c.Warnings = append(c.Warnings, "forwardAuth ("+mw.ForwardAuth.Address+") nicht übernommen – im Zusatzfeld mit forward_auth nachbauen")
			default:
				c.Warnings = append(c.Warnings, "Middleware "+mwName+" hat kein caddyforge-Gegenstück und wurde ausgelassen")
			}
		}
		c.Site = s
		res.Sites = append(res.Sites, c)
	}
	return nil
}

// traefikACL builds an access list from basicAuth/ipAllowList and returns
// its id ("" if nothing usable was left).
func traefikACL(res *Result, name string, mw *tkMiddleware) string {
	c := ACLCandidate{Source: "middleware " + name}
	acl := sites.AccessList{ID: sites.Slug(name), Name: name}
	for _, l := range []*tkIPList{mw.IPAllowList, mw.IPWhiteList} {
		if l != nil {
			acl.Allow = append(acl.Allow, l.SourceRange...)
		}
	}
	if mw.BasicAuth != nil {
		for _, u := range mw.BasicAuth.Users {
			user, hash, ok := strings.Cut(u, ":")
			if !ok {
				continue
			}
			// bcrypt ($2y$/$2a$/$2b$) works in caddy as is; apr1/sha1 cannot be converted.
			if strings.HasPrefix(hash, "$2") {
				acl.Users = append(acl.Users, sites.ACLUser{Username: user, Hash: strings.Replace(hash, "$2y$", "$2a$", 1)})
			} else {
				c.Warnings = append(c.Warnings, "Benutzer "+user+": Hash-Verfahren nicht bcrypt – Passwort in caddyforge neu setzen")
			}
		}
	}
	if len(acl.Allow)+len(acl.Users) == 0 {
		res.warn("Middleware %s: nichts übernehmbar (keine IP-Bereiche, keine bcrypt-Benutzer)", name)
		return ""
	}
	c.AccessList = acl
	res.AccessLists = append(res.AccessLists, c)
	return acl.ID
}

func onlyWeb(eps []string) bool {
	if len(eps) == 0 {
		return false
	}
	for _, e := range eps {
		if e != "web" && e != "http" {
			return false
		}
	}
	return true
}

func stripProvider(name string) string {
	if i := strings.IndexByte(name, '@'); i >= 0 {
		return name[:i]
	}
	return name
}

func mergeDynamic(dst *tkDynamic, src tkDynamic) {
	for k, v := range src.HTTP.Routers {
		dst.HTTP.Routers[k] = v
	}
	for k, v := range src.HTTP.Services {
		dst.HTTP.Services[k] = v
	}
	for k, v := range src.HTTP.Middlewares {
		dst.HTTP.Middlewares[k] = v
	}
	for k, v := range src.HTTP.ServersTransports {
		dst.HTTP.ServersTransports[k] = v
	}
}

// composeLabels reads traefik.* labels from a docker-compose file and builds
// the same structure the file provider would. Labels come as a list
// ("k=v") or a map.
func composeLabels(data []byte) (tkDynamic, map[string]string, error) {
	var doc struct {
		Services map[string]struct {
			Labels yaml.Node `yaml:"labels"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return tkDynamic{}, nil, err
	}
	d := tkDynamic{HTTP: tkHTTP{Routers: map[string]*tkRouter{}, Services: map[string]*tkService{}, Middlewares: map[string]*tkMiddleware{}}}
	hosts := map[string]string{}
	for svcName, svc := range doc.Services {
		labels := map[string]string{}
		switch svc.Labels.Kind {
		case yaml.SequenceNode:
			for _, n := range svc.Labels.Content {
				if k, v, ok := strings.Cut(n.Value, "="); ok {
					labels[strings.TrimSpace(k)] = strings.TrimSpace(v)
				}
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(svc.Labels.Content); i += 2 {
				labels[svc.Labels.Content[i].Value] = svc.Labels.Content[i+1].Value
			}
		}
		if labels["traefik.enable"] == "false" {
			continue
		}
		port, scheme, url := "", "http", ""
		var routerNames, svcLabels []string
		for k, v := range labels {
			v = strings.ReplaceAll(v, "$$", "$")
			parts := strings.Split(k, ".")
			if len(parts) < 5 || parts[0] != "traefik" || parts[1] != "http" {
				continue
			}
			name, field := parts[3], strings.ToLower(strings.Join(parts[4:], "."))
			switch parts[2] {
			case "routers":
				r := d.HTTP.Routers[name]
				if r == nil {
					r = &tkRouter{}
					d.HTTP.Routers[name] = r
					routerNames = append(routerNames, name)
				}
				switch field {
				case "rule":
					r.Rule = v
				case "entrypoints":
					r.EntryPoints = splitComma(v)
				case "service":
					r.Service = v
				case "middlewares":
					r.Middlewares = splitComma(v)
				case "tls", "tls.certresolver":
					if r.TLS == nil {
						r.TLS = &struct {
							CertResolver string `yaml:"certResolver" toml:"certResolver"`
						}{}
					}
				}
			case "services":
				svcLabels = append(svcLabels, name)
				switch field {
				case "loadbalancer.server.port":
					port = v
				case "loadbalancer.server.scheme":
					scheme = v
				case "loadbalancer.server.url":
					url = v
				}
			case "middlewares":
				mw := d.HTTP.Middlewares[name]
				if mw == nil {
					mw = &tkMiddleware{}
					d.HTTP.Middlewares[name] = mw
				}
				switch field {
				case "basicauth.users":
					mw.BasicAuth = &struct {
						Users []string `yaml:"users" toml:"users"`
					}{Users: splitComma(v)}
				case "ipallowlist.sourcerange", "ipwhitelist.sourcerange":
					mw.IPAllowList = &tkIPList{SourceRange: splitComma(v)}
				case "compress":
					mw.Compress = &struct{}{}
				}
			}
		}
		if len(routerNames) == 0 {
			continue
		}
		if url == "" {
			if port == "" {
				port = "80"
			}
			url = scheme + "://" + svcName + ":" + port
			hosts[svcName] = svcName
		}
		// Docker routers without an explicit service use the container's own;
		// a labelled service name points at the same container.
		lb := &tkService{LoadBalancer: &struct {
			Servers          []tkServer `yaml:"servers" toml:"servers"`
			ServersTransport string     `yaml:"serversTransport" toml:"serversTransport"`
		}{Servers: []tkServer{{URL: url}}}}
		d.HTTP.Services[svcName] = lb
		for _, n := range svcLabels {
			d.HTTP.Services[n] = lb
		}
		for _, rn := range routerNames {
			if d.HTTP.Routers[rn].Service == "" {
				d.HTTP.Routers[rn].Service = svcName
			}
		}
	}
	return d, hosts, nil
}

func splitComma(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
