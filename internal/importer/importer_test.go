package importer

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func find(t *testing.T, r Result, domain string) Candidate {
	t.Helper()
	for _, c := range r.Sites {
		for _, d := range c.Site.Domains {
			if d == domain {
				return c
			}
		}
	}
	t.Fatalf("keine Site für %s in %+v", domain, r.Sites)
	return Candidate{}
}

func TestCaddyfile(t *testing.T) {
	src := `{
	email admin@example.com
}

(common) {
	encode gzip
}

app.example.com, www.example.com {
	encode zstd gzip
	reverse_proxy 10.0.0.5:8080 10.0.0.6:8080
}

http://plain.lan {
	reverse_proxy 10.0.0.7:80
}

files.example.com {
	# a comment with a { brace
	root * /srv/files
	file_server browse
	header X-Test "a } b"
}
`
	r, err := Run(FormatCaddyfile, []File{{Name: "Caddyfile", Content: b64(src)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Sites) != 3 {
		t.Fatalf("%d Sites: %+v", len(r.Sites), r.Sites)
	}
	app := find(t, r, "app.example.com")
	if app.Site.Mode != "proxy" || len(app.Site.Upstreams) != 2 || !app.Site.Compress || len(app.Problems) > 0 {
		t.Errorf("app: %+v", app)
	}
	if p := find(t, r, "plain.lan"); p.Site.TLS != "off" {
		t.Errorf("http:// muss TLS aus ergeben: %+v", p.Site)
	}
	files := find(t, r, "files.example.com")
	if files.Site.Mode != "raw" || !strings.Contains(files.Site.Raw, `header X-Test "a } b"`) || len(files.Problems) > 0 {
		t.Errorf("raw: %+v", files)
	}
	if len(r.Warnings) < 2 {
		t.Errorf("globale Optionen und Snippet müssen gemeldet werden: %v", r.Warnings)
	}
}

func TestZoraxy(t *testing.T) {
	proxy := `{"ProxyType":1,"RootOrMatchingDomain":"nas.example.com","MatchingDomainAlias":["nas2.example.com"],
"ActiveOrigins":[{"OriginIpOrDomain":"192.168.1.20:5001","RequireTLS":true,"SkipCertValidations":true,"Weight":1}],
"Disabled":false,"AccessFilterUUID":"abc","VirtualDirectories":[{"MatchingPath":"/api/","Domain":"192.168.1.21:8080","Disabled":false}],
"AuthenticationProvider":{"AuthMethod":1,"BasicAuthCredentials":[{"Username":"u","PasswordHash":"x"}]}}`
	access := `{"ID":"abc","Name":"Heimnetz","WhitelistEnabled":true,"WhitelistAllowLocalAndLoopback":true,
"WhiteListIP":{"203.0.113.5":"Büro"},"BlacklistEnabled":true,"BlackListContryCode":{"cn":""},"BlackListIP":{}}`
	redirect := `{"RedirectURL":"old.example.com","TargetURL":"new.example.com","ForwardChildpath":true,"StatusCode":307}`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{
		"conf/proxy/nas.example.com.config":  proxy,
		"conf/access/abc.json":               access,
		"conf/redirect/old.example.com.json": redirect,
	} {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()

	r, err := Run(FormatZoraxy, []File{{Name: "zoraxy-backup.zip", Content: base64.StdEncoding.EncodeToString(buf.Bytes())}})
	if err != nil {
		t.Fatal(err)
	}
	nas := find(t, r, "nas.example.com")
	s := nas.Site
	if len(s.Domains) != 2 || s.Upstreams[0] != "192.168.1.20:5001" || !s.UpstreamTLS || !s.UpstreamInsecure {
		t.Errorf("nas: %+v", s)
	}
	if !strings.Contains(s.Extra, "handle_path /api/*") || s.AccessList != "heimnetz" {
		t.Errorf("vdir/acl: extra=%q acl=%q", s.Extra, s.AccessList)
	}
	if len(r.AccessLists) != 1 {
		t.Fatalf("acl: %+v", r.AccessLists)
	}
	acl := r.AccessLists[0].AccessList
	if acl.ID != "heimnetz" || len(acl.Allow) != 2 || acl.DenyCountries[0] != "CN" {
		t.Errorf("acl: %+v", acl)
	}
	red := find(t, r, "old.example.com")
	if red.Site.Mode != "redirect" || red.Site.RedirectTo != "https://new.example.com" {
		t.Errorf("redirect: %+v", red.Site)
	}
}

func TestTraefikYAMLAndTOML(t *testing.T) {
	y := "http:\n" +
		"  routers:\n" +
		"    nextcloud:\n" +
		"      rule: \"Host(`cloud.example.com`) || Host(`nc.example.com`)\"\n" +
		"      entryPoints: [websecure]\n" +
		"      service: nc\n" +
		"      middlewares: [lan-only@file, gzip]\n" +
		"      tls:\n" +
		"        certResolver: le\n" +
		"    api:\n" +
		"      rule: \"Host(`api.example.com`) && PathPrefix(`/v1`)\"\n" +
		"      service: apisvc\n" +
		"      middlewares: [auth]\n" +
		"  services:\n" +
		"    nc:\n" +
		"      loadBalancer:\n" +
		"        servers:\n" +
		"          - url: \"https://10.0.0.10:443\"\n" +
		"        serversTransport: insecure\n" +
		"    apisvc:\n" +
		"      loadBalancer:\n" +
		"        servers:\n" +
		"          - url: \"http://10.0.0.11:3000/\"\n" +
		"  middlewares:\n" +
		"    lan-only:\n" +
		"      ipAllowList:\n" +
		"        sourceRange: [\"192.168.0.0/16\", \"10.0.0.0/8\"]\n" +
		"    gzip:\n" +
		"      compress: {}\n" +
		"    auth:\n" +
		"      basicAuth:\n" +
		"        users:\n" +
		"          - \"nico:$2y$05$c4WoMPo3SXsafkva.HHa6uXQZWr7oboPiC2bT/r7q1BB8I2s0BRqC\"\n" +
		"          - \"old:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/\"\n" +
		"  serversTransports:\n" +
		"    insecure:\n" +
		"      insecureSkipVerify: true\n"
	r, err := Run(FormatTraefik, []File{{Name: "dynamic.yml", Content: b64(y)}})
	if err != nil {
		t.Fatal(err)
	}
	nc := find(t, r, "cloud.example.com")
	if len(nc.Site.Domains) != 2 || !nc.Site.UpstreamInsecure || !nc.Site.Compress || nc.Site.AccessList != "lan-only" || len(nc.Problems) > 0 {
		t.Errorf("nextcloud: %+v", nc)
	}
	api := find(t, r, "api.example.com")
	if api.Site.Upstreams[0] != "10.0.0.11:3000" || len(api.Warnings) == 0 || api.Site.AccessList != "auth" {
		t.Errorf("api: %+v", api)
	}
	var auth ACLCandidate
	for _, a := range r.AccessLists {
		if a.AccessList.ID == "auth" {
			auth = a
		}
	}
	if len(auth.AccessList.Users) != 1 || len(auth.Warnings) != 1 {
		t.Errorf("basicAuth: bcrypt übernehmen, apr1 melden: %+v", auth)
	}

	tml := "[http.routers.wiki]\nrule = \"Host(`wiki.lan`)\"\nservice = \"wiki\"\nentryPoints = [\"web\"]\n" +
		"[[http.services.wiki.loadBalancer.servers]]\nurl = \"http://10.0.0.12:8080\"\n"
	r, err = Run(FormatTraefik, []File{{Name: "dynamic.toml", Content: b64(tml)}})
	if err != nil {
		t.Fatal(err)
	}
	if w := find(t, r, "wiki.lan"); w.Site.TLS != "off" || w.Site.Upstreams[0] != "10.0.0.12:8080" {
		t.Errorf("toml: %+v", w.Site)
	}
}

func TestTraefikCompose(t *testing.T) {
	compose := `services:
  grafana:
    image: grafana/grafana
    labels:
      - traefik.enable=true
      - traefik.http.routers.graf.rule=Host(` + "`grafana.example.com`" + `)
      - traefik.http.routers.graf.tls.certresolver=le
      - traefik.http.services.graf.loadbalancer.server.port=3000
`
	r, err := Run(FormatTraefik, []File{{Name: "docker-compose.yml", Content: b64(compose)}})
	if err != nil {
		t.Fatal(err)
	}
	g := find(t, r, "grafana.example.com")
	if g.Site.Upstreams[0] != "grafana:3000" {
		t.Errorf("compose upstream: %+v", g.Site)
	}
	found := false
	for _, w := range g.Warnings {
		if strings.Contains(w, "Docker-Service") {
			found = true
		}
	}
	if !found {
		t.Errorf("Hinweis auf Docker-Namen fehlt: %v", g.Warnings)
	}
}

func TestNPMApiAndSqlite(t *testing.T) {
	api := `[{"id":1,"domain_names":["jelly.example.com"],"forward_scheme":"http","forward_host":"192.168.1.30","forward_port":8096,
"enabled":true,"certificate_id":3,"block_exploits":true,"advanced_config":"",
"access_list":{"id":2,"name":"Familie","items":[{"username":"oma"}],"clients":[{"address":"192.168.1.0/24","directive":"allow"},{"address":"all","directive":"deny"}]},
"locations":[{"path":"/admin","forward_scheme":"http","forward_host":"192.168.1.31","forward_port":81}]},
{"id":2,"domain_names":["go.example.com"],"forward_domain_name":"example.org","forward_scheme":"auto","preserve_path":1,"enabled":1}]`
	r, err := Run(FormatNPM, []File{{Name: "proxy-hosts.json", Content: b64(api)}})
	if err != nil {
		t.Fatal(err)
	}
	j := find(t, r, "jelly.example.com")
	if j.Site.Upstreams[0] != "192.168.1.30:8096" || j.Site.AccessList != "familie" || !strings.Contains(j.Site.Extra, "handle_path /admin/*") {
		t.Errorf("jelly: %+v", j.Site)
	}
	if g := find(t, r, "go.example.com"); g.Site.Mode != "redirect" || g.Site.RedirectTo != "https://example.org" {
		t.Errorf("redirect: %+v", g.Site)
	}

	sqlite := `[{"id":5,"domain_names":"[\"ha.example.com\"]","forward_scheme":"http","forward_host":"10.0.0.40","forward_port":8123,"enabled":1,"is_deleted":0,"certificate_id":0,"access_list_id":0,"locations":"[]"},
{"id":6,"domain_names":"[\"gone.example.com\"]","forward_host":"x","forward_port":1,"is_deleted":1}]`
	r, err = Run(FormatNPM, []File{{Name: "rows.json", Content: b64(sqlite)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Sites) != 1 {
		t.Fatalf("gelöschte Zeile nicht gefiltert: %+v", r.Sites)
	}
	if h := find(t, r, "ha.example.com"); h.Site.Upstreams[0] != "10.0.0.40:8123" || !h.Site.Enabled {
		t.Errorf("sqlite-Form: %+v", h.Site)
	}
}
