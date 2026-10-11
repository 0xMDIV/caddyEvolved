package sites

import (
	"strings"
	"testing"
)

func TestWithGlobalImport(t *testing.T) {
	line := "import /etc/caddy/caddyevolved-global.caddy"
	cases := []struct{ name, in, want string }{
		{"in den bestehenden Block", "# Kopf\n\n{\n\tadmin localhost:2019\n\tservers {\n\t\tprotocols h1 h2\n\t}\n}\n\nimport /etc/caddy/sites/*.caddy\n",
			"{\n\tadmin localhost:2019\n\tservers {\n\t\tprotocols h1 h2\n\t}\n\t# Von caddyEvolved verwaltete globale Optionen (WebUI)\n\t" + line + "\n}\n"},
		{"ohne globalen Block", "example.com {\n\trespond hi\n}\n", "{\n\t# Von caddyEvolved verwaltete globale Optionen (WebUI)\n\t" + line + "\n}\n\nexample.com {"},
	}
	for _, c := range cases {
		out, changed := withGlobalImport(c.in, line)
		if !changed || !strings.Contains(out, c.want) {
			t.Errorf("%s: changed=%v\n%s", c.name, changed, out)
		}
		if again, ch := withGlobalImport(out, line); ch || again != out {
			t.Errorf("%s: nicht idempotent", c.name)
		}
	}
}

func TestRenderGlobal(t *testing.T) {
	g := Global{RealIP: RealIP{Cloudflare: true}}
	g.Normalize()
	// Without the plugin the built-in list goes in as a static source.
	out := RenderGlobal(Options{Global: g})
	for _, want := range []string{"trusted_proxies static 173.245.48.0/20", "2c0f:f248::/32", "client_ip_headers Cf-Connecting-Ip X-Forwarded-For"} {
		if !strings.Contains(out, want) {
			t.Errorf("fehlt %q in\n%s", want, out)
		}
	}
	out = RenderGlobal(Options{Global: g, Caps: Caps{CloudflareIP: true}})
	if !strings.Contains(out, "trusted_proxies cloudflare {") {
		t.Errorf("Plugin nicht genutzt:\n%s", out)
	}
	// Extra proxies force the static form, which can hold both.
	g.RealIP.Proxies = []string{"10.0.0.0/8"}
	out = RenderGlobal(Options{Global: g, Caps: Caps{CloudflareIP: true}})
	if !strings.Contains(out, "trusted_proxies static") || !strings.Contains(out, " 10.0.0.0/8") {
		t.Errorf("statische Liste erwartet:\n%s", out)
	}

	g = Global{
		DynDNS:   DynDNS{Enabled: true, Provider: "cloudflare", Domains: []DynDomain{{Zone: "Example.com.", Names: []string{"@", "WWW"}}}},
		CrowdSec: CrowdSec{Enabled: true, AppSecURL: "http://127.0.0.1:7422"},
		Cache:    Cache{Enabled: true},
	}
	g.Normalize()
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	all := Caps{DynDNS: true, CrowdSec: true, AppSec: true, Cache: true, DNS: map[string]bool{"cloudflare": true}}
	out = RenderGlobal(Options{Global: g, Caps: all})
	for _, want := range []string{"dynamic_dns {", "\tprovider cloudflare", "\t\texample.com @ www", "check_interval 5m", "versions ipv4\n",
		"crowdsec {", "api_url http://127.0.0.1:8080", "api_key {env.CROWDSEC_API_KEY}", "appsec_url http://127.0.0.1:7422", "cache {\n\tttl 120s"} {
		if !strings.Contains(out, want) {
			t.Errorf("fehlt %q in\n%s", want, out)
		}
	}
	// Nothing for modules the binary lacks.
	out = RenderGlobal(Options{Global: g, Caps: Caps{DNS: map[string]bool{}}})
	for _, no := range []string{"dynamic_dns", "crowdsec", "cache"} {
		if strings.Contains(out, no) {
			t.Errorf("%s ohne Modul gerendert:\n%s", no, out)
		}
	}
}

func TestGlobalValidate(t *testing.T) {
	g := Global{
		RealIP:   RealIP{Proxies: []string{"nope"}},
		DynDNS:   DynDNS{Enabled: true, Provider: "hetzner", Domains: []DynDomain{{Zone: "kein zone", Names: []string{"a b"}}}, Interval: "5x"},
		CrowdSec: CrowdSec{Enabled: true, APIURL: "ftp://x"},
	}
	err := g.Validate()
	if err == nil {
		t.Fatal("Fehler erwartet")
	}
	for _, want := range []string{"Proxy", "Zone", "Eintrag", "Intervall", "CrowdSec"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q fehlt in %v", want, err)
		}
	}
}

func TestRenderSiteFeatures(t *testing.T) {
	opt := Options{
		Global: Global{CrowdSec: CrowdSec{Enabled: true, AppSecURL: "http://x:7422"}, Tailscale: Tailscale{Enabled: true}, Cache: Cache{Enabled: true, TTL: "60s"}},
		Caps:   Caps{CrowdSec: true, AppSec: true, Tailscale: true, Cache: true, Brotli: true},
	}
	s := Site{ID: "app", Domains: []string{"app.example.com"}, Mode: ModeProxy, Upstreams: []string{"10.0.0.2:80"}, TLS: TLSAuto, Compress: true, Cache: true, Tailnet: "app", Enabled: true}
	out := RenderWith(s, nil, opt)
	for _, want := range []string{"bind tailscale/app", "encode zstd br gzip", "\tcache\n", "route {\n\t\tcrowdsec\n\t\tappsec\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("fehlt %q in\n%s", want, out)
		}
	}
	s.NoCrowdSec = true
	if out := RenderWith(s, nil, opt); strings.Contains(out, "crowdsec") || strings.Contains(out, "route {") {
		t.Errorf("Ausnahme ignoriert:\n%s", out)
	}
	// The same site on a binary without the modules renders none of it.
	plain := RenderWith(Site{ID: "app", Domains: []string{"app.example.com"}, Mode: ModeProxy, Upstreams: []string{"10.0.0.2:80"}, TLS: TLSAuto, Compress: true, Cache: true, Tailnet: "app", Enabled: true}, nil, Options{Global: opt.Global})
	for _, no := range []string{"bind tailscale", " br ", "\tcache\n", "crowdsec"} {
		if strings.Contains(plain, no) {
			t.Errorf("%q ohne Modul:\n%s", no, plain)
		}
	}

	dav := Site{ID: "dav", Domains: []string{"dav.example.com"}, Mode: ModeWebDAV, Root: "/srv/dav", TLS: TLSAuto, Enabled: true}
	if err := dav.Validate(); err != nil {
		t.Fatal(err)
	}
	if out := RenderWith(dav, nil, Options{}); !strings.Contains(out, "route {\n\t\twebdav {\n\t\t\troot /srv/dav") {
		t.Errorf("WebDAV:\n%s", out)
	}
}

func TestWAFTuning(t *testing.T) {
	s := Site{ID: "w", Domains: []string{"w.example.com"}, Mode: ModeProxy, Upstreams: []string{"10.0.0.2:80"}, TLS: TLSAuto,
		WAF: &WAF{Enabled: true, Paranoia: 2, Threshold: 10, Exclude: []int{942100, 920350}}, Enabled: true}
	s.Normalize()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	out := RenderWith(s, nil, Options{})
	setup := strings.Index(out, "Include @crs-setup.conf.example")
	pl := strings.Index(out, "tx.blocking_paranoia_level=2")
	rules := strings.Index(out, "Include @owasp_crs/*.conf")
	rm := strings.Index(out, "SecRuleRemoveById 920350 942100")
	if setup < 0 || pl < setup || rules < pl || rm < rules || !strings.Contains(out, "inbound_anomaly_score_threshold=10") {
		t.Errorf("Reihenfolge oder Inhalt falsch:\n%s", out)
	}
	s.WAF.Paranoia = 5
	if s.Validate() == nil {
		t.Error("Paranoia 5 sollte abgelehnt werden")
	}
}
