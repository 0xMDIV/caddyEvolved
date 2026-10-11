package sites

import (
	"strings"
	"testing"
)

func fwOptions(f Firewall) Options {
	f.Enabled = true
	f.Normalize()
	return Options{
		Global:        Global{Firewall: f},
		Caps:          Caps{Geo: true},
		GeoDB:         "/var/lib/caddy/geoip/dbip-country-lite-2026-10.mmdb",
		ASNDB:         "/var/lib/caddy/geoip/dbip-asn-lite-2026-10.mmdb",
		FirewallPath:  "/etc/caddy/caddyevolved-firewall.caddy",
		FirewallLists: map[string][]string{"spamhaus-drop": {"1.10.16.0/20", "2.56.0.0/16"}},
	}
}

func TestRenderFirewall(t *testing.T) {
	o := fwOptions(Firewall{
		Allow: []string{"203.0.113.7"}, Block: []string{"198.51.100.0/24"}, Lists: []string{"spamhaus-drop"},
		AllowCountries: []string{"de", "AT"}, BlockASN: []int{14061},
	})
	got := RenderFirewall(o)
	for _, want := range []string{
		"client_ip 198.51.100.0/24 1.10.16.0/20 2.56.0.0/16",
		"not client_ip 203.0.113.7",
		"log_append @cev_fw_ip cev_block firewall-ip",
		"respond @cev_fw_ip \"Zugriff verweigert\" 403",
		"not client_ip private_ranges 203.0.113.7",
		"allow_countries AT DE",
		"db_path /var/lib/caddy/geoip/dbip-country-lite-2026-10.mmdb",
		"deny_asn 14061",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fehlt %q in\n%s", want, got)
		}
	}
	if !balanced(got) {
		t.Errorf("Klammern unausgeglichen:\n%s", got)
	}

	o.Global.Firewall.Drop = true
	if got := RenderFirewall(o); !strings.Contains(got, "abort @cev_fw_ip") || strings.Contains(got, "respond @cev_fw_ip") {
		t.Errorf("Drop muss abort statt respond rendern:\n%s", got)
	}
	// Without the plugin no geo rule may be rendered: caddy would refuse it.
	o.Caps.Geo = false
	if got := RenderFirewall(o); strings.Contains(got, "maxmind") {
		t.Errorf("Geo-Regel ohne Plugin gerendert:\n%s", got)
	}
}

func TestFirewallSiteImport(t *testing.T) {
	o := fwOptions(Firewall{Allow: []string{"10.1.2.3"}})
	s := Site{
		ID: "app", Domains: []string{"app.example.com"}, Upstreams: []string{"10.0.0.9:3000"},
		RateLimit: &RateLimit{Enabled: true, Events: 50},
	}
	s.Normalize()
	got := RenderWith(s, nil, o)
	for _, want := range []string{
		"\troute {\n\t\timport /etc/caddy/caddyevolved-firewall.caddy\n",
		"@cev_fw_untrusted not client_ip 10.1.2.3",
		"route @cev_fw_untrusted {\n\t\t\trate_limit {",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fehlt %q in\n%s", want, got)
		}
	}
	if !balanced(got) {
		t.Errorf("Klammern unausgeglichen:\n%s", got)
	}
	s.NoFirewall = true
	if got := RenderWith(s, nil, o); strings.Contains(got, "caddyevolved-firewall") || strings.Contains(got, "cev_fw_untrusted") {
		t.Errorf("Site mit NoFirewall importiert die Regeln:\n%s", got)
	}
}

func TestFirewallValidate(t *testing.T) {
	bad := []Firewall{
		{Allow: []string{"10.0.0.0/8 }"}},
		{Block: []string{"private_ranges"}},
		{Lists: []string{"no-such-list"}},
		{BlockCountries: []string{"DEU"}},
		{BlockCountries: []string{"CN"}, AllowCountries: []string{"DE"}},
		{BlockASN: []int{0}},
	}
	for i, f := range bad {
		f.Normalize()
		if len(f.validate()) == 0 {
			t.Errorf("Fall %d hätte abgelehnt werden müssen: %+v", i, f)
		}
	}
}

func TestWAFOptionsRender(t *testing.T) {
	s := Site{
		ID: "dav", Domains: []string{"dav.example.com"}, Upstreams: []string{"10.0.0.9:80"},
		WAF: &WAF{
			Enabled: true, Paranoia: 2, DetectParanoia: 3, Threshold: 10, OutThreshold: 8, EarlyBlocking: true,
			Methods: []string{"get", "PUT", "PROPFIND"}, ContentTypes: []string{"application/octet-stream"},
			BodyLimitMB: 100, BodyPartial: true, NoResponse: true, GroupsOff: []string{"sqli"},
			Exclude: []int{920350}, SkipPaths: []string{"/upload"},
			PathExcludes: []WAFPathExclude{{Path: "/api", IDs: []int{942100, 941100}}},
			Custom:       "SecRule ARGS:foo \"@streq bar\" \"id:12345,phase:1,deny,status:403\"",
		},
	}
	s.Normalize()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	got := Render(s)
	for _, want := range []string{
		"SecRequestBodyLimit 104857600",
		"SecRequestBodyLimitAction ProcessPartial",
		"SecResponseBodyAccess Off",
		"setvar:'tx.blocking_paranoia_level=2'",
		"setvar:'tx.detection_paranoia_level=3'",
		"setvar:'tx.inbound_anomaly_score_threshold=10',setvar:'tx.outbound_anomaly_score_threshold=8'",
		"setvar:'tx.early_blocking=1'",
		"setvar:'tx.allowed_methods=GET PUT PROPFIND'",
		"|application/json| |application/octet-stream|",
		"setvar:'tx.crs_skip_response_analysis=1'",
		"\"@beginsWith /upload\" \"id:10000,phase:1,pass,t:none,nolog,ctl:ruleEngine=Off\"",
		"ctl:ruleRemoveById=941100,ctl:ruleRemoveById=942100",
		"SecRuleRemoveById 942000-942999 920350",
		"id:12345",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fehlt %q in\n%s", want, got)
		}
	}
	// Settings before the rules, exceptions after them.
	if strings.Index(got, "tx.allowed_methods") > strings.Index(got, "Include @owasp_crs") ||
		strings.Index(got, "SecRuleRemoveById") < strings.Index(got, "Include @owasp_crs") {
		t.Errorf("Reihenfolge der WAF-Direktiven falsch:\n%s", got)
	}

	s.WAF.Custom = "SecRule `x`"
	if s.Validate() == nil {
		t.Error("Backtick in eigenen Regeln hätte abgelehnt werden müssen")
	}
}

func TestDefenderAndRateLimitOptions(t *testing.T) {
	s := Site{
		ID: "web", Domains: []string{"web.example.com"}, Upstreams: []string{"10.0.0.9:80"},
		Defender: &Defender{Enabled: true, Responder: "custom", Message: "Nein danke", StatusCode: 451,
			Whitelist: []string{"20.1.2.3"}, ServeIgnore: true, Ranges: []string{"aws", "openai"}},
		RateLimit: &RateLimit{Enabled: true, Events: 100, Key: "ip-path",
			Rules: []RateRule{{Paths: []string{"/login*"}, Methods: []string{"post"}, Events: 5, Window: "1m"}}},
	}
	s.Normalize()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	got := Render(s)
	for _, want := range []string{
		"defender custom {", "message \"Nein danke\"", "status_code 451", "whitelist 20.1.2.3", "serve_ignore",
		"key {client_ip}{path}", "zone cf_web_1 {", "path /login*", "method POST", "events 5",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fehlt %q in\n%s", want, got)
		}
	}
	if !balanced(got) {
		t.Errorf("Klammern unausgeglichen:\n%s", got)
	}
	s.Defender.Message = `x" }`
	if s.Validate() == nil {
		t.Error("Anführungszeichen im Antworttext hätte abgelehnt werden müssen")
	}
}

func TestRenderAutoBan(t *testing.T) {
	o := fwOptions(Firewall{
		Allow:   []string{"203.0.113.7"},
		AutoBan: AutoBan{Enabled: true, Traps: []string{"/wp-login.php", "/phpmyadmin*"}},
	})
	o.AutoBanned = []string{"198.51.100.9", "2001:db8:1:2::/64"}
	got := RenderFirewall(o)
	for _, want := range []string{
		"client_ip 198.51.100.9 2001:db8:1:2::/64",
		"log_append @cev_fw_ban cev_block autoban",
		"path /phpmyadmin* /wp-login.php",
		"log_append @cev_fw_trap cev_block falle",
		"respond @cev_fw_trap 404",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fehlt %q in\n%s", want, got)
		}
	}
	o.Global.Firewall.AutoBan.Enabled = false
	if got := RenderFirewall(o); strings.Contains(got, "cev_fw_ban") || strings.Contains(got, "cev_fw_trap") {
		t.Errorf("Auto-Bann aus, trotzdem gerendert:\n%s", got)
	}
	bad := Firewall{AutoBan: AutoBan{Traps: []string{"wp-login.php", "/a b", "/x{y}"}, Strikes: 5}}
	if p := bad.validate(); len(p) != 4 {
		t.Errorf("validate = %v", p)
	}
}

func TestCustomLists(t *testing.T) {
	f := Firewall{
		Lists:       []string{"spamhaus-drop", "eigene-meine", "eigene-weg"},
		CustomLists: []CustomList{{ID: "eigene-meine", Name: " Meine ", URL: " https://example.com/l.txt "}},
	}
	f.Normalize()
	if len(f.Lists) != 2 || f.CustomLists[0].URL != "https://example.com/l.txt" {
		t.Fatalf("normalize: %+v", f)
	}
	if p := f.validate(); len(p) != 0 {
		t.Fatalf("validate: %v", p)
	}
	if l, ok := f.ListByID("eigene-meine"); !ok || !l.Custom || l.URLs[0] != "https://example.com/l.txt" {
		t.Fatalf("ListByID: %+v", l)
	}
	bad := Firewall{CustomLists: []CustomList{{ID: "x", Name: "a", URL: "https://a"}, {ID: "eigene-b", Name: "b", URL: "ftp://b"}}}
	if p := bad.validate(); len(p) != 2 {
		t.Fatalf("validate bad: %v", p)
	}
	// Overlapping lists render each entry once.
	o := fwOptions(Firewall{Block: []string{"2.56.0.0/16"}, Lists: []string{"spamhaus-drop"}})
	if got := RenderFirewall(o); strings.Count(got, "2.56.0.0/16") != 1 {
		t.Fatalf("doppelt:\n%s", got)
	}
}
