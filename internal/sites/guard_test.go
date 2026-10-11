package sites

import (
	"strings"
	"testing"
)

func TestGuardBlocks(t *testing.T) {
	blocked := []string{
		"/.env", "/.ENV", "/app/.env", "/.env.local", "/.env.production", "/prod.env",
		"/.git/config", "/.git/HEAD", "/repo/.svn/entries", "/.ssh/id_rsa", "/.aws/credentials",
		"/.htpasswd", "/.DS_Store", "//.env", "/a/../.env", "/.well-known/../.git/config",
		"/.well-known/.env", "/docker-compose.yml", "/stack/compose.yaml", "/docker-compose.prod.yml",
		"/backup.sql", "/dump.sql.gz", "/db.sqlite3", "/data/app.db", "/server.key", "/cert.pem",
		"/keys/id_ed25519", "/vault.kdbx", "/wp-config.php.bak", "/config.php~", "/index.php.old",
		"/credentials.json", "/secrets.yml", "/phpinfo.php", "/web.config", "/error.log", "/terraform.tfstate",
	}
	for _, p := range blocked {
		if !GuardBlocks(p, nil) {
			t.Errorf("%s sollte gesperrt sein", p)
		}
	}
	allowed := []string{
		"/", "/index.html", "/.well-known/acme-challenge/AbC-123_x", "/.well-known/security.txt",
		"/.well-known/carddav", "/api/v1/users", "/static/app.js", "/images/logo.png", "/favicon.ico",
		"/environment", "/docs/env-setup", "/login", "/download/file.zip", "/ca.crt", "/blog/my.post",
		"/identity/connect/token", "/alive", "/api/config",
	}
	for _, p := range allowed {
		if GuardBlocks(p, nil) {
			t.Errorf("%s sollte erreichbar sein", p)
		}
	}
	extra := []string{"/backup/*", "*.xlsx", "/intern"}
	for _, p := range []string{"/backup/2026.zip", "/Docs/Plan.XLSX", "/intern"} {
		if !GuardBlocks(p, extra) {
			t.Errorf("%s sollte durch eigene Muster gesperrt sein", p)
		}
	}
	if GuardBlocks("/internal", extra) {
		t.Error("/intern darf /internal nicht treffen")
	}
}

func TestValidGuardPattern(t *testing.T) {
	for _, ok := range []string{"/backup/*", "*.xlsx", "/intern", "/a/*/b"} {
		if err := ValidGuardPattern(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "*", "/*", "/", "backup", "/a b", "/x}", "/#"} {
		if ValidGuardPattern(bad) == nil {
			t.Errorf("%q sollte abgelehnt werden", bad)
		}
	}
}

func TestRenderHasGuard(t *testing.T) {
	for _, s := range []Site{
		{ID: "p", Domains: []string{"a.example.com"}, Mode: ModeProxy, Upstreams: []string{"10.0.0.1:80"}, TLS: TLSAuto, Enabled: true},
		{ID: "r", Domains: []string{"b.example.com"}, Mode: ModeRedirect, RedirectTo: "https://c.example.com", TLS: TLSAuto, Enabled: true},
		{ID: "x", Domains: []string{"d.example.com"}, Mode: ModeRaw, Raw: "handle /api/* {\n\treverse_proxy 10.0.0.2:80\n}", TLS: TLSAuto, Enabled: true},
	} {
		out := RenderWith(s, nil, Options{GuardExtra: []string{"/backup/*"}})
		for _, want := range []string{"handle @cev_hidden", "handle @cev_secret", "handle @cev_custom", "path " + guardPad + " /backup/*"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: %q fehlt in\n%s", s.ID, want, out)
			}
		}
	}
}
