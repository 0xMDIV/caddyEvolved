package probe

import (
	"strings"
	"testing"

	"caddyevolved/internal/sites"
)

func TestPublicDomain(t *testing.T) {
	for d, want := range map[string]bool{
		"cloud.example.com": true, "*.example.com": true, "https://a.example.org": true,
		"nas.lan": false, "pve.home.arpa": false, "fritz.box": false, "192.168.10.5": false, ":8080": false, "localhost": false,
	} {
		if got := PublicDomain(d); got != want {
			t.Errorf("PublicDomain(%q) = %v, want %v", d, got, want)
		}
	}
}

func TestHost(t *testing.T) {
	for in, want := range map[string]string{"pve.example.com": "pve.example.com", "https://a.example.com": "a.example.com", "nas.lan:8443": "nas.lan", "*.example.com": "", ":8080": ""} {
		got, ok := Host(in)
		if got != want || ok != (want != "") {
			t.Errorf("Host(%q) = %q,%v", in, got, ok)
		}
	}
}

func TestClassify(t *testing.T) {
	s := sites.Site{Upstreams: []string{"192.168.10.132:8006"}, UpstreamTLS: true}
	cases := map[int]Level{200: OK, 302: OK, 401: OK, 403: Warn, 404: Info, 502: Fail, 503: Fail, 500: Warn, 521: Fail, 525: Fail, 526: Fail}
	for code, want := range cases {
		if got, _, _ := Classify(code, s); got != want {
			t.Errorf("Classify(%d) = %s, want %s", code, got, want)
		}
	}
	if _, detail, _ := Classify(502, s); !strings.Contains(detail, "https://192.168.10.132:8006") {
		t.Errorf("502 detail does not name the target: %q", detail)
	}
}

func TestIsCloudflare(t *testing.T) {
	for ip, want := range map[string]bool{
		"104.21.92.218": true, "172.67.198.221": true, "2606:4700:3031::6815:5cda": true,
		"77.21.84.246": false, "192.168.10.28": false, "1.1.1.1": false,
	} {
		if IsCloudflare(ip) != want {
			t.Errorf("IsCloudflare(%s) != %v", ip, want)
		}
	}
	if !allCloudflare([]string{"104.21.92.218", "2606:4700:3032::ac43:c6dd"}) || allCloudflare([]string{"104.21.92.218", "77.21.84.246"}) || allCloudflare(nil) {
		t.Error("allCloudflare")
	}
}

func TestACMEHint(t *testing.T) {
	cases := []struct {
		msg  string
		cf   bool
		want string
	}{
		{"dial tcp 1.2.3.4:80: i/o timeout", false, "Portweiterleitung"},
		{"DNS problem: NXDOMAIN looking up A for x.de", false, "DNS-Eintrag"},
		{"urn:ietf:params:acme:error:rejectedIdentifier", false, "grundsätzlich nicht"},
		{"urn:ietf:params:acme:error:tls - Fetching https://x.de/.well-known/acme-challenge/a", false, "Port 80 im Router"},
		{"urn:ietf:params:acme:error:tls - Fetching https://x.de/.well-known/acme-challenge/a", true, "DNS-Challenge"},
		{"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many failed authorizations (5)", true, "Fehlversuche"},
		{"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many failed authorizations (5)", true, "Cloudflare"},
		{"something else", false, "journalctl"},
	}
	for _, c := range cases {
		if got := ACMEHint(c.msg, c.cf, "192.168.10.28"); !strings.Contains(got, c.want) {
			t.Errorf("ACMEHint(%q, cf=%v) = %q, want it to mention %q", c.msg, c.cf, got, c.want)
		}
	}
}

func TestParseACMEErrors(t *testing.T) {
	// Shortened from a real run behind the Cloudflare proxy: the reason is the
	// 403, the final errors only say "canceled" and "rate limited".
	log := strings.Join([]string{
		`{"level":"error","logger":"tls.obtain","msg":"challenge failed","identifier":"vault.example.de","challenge_type":"http-01","problem":{"type":"urn:ietf:params:acme:error:unauthorized","detail":"2606:4700:3032::ac43:c6dd: Invalid response from http://vault.example.de/.well-known/acme-challenge/x: 403"}}`,
		`{"level":"error","logger":"tls.obtain","msg":"challenge failed","identifier":"vault.example.de","challenge_type":"tls-alpn-01","problem":{"detail":"Cannot negotiate ALPN protocol \"acme-tls/1\" for tls-alpn-01 challenge"}}`,
		`{"level":"error","logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"vault.example.de","error":"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many failed authorizations (5)"}`,
		`{"level":"error","logger":"tls","msg":"job failed","identifier":"vault.example.de","error":"vault.example.de: obtaining certificate: context canceled"}`,
		`Oct 11 02:00:00 host caddy[1]: {"level":"error","logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"ok.example.de","error":"timeout"}`,
		`{"level":"info","logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"ok.example.de"}`,
	}, "\n")
	got := parseACMEErrors([]byte(log))
	msg := got["vault.example.de"]
	if !strings.Contains(msg, "http-01") || !strings.Contains(msg, ": 403") {
		t.Fatalf("challenge detail missing: %q", msg)
	}
	if !strings.Contains(msg, "rateLimited") {
		t.Errorf("rate limit missing: %q", msg)
	}
	if _, ok := got["ok.example.de"]; ok {
		t.Errorf("success should clear the domain: %v", got)
	}
	if h := ACMEHint(msg, true, ""); !strings.Contains(h, "Cloudflare blockt") || !strings.Contains(h, "DNS-Challenge") {
		t.Errorf("hint = %q", h)
	}
}
