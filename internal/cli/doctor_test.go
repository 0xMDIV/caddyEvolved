package cli

import (
	"strings"
	"testing"

	"caddyevolved/internal/sites"
)

func TestUfwAllows(t *testing.T) {
	status := `Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       192.168.10.0/24
80/tcp                     ALLOW       Anywhere
443                        ALLOW       Anywhere
8000:8100/tcp              ALLOW       Anywhere
8484/tcp                   DENY        Anywhere
80/tcp (v6)                ALLOW       Anywhere (v6)
`
	for port, want := range map[int]bool{22: true, 80: true, 443: true, 8050: true, 8484: false, 2019: false} {
		if got := ufwAllows(status, port); got != want {
			t.Errorf("ufwAllows(%d) = %v, want %v", port, got, want)
		}
	}
}

func TestPublicDomain(t *testing.T) {
	for d, want := range map[string]bool{
		"cloud.example.com":     true,
		"*.example.com":         true,
		"https://a.example.org": true,
		"nas.lan":               false,
		"pve.home.arpa":         false,
		"fritz.box":             false,
		"192.168.10.5":          false,
		":8080":                 false,
		"localhost":             false,
	} {
		if got := publicDomain(d); got != want {
			t.Errorf("publicDomain(%q) = %v, want %v", d, got, want)
		}
	}
}

func TestAcmeHint(t *testing.T) {
	cases := map[string]string{
		"dial tcp 1.2.3.4:80: i/o timeout":              "Portweiterleitung",
		"DNS problem: NXDOMAIN looking up A for x.de":   "DNS-Eintrag",
		"urn:ietf:params:acme:error:rejectedIdentifier": "stellt Let's Encrypt grundsätzlich nicht aus",
		"too many certificates: see rate limits":        "Limit",
		"something completely different":                "journalctl",
		"urn:ietf:params:acme:error:tls - Fetching https://x.de/.well-known/acme-challenge/a: remote error": "Port 80 im Router",
	}
	for msg, want := range cases {
		if got := acmeHint(msg); !strings.Contains(got, want) {
			t.Errorf("acmeHint(%q) = %q, want it to mention %q", msg, got, want)
		}
	}
}

func TestClassifyStatus(t *testing.T) {
	s := sites.Site{Upstreams: []string{"192.168.10.132:8006"}, UpstreamTLS: true}
	cases := map[int]checkLevel{200: levelOK, 302: levelOK, 401: levelOK, 403: levelWarn, 404: levelInfo, 502: levelFail, 503: levelFail, 500: levelWarn}
	for code, want := range cases {
		if got, _, _ := classifyStatus(code, s); got != want {
			t.Errorf("classifyStatus(%d) = %s, want %s", code, got, want)
		}
	}
	if _, detail, _ := classifyStatus(502, s); !strings.Contains(detail, "https://192.168.10.132:8006") {
		t.Errorf("502 detail does not name the target: %q", detail)
	}
}

func TestProbeHost(t *testing.T) {
	for in, want := range map[string]string{"pve.example.com": "pve.example.com", "https://a.example.com": "a.example.com", "nas.lan:8443": "nas.lan", "*.example.com": "", ":8080": ""} {
		got, ok := probeHost(in)
		if got != want || ok != (want != "") {
			t.Errorf("probeHost(%q) = %q,%v", in, got, ok)
		}
	}
}
