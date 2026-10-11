package cli

import (
	"strings"
	"testing"
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
	}
	for msg, want := range cases {
		if got := acmeHint(msg); !strings.Contains(got, want) {
			t.Errorf("acmeHint(%q) = %q, want it to mention %q", msg, got, want)
		}
	}
}
