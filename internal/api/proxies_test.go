package api

import (
	"testing"

	"caddyevolved/internal/blocklists"
	"caddyevolved/internal/config"
	"caddyevolved/internal/sites"
)

func TestProxyInfoAndRanges(t *testing.T) {
	s := &Server{Paths: config.Paths{StateDir: t.TempDir()}}
	info := s.proxyInfo()
	if len(info) != len(blocklists.ProxyProviders) || info[0].ID != "cloudflare" || info[0].Ranges != len(blocklists.CloudflareRanges) {
		t.Fatalf("info: %+v", info)
	}
	for _, p := range info {
		if p.ID == "bunny" && (p.Ranges != 0 || p.Builtin) {
			t.Errorf("bunny ohne Download: %+v", p)
		}
	}
	g := sites.Global{RealIP: sites.RealIP{Providers: []string{"fastly"}}}
	r := s.proxyRanges(g)
	if len(r) != 1 || len(r["fastly"]) == 0 {
		t.Fatalf("ranges: %v", r)
	}
	if ex := s.proxyExempt(g); len(ex) != len(r["fastly"]) {
		t.Fatalf("exempt: %v", ex)
	}
}
