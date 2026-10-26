package blocklists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestParseProxyRangesGeneric(t *testing.T) {
	fastly := []byte(`{"addresses":["23.235.32.0/20","151.101.0.0/16"],"ipv6_addresses":["2a04:4e40::/32"]}`)
	if got := parseRanges(fastly); !slices.Equal(got, []string{"23.235.32.0/20", "151.101.0.0/16", "2a04:4e40::/32"}) {
		t.Errorf("fastly: %v", got)
	}
	bunny := []byte("89.187.188.227\r\n89.187.188.228\n[\"2400:52e0:1500::714:1\"]")
	if got := parseRanges(bunny); !slices.Equal(got, []string{"89.187.188.227", "89.187.188.228", "2400:52e0:1500::714:1"}) {
		t.Errorf("bunny: %v", got)
	}
	if got := parseRanges([]byte("<html>Fehler 500</html>")); len(got) != 0 {
		t.Errorf("html: %v", got)
	}
}

func TestParseCloudFront(t *testing.T) {
	body := []byte(`{"prefixes":[{"ip_prefix":"3.0.0.0/15","service":"AMAZON"},{"ip_prefix":"13.32.0.0/15","service":"CLOUDFRONT"}],
	"ipv6_prefixes":[{"ipv6_prefix":"2600:9000::/28","service":"CLOUDFRONT"},{"ipv6_prefix":"2600:1f00::/24","service":"EC2"}]}`)
	if got := parseCloudFront(body); !slices.Equal(got, []string{"13.32.0.0/15", "2600:9000::/28"}) {
		t.Errorf("cloudfront: %v", got)
	}
}

func TestProxyRangesFallback(t *testing.T) {
	dir := t.TempDir()
	if got := ProxyRanges(dir, "cloudflare"); len(got) < 10 || got[0] != "173.245.48.0/20" {
		t.Errorf("cloudflare builtin: %v", got)
	}
	if got := ProxyRanges(dir, "bunny"); len(got) != 0 {
		t.Errorf("bunny ohne Download: %v", got)
	}
	if got := ProxyRanges(dir, "unknown"); got != nil {
		t.Errorf("unknown: %v", got)
	}
}

func TestUpdateProxyKeepsOldOnEmpty(t *testing.T) {
	body := `{"addresses":["198.51.100.0/24"]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(body)) }))
	defer srv.Close()
	p := ProxyProvider{ID: "test", URLs: []string{srv.URL}}
	dir := t.TempDir()
	if n, err := updateProxy(context.Background(), dir, p); err != nil || n != 1 {
		t.Fatalf("update: %d %v", n, err)
	}
	body = "kaputt"
	if _, err := updateProxy(context.Background(), dir, p); err == nil {
		t.Fatal("leere Antwort ohne Fehler")
	}
	if got := proxyCache(dir, "test"); !slices.Equal(got, []string{"198.51.100.0/24"}) {
		t.Fatalf("alte Liste verloren: %v", got)
	}
}
