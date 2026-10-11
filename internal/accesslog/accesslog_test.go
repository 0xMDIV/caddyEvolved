package accesslog

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func logLine(ts float64, host, uri, ua string, status int, size, read int64) string {
	return fmt.Sprintf(`{"level":"info","ts":%f,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"10.0.0.9","client_ip":"203.0.113.7","proto":"HTTP/2.0","method":"GET","host":"%s:443","uri":%q,"headers":{"User-Agent":[%q]}},"bytes_read":%d,"duration":0.0123,"size":%d,"status":%d}`,
		ts, host, uri, ua, read, size, status)
}

func TestParse(t *testing.T) {
	e, ok := Parse([]byte(logLine(1760140800.5, "Vault.Example.com", "/api/x?y=1", "Mozilla/5.0", 200, 1234, 56)))
	if !ok {
		t.Fatal("not parsed")
	}
	if e.Host != "vault.example.com" || e.Path != "/api/x" || e.IP != "203.0.113.7" || e.Size != 1234 || e.BytesRead != 56 || e.Duration != 12.3 || e.Proto != "HTTP/2.0" {
		t.Fatalf("%+v", e)
	}
	if _, ok := Parse([]byte(`{"msg":"tls handshake"}`)); ok {
		t.Fatal("non-access line parsed")
	}
}

func TestTags(t *testing.T) {
	cases := []struct {
		uri, ua string
		status  int
		want    []string
	}{
		{"/announce?info_hash=abc&peer_id=x", "qBittorrent/4.6.0", 200, []string{TagTorrent}},
		{"/scrape", "curl/8", 200, []string{TagTorrent}},
		{"/", "Mozilla/5.0 (compatible; GPTBot/1.2)", 200, []string{TagAI}},
		{"/", "Mozilla/5.0 (compatible; Googlebot/2.1)", 200, []string{TagBot}},
		{"/.env", "Mozilla/5.0", 404, []string{TagScanner}},
		{"/", "zgrab/0.x", 403, []string{TagScanner, TagBlocked}},
		{"/api", "Mozilla/5.0", 502, []string{TagError}},
		{"/", "Mozilla/5.0", 200, nil},
	}
	for _, c := range cases {
		e, _ := Parse([]byte(logLine(1, "a.example.com", c.uri, c.ua, c.status, 1, 0)))
		if strings.Join(e.Tags, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s %s %d: tags %v, want %v", c.uri, c.ua, c.status, e.Tags, c.want)
		}
	}
}

func TestStatusMatch(t *testing.T) {
	for spec, want := range map[string]bool{"4xx": true, "404": true, "5xx": false, "200,404": true, "3xx, 5xx": false} {
		if statusMatch(spec, 404) != want {
			t.Errorf("statusMatch(%q, 404) != %v", spec, want)
		}
	}
}

// TestQueryAcrossRotation: newest first, rotated gzip files included, the
// limit honoured, tags counted over all matches.
func TestQueryAcrossRotation(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "access.log")
	base := float64(time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC).Unix())

	var old bytes.Buffer
	gz := gzip.NewWriter(&old)
	for i := 0; i < 50; i++ {
		fmt.Fprintln(gz, logLine(base+float64(i), "a.example.com", fmt.Sprintf("/old/%d", i), "qBittorrent/4", 200, 10, 0))
	}
	gz.Close()
	rotated := filepath.Join(dir, "access-2026-10-11T10-01-00.000.log.gz")
	os.WriteFile(rotated, old.Bytes(), 0o644)
	os.Chtimes(rotated, time.Unix(int64(base)+60, 0), time.Unix(int64(base)+60, 0))

	var now strings.Builder
	for i := 0; i < 30; i++ {
		fmt.Fprintln(&now, logLine(base+100+float64(i), "b.example.com", fmt.Sprintf("/new/%d", i), "Mozilla/5.0", 404, 10, 0))
	}
	os.WriteFile(cur, []byte(now.String()), 0o644)

	files := Files(cur)
	if len(files) != 2 || !files[0].Current || !files[1].Compressed {
		t.Fatalf("files: %+v", files)
	}

	r := Query(cur, Filter{}, 40, 0)
	if len(r.Entries) != 40 || r.Entries[0].URI != "/new/29" || r.Entries[29].URI != "/new/0" || r.Entries[30].URI != "/old/49" {
		t.Fatalf("order: first %s, [29] %s, [30] %s (n=%d)", r.Entries[0].URI, r.Entries[29].URI, r.Entries[30].URI, len(r.Entries))
	}
	if r.Files != 2 {
		t.Fatalf("files read: %d", r.Files)
	}

	r = Query(cur, Filter{Tag: TagTorrent}, 5, 0)
	if r.Matched != 50 || len(r.Entries) != 5 || r.Entries[0].URI != "/old/49" || r.Tags[TagTorrent] != 50 {
		t.Fatalf("torrent: matched %d, n %d, first %s, tags %v", r.Matched, len(r.Entries), r.Entries[0].URI, r.Tags)
	}

	r = Query(cur, Filter{Status: "4xx", Host: "b.example.com", Path: "/new/1"}, 100, 0)
	if r.Matched != 11 { // /new/1 and /new/10..19
		t.Fatalf("filter matched %d", r.Matched)
	}
}
