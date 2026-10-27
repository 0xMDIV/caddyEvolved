package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeAPI is a minimal Cloudflare with one zone and an in-memory record set.
type fakeAPI struct {
	mu      sync.Mutex
	records []Record
	posts   []Record
	patches int
	auth    string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = r.Header.Get("Authorization") + "|" + r.Header.Get("X-Auth-Key")
	ok := func(v any) {
		data, _ := json.Marshal(v)
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": json.RawMessage(data), "result_info": map[string]int{"page": 1, "total_pages": 1}})
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/zones":
		ok([]Zone{{ID: "z1", Name: "example.com"}, {ID: "z2", Name: "sub.example.com"}})
	case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/dns_records"):
		var out []Record
		for _, rec := range f.records {
			if rec.Name == r.URL.Query().Get("name") {
				out = append(out, rec)
			}
		}
		ok(out)
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/dns_records"):
		var rec Record
		json.NewDecoder(r.Body).Decode(&rec)
		if rec.Name == "bad.example.com" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []apiError{{Code: 81053, Message: "record already exists"}}})
			return
		}
		rec.ID = "r" + rec.Name
		f.posts = append(f.posts, rec)
		f.records = append(f.records, rec)
		ok(rec)
	case r.Method == "PATCH":
		f.patches++
		ok(Record{})
	default:
		http.NotFound(w, r)
	}
}

func TestEnsure(t *testing.T) {
	f := &fakeAPI{records: []Record{
		{ID: "a", Type: "A", Name: "old.example.com", Content: "198.51.100.1", Proxied: false, Proxiable: true},
		{ID: "b", Type: "CNAME", Name: "same.example.com", Content: "x.example.com", Proxied: true, Proxiable: true},
		{ID: "c", Type: "TXT", Name: "new.example.com", Content: "v=spf1"},
	}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New(Config{APIToken: "tok"}, srv.URL)

	res := c.Ensure(context.Background(), []string{
		"new.example.com", "https://New.Example.com:443", "old.example.com", "same.example.com",
		"app.sub.example.com", "nas.lan", ":8080", "192.168.1.1", "foo.other.org", "bad.example.com",
	}, "203.0.113.5", true)

	got := map[string]Result{}
	for _, r := range res {
		got[r.Name] = r
	}
	if len(res) != 7 {
		t.Fatalf("Ergebnisse %d, erwartet 7 (Duplikate, Ports und IPs fallen weg): %+v", len(res), res)
	}
	if r := got["nas.lan"]; r.Action != "skipped" {
		t.Errorf("nas.lan: %+v", r)
	}
	if r := got["new.example.com"]; r.Action != "created" || r.Type != "A" || r.Zone != "example.com" {
		t.Errorf("new: %+v", r)
	}
	if r := got["old.example.com"]; r.Action != "updated" || !r.Proxied || r.Content != "198.51.100.1" {
		t.Errorf("old: %+v", r)
	}
	if r := got["same.example.com"]; r.Action != "exists" {
		t.Errorf("same: %+v", r)
	}
	if r := got["app.sub.example.com"]; r.Action != "created" || r.Zone != "sub.example.com" {
		t.Errorf("sub: %+v", r)
	}
	if r := got["foo.other.org"]; r.Action != "skipped" {
		t.Errorf("fremde Zone: %+v", r)
	}
	if r := got["bad.example.com"]; r.Action != "error" || !strings.Contains(r.Message, "81053") {
		t.Errorf("Fehler: %+v", r)
	}
	if f.patches != 1 || len(f.posts) != 2 {
		t.Errorf("patches=%d posts=%d", f.patches, len(f.posts))
	}
	if f.posts[0].Comment != Comment || f.posts[0].TTL != 1 || !f.posts[0].Proxied {
		t.Errorf("angelegter Eintrag: %+v", f.posts[0])
	}
	if f.auth != "Bearer tok|" {
		t.Errorf("Auth %q", f.auth)
	}
}

func TestEnsureGlobalKeyAndCNAME(t *testing.T) {
	f := &fakeAPI{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New(Config{APIToken: "key", Email: "a@b.c"}, srv.URL)
	res := c.Ensure(context.Background(), []string{"x.example.com"}, "home.example.net", false)
	if len(res) != 1 || res[0].Action != "created" || res[0].Type != "CNAME" || res[0].Proxied {
		t.Fatalf("%+v", res)
	}
	if f.auth != "|key" {
		t.Errorf("Auth %q", f.auth)
	}
}

func TestHostNameAndType(t *testing.T) {
	for in, want := range map[string]string{
		"App.Example.com": "app.example.com", "http://a.b.de/x": "a.b.de", "a.b.de:8443": "a.b.de",
		":8080": "", "localhost": "", "10.0.0.1": "", "[::1]:443": "", "*.example.com": "*.example.com",
	} {
		if got := HostName(in); got != want {
			t.Errorf("HostName(%q) = %q, erwartet %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"1.2.3.4": "A", "2001:db8::1": "AAAA", "home.example.net": "CNAME"} {
		if got := RecordType(in); got != want {
			t.Errorf("RecordType(%q) = %q", in, got)
		}
	}
	if (Config{Target: "https://x.de"}).Validate() == nil || (Config{Target: "x.de"}).Validate() != nil {
		t.Error("Validate")
	}
}
