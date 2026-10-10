package analytics

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func line(ts time.Time, host, uri string, status int, dur float64) string {
	return fmt.Sprintf(`{"level":"info","ts":%f,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"10.0.0.7","client_ip":"10.0.0.7","proto":"HTTP/2.0","method":"GET","host":"%s","uri":"%s","headers":{"User-Agent":["curl/8"],"Referer":["https://ref.example/x"]}},"bytes_read":0,"duration":%f,"size":512,"status":%d}`+"\n",
		float64(ts.UnixNano())/1e9, host, uri, dur, status)
}

func TestIngestAndQuery(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "a.json"))
	now := time.Now()
	s.Ingest([]byte(line(now, "app.example.com:443", "/a?x=1", 200, 0.012)))
	s.Ingest([]byte(line(now, "app.example.com", "/a", 403, 0.001)))
	s.Ingest([]byte(line(now, "other.lan", "/b", 502, 0.3)))
	s.Ingest([]byte(`{"level":"info","msg":"started background certificate maintenance"}`))

	rep := s.Query(time.Hour, nil)
	if rep.Totals.Requests != 3 || rep.Totals.S5xx != 1 || rep.Totals.Blocked != 1 {
		t.Fatalf("totals = %+v", rep.Totals.Bucket)
	}
	if rep.Step != "1m" || len(rep.Series) < 60 {
		t.Errorf("step %s, %d Punkte", rep.Step, len(rep.Series))
	}
	app := s.Query(time.Hour, []string{"app.example.com"})
	if app.Totals.Requests != 2 {
		t.Errorf("Filter nach Host: %d", app.Totals.Requests)
	}
	if got := app.Top["paths"]; len(got) != 1 || got[0].Key != "/a" || got[0].Count != 2 {
		t.Errorf("Top-Pfade (Query-String muss weg): %+v", got)
	}
	if got := app.Top["referers"]; len(got) != 1 || got[0].Key != "ref.example" {
		t.Errorf("Referer: %+v", got)
	}
	if long := s.Query(7*24*time.Hour, nil); long.Step != "1h" || long.Totals.Requests != 3 {
		t.Errorf("Stundenreihe: %s %d", long.Step, long.Totals.Requests)
	}
	if r := s.Recent(10, nil); len(r) != 3 || r[0].Host != "other.lan" {
		t.Errorf("recent: %+v", r)
	}
}

func TestFollowResumesAndSurvivesRoll(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "access.log")
	snap := filepath.Join(dir, "a.json")
	os.WriteFile(log, []byte(line(time.Now(), "a.lan", "/", 200, 0.01)), 0o644)

	run := func(s *Store, d time.Duration) {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		defer cancel()
		s.Follow(ctx, log)
	}
	s := New(snap)
	run(s, 1500*time.Millisecond)
	if n := s.Query(time.Hour, nil).Totals.Requests; n != 1 {
		t.Fatalf("erster Lauf: %d", n)
	}
	// A restart must not count the same lines twice.
	s2 := New(snap)
	f, _ := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(line(time.Now(), "a.lan", "/2", 200, 0.01))
	f.Close()
	run(s2, 1500*time.Millisecond)
	if n := s2.Query(time.Hour, nil).Totals.Requests; n != 2 {
		t.Fatalf("nach Neustart: %d (erwartet 2)", n)
	}
	// Roll: the old file is renamed, a new one appears under the same name.
	os.Rename(log, log+".1")
	os.WriteFile(log, []byte(line(time.Now(), "a.lan", "/3", 200, 0.01)), 0o644)
	s3 := New(snap)
	run(s3, 1500*time.Millisecond)
	if n := s3.Query(time.Hour, nil).Totals.Requests; n != 3 {
		t.Fatalf("nach Rotation: %d (erwartet 3)", n)
	}
}
