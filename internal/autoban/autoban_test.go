package autoban

import (
	"path/filepath"
	"testing"
	"time"

	"caddyevolved/internal/accesslog"
	"caddyevolved/internal/sites"
)

func newStore(t *testing.T, a sites.AutoBan, exempt ...string) (*Store, *time.Time) {
	t.Helper()
	s := Open(filepath.Join(t.TempDir(), "autoban.json"))
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	a.Enabled = true
	s.Configure(sites.Firewall{Enabled: true, AutoBan: a}, exempt)
	return s, &now
}

func entry(ip, block string, status int, ts time.Time) accesslog.Entry {
	return accesslog.Entry{TS: ts, IP: ip, Block: block, Status: status, Method: "GET", Host: "example.com", URI: "/x"}
}

func TestTrapBansAtOnce(t *testing.T) {
	s, now := newStore(t, sites.AutoBan{Guarded: true, Hours: 24})
	s.Observe(entry("203.0.113.7", "falle", 404, *now))
	s.Observe(entry("198.51.100.2", "geschuetzt", 404, *now))
	got := s.Active()
	if len(got) != 2 || got[0] != "198.51.100.2" || got[1] != "203.0.113.7" {
		t.Fatalf("active = %v", got)
	}
	if changed, added := s.TakeChanges(); !changed || len(added) != 2 {
		t.Fatalf("changes = %v %v", changed, added)
	}
	b := s.List()[0]
	if b.Until.Sub(b.Since) != 24*time.Hour || b.Times != 1 {
		t.Fatalf("ban = %+v", b)
	}
	// Persisted.
	s2 := Open(s.path)
	s2.Configure(sites.Firewall{Enabled: true, AutoBan: sites.AutoBan{Enabled: true}}, nil)
	if len(s2.Active()) != 2 {
		t.Fatalf("reloaded = %v", s2.Active())
	}
}

func TestExemptAndOff(t *testing.T) {
	s, now := newStore(t, sites.AutoBan{Guarded: true}, "203.0.113.0/24")
	for _, ip := range []string{"192.168.1.5", "10.0.0.1", "127.0.0.1", "fd00::1", "203.0.113.9"} {
		s.Observe(entry(ip, "falle", 404, *now))
	}
	if got := s.Active(); len(got) != 0 {
		t.Fatalf("exempt got banned: %v", got)
	}
	// Guarded off: protected files do not ban.
	s.Configure(sites.Firewall{Enabled: true, AutoBan: sites.AutoBan{Enabled: true}}, nil)
	s.Observe(entry("198.51.100.2", "geschuetzt", 404, *now))
	// Firewall off: nothing is collected.
	s.Configure(sites.Firewall{AutoBan: sites.AutoBan{Enabled: true}}, nil)
	s.Observe(entry("198.51.100.3", "falle", 404, *now))
	s.Configure(sites.Firewall{Enabled: true, AutoBan: sites.AutoBan{Enabled: true}}, nil)
	if got := s.Active(); len(got) != 0 {
		t.Fatalf("banned = %v", got)
	}
	// Old entries (replayed log) are ignored.
	s.Observe(entry("198.51.100.4", "falle", 404, now.Add(-time.Hour)))
	if got := s.Active(); len(got) != 0 {
		t.Fatalf("old entry banned: %v", got)
	}
}

func TestThresholds(t *testing.T) {
	s, now := newStore(t, sites.AutoBan{Strikes: 3, StrikeMinutes: 10, NotFound: 4, NotFoundMinutes: 5})
	ip := "198.51.100.7"
	s.Observe(entry(ip, "", 403, now.Add(-11*time.Minute+time.Second))) // ignored: older than window
	s.Observe(entry(ip, "", 403, now.Add(-9*time.Minute)))
	s.Observe(entry(ip, "", 429, *now))
	if len(s.Active()) != 0 {
		t.Fatal("banned too early")
	}
	s.Observe(entry(ip, "ratelimit", 429, *now))
	if got := s.Active(); len(got) != 1 || s.List()[0].Reason != ReasonStrikes {
		t.Fatalf("strikes: %v", s.List())
	}
	other := "198.51.100.8"
	for i := range 4 {
		s.Observe(entry(other, "", 404, now.Add(time.Duration(i)*time.Second)))
	}
	if got := s.Active(); len(got) != 2 {
		t.Fatalf("404: %v", got)
	}
	// Requests refused by the firewall itself never count.
	third := "198.51.100.9"
	for range 10 {
		s.Observe(entry(third, "firewall-land", 403, *now))
	}
	if got := s.Active(); len(got) != 2 {
		t.Fatalf("firewall refusals counted: %v", got)
	}
}

func TestEscalationAndExpiry(t *testing.T) {
	s, now := newStore(t, sites.AutoBan{Hours: 1, Escalate: true})
	ip := "203.0.113.50"
	want := []time.Duration{time.Hour, 2 * time.Hour, 0}
	for i, d := range want {
		s.Observe(entry(ip, "falle", 404, *now))
		b := s.List()[0]
		if b.Times != i+1 {
			t.Fatalf("round %d: times %d", i, b.Times)
		}
		if d == 0 {
			if !b.Until.IsZero() {
				t.Fatalf("third ban not permanent: %+v", b)
			}
			break
		}
		if b.Until.Sub(b.Since) != d {
			t.Fatalf("round %d: duration %v", i, b.Until.Sub(b.Since))
		}
		*now = now.Add(d + time.Minute)
		s.Sweep()
		if len(s.Active()) != 0 {
			t.Fatalf("round %d: not expired", i)
		}
	}
	if !s.Unban(ip) || len(s.Active()) != 0 {
		t.Fatal("unban")
	}
	s.Observe(entry(ip, "falle", 404, *now))
	if s.List()[0].Times != 1 {
		t.Fatal("unban should forget the history")
	}
}

func TestIPv6Net(t *testing.T) {
	s, now := newStore(t, sites.AutoBan{V6Net: true})
	s.Observe(entry("2001:db8:1:2:aaaa::1", "falle", 404, *now))
	s.Observe(entry("2001:db8:1:2:bbbb::1", "falle", 404, *now))
	if got := s.Active(); len(got) != 1 || got[0] != "2001:db8:1:2::/64" {
		t.Fatalf("active = %v", got)
	}
}
