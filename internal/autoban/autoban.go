// Package autoban turns what clients do into bans: it watches the access
// log entries the analytics follower reads, bans an address at once when it
// steps into a trap (or asks for a protected file such as /.env), and after
// too many refused requests or 404s within a window. The bans are kept on
// disk; the API renders them into the firewall file, so caddy refuses the
// address from then on. The list grows with every scanner and shrinks only
// as bans expire.
package autoban

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"caddyevolved/internal/accesslog"
	"caddyevolved/internal/sites"
)

// MaxBans caps the list; caddy checks every address on each request.
const MaxBans = 20000

// Reasons a ban names.
const (
	ReasonTrap     = "falle"
	ReasonGuarded  = "geschuetzt"
	ReasonStrikes  = "verstoesse"
	ReasonNotFound = "404"
)

// Ban is one blocked address or IPv6 /64.
type Ban struct {
	IP     string    `json:"ip"`
	Reason string    `json:"reason"`
	Detail string    `json:"detail,omitempty"` // the request that triggered it
	Host   string    `json:"host,omitempty"`
	Since  time.Time `json:"since"`
	Until  time.Time `json:"until,omitzero"` // zero: permanent
	Times  int       `json:"times"`          // how often this address was banned
	Hits   int       `json:"hits"`           // requests refused since
}

type record struct {
	Times int       `json:"times"`
	Last  time.Time `json:"last"`
}

type window struct {
	strikes, notFound []time.Time
	last              time.Time
}

// Store holds the bans. All methods are safe on a nil Store.
type Store struct {
	mu      sync.Mutex
	path    string
	rules   sites.AutoBan
	on      bool
	exempt  []netip.Prefix
	bans    map[string]*Ban
	history map[string]record // past bans, for escalation
	windows map[string]*window
	changes []string // summaries since the last TakeChanges
	dirty   bool
	now     func() time.Time
}

type file struct {
	Bans    []*Ban            `json:"bans"`
	History map[string]record `json:"history,omitempty"`
}

// Open loads the bans stored at path.
func Open(path string) *Store {
	s := &Store{path: path, bans: map[string]*Ban{}, history: map[string]record{}, windows: map[string]*window{}, now: time.Now}
	if data, err := os.ReadFile(path); err == nil {
		var f file
		if json.Unmarshal(data, &f) == nil {
			for _, b := range f.Bans {
				s.bans[b.IP] = b
			}
			if f.History != nil {
				s.history = f.History
			}
		}
	}
	return s
}

// Configure sets the rules and the addresses never to ban (allowlist,
// trusted proxies); private and loopback addresses are always exempt.
func (s *Store) Configure(f sites.Firewall, exempt []string) {
	if s == nil {
		return
	}
	var pre []netip.Prefix
	for _, r := range exempt {
		if p, err := netip.ParsePrefix(r); err == nil {
			pre = append(pre, p.Masked())
		} else if a, err := netip.ParseAddr(r); err == nil {
			pre = append(pre, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules, s.on, s.exempt = f.AutoBan, f.AutoBanOn(), pre
	// A newly trusted address loses its ban at once.
	for k := range s.bans {
		if s.isExempt(k) {
			delete(s.bans, k)
			s.dirty = true
		}
	}
}

func (s *Store) isExempt(key string) bool {
	var a netip.Addr
	if p, err := netip.ParsePrefix(key); err == nil {
		a = p.Addr()
	} else if x, err := netip.ParseAddr(key); err == nil {
		a = x
	} else {
		return true
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || a.IsMulticast() {
		return true
	}
	for _, p := range s.exempt {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// keyFor is the address to ban: the IP, or its /64 for IPv6 if wanted.
func (s *Store) keyFor(ip string) (string, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", false
	}
	a = a.Unmap()
	if a.Is6() && s.rules.V6Net {
		p, _ := a.Prefix(64)
		return p.String(), true
	}
	return a.String(), true
}

// Observe looks at one handled request. Entries older than the longest
// window are ignored, so reading an old log does not ban anybody.
func (s *Store) Observe(e accesslog.Entry) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.on {
		return
	}
	now := s.now()
	maxAge := time.Duration(max(s.rules.StrikeMinutes, s.rules.NotFoundMinutes, 10)) * time.Minute
	if now.Sub(e.TS) > maxAge {
		return
	}
	key, ok := s.keyFor(e.IP)
	if !ok || s.isExempt(key) {
		return
	}
	if b, banned := s.bans[key]; banned {
		if e.Block == "autoban" {
			b.Hits++
		}
		return
	}
	detail := e.Method + " " + e.Host + e.URI
	switch {
	case e.Block == "autoban" || strings.HasPrefix(e.Block, "firewall"):
		return // refused by an existing rule already
	case e.Block == ReasonTrap:
		s.ban(key, ReasonTrap, detail, e.Host)
		return
	case e.Block == ReasonGuarded && s.rules.Guarded:
		s.ban(key, ReasonGuarded, detail, e.Host)
		return
	}
	w := s.windows[key]
	if w == nil {
		w = &window{}
		s.windows[key] = w
	}
	w.last = e.TS
	strike := e.Block == "ratelimit" || (e.Block == "" && (e.Status == 403 || e.Status == 429))
	if strike && s.rules.Strikes > 0 {
		w.strikes = within(append(w.strikes, e.TS), e.TS, s.rules.StrikeMinutes)
		if len(w.strikes) >= s.rules.Strikes {
			s.ban(key, ReasonStrikes, fmt.Sprintf("%d abgewiesene Anfragen, zuletzt %s", len(w.strikes), detail), e.Host)
			return
		}
	}
	if e.Status == 404 && e.Block == "" && s.rules.NotFound > 0 {
		w.notFound = within(append(w.notFound, e.TS), e.TS, s.rules.NotFoundMinutes)
		if len(w.notFound) >= s.rules.NotFound {
			s.ban(key, ReasonNotFound, fmt.Sprintf("%d× nicht gefunden, zuletzt %s", len(w.notFound), detail), e.Host)
		}
	}
}

// within keeps the times inside the window ending at now.
func within(ts []time.Time, now time.Time, minutes int) []time.Time {
	from := now.Add(-time.Duration(minutes) * time.Minute)
	i := 0
	for i < len(ts) && ts[i].Before(from) {
		i++
	}
	return ts[i:]
}

// ban adds key; the caller holds the lock.
func (s *Store) ban(key, reason, detail, host string) {
	now := s.now().UTC()
	h := s.history[key]
	h.Times++
	h.Last = now
	s.history[key] = h
	b := &Ban{IP: key, Reason: reason, Detail: cut(detail, 300), Host: host, Since: now, Times: h.Times}
	if hours := s.rules.Hours; hours > 0 {
		if s.rules.Escalate && h.Times >= 3 {
			// permanent
		} else {
			d := time.Duration(hours) * time.Hour
			if s.rules.Escalate {
				d <<= h.Times - 1
			}
			b.Until = now.Add(d)
		}
	}
	s.bans[key] = b
	delete(s.windows, key)
	s.changes = append(s.changes, key+" ("+reason+")")
	s.dirty = true
	if len(s.bans) > MaxBans {
		s.evict()
	}
}

// evict drops the oldest ban.
func (s *Store) evict() {
	var oldest *Ban
	for _, b := range s.bans {
		if oldest == nil || b.Since.Before(oldest.Since) {
			oldest = b
		}
	}
	if oldest != nil {
		delete(s.bans, oldest.IP)
	}
}

// Sweep ends expired bans and forgets idle counters and old history.
func (s *Store) Sweep() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, b := range s.bans {
		if !b.Until.IsZero() && now.After(b.Until) {
			delete(s.bans, k)
			s.dirty = true
		}
	}
	idle := time.Duration(max(s.rules.StrikeMinutes, s.rules.NotFoundMinutes, 10)) * time.Minute
	for k, w := range s.windows {
		if now.Sub(w.last) > idle {
			delete(s.windows, k)
		}
	}
	for k, h := range s.history {
		if _, banned := s.bans[k]; !banned && now.Sub(h.Last) > 90*24*time.Hour {
			delete(s.history, k)
		}
	}
}

// TakeChanges reports whether the list changed since the last call, with
// the new bans for the event log, and saves the store if so.
func (s *Store) TakeChanges() (bool, []string) {
	if s == nil {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return false, nil
	}
	ch := s.changes
	s.dirty, s.changes = false, nil
	s.save()
	return true, ch
}

// Unban removes key and forgets its history: an operator who lifts a ban
// considers it a mistake, so a repeat starts at the short duration again.
func (s *Store) Unban(key string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.bans[key]
	delete(s.bans, key)
	delete(s.history, key)
	delete(s.windows, key)
	if ok {
		s.dirty = true
	}
	return ok
}

// Clear lifts every ban.
func (s *Store) Clear() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.bans)
	s.bans, s.history, s.windows = map[string]*Ban{}, map[string]record{}, map[string]*window{}
	s.dirty = true
	return n
}

// Active lists the banned addresses, sorted, for the firewall file; empty
// while the auto-ban is off.
func (s *Store) Active() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.on {
		return nil
	}
	now := s.now()
	out := make([]string, 0, len(s.bans))
	for k, b := range s.bans {
		if b.Until.IsZero() || now.Before(b.Until) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// List returns the bans, newest first.
func (s *Store) List() []Ban {
	out := []Ban{}
	if s == nil {
		return out
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.bans {
		out = append(out, *b)
	}
	slices.SortFunc(out, func(a, b Ban) int { return b.Since.Compare(a.Since) })
	return out
}

// save writes the store; the caller holds the lock.
func (s *Store) save() {
	f := file{Bans: make([]*Ban, 0, len(s.bans)), History: s.history}
	for _, b := range s.bans {
		f.Bans = append(f.Bans, b)
	}
	slices.SortFunc(f.Bans, func(a, b *Ban) int { return strings.Compare(a.IP, b.IP) })
	data, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(s.path), 0o755)
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		os.Rename(tmp, s.path)
	}
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
