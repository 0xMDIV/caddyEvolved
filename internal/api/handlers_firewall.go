package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"caddyevolved/internal/analytics"
	"caddyevolved/internal/blocklists"

	"caddyevolved/internal/sites"
)

// The firewall (sites/firewall.go) lives in global.json next to the other
// host-wide options but has its own page: rules, public blocklists, geo
// databases and the log of what was refused.

func (s *Server) listDir() string { return filepath.Join(s.Paths.StateDir, "firewall") }

// geoDir must be readable by caddy, which opens the databases itself.
func (s *Server) geoDir() string { return filepath.Join(s.Paths.CaddyData, "geoip") }

func (s *Server) wafLog() string { return filepath.Join(s.Paths.LogDir, "waf.log") }

type geoInfo struct {
	Path    string    `json:"path"`
	Updated time.Time `json:"updated,omitzero"`
}

func geoState(dir, kind string) geoInfo {
	p := blocklists.GeoPath(dir, kind)
	i := geoInfo{Path: p}
	if st, err := os.Stat(p); err == nil {
		i.Updated = st.ModTime().UTC()
	}
	return i
}

type listOut struct {
	blocklists.List
	Entries int       `json:"entries"`
	Updated time.Time `json:"updated,omitzero"`
}

func (s *Server) handleFirewallGet(w http.ResponseWriter, r *http.Request) {
	caps := s.Sites.Options().Caps
	fw := s.loadGlobal().Firewall
	all := slices.Clone(blocklists.Catalog)
	for _, c := range fw.CustomLists {
		l, _ := fw.ListByID(c.ID)
		all = append(all, l)
	}
	ids := make([]string, len(all))
	for i, l := range all {
		ids[i] = l.ID
	}
	stats := blocklists.Stat(s.listDir(), ids)
	lists := make([]listOut, 0, len(all))
	for _, l := range all {
		lists = append(lists, listOut{List: l, Entries: stats[l.ID].Entries, Updated: stats[l.ID].Updated})
	}
	out := map[string]any{
		"firewall": fw,
		"lists":    lists,
		"geo": map[string]geoInfo{
			"country": geoState(s.geoDir(), blocklists.GeoCountry),
			"asn":     geoState(s.geoDir(), blocklists.GeoASN),
		},
		"caps":           map[string]bool{"geo": caps.Geo, "waf": caps.WAF},
		"wafGroups":      sites.WAFGroups,
		"defenderRanges": sites.DefenderRanges,
		"file":           s.Sites.FirewallFile(),
		"yourIp":         clientIP(r),
		"bans":           s.Bans.List(),
	}
	writeJSON(w, http.StatusOK, out)
}

// handleFirewallSave replaces the firewall rules. Lists and databases the
// rules need are fetched first, so the rules work as soon as they are saved.
func (s *Server) handleFirewallSave(w http.ResponseWriter, r *http.Request) {
	var f sites.Firewall
	if err := decode(r, &f); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	g := s.loadGlobal()
	before := g.Firewall
	g.Firewall = f
	g.Normalize()
	if err := g.Validate(); err != nil {
		s.siteError(w, r, err)
		return
	}
	// A custom list with a new address is downloaded again.
	for _, c := range g.Firewall.CustomLists {
		if old, ok := before.ListByID(c.ID); ok && old.URLs[0] != c.URL {
			blocklists.Remove(s.listDir(), c.ID)
		}
	}
	if err := s.ensureFirewallData(r.Context(), g.Firewall, false); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "invalid_site", "Firewall-Daten fehlen", err.Error())
		return
	}
	reloaded, err := s.applyGlobal(r.Context(), g, "Firewall geändert")
	if err != nil {
		s.siteError(w, r, err)
		return
	}
	for _, c := range before.CustomLists {
		if _, ok := g.Firewall.ListByID(c.ID); !ok {
			blocklists.Remove(s.listDir(), c.ID)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"firewall": g.Firewall, "reloaded": reloaded})
}

// handleFirewallListTest downloads a list without saving it, so the
// operator sees before adding it whether the address works.
func (s *Server) handleFirewallListTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		URL string `json:"url"`
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	in.URL = strings.TrimSpace(in.URL)
	if !blocklists.ValidURL(in.URL) {
		writeErr(w, http.StatusBadRequest, "bad_request", "Adresse muss mit https:// oder http:// beginnen")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	entries, err := blocklists.Fetch(ctx, []string{in.URL})
	if err != nil {
		writeErr(w, http.StatusBadGateway, "download", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": len(entries), "sample": entries[:min(len(entries), 5)], "limited": len(entries) >= blocklists.MaxEntries})
}

// handleFirewallQuick adds one address to the block or allow list, the
// one-click action next to a refused request.
func (s *Server) handleFirewallQuick(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP     string `json:"ip"`
		Action string `json:"action"` // block | allow | unblock | unban
	}
	if err := decode(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", errText(err))
		return
	}
	in.IP = strings.TrimSpace(in.IP)
	if in.Action == "unban" {
		if !s.Bans.Unban(in.IP) {
			writeErr(w, http.StatusNotFound, "not_found", in.IP+" ist nicht automatisch gesperrt")
			return
		}
		s.Bans.TakeChanges()
		s.resyncSites(r.Context(), "Auto-Bann: "+in.IP+" entsperrt")
		writeJSON(w, http.StatusOK, map[string]any{"unbanned": in.IP})
		return
	}
	// A manual decision replaces the automatic one.
	if s.Bans.Unban(in.IP) {
		s.Bans.TakeChanges()
	}
	g := s.loadGlobal()
	f := &g.Firewall
	without := func(l []string) []string {
		return slices.DeleteFunc(slices.Clone(l), func(x string) bool { return x == in.IP })
	}
	switch in.Action {
	case "block":
		f.Allow = without(f.Allow)
		f.Block = append(without(f.Block), in.IP)
		f.Enabled = true
	case "allow":
		f.Block = without(f.Block)
		f.Allow = append(without(f.Allow), in.IP)
		f.Enabled = true
	case "unblock":
		f.Block = without(f.Block)
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "action: block, allow oder unblock")
		return
	}
	g.Normalize()
	if err := g.Validate(); err != nil {
		s.siteError(w, r, err)
		return
	}
	verb := map[string]string{"block": "gesperrt", "allow": "freigegeben", "unblock": "entsperrt"}[in.Action]
	reloaded, err := s.applyGlobal(r.Context(), g, "Firewall: "+in.IP+" "+verb)
	if err != nil {
		s.siteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"firewall": g.Firewall, "reloaded": reloaded})
}

// handleFirewallRefresh downloads every list and database in use again.
func (s *Server) handleFirewallRefresh(w http.ResponseWriter, r *http.Request) {
	g := s.loadGlobal()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	if err := s.ensureFirewallData(ctx, g.Firewall, true); err != nil {
		writeErr(w, http.StatusBadGateway, "download", err.Error())
		return
	}
	s.resyncSites(ctx, "Firewall-Listen aktualisiert")
	s.handleFirewallGet(w, r)
}

// ensureFirewallData fetches what the rules need: missing lists and
// databases always, stale ones when force is set or they are old enough.
// A failed refresh of data already on disk is not an error.
func (s *Server) ensureFirewallData(ctx context.Context, f sites.Firewall, force bool) error {
	if !f.Enabled {
		return nil
	}
	var errs []error
	for _, id := range f.Lists {
		age := blocklists.Age(s.listDir(), id)
		if !force && age < 20*time.Hour {
			continue
		}
		l, ok := f.ListByID(id)
		if !ok {
			continue
		}
		if _, err := blocklists.Update(ctx, s.listDir(), l); err != nil && age > 1<<61 {
			errs = append(errs, err)
		}
	}
	if err := s.ensureGeoRules(ctx, f.UsesGeo(), f.UsesASN()); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ensureGeoRules makes sure the geo plugin is built and the databases exist.
func (s *Server) ensureGeoRules(ctx context.Context, country, asn bool) error {
	if !country && !asn {
		return nil
	}
	if !s.Sites.Options().Caps.Geo {
		return errors.New("Länder- und Netzregeln brauchen das Plugin „Geo-Blocking (MaxMind)“ – unter Plugins & Build bauen und aktivieren")
	}
	blocklists.FixGeoPerms(s.geoDir())
	var errs []error
	for kind, need := range map[string]bool{blocklists.GeoCountry: country, blocklists.GeoASN: asn} {
		if !need || !blocklists.GeoStale(s.geoDir(), kind) {
			continue
		}
		if _, err := blocklists.UpdateGeo(ctx, s.geoDir(), kind); err != nil && blocklists.GeoPath(s.geoDir(), kind) == "" {
			errs = append(errs, fmt.Errorf("Geo-Datenbank (%s) nicht ladbar: %w", kind, err))
		}
	}
	s.Sites.SetOptions(s.siteOptions())
	return errors.Join(errs...)
}

// firewallLoop keeps lists and databases fresh: lists daily, the geo
// databases when DB-IP publishes the new month.
func (s *Server) firewallLoop(ctx context.Context) {
	tick := time.NewTicker(6 * time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		g := s.loadGlobal()
		geo := g.Firewall.UsesGeo()
		if acls, err := s.Sites.ListACL(); err == nil {
			for _, a := range acls {
				geo = geo || (a.UsesGeo() && a.GeoDB == "")
			}
		}
		before := s.siteOptions()
		rctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		_ = s.ensureFirewallData(rctx, g.Firewall, false)
		_ = s.ensureGeoRules(rctx, geo, g.Firewall.UsesASN())
		if after := s.siteOptions(); after.GeoDB != before.GeoDB || after.ASNDB != before.ASNDB || len(g.Firewall.Lists) > 0 {
			s.resyncSites(rctx, "Firewall-Listen aktualisiert")
		}
		cancel()
	}
}

// ---- refused requests ---------------------------------------------------------

// handleFirewallLog lists the latest refused requests and WAF matches.
func (s *Server) handleFirewallLog(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"blocked": []analytics.Request{}, "waf": wafEvents(s.wafLog(), 100)}
	if s.Analytics != nil {
		out["blocked"] = s.Analytics.RecentBlocked(200)
		rep := s.Analytics.Query(24*time.Hour, nil)
		out["reasons"] = rep.Top["blocks"]
		out["ips"] = rep.Top["blockedIps"]
	}
	writeJSON(w, http.StatusOK, out)
}

// WAFRule is one rule that matched.
type WAFRule struct {
	ID       int    `json:"id"`
	Msg      string `json:"msg"`
	Severity string `json:"severity,omitempty"`
	Data     string `json:"data,omitempty"`
}

// WAFEvent groups the matches of one request.
type WAFEvent struct {
	TS      time.Time `json:"ts"`
	ID      string    `json:"id"`
	Host    string    `json:"host"`
	URI     string    `json:"uri"`
	IP      string    `json:"ip"`
	Blocked bool      `json:"blocked"`
	Rules   []WAFRule `json:"rules"`
}

var reWAFField = regexp.MustCompile(`\[(\w+) "((?:[^"\\]|\\.)*)"\]`)

// wafEvents reads the tail of Coraza's log and groups it by transaction.
func wafEvents(path string, limit int) []WAFEvent {
	out := []WAFEvent{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > 4<<20 {
		f.Seek(st.Size()-4<<20, io.SeekStart)
	}
	byID := map[string]*WAFEvent{}
	var order []string
	get := func(id string) *WAFEvent {
		if e, ok := byID[id]; ok {
			return e
		}
		e := &WAFEvent{ID: id, Rules: []WAFRule{}}
		byID[id] = e
		order = append(order, id)
		return e
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if !bytes.Contains(line, []byte(`"http.handlers.waf"`)) {
			continue
		}
		var l struct {
			TS       float64 `json:"ts"`
			Msg      string  `json:"msg"`
			Host     string  `json:"hostname"`
			URI      string  `json:"uri"`
			ClientIP string  `json:"client_ip"`
			UniqueID string  `json:"unique_id"`
		}
		if json.Unmarshal(line, &l) != nil {
			continue
		}
		ts := time.Unix(int64(l.TS), 0).UTC()
		if l.Msg == "WAF rule violation detected" && l.UniqueID != "" {
			e := get(l.UniqueID)
			e.Blocked, e.TS = true, ts
			e.Host, e.URI, e.IP = firstNonEmptyStr(e.Host, l.Host), firstNonEmptyStr(e.URI, l.URI), firstNonEmptyStr(e.IP, l.ClientIP)
			continue
		}
		if !strings.Contains(l.Msg, "Coraza:") {
			continue
		}
		fields := map[string]string{}
		for _, m := range reWAFField.FindAllStringSubmatch(l.Msg, -1) {
			if _, seen := fields[m[1]]; !seen {
				fields[m[1]] = m[2]
			}
		}
		// The rule's message is the second "msg" field; the first is the
		// generic log text. FindAll keeps the first, so look again.
		msgs := []string{}
		for _, m := range reWAFField.FindAllStringSubmatch(l.Msg, -1) {
			if m[1] == "msg" {
				msgs = append(msgs, m[2])
			}
		}
		uid := fields["unique_id"]
		id, _ := strconv.Atoi(fields["id"])
		if uid == "" || id == 0 {
			continue
		}
		e := get(uid)
		if e.TS.IsZero() || ts.After(e.TS) {
			e.TS = ts
		}
		e.Host, e.URI, e.IP = firstNonEmptyStr(e.Host, fields["hostname"]), firstNonEmptyStr(e.URI, fields["uri"]), firstNonEmptyStr(e.IP, fields["client"])
		rule := WAFRule{ID: id, Severity: fields["severity"], Data: cutStr(fields["data"], 200)}
		if len(msgs) > 0 {
			rule.Msg = msgs[len(msgs)-1]
		}
		e.Rules = append(e.Rules, rule)
	}
	for i := len(order) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, *byID[order[i]])
	}
	return out
}

func cutStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
