// Package blocklists fetches the free data the firewall builds on: public IP
// blocklists and the DB-IP Lite geo databases (country, ASN). Nothing here
// needs an account or a key.
package blocklists

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
)

// List is one public blocklist.
type List struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Desc   string   `json:"desc"`
	URLs   []string `json:"urls"`
	Source string   `json:"source"`
	// Level says how likely real visitors are hit: "sicher" (almost
	// never), "mittel" or "streng" (recent reports, some false alarms).
	Level   string `json:"level"`
	License string `json:"license"`
	Custom  bool   `json:"custom,omitempty"`
}

// Catalog are the lists the firewall offers, all free for this use.
var Catalog = []List{
	{
		ID: "spamhaus-drop", Name: "Spamhaus DROP", Level: "sicher",
		Desc:    "Gekaperte Netze und Netze krimineller Betreiber. Sehr wenige Fehlalarme – die sichere Grundlage.",
		URLs:    []string{"https://www.spamhaus.org/drop/drop.txt", "https://www.spamhaus.org/drop/drop_v6.txt"},
		Source:  "https://www.spamhaus.org/blocklists/do-not-route-or-peer/",
		License: "frei nutzbar (Spamhaus DROP)",
	},
	{
		ID: "firehol-level1", Name: "FireHOL Level 1", Level: "sicher",
		Desc:    "Sammelliste bekannter Angreifer (DShield, Feodo, Spamhaus u. a.). Für Firewalls gedacht, wenige Fehlalarme.",
		URLs:    []string{"https://iplists.firehol.org/files/firehol_level1.netset"},
		Source:  "https://iplists.firehol.org/?ipset=firehol_level1",
		License: "frei nutzbar (FireHOL)",
	},
	{
		ID: "dshield", Name: "DShield Top 20", Level: "sicher",
		Desc:    "Die 20 Netze, aus denen in den letzten Tagen am meisten angegriffen wurde (SANS Internet Storm Center).",
		URLs:    []string{"https://iplists.firehol.org/files/dshield.netset"},
		Source:  "https://isc.sans.edu/block.txt",
		License: "frei nutzbar (SANS ISC)",
	},
	{
		ID: "et-compromised", Name: "Emerging Threats: kompromittierte Hosts", Level: "sicher",
		Desc:    "Übernommene Rechner, die gerade für Angriffe genutzt werden (Proofpoint).",
		URLs:    []string{"https://rules.emergingthreats.net/blockrules/compromised-ips.txt"},
		Source:  "https://rules.emergingthreats.net/blockrules/",
		License: "frei nutzbar (Proofpoint ET Open)",
	},
	{
		ID: "firehol-level2", Name: "FireHOL Level 2", Level: "mittel",
		Desc:    "Angriffe der letzten 48 Stunden aus mehreren Quellen (blocklist.de, GreenSnow, DShield …).",
		URLs:    []string{"https://iplists.firehol.org/files/firehol_level2.netset"},
		Source:  "https://iplists.firehol.org/?ipset=firehol_level2",
		License: "frei nutzbar (FireHOL)",
	},
	{
		ID: "blocklist-de", Name: "blocklist.de", Level: "mittel",
		Desc:    "Von fail2ban-Servern gemeldete Angreifer der letzten 48 Stunden: SSH, Mail, Web, Brute Force.",
		URLs:    []string{"https://lists.blocklist.de/lists/all.txt"},
		Source:  "https://www.blocklist.de/",
		License: "frei nutzbar (blocklist.de)",
	},
	{
		ID: "cins-army", Name: "CINS Army", Level: "mittel",
		Desc:    "Adressen mit schlechtem Ruf aus dem Sentinel-IPS-Netz von Collective Intelligence.",
		URLs:    []string{"https://cinsscore.com/list/ci-badguys.txt"},
		Source:  "https://cinsscore.com/",
		License: "frei nutzbar (CINS Score)",
	},
	{
		ID: "greensnow", Name: "GreenSnow", Level: "mittel",
		Desc:    "Von GreenSnow-Sensoren erkannte Angreifer: Scans, Brute Force, Spam.",
		URLs:    []string{"https://blocklist.greensnow.co/greensnow.txt"},
		Source:  "https://greensnow.co/",
		License: "frei nutzbar (GreenSnow)",
	},
	{
		ID: "ipsum-3", Name: "IPsum (Stufe 3)", Level: "mittel",
		Desc:    "Adressen, die auf mindestens 3 von über 30 öffentlichen Sperrlisten stehen – täglich neu.",
		URLs:    []string{"https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"},
		Source:  "https://github.com/stamparm/ipsum",
		License: "Unlicense (stamparm/ipsum)",
	},
	{
		ID: "firehol-level3", Name: "FireHOL Level 3", Level: "streng",
		Desc:    "Angriffe der letzten 30 Tage. Erwischt mehr, sperrt aber auch neu vergebene Adressen ehemaliger Angreifer.",
		URLs:    []string{"https://iplists.firehol.org/files/firehol_level3.netset"},
		Source:  "https://iplists.firehol.org/?ipset=firehol_level3",
		License: "frei nutzbar (FireHOL)",
	},
	{
		ID: "tor-exit", Name: "Tor-Exit-Knoten", Level: "streng",
		Desc:    "Anfragen aus dem Tor-Netz. Sperrt auch harmlose Tor-Nutzer – nur bei Bedarf.",
		URLs:    []string{"https://check.torproject.org/torbulkexitlist"},
		Source:  "https://check.torproject.org/",
		License: "öffentlich (Tor Project)",
	},
}

// ByID finds a catalog list.
func ByID(id string) (List, bool) {
	for _, l := range Catalog {
		if l.ID == id {
			return l, true
		}
	}
	return List{}, false
}

// CustomPrefix marks the ids of lists the operator added by URL.
const CustomPrefix = "eigene-"

// ValidURL reports whether u can be fetched as a list.
func ValidURL(u string) bool {
	p, err := url.Parse(u)
	return err == nil && (p.Scheme == "https" || p.Scheme == "http") && p.Host != "" && len(u) <= 1000
}

// MaxEntries keeps a broken upstream from bloating the Caddyfile.
const MaxEntries = 30000

// special are ranges no public list may block: the operator's own network,
// loopback and documentation space. FireHOL level 1 ships the bogons,
// including 192.168.0.0/16 – taken over verbatim it would lock out the LAN.
var special = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/3", "::/8", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Parse reads a list in any of the usual formats: one IP or CIDR per line,
// comments after # or ;. Private and special ranges are dropped.
func Parse(r io.Reader) []string {
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() && len(out) < MaxEntries {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		// The address is the first field, separated by blanks or commas
		// (CSV exports, "ip<TAB>count" as in IPsum).
		f := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' || r == '\r' })
		if len(f) == 0 {
			continue
		}
		p, ok := prefix(f[0])
		if !ok || isSpecial(p) {
			continue
		}
		s := p.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func prefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func isSpecial(p netip.Prefix) bool {
	for _, s := range special {
		if s.Overlaps(p) {
			return true
		}
	}
	return false
}

// Info describes a downloaded list.
type Info struct {
	ID      string    `json:"id"`
	Entries int       `json:"entries"`
	Updated time.Time `json:"updated,omitzero"`
	Error   string    `json:"error,omitempty"`
}

func listFile(dir, id string) string { return filepath.Join(dir, id+".txt") }

// Load returns the stored entries of the given lists; missing ones are empty.
func Load(dir string, ids []string) map[string][]string {
	out := map[string][]string{}
	for _, id := range ids {
		data, err := os.ReadFile(listFile(dir, id))
		if err != nil {
			continue
		}
		out[id] = Parse(bytes.NewReader(data))
	}
	return out
}

// Stat reports what is on disk for the given lists.
func Stat(dir string, ids []string) map[string]Info {
	out := map[string]Info{}
	for _, id := range ids {
		i := Info{ID: id}
		if data, err := os.ReadFile(listFile(dir, id)); err == nil {
			if st, err := os.Stat(listFile(dir, id)); err == nil {
				i.Updated = st.ModTime().UTC()
			}
			i.Entries = bytes.Count(data, []byte("\n"))
		}
		out[id] = i
	}
	return out
}

// Remove deletes a stored list (a custom list the operator dropped).
func Remove(dir, id string) { os.Remove(listFile(dir, id)) }

// Age is how old a stored list is; missing lists are infinitely old.
func Age(dir, id string) time.Duration {
	st, err := os.Stat(listFile(dir, id))
	if err != nil {
		return 1 << 62
	}
	return time.Since(st.ModTime())
}

var client = &http.Client{Timeout: 90 * time.Second}

func get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "caddyEvolved-firewall")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: größer als %d MB", url, limit>>20)
	}
	return data, nil
}

// Update downloads one list. An empty result keeps the old file: an upstream
// hiccup must not silently switch a list off.
func Update(ctx context.Context, dir string, l List) (Info, error) {
	id := l.ID
	entries, err := Fetch(ctx, l.URLs)
	if err != nil {
		err = fmt.Errorf("%s: %w", l.Name, err)
		return Info{ID: id, Error: err.Error()}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Info{ID: id}, err
	}
	if err := writeAtomic(listFile(dir, id), []byte(strings.Join(entries, "\n")+"\n")); err != nil {
		return Info{ID: id}, err
	}
	return Info{ID: id, Entries: len(entries), Updated: time.Now().UTC()}, nil
}

// Fetch downloads and parses the URLs of one list. A list without a single
// address is an error: most likely an HTML page or a changed format.
func Fetch(ctx context.Context, urls []string) ([]string, error) {
	var buf bytes.Buffer
	for _, u := range urls {
		data, err := get(ctx, u, 16<<20)
		if err != nil {
			return nil, err
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}
	entries := Parse(&buf)
	if len(entries) == 0 {
		return nil, errors.New("keine IP-Adressen gefunden – eine Adresse oder ein Bereich pro Zeile erwartet")
	}
	return entries, nil
}

// writeAtomic writes a world-readable file: caddy runs as its own user and
// opens the geo databases itself. Chmod, because the service umask (077)
// would otherwise leave 0600 – and an unreadable database makes the geo
// matcher fail closed, refusing every visitor.
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// mkdirReadable creates dir so that other users may enter it.
func mkdirReadable(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.Chmod(dir, 0o755)
}

// ---- geo databases -----------------------------------------------------------

// Geo kinds.
const (
	GeoCountry = "country"
	GeoASN     = "asn"
)

// mmdbMarker starts the metadata section every MaxMind-format file ends with.
var mmdbMarker = []byte("\xab\xcd\xefMaxMind.com")

// GeoPath returns the newest database of the kind, or "" when none exists.
// The month is part of the name, so a new database changes the rendered
// config and caddy reopens it on reload.
func GeoPath(dir, kind string) string {
	files, _ := filepath.Glob(filepath.Join(dir, "dbip-"+kind+"-lite-*.mmdb"))
	if len(files) == 0 {
		return ""
	}
	slices.Sort(files)
	return files[len(files)-1]
}

// FixGeoPerms makes existing databases readable for caddy again, e.g. ones
// an older version wrote with the service umask.
func FixGeoPerms(dir string) {
	if _, err := os.Stat(dir); err != nil {
		return
	}
	os.Chmod(dir, 0o755)
	files, _ := filepath.Glob(filepath.Join(dir, "*.mmdb"))
	for _, f := range files {
		os.Chmod(f, 0o644)
	}
}

// GeoStale reports whether a newer monthly database may be available.
func GeoStale(dir, kind string) bool {
	p := GeoPath(dir, kind)
	return p == "" || !strings.Contains(filepath.Base(p), time.Now().UTC().Format("2006-01"))
}

// UpdateGeo fetches the DB-IP Lite database of the current month (falling
// back to the previous one early in the month) and removes older copies.
// DB-IP Lite is CC BY 4.0 and needs no account.
func UpdateGeo(ctx context.Context, dir, kind string) (string, error) {
	if kind != GeoCountry && kind != GeoASN {
		return "", fmt.Errorf("unbekannte Geo-Datenbank %q", kind)
	}
	if err := mkdirReadable(dir); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	var lastErr error
	for _, t := range []time.Time{now, now.AddDate(0, -1, 0)} {
		name := fmt.Sprintf("dbip-%s-lite-%s.mmdb", kind, t.Format("2006-01"))
		dest := filepath.Join(dir, name)
		if _, err := os.Stat(dest); err == nil {
			return dest, nil
		}
		gz, err := get(ctx, "https://download.db-ip.com/free/"+name+".gz", 200<<20)
		if err != nil {
			lastErr = err
			continue
		}
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			lastErr = err
			continue
		}
		data, err := io.ReadAll(io.LimitReader(zr, 500<<20))
		if err != nil {
			lastErr = err
			continue
		}
		tail := data[max(0, len(data)-128*1024):]
		if !bytes.Contains(tail, mmdbMarker) {
			lastErr = errors.New(name + ": keine gültige MaxMind-Datenbank")
			continue
		}
		if err := writeAtomic(dest, data); err != nil {
			return "", err
		}
		old, _ := filepath.Glob(filepath.Join(dir, "dbip-"+kind+"-lite-*.mmdb"))
		for _, o := range old {
			if o != dest {
				os.Remove(o)
			}
		}
		return dest, nil
	}
	return "", lastErr
}
