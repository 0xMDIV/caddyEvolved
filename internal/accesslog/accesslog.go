// Package accesslog reads caddy's JSON access log: one parser shared by the
// analytics follower and the log viewer, tags that mark notable requests
// (torrent clients, crawlers, scanners, blocks), and queries that walk the
// current file plus caddy's rotated (and gzip-compressed) siblings.
package accesslog

import (
	"encoding/json"
	"math"
	"strings"
	"time"
)

// Entry is one handled request.
type Entry struct {
	TS        time.Time `json:"ts"`
	Host      string    `json:"host"`
	Method    string    `json:"method"`
	URI       string    `json:"uri"`
	Path      string    `json:"-"`
	Proto     string    `json:"proto,omitempty"`
	Status    int       `json:"status"`
	Size      int64     `json:"size"`      // bytes sent to the client
	BytesRead int64     `json:"bytesRead"` // request body bytes received
	Duration  float64   `json:"durationMs"`
	IP        string    `json:"ip"`
	Country   string    `json:"country,omitempty"`
	Agent     string    `json:"agent,omitempty"`
	Referer   string    `json:"referer,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	// Block names the rule that refused the request (log_append cev_block),
	// or a guess from the status for the plugins that cannot tag.
	Block string `json:"block,omitempty"`
}

type line struct {
	TS        float64 `json:"ts"`
	Msg       string  `json:"msg"`
	Block     string  `json:"cev_block"`
	Status    int     `json:"status"`
	Size      int64   `json:"size"`
	BytesRead int64   `json:"bytes_read"`
	Dur       float64 `json:"duration"`
	Request   struct {
		RemoteIP string              `json:"remote_ip"`
		ClientIP string              `json:"client_ip"`
		Proto    string              `json:"proto"`
		Method   string              `json:"method"`
		Host     string              `json:"host"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
}

// Parse reads one log line; ok is false for anything that is not an access
// entry, so mixed logs are safe to feed in.
func Parse(raw []byte) (Entry, bool) {
	var l line
	if json.Unmarshal(raw, &l) != nil || l.Msg != "handled request" || l.Request.Host == "" {
		return Entry{}, false
	}
	host := strings.ToLower(l.Request.Host)
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	ip := l.Request.ClientIP
	if ip == "" {
		ip = l.Request.RemoteIP
	}
	path := l.Request.URI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	e := Entry{
		TS:        time.Unix(int64(l.TS), int64((l.TS-math.Floor(l.TS))*1e9)).UTC(),
		Host:      host,
		Method:    l.Request.Method,
		URI:       cut(l.Request.URI, 500),
		Path:      cut(path, 200),
		Proto:     l.Request.Proto,
		Status:    l.Status,
		Size:      l.Size,
		BytesRead: l.BytesRead,
		Duration:  math.Round(l.Dur*100000) / 100,
		IP:        ip,
		Agent:     cut(first(l.Request.Headers["User-Agent"]), 300),
		Referer:   cut(first(l.Request.Headers["Referer"]), 300),
		Block:     cut(l.Block, 40),
	}
	if e.Block == "" && l.Status == 429 {
		e.Block = "ratelimit"
	}
	e.Tags = Tags(e)
	return e, true
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- tags ------------------------------------------------------------------

// Tag names, in display order.
const (
	TagTorrent = "torrent"
	TagAI      = "ki-crawler"
	TagBot     = "bot"
	TagScanner = "scanner"
	TagBlocked = "geblockt"
	TagError   = "fehler"
)

// AllTags lists every tag with its description for the UI.
var AllTags = []struct {
	Tag, Label, Desc string
}{
	{TagTorrent, "Torrent", "BitTorrent-Clients und Tracker-Anfragen (/announce, /scrape, info_hash)"},
	{TagAI, "KI-Crawler", "Crawler von KI-Anbietern (GPTBot, ClaudeBot, CCBot, Bytespider, …)"},
	{TagBot, "Bot", "Suchmaschinen und sonstige automatisierte Clients"},
	{TagScanner, "Scanner", "Sicherheits-Scanner und Angriffs-Pfade (/.env, /wp-login.php, /.git, …)"},
	{TagBlocked, "Geblockt", "Abgewiesen durch Access List, WAF, Bot-Abwehr oder Rate Limit (403/429)"},
	{TagError, "Fehler", "Serverfehler (5xx)"},
}

var torrentAgents = []string{
	"qbittorrent", "transmission", "utorrent", "µtorrent", "bittorrent", "deluge", "libtorrent", "rtorrent",
	"azureus", "vuze", "bitcomet", "aria2", "tixati", "frostwire", "ktorrent", "webtorrent", "biglybt", "flud", "tribler", "picotorrent",
}

var aiAgents = []string{
	"gptbot", "chatgpt-user", "oai-searchbot", "claudebot", "claude-web", "anthropic-ai", "ccbot", "bytespider",
	"perplexitybot", "google-extended", "amazonbot", "applebot-extended", "meta-externalagent", "facebookbot",
	"cohere-ai", "diffbot", "youbot", "imagesiftbot", "omgili", "timpibot", "petalbot",
}

var scannerAgents = []string{
	"zgrab", "masscan", "nmap", "nikto", "sqlmap", "nuclei", "httpx", "wpscan", "dirbuster", "gobuster", "ffuf",
	"censysinspect", "expanse", "internet-measurement", "paloalto", "l9scan", "leakix", "odin", "shodan",
}

var scannerPaths = []string{
	"/.env", "/.git/", "/wp-login.php", "/xmlrpc.php", "/wp-admin", "/phpmyadmin", "/pma", "/cgi-bin/",
	"/boaform", "/actuator", "/.aws/", "/server-status", "/vendor/phpunit", "/hnap1", "/shell", "/.ds_store",
	"/config.json", "/owa/", "/autodiscover", "/solr/", "/manager/html", "/console", "/.well-known/security.txt.bak",
}

// Tags marks notable requests. A request can carry several tags.
func Tags(e Entry) []string {
	var out []string
	ua := strings.ToLower(e.Agent)
	path := strings.ToLower(e.Path)
	uri := strings.ToLower(e.URI)

	if containsAny(ua, torrentAgents) || strings.HasSuffix(path, "/announce") || strings.HasSuffix(path, "/scrape") ||
		strings.Contains(uri, "info_hash=") || strings.HasSuffix(path, ".torrent") {
		out = append(out, TagTorrent)
	}
	switch {
	case containsAny(ua, aiAgents):
		out = append(out, TagAI)
	case containsAny(ua, scannerAgents):
		out = append(out, TagScanner)
	case strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") || strings.Contains(ua, "spider") || strings.Contains(ua, "slurp"):
		out = append(out, TagBot)
	}
	if !contains(out, TagScanner) && containsAnyPrefix(path, scannerPaths) {
		out = append(out, TagScanner)
	}
	if e.Block != "" || e.Status == 403 || e.Status == 429 {
		out = append(out, TagBlocked)
	}
	if e.Status >= 500 {
		out = append(out, TagError)
	}
	return out
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func containsAnyPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
