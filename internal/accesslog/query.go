package accesslog

import (
	"bufio"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// File is the current log or one of its rotated copies.
type File struct {
	Name       string    `json:"name"`
	Path       string    `json:"-"`
	Size       int64     `json:"size"`
	ModTime    time.Time `json:"modTime"`
	Compressed bool      `json:"compressed"`
	Current    bool      `json:"current"`
}

// Files lists the log and its rotated siblings, newest first. Caddy names
// rotated files "<base>-<timestamp>.log", gzip adds ".gz".
func Files(path string) []File {
	dir, base := filepath.Dir(path), filepath.Base(path)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []File
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !(n == base || strings.HasPrefix(n, stem+"-") && (strings.HasSuffix(n, ".log") || strings.HasSuffix(n, ".log.gz"))) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, File{Name: n, Path: filepath.Join(dir, n), Size: info.Size(), ModTime: info.ModTime().UTC(), Compressed: strings.HasSuffix(n, ".gz"), Current: n == base})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Current != out[j].Current {
			return out[i].Current
		}
		return out[i].ModTime.After(out[j].ModTime)
	})
	return out
}

// Filter narrows a query; zero values match everything.
type Filter struct {
	From, To time.Time
	Host     string // exact host
	IP       string // prefix, so "192.168.10." works
	Method   string
	Status   string // "404", "4xx" or "" ; several comma separated
	Path     string // substring of the URI
	Agent    string // substring, case-insensitive
	Text     string // substring anywhere (host, uri, ip, agent, referer)
	Tag      string
	MinMs    float64
}

func (f Filter) match(e Entry) bool {
	if !f.From.IsZero() && e.TS.Before(f.From) || !f.To.IsZero() && e.TS.After(f.To) {
		return false
	}
	if f.Host != "" && e.Host != f.Host {
		return false
	}
	if f.IP != "" && !strings.HasPrefix(e.IP, f.IP) {
		return false
	}
	if f.Method != "" && !strings.EqualFold(e.Method, f.Method) {
		return false
	}
	if f.Status != "" && !statusMatch(f.Status, e.Status) {
		return false
	}
	if f.Path != "" && !strings.Contains(strings.ToLower(e.URI), strings.ToLower(f.Path)) {
		return false
	}
	if f.Agent != "" && !strings.Contains(strings.ToLower(e.Agent), strings.ToLower(f.Agent)) {
		return false
	}
	if f.Tag != "" && !contains(e.Tags, f.Tag) {
		return false
	}
	if f.MinMs > 0 && e.Duration < f.MinMs {
		return false
	}
	if f.Text != "" {
		t := strings.ToLower(f.Text)
		hay := strings.ToLower(e.Host + " " + e.URI + " " + e.IP + " " + e.Agent + " " + e.Referer + " " + e.Method)
		if !strings.Contains(hay, t) {
			return false
		}
	}
	return true
}

func statusMatch(spec string, status int) bool {
	s := strconv.Itoa(status)
	for _, part := range strings.Split(spec, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		switch {
		case part == "":
		case len(part) == 3 && strings.HasSuffix(part, "xx"):
			if s[0] == part[0] {
				return true
			}
		case part == s:
			return true
		}
	}
	return false
}

// Result is a query answer.
type Result struct {
	Entries []Entry        `json:"entries"`
	Matched int            `json:"matched"` // matches found while scanning (≥ len(Entries))
	Scanned int            `json:"scanned"` // access entries read
	Files   int            `json:"files"`   // files read
	Tags    map[string]int `json:"tags"`    // tag counts among the matches
	Partial bool           `json:"partial"` // stopped before reading everything
}

// Query returns the newest limit entries matching f, reading the current log
// and rotated copies until the limit is reached, the time window is passed or
// maxBytes of log have been read.
func Query(path string, f Filter, limit int, maxBytes int64) Result {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	if maxBytes <= 0 {
		maxBytes = 512 << 20
	}
	res := Result{Tags: map[string]int{}}
	var read int64
	for _, file := range Files(path) {
		// A rotated file only holds entries older than its mtime.
		if !f.From.IsZero() && !file.Current && file.ModTime.Before(f.From) {
			break
		}
		if read > maxBytes {
			res.Partial = true
			break
		}
		matches, matched, scanned, n := scanFile(file, f, limit-len(res.Entries), res.Tags)
		read += n
		res.Files++
		res.Scanned += scanned
		res.Matched += matched
		// Files are oldest-first inside; newest entries come from the end.
		for i := len(matches) - 1; i >= 0 && len(res.Entries) < limit; i-- {
			res.Entries = append(res.Entries, matches[i])
		}
		if len(res.Entries) >= limit {
			res.Partial = res.Partial || file.Current && len(Files(path)) > 1
			break
		}
	}
	if res.Entries == nil {
		res.Entries = []Entry{}
	}
	return res
}

// scanFile keeps only the newest keep matches (a ring), but counts all of
// them and their tags, so a broad filter on a big file stays cheap.
func scanFile(file File, f Filter, keep int, tags map[string]int) ([]Entry, int, int, int64) {
	fh, err := os.Open(file.Path)
	if err != nil {
		return nil, 0, 0, 0
	}
	defer fh.Close()
	var r io.Reader = fh
	if file.Compressed {
		gz, err := gzip.NewReader(fh)
		if err != nil {
			return nil, 0, 0, 0
		}
		defer gz.Close()
		r = gz
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	ring := make([]Entry, 0, keep)
	start, matched, scanned := 0, 0, 0
	var n int64
	for sc.Scan() {
		raw := sc.Bytes()
		n += int64(len(raw)) + 1
		e, ok := Parse(raw)
		if !ok {
			continue
		}
		scanned++
		if !f.match(e) {
			continue
		}
		matched++
		for _, t := range e.Tags {
			tags[t]++
		}
		switch {
		case keep <= 0:
		case len(ring) < keep:
			ring = append(ring, e)
		default:
			ring[start] = e
			start = (start + 1) % keep
		}
	}
	// Unroll the ring into chronological order.
	out := append(append([]Entry{}, ring[start:]...), ring[:start]...)
	return out, matched, scanned, n
}
