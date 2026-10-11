// Package analytics turns caddy's JSON access log into traffic statistics.
//
// Every managed site logs to one shared file; a follower reads it like
// `tail -F` (surviving caddy's log rolling), and each request lands in a
// per-minute bucket per host. Minute buckets are kept for two days, hourly
// roll-ups for 35 days, and a snapshot on disk survives restarts. Top lists
// are kept per hour so a range query can merge them.
package analytics

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"caddyevolved/internal/accesslog"
)

const (
	minuteKeep  = 48 * time.Hour
	hourKeep    = 35 * 24 * time.Hour
	topKeep     = 200 // entries per top list per hour bucket
	recentKeep  = 300
	blockedKeep = 500
)

// Bucket aggregates requests of one host in one time slot.
type Bucket struct {
	Requests int64   `json:"requests"`
	S2xx     int64   `json:"s2xx"`
	S3xx     int64   `json:"s3xx"`
	S4xx     int64   `json:"s4xx"`
	S5xx     int64   `json:"s5xx"`
	Blocked  int64   `json:"blocked"` // 403 and 429: access list, WAF, bot filter, rate limit
	Bytes    int64   `json:"bytes"`   // sent to clients
	BytesIn  int64   `json:"bytesIn"` // received from clients (request bodies)
	DurSum   float64 `json:"durSum"`  // seconds
	DurMax   float64 `json:"durMax"`
	// Lat is a coarse latency histogram (ms upper bounds in latBounds).
	Lat [len(latBounds) + 1]int64 `json:"lat"`
}

var latBounds = [...]float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

func (b *Bucket) add(o *Bucket) {
	b.Requests += o.Requests
	b.S2xx += o.S2xx
	b.S3xx += o.S3xx
	b.S4xx += o.S4xx
	b.S5xx += o.S5xx
	b.Blocked += o.Blocked
	b.Bytes += o.Bytes
	b.BytesIn += o.BytesIn
	b.DurSum += o.DurSum
	b.DurMax = math.Max(b.DurMax, o.DurMax)
	for i := range b.Lat {
		b.Lat[i] += o.Lat[i]
	}
}

func (b *Bucket) record(status int, size, read int64, dur float64, blocked bool) {
	b.Requests++
	switch {
	case status >= 500:
		b.S5xx++
	case status >= 400:
		b.S4xx++
	case status >= 300:
		b.S3xx++
	default:
		b.S2xx++
	}
	if blocked || status == 403 || status == 429 {
		b.Blocked++
	}
	b.Bytes += size
	b.BytesIn += read
	b.DurSum += dur
	b.DurMax = math.Max(b.DurMax, dur)
	ms := dur * 1000
	i := sort.SearchFloat64s(latBounds[:], ms)
	b.Lat[i]++
}

// percentile estimates from the histogram (upper bound of the bucket).
func (b *Bucket) percentile(p float64) float64 {
	if b.Requests == 0 {
		return 0
	}
	want := int64(math.Ceil(float64(b.Requests) * p))
	var n int64
	for i, c := range b.Lat {
		n += c
		if n >= want {
			if i < len(latBounds) {
				return latBounds[i]
			}
			return b.DurMax * 1000
		}
	}
	return b.DurMax * 1000
}

// Top counts keys of one dimension.
type Top map[string]int64

func (t Top) inc(k string) {
	if k == "" {
		return
	}
	t[k]++
}

// trim keeps the n largest entries so memory stays bounded under scans.
func (t Top) trim(n int) {
	if len(t) <= n*2 {
		return
	}
	type kv struct {
		k string
		v int64
	}
	all := make([]kv, 0, len(t))
	for k, v := range t {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	for _, x := range all[n:] {
		delete(t, x.k)
	}
}

type hourTops struct {
	Paths    Top `json:"paths"`
	IPs      Top `json:"ips"`
	Agents   Top `json:"agents"`
	Status   Top `json:"status"`
	Referers Top `json:"referers"`
	Tags     Top `json:"tags"`
	// Blocks counts refusals by reason, BlockedIPs the refused clients.
	Blocks     Top `json:"blocks"`
	BlockedIPs Top `json:"blockedIps"`
}

func newTops() *hourTops {
	return &hourTops{Paths: Top{}, IPs: Top{}, Agents: Top{}, Status: Top{}, Referers: Top{}, Tags: Top{}, Blocks: Top{}, BlockedIPs: Top{}}
}

// Request is one entry of the live list.
type Request struct {
	TS       time.Time `json:"ts"`
	Host     string    `json:"host"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	Status   int       `json:"status"`
	Size     int64     `json:"size"`
	Duration float64   `json:"durationMs"`
	IP       string    `json:"ip"`
	Agent    string    `json:"agent,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
	Block    string    `json:"block,omitempty"`
}

// BlockReason names why a request was refused: the tag the firewall, access
// list or guard wrote, else a guess from the status. A plain 403 comes from
// a plugin that cannot tag (WAF, CrowdSec, bot filter) – or from the app.
func BlockReason(tag string, status int) string {
	switch {
	case tag != "":
		return tag
	case status == 429:
		return "ratelimit"
	case status == 403:
		return "403"
	}
	return ""
}

// Store holds all aggregates.
type Store struct {
	mu      sync.Mutex
	minutes map[int64]map[string]*Bucket // unix minute -> host -> bucket
	hours   map[int64]map[string]*Bucket // unix hour -> host -> bucket
	tops    map[int64]map[string]*hourTops
	recent  []Request
	blocked []Request
	offset  int64 // read position in the log, persisted
	inode   uint64
	snap    string
	// OnEntry sees every parsed entry, outside the lock (the auto-ban).
	// Set it before Follow starts.
	OnEntry func(accesslog.Entry)
}

// New loads a snapshot if one exists.
func New(snapshot string) *Store {
	s := &Store{
		minutes: map[int64]map[string]*Bucket{},
		hours:   map[int64]map[string]*Bucket{},
		tops:    map[int64]map[string]*hourTops{},
		snap:    snapshot,
	}
	s.load()
	return s
}

// logLine is the subset of caddy's access log we read.
// Ingest parses one log line; anything that is not an access entry is
// ignored, so the follower can read a mixed log safely.
func (s *Store) Ingest(line []byte) {
	e, ok := accesslog.Parse(line)
	if !ok {
		return
	}
	if s.OnEntry != nil {
		s.OnEntry(e)
	}
	ts, host, ip, path, agent := e.TS, e.Host, e.IP, e.Path, e.Agent
	if len(agent) > 200 {
		agent = agent[:200]
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	minute := ts.Unix() / 60
	hour := ts.Unix() / 3600
	bucket(s.minutes, minute, host).record(e.Status, e.Size, e.BytesRead, e.Duration/1000, e.Block != "")
	bucket(s.hours, hour, host).record(e.Status, e.Size, e.BytesRead, e.Duration/1000, e.Block != "")
	t := s.topsFor(hour, host)
	t.Paths.inc(path)
	t.IPs.inc(ip)
	t.Agents.inc(agent)
	t.Status.inc(itoa(e.Status))
	t.Referers.inc(refHost(e.Referer))
	for _, tag := range e.Tags {
		t.Tags.inc(tag)
	}
	if reason := BlockReason(e.Block, e.Status); reason != "" {
		t.Blocks.inc(reason)
		t.BlockedIPs.inc(ip)
	}
	s.recent = append(s.recent, Request{
		TS: ts, Host: host, Method: e.Method, URI: truncate(e.URI, 300), Status: e.Status,
		Size: e.Size, Duration: e.Duration, IP: ip, Agent: agent, Tags: e.Tags,
		Block: BlockReason(e.Block, e.Status),
	})
	if len(s.recent) > recentKeep {
		s.recent = s.recent[len(s.recent)-recentKeep:]
	}
	if req := s.recent[len(s.recent)-1]; req.Block != "" {
		s.blocked = append(s.blocked, req)
		if len(s.blocked) > blockedKeep {
			s.blocked = s.blocked[len(s.blocked)-blockedKeep:]
		}
	}
}

func bucket(m map[int64]map[string]*Bucket, slot int64, host string) *Bucket {
	hosts, ok := m[slot]
	if !ok {
		hosts = map[string]*Bucket{}
		m[slot] = hosts
	}
	b, ok := hosts[host]
	if !ok {
		b = &Bucket{}
		hosts[host] = b
	}
	return b
}

func (s *Store) topsFor(hour int64, host string) *hourTops {
	hosts, ok := s.tops[hour]
	if !ok {
		hosts = map[string]*hourTops{}
		s.tops[hour] = hosts
	}
	t, ok := hosts[host]
	if !ok {
		t = newTops()
		hosts[host] = t
	}
	// Snapshots from before tags existed load without the map.
	if t.Blocks == nil {
		t.Blocks, t.BlockedIPs = Top{}, Top{}
	}
	if t.Tags == nil {
		t.Tags = Top{}
	}
	return t
}

// Point is one sample of a time series.
type Point struct {
	T time.Time `json:"t"`
	Bucket
	AvgMs float64 `json:"avgMs"`
	P95Ms float64 `json:"p95Ms"`
}

// Entry is one row of a top list.
type Entry struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// Report answers one dashboard query.
type Report struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Step   string    `json:"step"`
	Series []Point   `json:"series"`
	Totals Point     `json:"totals"`
	Hosts  []Entry   `json:"hosts"`
	// Traffic is bytes per site, largest first.
	Traffic []HostTraffic      `json:"traffic"`
	Top     map[string][]Entry `json:"top"`
}

// Query aggregates the range ending now. hosts filters (empty = all).
// Ranges up to 6h use minute buckets, longer ones hourly buckets.
func (s *Store) Query(rng time.Duration, hosts []string) Report {
	now := time.Now().UTC()
	from := now.Add(-rng)
	filter := map[string]bool{}
	for _, h := range hosts {
		filter[strings.ToLower(h)] = true
	}
	match := func(h string) bool { return len(filter) == 0 || filter[h] }

	s.mu.Lock()
	defer s.mu.Unlock()

	src, step, unit := s.hours, "1h", int64(3600)
	if rng <= 6*time.Hour {
		src, step, unit = s.minutes, "1m", 60
	}
	start, end := from.Unix()/unit, now.Unix()/unit
	rep := Report{From: from, To: now, Step: step, Top: map[string][]Entry{}}
	var total Bucket
	perHost := map[string]int64{}
	traffic := map[string]*HostTraffic{}
	for slot := start; slot <= end; slot++ {
		var b Bucket
		for h, hb := range src[slot] {
			if match(h) {
				b.add(hb)
				perHost[h] += hb.Requests
				ht := traffic[h]
				if ht == nil {
					ht = &HostTraffic{Host: h}
					traffic[h] = ht
				}
				ht.Requests += hb.Requests
				ht.BytesOut += hb.Bytes
				ht.BytesIn += hb.BytesIn
			}
		}
		total.add(&b)
		rep.Series = append(rep.Series, point(time.Unix(slot*unit, 0).UTC(), b))
	}
	rep.Totals = point(from, total)
	rep.Hosts = topN(Top(perHost), 50)
	for _, ht := range traffic {
		rep.Traffic = append(rep.Traffic, *ht)
	}
	sort.Slice(rep.Traffic, func(i, j int) bool {
		return rep.Traffic[i].BytesOut+rep.Traffic[i].BytesIn > rep.Traffic[j].BytesOut+rep.Traffic[j].BytesIn
	})

	merged := newTops()
	for hour := from.Unix() / 3600; hour <= now.Unix()/3600; hour++ {
		for h, t := range s.tops[hour] {
			if !match(h) {
				continue
			}
			mergeTop(merged.Paths, t.Paths)
			mergeTop(merged.IPs, t.IPs)
			mergeTop(merged.Agents, t.Agents)
			mergeTop(merged.Status, t.Status)
			mergeTop(merged.Referers, t.Referers)
			mergeTop(merged.Tags, t.Tags)
			mergeTop(merged.Blocks, t.Blocks)
			mergeTop(merged.BlockedIPs, t.BlockedIPs)
		}
	}
	rep.Top["paths"] = topN(merged.Paths, 15)
	rep.Top["ips"] = topN(merged.IPs, 15)
	rep.Top["agents"] = topN(merged.Agents, 10)
	rep.Top["status"] = topN(merged.Status, 20)
	rep.Top["referers"] = topN(merged.Referers, 10)
	rep.Top["tags"] = topN(merged.Tags, 10)
	rep.Top["blocks"] = topN(merged.Blocks, 15)
	rep.Top["blockedIps"] = topN(merged.BlockedIPs, 15)
	return rep
}

func point(t time.Time, b Bucket) Point {
	p := Point{T: t, Bucket: b, P95Ms: b.percentile(0.95)}
	if b.Requests > 0 {
		p.AvgMs = math.Round(b.DurSum/float64(b.Requests)*100000) / 100
	}
	return p
}

// RecentBlocked returns the newest refused requests, newest first. They are
// kept apart from the general list, which busy sites flush within seconds.
func (s *Store) RecentBlocked(limit int) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Request{}
	for i := len(s.blocked) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.blocked[i])
	}
	return out
}

// Recent returns the newest requests, newest first.
func (s *Store) Recent(limit int, hosts []string) []Request {
	filter := map[string]bool{}
	for _, h := range hosts {
		filter[strings.ToLower(h)] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Request{}
	for i := len(s.recent) - 1; i >= 0 && len(out) < limit; i-- {
		if len(filter) == 0 || filter[s.recent[i].Host] {
			out = append(out, s.recent[i])
		}
	}
	return out
}

func mergeTop(dst, src Top) {
	for k, v := range src {
		dst[k] += v
	}
}

func topN(t Top, n int) []Entry {
	out := make([]Entry, 0, len(t))
	for k, v := range t {
		out = append(out, Entry{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// prune drops old buckets and trims top lists.
func (s *Store) prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for m := range s.minutes {
		if time.Unix(m*60, 0).Before(now.Add(-minuteKeep)) {
			delete(s.minutes, m)
		}
	}
	for h := range s.hours {
		if time.Unix(h*3600, 0).Before(now.Add(-hourKeep)) {
			delete(s.hours, h)
			delete(s.tops, h)
		}
	}
	for _, hosts := range s.tops {
		for _, t := range hosts {
			t.Paths.trim(topKeep)
			t.IPs.trim(topKeep)
			t.Agents.trim(topKeep)
			t.Referers.trim(topKeep)
		}
	}
}

type snapshot struct {
	Minutes map[int64]map[string]*Bucket   `json:"minutes"`
	Hours   map[int64]map[string]*Bucket   `json:"hours"`
	Tops    map[int64]map[string]*hourTops `json:"tops"`
	Offset  int64                          `json:"offset"`
	Inode   uint64                         `json:"inode"`
	Blocked []Request                      `json:"blocked,omitempty"`
}

func (s *Store) load() {
	data, err := os.ReadFile(s.snap)
	if err != nil {
		return
	}
	var sn snapshot
	if json.Unmarshal(data, &sn) != nil {
		return
	}
	if sn.Minutes != nil {
		s.minutes = sn.Minutes
	}
	if sn.Hours != nil {
		s.hours = sn.Hours
	}
	if sn.Tops != nil {
		s.tops = sn.Tops
	}
	s.offset, s.inode = sn.Offset, sn.Inode
	s.blocked = sn.Blocked
}

// Save writes the snapshot atomically.
func (s *Store) Save() error {
	s.mu.Lock()
	data, err := json.Marshal(snapshot{Minutes: s.minutes, Hours: s.hours, Tops: s.tops, Offset: s.offset, Inode: s.inode, Blocked: s.blocked})
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.snap), 0o750); err != nil {
		return err
	}
	tmp := s.snap + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.snap)
}

// Follow reads the log until ctx ends. It resumes at the stored offset when
// the file is the same one (inode), starts over after a roll or truncation,
// and polls once a second: no inotify dependency, and the volume of an
// access log on a homelab proxy is small.
func (s *Store) Follow(ctx context.Context, path string) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	save := time.NewTicker(time.Minute)
	defer save.Stop()
	var f *os.File
	var rd *bufio.Reader
	defer func() {
		if f != nil {
			f.Close()
		}
		s.Save()
	}()
	for {
		if f == nil {
			if nf, err := os.Open(path); err == nil {
				ino := inodeOf(nf)
				s.mu.Lock()
				if ino != s.inode {
					s.offset, s.inode = 0, ino
				}
				off := s.offset
				s.mu.Unlock()
				if st, err := nf.Stat(); err == nil && st.Size() < off {
					off = 0 // truncated
				}
				nf.Seek(off, io.SeekStart)
				f, rd = nf, bufio.NewReaderSize(nf, 256<<10)
			}
		}
		if f != nil {
			for {
				line, err := rd.ReadBytes('\n')
				if len(line) > 0 && line[len(line)-1] == '\n' {
					s.Ingest(line)
					s.mu.Lock()
					s.offset += int64(len(line))
					s.mu.Unlock()
					continue
				}
				if len(line) > 0 {
					// Partial line: rewind and wait for the rest.
					f.Seek(-int64(len(line)), io.SeekCurrent)
					rd.Reset(f)
				}
				_ = err
				break
			}
			// A rolled log is a new file under the same name.
			if st, err := os.Stat(path); err == nil {
				if ino := inodeOfInfo(st); ino != 0 && ino != inodeOf(f) {
					f.Close()
					f = nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-save.C:
			s.prune()
			s.Save()
		case <-tick.C:
		}
	}
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func refHost(ref string) string {
	if ref == "" {
		return ""
	}
	rest := ref
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	return strings.ToLower(rest)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// HostTraffic is the volume of one site in a range.
type HostTraffic struct {
	Host     string `json:"host"`
	Requests int64  `json:"requests"`
	BytesOut int64  `json:"bytesOut"`
	BytesIn  int64  `json:"bytesIn"`
}
