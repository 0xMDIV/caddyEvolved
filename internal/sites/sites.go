// Package sites manages reverse-proxy sites as one Caddyfile snippet each.
//
// The structured definitions live in sites.json; every enabled site is
// rendered to <sitesDir>/<id>.caddy, which the main Caddyfile pulls in with
// one import line. A change is applied as a transaction: files are written,
// the caller validates and reloads, and on failure the previous files come
// back. The main Caddyfile stays hand-editable around the import.
package sites

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Modes a site can have.
const (
	ModeProxy    = "proxy"
	ModeRedirect = "redirect"
	ModeStatic   = "static"
	ModeRaw      = "raw"
)

// TLS settings.
const (
	TLSAuto     = "auto"
	TLSInternal = "internal"
	TLSDNS      = "dns"
	TLSOff      = "off"
)

// Site is one virtual host.
type Site struct {
	ID               string     `json:"id"`
	Domains          []string   `json:"domains"`
	Mode             string     `json:"mode"`
	Upstreams        []string   `json:"upstreams,omitempty"`
	UpstreamTLS      bool       `json:"upstreamTls,omitempty"`
	UpstreamInsecure bool       `json:"upstreamInsecure,omitempty"`
	LBPolicy         string     `json:"lbPolicy,omitempty"`
	HealthURI        string     `json:"healthUri,omitempty"`
	TLS              string     `json:"tls"`
	DNSProvider      string     `json:"dnsProvider,omitempty"`
	Compress         bool       `json:"compress"`
	RedirectTo       string     `json:"redirectTo,omitempty"`
	Root             string     `json:"root,omitempty"`
	Extra            string     `json:"extra,omitempty"`
	Raw              string     `json:"raw,omitempty"`
	AccessList       string     `json:"accessList,omitempty"`
	NoLog            bool       `json:"noLog,omitempty"`
	WAF              *WAF       `json:"waf,omitempty"`
	Defender         *Defender  `json:"defender,omitempty"`
	RateLimit        *RateLimit `json:"rateLimit,omitempty"`
	Enabled          bool       `json:"enabled"`
	UpdatedAt        time.Time  `json:"updatedAt,omitzero"`
}

// Commit validates and activates the files on disk. It returns caddy's output
// so a rejection can be shown verbatim.
type Commit func(ctx context.Context) (output string, err error)

// ErrInvalid wraps a configuration caddy rejected; Output is caddy's message.
type ErrInvalid struct {
	Output string
	Err    error
}

func (e *ErrInvalid) Error() string { return "Konfiguration abgelehnt: " + e.Err.Error() }
func (e *ErrInvalid) Unwrap() error { return e.Err }

// Manager owns sites.json and the snippet directory.
type Manager struct {
	file      string
	dir       string
	caddyfile string
	opt       Options
	mu        sync.Mutex
}

// New points at the definitions file, the snippet dir and the main Caddyfile.
func New(file, dir, caddyfile string) *Manager {
	return &Manager{file: file, dir: dir, caddyfile: caddyfile}
}

// SetOptions changes host-wide rendering; the next change re-renders all
// sites with it (call Sync to apply immediately).
func (m *Manager) SetOptions(o Options) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.opt = o
}

// Options returns the current rendering options.
func (m *Manager) Options() Options {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.opt
}

// NeedsSync reports whether any snippet on disk differs from what the
// current definitions and options render, e.g. after an upgrade that added
// request logging.
func (m *Manager) NeedsSync() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, err := m.loadDoc()
	if err != nil {
		return false
	}
	for _, s := range doc.Sites {
		if !s.Enabled {
			continue
		}
		data, err := os.ReadFile(filepath.Join(m.dir, s.ID+".caddy"))
		if err != nil || string(data) != RenderWith(s, doc.acl(s.AccessList), m.opt) {
			return true
		}
	}
	return false
}

// PreviewFor renders a site with the stored access list and options.
func (m *Manager) PreviewFor(s Site) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, _ := m.loadDoc()
	return RenderWith(s, doc.acl(s.AccessList), m.opt)
}

// Dir is the snippet directory.
func (m *Manager) Dir() string { return m.dir }

// ImportLine is what the main Caddyfile must contain.
func (m *Manager) ImportLine() string { return "import " + filepath.ToSlash(m.dir) + "/*.caddy" }

// List returns the stored sites sorted by id.
func (m *Manager) List() ([]Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.load()
}

// Get returns one site.
func (m *Manager) Get(id string) (Site, error) {
	list, err := m.List()
	if err != nil {
		return Site{}, err
	}
	for _, s := range list {
		if s.ID == id {
			return s, nil
		}
	}
	return Site{}, fmt.Errorf("Site %q: %w", id, os.ErrNotExist)
}

// ImportOK reports whether the main Caddyfile pulls in the snippets.
func (m *Manager) ImportOK() bool {
	data, err := os.ReadFile(m.caddyfile)
	if err != nil {
		return false
	}
	return HasImport(string(data), m.ImportLine())
}

// HasImport reports whether content contains line as a directive of its own.
func HasImport(content, line string) bool {
	for _, l := range strings.Split(content, "\n") {
		if strings.TrimSpace(l) == line {
			return true
		}
	}
	return false
}

// Upsert creates or replaces a site. create=true refuses an existing id.
func (m *Manager) Upsert(ctx context.Context, s Site, create bool, commit Commit) (Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	list, err := m.load()
	if err != nil {
		return Site{}, err
	}
	if s.ID == "" {
		s.ID = uniqueID(Slug(firstOr(s.Domains, "site")), list)
	}
	s.Normalize()
	if err := s.Validate(); err != nil {
		return Site{}, err
	}
	idx := -1
	for i, x := range list {
		if x.ID == s.ID {
			idx = i
		}
	}
	if create && idx >= 0 {
		return Site{}, &ValidationError{Problems: []string{fmt.Sprintf("Site %q existiert bereits", s.ID)}}
	}
	if !create && idx < 0 {
		return Site{}, fmt.Errorf("Site %q: %w", s.ID, os.ErrNotExist)
	}
	s.UpdatedAt = time.Now().UTC()
	next := append([]Site(nil), list...)
	if idx >= 0 {
		next[idx] = s
	} else {
		next = append(next, s)
	}
	if err := checkDuplicates(next); err != nil {
		return Site{}, err
	}
	if err := m.apply(ctx, list, next, commit); err != nil {
		return Site{}, err
	}
	return s, nil
}

// Delete removes a site.
func (m *Manager) Delete(ctx context.Context, id string, commit Commit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	list, err := m.load()
	if err != nil {
		return err
	}
	next := make([]Site, 0, len(list))
	found := false
	for _, s := range list {
		if s.ID == id {
			found = true
			continue
		}
		next = append(next, s)
	}
	if !found {
		return fmt.Errorf("Site %q: %w", id, os.ErrNotExist)
	}
	return m.apply(ctx, list, next, commit)
}

// SetEnabled switches a site on or off without touching its definition.
func (m *Manager) SetEnabled(ctx context.Context, id string, enabled bool, commit Commit) (Site, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	list, err := m.load()
	if err != nil {
		return Site{}, err
	}
	next := append([]Site(nil), list...)
	for i := range next {
		if next[i].ID != id {
			continue
		}
		next[i].Enabled = enabled
		next[i].UpdatedAt = time.Now().UTC()
		if err := checkDuplicates(next); err != nil {
			return Site{}, err
		}
		if err := m.apply(ctx, list, next, commit); err != nil {
			return Site{}, err
		}
		return next[i], nil
	}
	return Site{}, fmt.Errorf("Site %q: %w", id, os.ErrNotExist)
}

// Sync rewrites every snippet from sites.json and makes sure the import line
// exists, e.g. right after an install.
func (m *Manager) Sync(ctx context.Context, commit Commit) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	list, err := m.load()
	if err != nil {
		return err
	}
	return m.apply(ctx, list, list, commit)
}

// apply replaces the site list and keeps the access lists as they are.
func (m *Manager) apply(ctx context.Context, prev, next []Site, commit Commit) error {
	doc, err := m.loadDoc()
	if err != nil {
		return err
	}
	before, after := doc, doc
	before.Sites, after.Sites = prev, next
	return m.applyDoc(ctx, before, after, commit)
}

// applyDoc writes next, ensures the import line, commits, and restores prev
// on any failure. The caller holds m.mu.
func (m *Manager) applyDoc(ctx context.Context, prev, next document, commit Commit) error {
	if err := next.checkRefs(); err != nil {
		return err
	}
	if err := ensureDir(m.dir); err != nil {
		return err
	}
	backup, err := snapshotDir(m.dir)
	if err != nil {
		return err
	}
	mainBefore, mainErr := os.ReadFile(m.caddyfile)

	restore := func() {
		restoreDir(m.dir, backup)
		if mainErr == nil {
			writeAtomic(m.caddyfile, mainBefore, 0o644)
		}
		m.saveDoc(prev)
	}

	if err := m.writeSnippets(next); err != nil {
		restore()
		return err
	}
	if err := m.ensureImport(); err != nil {
		restore()
		return err
	}
	if err := m.saveDoc(next); err != nil {
		restore()
		return err
	}
	if commit != nil {
		if out, err := commit(ctx); err != nil {
			restore()
			return &ErrInvalid{Output: out, Err: err}
		}
	}
	return nil
}

func (m *Manager) writeSnippets(doc document) error {
	want := map[string][]byte{}
	for _, s := range doc.Sites {
		if !s.Enabled {
			continue
		}
		want[s.ID+".caddy"] = []byte(RenderWith(s, doc.acl(s.AccessList), m.opt))
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".caddy") {
			continue
		}
		if _, ok := want[e.Name()]; !ok {
			if err := os.Remove(filepath.Join(m.dir, e.Name())); err != nil {
				return err
			}
		}
	}
	for name, data := range want {
		if err := writeAtomic(filepath.Join(m.dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// ensureImport appends the import line once. It goes at the end so the
// global options block stays first, which caddy requires.
func (m *Manager) ensureImport() error {
	data, err := os.ReadFile(m.caddyfile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	content := string(data)
	if HasImport(content, m.ImportLine()) {
		return nil
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += "\n# Sites aus der caddyforge-WebUI (eine Datei pro Site)\n" + m.ImportLine() + "\n"
	return writeAtomic(m.caddyfile, []byte(content), 0o644)
}

// document is the content of sites.json.
type document struct {
	Schema      int          `json:"schema"`
	Sites       []Site       `json:"sites"`
	AccessLists []AccessList `json:"accessLists"`
}

func (d document) acl(id string) *AccessList {
	if id == "" {
		return nil
	}
	for i := range d.AccessLists {
		if d.AccessLists[i].ID == id {
			return &d.AccessLists[i]
		}
	}
	return nil
}

// checkRefs refuses a site that points at a missing access list; rendering it
// without the list would silently open the site.
func (d document) checkRefs() error {
	for _, s := range d.Sites {
		if s.AccessList != "" && d.acl(s.AccessList) == nil {
			return &ValidationError{Problems: []string{fmt.Sprintf("Site %s: Access List %q existiert nicht", s.ID, s.AccessList)}}
		}
	}
	return nil
}

func (m *Manager) load() ([]Site, error) {
	doc, err := m.loadDoc()
	return doc.Sites, err
}

func (m *Manager) loadDoc() (document, error) {
	doc := document{Sites: []Site{}, AccessLists: []AccessList{}}
	data, err := os.ReadFile(m.file)
	if errors.Is(err, os.ErrNotExist) {
		return doc, nil
	}
	if err != nil {
		return doc, err
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return doc, fmt.Errorf("%s: %w", m.file, err)
	}
	if doc.Sites == nil {
		doc.Sites = []Site{}
	}
	if doc.AccessLists == nil {
		doc.AccessLists = []AccessList{}
	}
	sort.Slice(doc.Sites, func(i, j int) bool { return doc.Sites[i].ID < doc.Sites[j].ID })
	sort.Slice(doc.AccessLists, func(i, j int) bool { return doc.AccessLists[i].ID < doc.AccessLists[j].ID })
	return doc, nil
}

func (m *Manager) saveDoc(doc document) error {
	doc.Schema = 2
	if doc.Sites == nil {
		doc.Sites = []Site{}
	}
	if doc.AccessLists == nil {
		doc.AccessLists = []AccessList{}
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.file), 0o750); err != nil {
		return err
	}
	return writeAtomic(m.file, append(data, '\n'), 0o640)
}

func snapshotDir(dir string) (map[string][]byte, error) {
	out := map[string][]byte{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out[e.Name()] = data
	}
	return out, nil
}

func restoreDir(dir string, files map[string][]byte) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if _, ok := files[e.Name()]; !ok && !e.IsDir() {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
	for name, data := range files {
		writeAtomic(filepath.Join(dir, name), data, 0o644)
	}
}

// writeAtomic sets the mode explicitly: the daemon runs with UMask=0077, and
// caddy, running as its own user, must still read the snippets.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".caddyforge-tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// ensureDir creates dir world-traversable for the same reason.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.Chmod(dir, 0o755)
}

// WriteInitial stores one site and its snippet without touching the main
// Caddyfile or reloading anything; the installer validates afterwards.
func WriteInitial(file, dir string, s Site) error {
	m := New(file, dir, "")
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, err := m.loadDoc()
	if err != nil {
		return err
	}
	s.Normalize()
	if err := s.Validate(); err != nil {
		return err
	}
	replaced := false
	for i := range doc.Sites {
		if doc.Sites[i].ID == s.ID {
			doc.Sites[i], replaced = s, true
		}
	}
	if !replaced {
		doc.Sites = append(doc.Sites, s)
	}
	if err := checkDuplicates(doc.Sites); err != nil {
		return err
	}
	if err := ensureDir(dir); err != nil {
		return err
	}
	if err := m.writeSnippets(doc); err != nil {
		return err
	}
	return m.saveDoc(doc)
}
