// Package importer converts other reverse-proxy configurations into
// caddyevolved sites and access lists.
//
// Every importer is best effort and says so: what maps cleanly becomes a
// structured site, what does not becomes a raw site or a warning. Nothing is
// written here; the API shows the result as a preview and applies the
// selection through the sites manager, where caddy validates each site.
package importer

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"caddyevolved/internal/sites"
)

// Formats the importer understands.
const (
	FormatCaddyfile = "caddyfile"
	FormatZoraxy    = "zoraxy"
	FormatTraefik   = "traefik"
	FormatNPM       = "npm"
)

// File is one uploaded file. Content is base64 so binary archives survive
// JSON transport.
type File struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// Candidate is one site the import proposes.
type Candidate struct {
	Site     sites.Site `json:"site"`
	Source   string     `json:"source"` // where it came from, e.g. "proxy/app.example.com.config"
	Warnings []string   `json:"warnings"`
	// Problems are validation errors; such a candidate cannot be applied
	// as is.
	Problems []string `json:"problems"`
}

// ACLCandidate is one access list the import proposes.
type ACLCandidate struct {
	AccessList sites.AccessList `json:"accessList"`
	Source     string           `json:"source"`
	Warnings   []string         `json:"warnings"`
}

// Result is the preview of one import.
type Result struct {
	Format      string         `json:"format"`
	Sites       []Candidate    `json:"sites"`
	AccessLists []ACLCandidate `json:"accessLists"`
	Warnings    []string       `json:"warnings"`
}

func (r *Result) warn(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// Run parses the files in the given format.
func Run(format string, files []File) (Result, error) {
	decoded, err := decodeFiles(files)
	if err != nil {
		return Result{}, err
	}
	res := Result{Format: format, Sites: []Candidate{}, AccessLists: []ACLCandidate{}, Warnings: []string{}}
	switch format {
	case FormatCaddyfile:
		importCaddyfile(&res, decoded)
	case FormatZoraxy:
		importZoraxy(&res, decoded)
	case FormatTraefik:
		if err := importTraefik(&res, decoded); err != nil {
			return res, err
		}
	case FormatNPM:
		if err := importNPM(&res, decoded); err != nil {
			return res, err
		}
	default:
		return res, fmt.Errorf("unbekanntes Format %q (caddyfile, zoraxy, traefik, npm)", format)
	}
	res.finish()
	return res, nil
}

// finish normalises every candidate, makes ids unique and records problems.
func (r *Result) finish() {
	taken := map[string]bool{}
	for i := range r.AccessLists {
		a := &r.AccessLists[i].AccessList
		a.ID = uniq(sites.Slug(firstNonEmpty(a.ID, a.Name)), taken)
		a.Normalize()
		if r.AccessLists[i].Warnings == nil {
			r.AccessLists[i].Warnings = []string{}
		}
	}
	taken = map[string]bool{}
	for i := range r.Sites {
		c := &r.Sites[i]
		if c.Site.ID == "" && len(c.Site.Domains) > 0 {
			c.Site.ID = sites.Slug(c.Site.Domains[0])
		}
		c.Site.ID = uniq(firstNonEmpty(c.Site.ID, "site"), taken)
		c.Site.Normalize()
		if err := c.Site.Validate(); err != nil {
			if v, ok := err.(*sites.ValidationError); ok {
				c.Problems = v.Problems
			} else {
				c.Problems = []string{err.Error()}
			}
		}
		if c.Warnings == nil {
			c.Warnings = []string{}
		}
		if c.Problems == nil {
			c.Problems = []string{}
		}
	}
	sort.SliceStable(r.Sites, func(i, j int) bool { return r.Sites[i].Site.ID < r.Sites[j].Site.ID })
}

func uniq(base string, taken map[string]bool) string {
	id := base
	for i := 2; taken[id]; i++ {
		id = fmt.Sprintf("%s-%d", base, i)
	}
	taken[id] = true
	return id
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// plainFile is a decoded upload; zip archives are expanded into their members.
type plainFile struct {
	Name string
	Data []byte
}

const maxUnzipped = 64 << 20

func decodeFiles(files []File) ([]plainFile, error) {
	var out []plainFile
	total := 0
	for _, f := range files {
		data, err := base64.StdEncoding.DecodeString(f.Content)
		if err != nil {
			return nil, fmt.Errorf("%s: kein gültiges base64", f.Name)
		}
		if strings.HasSuffix(strings.ToLower(f.Name), ".zip") || bytes.HasPrefix(data, []byte("PK\x03\x04")) {
			zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f.Name, err)
			}
			for _, zf := range zr.File {
				if zf.FileInfo().IsDir() {
					continue
				}
				rc, err := zf.Open()
				if err != nil {
					return nil, err
				}
				body, err := io.ReadAll(io.LimitReader(rc, maxUnzipped))
				rc.Close()
				if err != nil {
					return nil, err
				}
				total += len(body)
				if total > maxUnzipped {
					return nil, fmt.Errorf("%s: Archiv entpackt zu groß", f.Name)
				}
				out = append(out, plainFile{Name: path.Clean(zf.Name), Data: body})
			}
			continue
		}
		out = append(out, plainFile{Name: f.Name, Data: data})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("keine Dateien übergeben")
	}
	return out, nil
}

// upstreamFromURL turns "http://10.0.0.5:8080" into what reverse_proxy takes
// and reports a path, which reverse_proxy upstreams cannot carry.
func upstreamFromURL(raw string) (up string, tls bool, pathPart string) {
	raw = strings.TrimSpace(raw)
	scheme := ""
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme, raw = strings.ToLower(raw[:i]), raw[i+3:]
	}
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		raw, pathPart = raw[:i], raw[i:]
		if pathPart == "/" {
			pathPart = ""
		}
	}
	switch scheme {
	case "https":
		return "https://" + raw, true, pathPart
	case "h2c":
		return "h2c://" + raw, false, pathPart
	default:
		return raw, false, pathPart
	}
}
