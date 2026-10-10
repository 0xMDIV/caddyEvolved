package importer

import (
	"strings"

	"caddyevolved/internal/sites"
)

// block is one top-level Caddyfile block.
type block struct {
	header string
	body   string
}

// splitBlocks finds top-level blocks while honouring quotes, backtick
// strings and comments, so a brace inside a string does not end a block.
func splitBlocks(src string) (blocks []block, loose []string) {
	var (
		depth   int
		header  strings.Builder
		body    strings.Builder
		inQuote rune
		comment bool
		escaped bool
	)
	flushLoose := func() {
		for _, l := range strings.Split(header.String(), "\n") {
			if t := strings.TrimSpace(l); t != "" {
				loose = append(loose, t)
			}
		}
		header.Reset()
	}
	for _, r := range src {
		if comment {
			if r == '\n' {
				comment = false
				if depth == 0 {
					header.WriteRune(r)
				} else {
					body.WriteRune(r)
				}
			} else if depth > 0 {
				body.WriteRune(r)
			}
			continue
		}
		if inQuote != 0 {
			if depth > 0 {
				body.WriteRune(r)
			} else {
				header.WriteRune(r)
			}
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' && inQuote == '"' {
				escaped = true
			} else if r == inQuote {
				inQuote = 0
			}
			continue
		}
		switch r {
		case '#':
			comment = true
			if depth > 0 {
				body.WriteRune(r)
			}
			continue
		case '"', '`':
			inQuote = r
		case '{':
			depth++
			if depth == 1 {
				// The header is the last non-empty line before the brace;
				// earlier lines are loose top-level directives.
				h := header.String()
				lines := strings.Split(strings.TrimRight(h, " \t"), "\n")
				last := strings.TrimSpace(lines[len(lines)-1])
				header.Reset()
				header.WriteString(strings.Join(lines[:len(lines)-1], "\n"))
				flushLoose()
				header.WriteString(last)
				continue
			}
		case '}':
			depth--
			if depth == 0 {
				blocks = append(blocks, block{header: strings.TrimSpace(header.String()), body: body.String()})
				header.Reset()
				body.Reset()
				continue
			}
		}
		if depth > 0 {
			body.WriteRune(r)
		} else {
			header.WriteRune(r)
		}
	}
	flushLoose()
	return blocks, loose
}

func importCaddyfile(res *Result, files []plainFile) {
	for _, f := range files {
		blocks, loose := splitBlocks(string(f.Data))
		for _, l := range loose {
			res.warn("%s: Zeile außerhalb eines Blocks übersprungen: %s", f.Name, l)
		}
		for _, b := range blocks {
			switch {
			case b.header == "":
				res.warn("%s: globaler Optionsblock nicht übernommen – Optionen bei Bedarf im Caddyfile-Editor ergänzen", f.Name)
				continue
			case strings.HasPrefix(b.header, "("):
				res.warn("%s: Snippet %s nicht übernommen – Sites, die es importieren, werden abgelehnt", f.Name, b.header)
				continue
			}
			res.Sites = append(res.Sites, siteFromBlock(f.Name, b))
		}
	}
}

// siteFromBlock maps a site block to a structured site where the body is
// simple enough, and to a raw site otherwise.
func siteFromBlock(source string, b block) Candidate {
	c := Candidate{Source: source + ": " + b.header}
	s := sites.Site{Mode: sites.ModeRaw, TLS: sites.TLSAuto, Enabled: true}
	httpOnly := true
	for _, addr := range strings.FieldsFunc(b.header, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		a := addr
		switch {
		case strings.HasPrefix(a, "http://"):
			a = strings.TrimPrefix(a, "http://")
		case strings.HasPrefix(a, "https://"):
			a = strings.TrimPrefix(a, "https://")
			httpOnly = false
		default:
			httpOnly = false
		}
		if i := strings.IndexByte(a, '/'); i >= 0 {
			c.Warnings = append(c.Warnings, "Adresse "+addr+" enthält einen Pfad – nur der Host wird übernommen")
			a = a[:i]
		}
		if a != "" {
			s.Domains = append(s.Domains, a)
		}
	}
	if httpOnly {
		s.TLS = sites.TLSOff
	}

	var directives []string
	for _, l := range strings.Split(b.body, "\n") {
		t := strings.TrimSpace(l)
		if t != "" && !strings.HasPrefix(t, "#") {
			directives = append(directives, t)
		}
	}
	simple := true
	for _, d := range directives {
		f := strings.Fields(d)
		switch {
		case f[0] == "reverse_proxy" && len(f) > 1 && !strings.HasSuffix(d, "{") && !strings.HasPrefix(f[1], "@") && !strings.HasPrefix(f[1], "/") && s.Upstreams == nil:
			s.Upstreams = f[1:]
		case f[0] == "encode":
			s.Compress = true
		case d == "tls internal":
			s.TLS = sites.TLSInternal
		case f[0] == "tls" && len(f) == 2 && strings.Contains(f[1], "@"):
			// a per-site ACME email; the global one applies instead
		default:
			simple = false
		}
	}
	if simple && len(s.Upstreams) > 0 {
		s.Mode = sites.ModeProxy
	} else {
		s.Upstreams = nil
		s.Mode = sites.ModeRaw
		s.Compress = false
		s.Raw = dedent(b.body)
		c.Warnings = append(c.Warnings, "als Raw-Site übernommen – Inhalt unverändert, caddy prüft ihn beim Anlegen")
	}
	c.Site = s
	return c
}

// dedent strips the common leading indentation of a block body.
func dedent(body string) string {
	lines := strings.Split(strings.Trim(body, "\n"), "\n")
	prefix := ""
	first := true
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		ind := l[:len(l)-len(strings.TrimLeft(l, " \t"))]
		if first || !strings.HasPrefix(ind, prefix) {
			if first {
				prefix = ind
			} else {
				for !strings.HasPrefix(ind, prefix) {
					prefix = prefix[:len(prefix)-1]
				}
			}
			first = false
		}
	}
	for i, l := range lines {
		lines[i] = strings.TrimPrefix(l, prefix)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
