package sites

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"caddyforge/internal/plugins"
)

// Normalize trims input and fills defaults.
func (s *Site) Normalize() {
	s.ID = strings.TrimSpace(strings.ToLower(s.ID))
	s.Domains = cleanList(s.Domains)
	s.Upstreams = cleanList(s.Upstreams)
	if s.Mode == "" {
		s.Mode = ModeProxy
	}
	if s.TLS == "" {
		s.TLS = TLSAuto
	}
	s.LBPolicy = strings.TrimSpace(s.LBPolicy)
	s.HealthURI = strings.TrimSpace(s.HealthURI)
	s.RedirectTo = strings.TrimSpace(s.RedirectTo)
	s.Root = strings.TrimSpace(s.Root)
	s.DNSProvider = strings.TrimSpace(s.DNSProvider)
	s.Extra = normText(s.Extra)
	s.Raw = normText(s.Raw)
}

func normText(s string) string {
	return strings.TrimRight(strings.ReplaceAll(s, "\r\n", "\n"), " \t\r\n")
}

var (
	reID       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	reDomain   = regexp.MustCompile(`^((\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)?(:[0-9]{1,5})?$`)
	reUpstream = regexp.MustCompile(`^(https?://|h2c://)?[A-Za-z0-9._\-\[\]:]+$`)
	reLB       = regexp.MustCompile(`^(random|round_robin|least_conn|first|ip_hash|uri_hash|client_ip_hash|header [A-Za-z0-9-]+|cookie [A-Za-z0-9_-]+)?$`)
	rePath     = regexp.MustCompile(`^/[A-Za-z0-9._~/%-]*$`)
)

// Validate checks every structured field. These values are written into a
// Caddyfile verbatim, so anything that could open a block or start another
// directive is refused rather than escaped. Extra and Raw are expert fields
// whose content caddy itself validates before anything goes live.
func (s Site) Validate() error {
	var problems []string
	if !reID.MatchString(s.ID) {
		problems = append(problems, "ID: nur a-z, 0-9 und Bindestrich, max. 63 Zeichen")
	}
	if len(s.Domains) == 0 {
		problems = append(problems, "mindestens eine Domain (oder :Port) angeben")
	}
	for _, d := range s.Domains {
		if d == "" || !reDomain.MatchString(d) {
			problems = append(problems, fmt.Sprintf("Domain %q ungültig (ohne http://, z. B. app.example.com oder :8080)", d))
		}
	}
	switch s.TLS {
	case TLSAuto, TLSInternal, TLSOff:
	case TLSDNS:
		if e, ok := plugins.ByID(s.DNSProvider); !ok || e.Category != plugins.CatDNS {
			problems = append(problems, "TLS per DNS braucht ein DNS-Plugin aus dem Katalog")
		}
	default:
		problems = append(problems, "TLS: auto, internal, dns oder off")
	}
	switch s.Mode {
	case ModeProxy:
		if len(s.Upstreams) == 0 {
			problems = append(problems, "mindestens ein Ziel (Upstream) angeben, z. B. 192.168.1.10:8080")
		}
		for _, u := range s.Upstreams {
			if !reUpstream.MatchString(u) {
				problems = append(problems, fmt.Sprintf("Ziel %q ungültig (host:port oder http(s)://host:port, ohne Pfad)", u))
			}
		}
		if !reLB.MatchString(s.LBPolicy) {
			problems = append(problems, "Load-Balancing-Policy unbekannt")
		}
		if s.HealthURI != "" && !rePath.MatchString(s.HealthURI) {
			problems = append(problems, "Health-Check-Pfad muss mit / beginnen")
		}
	case ModeRedirect:
		u, err := url.Parse(s.RedirectTo)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(s.RedirectTo, " \t\n{}\"") {
			problems = append(problems, "Weiterleitungsziel muss eine URL wie https://neu.example.com sein")
		}
	case ModeStatic:
		if !strings.HasPrefix(s.Root, "/") || strings.ContainsAny(s.Root, " \t\n{}\"") || strings.Contains(s.Root, "..") {
			problems = append(problems, "Verzeichnis muss ein absoluter Pfad ohne Leerzeichen sein")
		}
	case ModeRaw:
		if strings.TrimSpace(s.Raw) == "" {
			problems = append(problems, "Raw-Modus braucht Inhalt")
		}
	default:
		problems = append(problems, "Modus: proxy, redirect, static oder raw")
	}
	if !balanced(s.Extra) || !balanced(s.Raw) {
		problems = append(problems, "geschweifte Klammern in Zusatz/Raw sind nicht ausgeglichen")
	}
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

// ValidationError lists every field problem at once.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string { return strings.Join(e.Problems, "; ") }

// Render produces the snippet for one site.
func Render(s Site) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s – verwaltet von caddyforge. Änderungen über die WebUI, sonst überschrieben.\n", s.ID)
	addrs := make([]string, 0, len(s.Domains))
	for _, d := range s.Domains {
		if s.TLS == TLSOff && !strings.HasPrefix(d, ":") {
			d = "http://" + d
		}
		addrs = append(addrs, d)
	}
	fmt.Fprintf(&b, "%s {\n", strings.Join(addrs, ", "))

	switch s.TLS {
	case TLSInternal:
		b.WriteString("\ttls internal\n")
	case TLSDNS:
		if e, ok := plugins.ByID(s.DNSProvider); ok {
			b.WriteString(plugins.DNSTLSBlock(e))
		}
	}
	if s.Compress && s.Mode != ModeRedirect {
		b.WriteString("\tencode zstd gzip\n")
	}

	switch s.Mode {
	case ModeProxy:
		fmt.Fprintf(&b, "\treverse_proxy %s", strings.Join(s.Upstreams, " "))
		var opts []string
		if s.LBPolicy != "" {
			opts = append(opts, "lb_policy "+s.LBPolicy)
		}
		if s.HealthURI != "" {
			opts = append(opts, "health_uri "+s.HealthURI)
		}
		if s.UpstreamTLS || s.UpstreamInsecure {
			t := "transport http {\n\t\t\ttls\n"
			if s.UpstreamInsecure {
				t += "\t\t\ttls_insecure_skip_verify\n"
			}
			t += "\t\t}"
			opts = append(opts, t)
		}
		if len(opts) == 0 {
			b.WriteString("\n")
		} else {
			b.WriteString(" {\n")
			for _, o := range opts {
				b.WriteString("\t\t" + o + "\n")
			}
			b.WriteString("\t}\n")
		}
	case ModeRedirect:
		fmt.Fprintf(&b, "\tredir %s{uri} permanent\n", strings.TrimRight(s.RedirectTo, "/"))
	case ModeStatic:
		fmt.Fprintf(&b, "\troot * %s\n\tfile_server\n", s.Root)
	case ModeRaw:
		b.WriteString(indent(s.Raw))
	}
	if s.Extra != "" {
		b.WriteString("\n\t# Zusatz\n")
		b.WriteString(indent(s.Extra))
	}
	b.WriteString("}\n")
	return b.String()
}

func indent(text string) string {
	var b strings.Builder
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString("\t" + strings.TrimRight(l, " \t") + "\n")
	}
	return b.String()
}

func balanced(s string) bool {
	depth := 0
	for _, r := range s {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

func checkDuplicates(list []Site) error {
	seen := map[string]string{}
	for _, s := range list {
		if !s.Enabled {
			continue
		}
		for _, d := range s.Domains {
			key := strings.ToLower(d)
			if other, ok := seen[key]; ok && other != s.ID {
				return &ValidationError{Problems: []string{fmt.Sprintf("Domain %s ist schon der Site %q zugeordnet", d, other)}}
			}
			seen[key] = s.ID
		}
	}
	return nil
}

// Slug derives an id from a domain.
func Slug(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	var b strings.Builder
	dash := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 50 {
		out = strings.Trim(out[:50], "-")
	}
	if out == "" {
		out = "site"
	}
	return out
}

func uniqueID(base string, list []Site) string {
	taken := map[string]bool{}
	for _, s := range list {
		taken[s.ID] = true
	}
	if !taken[base] {
		return base
	}
	for i := 2; ; i++ {
		id := fmt.Sprintf("%s-%d", base, i)
		if !taken[id] {
			return id
		}
	}
}

func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' }) {
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func firstOr(v []string, def string) string {
	for _, x := range v {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return def
}
