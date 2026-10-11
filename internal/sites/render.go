package sites

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	"caddyevolved/internal/plugins"
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
	s.AccessList = strings.TrimSpace(s.AccessList)
	s.Tailnet = strings.ToLower(strings.TrimSpace(s.Tailnet))
	s.normalizeUpstreams()
	s.normalizeSecurity()
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
	reNode     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
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
				if strings.Contains(u, "/") {
					problems = append(problems, fmt.Sprintf("Ziel %q enthält einen Pfad – nur Host und Port angeben, z. B. 192.168.10.132:8006", u))
				} else {
					problems = append(problems, fmt.Sprintf("Ziel %q ungültig – Host und Port angeben, z. B. 192.168.10.132:8006", u))
				}
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
	case ModeStatic, ModeWebDAV:
		if !strings.HasPrefix(s.Root, "/") || strings.ContainsAny(s.Root, " \t\n{}\"") || strings.Contains(s.Root, "..") {
			problems = append(problems, "Verzeichnis muss ein absoluter Pfad ohne Leerzeichen sein")
		}
	case ModeRaw:
		if strings.TrimSpace(s.Raw) == "" {
			problems = append(problems, "Raw-Modus braucht Inhalt")
		}
	default:
		problems = append(problems, "Modus: proxy, redirect, static, webdav oder raw")
	}
	if s.Tailnet != "" && !reNode.MatchString(s.Tailnet) {
		problems = append(problems, "Tailnet-Name: nur a-z, 0-9 und Bindestrich, z. B. nas")
	}
	problems = append(problems, s.validateSecurity()...)
	if s.AccessList != "" && !reID.MatchString(s.AccessList) {
		problems = append(problems, "Access-List-ID ungültig")
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

// Options carries host-wide rendering settings.
type Options struct {
	// AccessLog is the shared JSON access log every site writes to; empty
	// disables request logging (tests, installer).
	AccessLog string
	// Roll is the rotation of that file; the zero value is caddy's default
	// behaviour as caddyEvolved always shipped it (50 MiB, keep 5, gzip).
	Roll LogRoll
	// GuardExtra are the operator's own path patterns refused on every site,
	// on top of the built-in rules (guard.go).
	GuardExtra []string
	// Global are the host-wide options (global.go); Caps says which optional
	// modules the running caddy has, so nothing unknown gets rendered.
	Global Global
	Caps   Caps
	// StateDir keeps plugin state such as the tailscale node keys.
	StateDir string
	// FirewallLists are the downloaded public blocklists by id; GeoDB and
	// ASNDB the DB-IP databases ("" while not downloaded). FirewallPath is
	// set by the Manager: the rule file the sites import.
	FirewallLists map[string][]string
	GeoDB, ASNDB  string
	FirewallPath  string
	// WAFLog receives Coraza's rule matches, so the UI can name the rule
	// behind a block; empty leaves them in caddy's own log.
	WAFLog string
}

// LogRoll configures caddy's file rotation. Field names follow the zero
// value = default rule, hence "Disabled" and "Uncompressed".
type LogRoll struct {
	Disabled     bool `json:"disabled"`
	SizeMB       int  `json:"sizeMb"`
	Keep         int  `json:"keep"`
	KeepDays     int  `json:"keepDays"`
	Uncompressed bool `json:"uncompressed"`
	LocalTime    bool `json:"localTime"`
}

// renderLog is the log directive every site shares. All sites must render it
// identically: caddy pools writers by filename and the first config wins.
func renderLog(path string, r LogRoll) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\tlog {\n\t\toutput file %s {\n", path)
	if r.Disabled {
		b.WriteString("\t\t\troll_disabled\n")
	} else {
		size, keep := r.SizeMB, r.Keep
		if size <= 0 {
			size = 50
		}
		if keep <= 0 {
			keep = 5
		}
		fmt.Fprintf(&b, "\t\t\troll_size %dMiB\n\t\t\troll_keep %d\n", size, keep)
		if r.KeepDays > 0 {
			fmt.Fprintf(&b, "\t\t\troll_keep_for %dh\n", r.KeepDays*24)
		}
		if r.Uncompressed {
			b.WriteString("\t\t\troll_uncompressed\n")
		}
		if r.LocalTime {
			b.WriteString("\t\t\troll_local_time\n")
		}
	}
	b.WriteString("\t\t}\n\t\tformat json\n\t}\n")
	return b.String()
}

// Render produces the snippet for a site without an access list.
func Render(s Site) string { return RenderWith(s, nil, Options{}) }

// RenderWith produces the snippet for one site. With an access list or a
// protection module, the checks and the site's handlers go into one `route`
// block so they run in the written order: deny first, then login, then the
// handler.
func RenderWith(s Site, acl *AccessList, opt Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s – verwaltet von caddyEvolved. Änderungen über die WebUI, sonst überschrieben.\n", s.ID)
	addrs := make([]string, 0, len(s.Domains))
	for _, d := range s.Domains {
		if s.TLS == TLSOff && !strings.HasPrefix(d, ":") {
			d = "http://" + d
		}
		addrs = append(addrs, d)
	}
	fmt.Fprintf(&b, "%s {\n", strings.Join(addrs, ", "))
	if s.Tailnet != "" && opt.tailscaleOn() {
		fmt.Fprintf(&b, "\tbind tailscale/%s\n", s.Tailnet)
	}

	switch s.TLS {
	case TLSInternal:
		b.WriteString("\ttls internal\n")
	case TLSDNS:
		if e, ok := plugins.ByID(s.DNSProvider); ok {
			b.WriteString(plugins.DNSTLSBlock(e))
		}
	}
	if s.Compress && s.Mode != ModeRedirect {
		if opt.Caps.Brotli {
			b.WriteString("\tencode zstd br gzip\n")
		} else {
			b.WriteString("\tencode zstd gzip\n")
		}
	}
	if opt.AccessLog != "" && !s.NoLog {
		// One file for all sites: caddy pools writers by filename, and the
		// analytics follower then reads a single log.
		b.WriteString(renderLog(opt.AccessLog, opt.Roll))
	}

	b.WriteString(renderGuard(opt.GuardExtra))
	if s.Cache && opt.cacheOn() && (s.Mode == ModeProxy || s.Mode == ModeStatic) {
		b.WriteString("\tcache\n")
	}

	body := renderBody(s)
	if s.needsRoute(acl, opt) {
		b.WriteString("\troute {\n")
		if s.firewallOn(opt) {
			fmt.Fprintf(&b, "\t\timport %s\n", filepath.ToSlash(opt.FirewallPath))
		}
		if acl != nil {
			b.WriteString(renderACL(*acl, opt))
		}
		if sec := renderSecurity(s, opt); sec != "" && s.trusted(opt) {
			// Trusted addresses skip the filters, not the site's access list.
			fmt.Fprintf(&b, "\t\t@cev_fw_untrusted not client_ip %s\n", strings.Join(opt.Global.Firewall.Allow, " "))
			b.WriteString("\t\troute @cev_fw_untrusted {\n")
			b.WriteString(indent(strings.TrimRight(sec, "\n")))
			b.WriteString("\t\t}\n")
		} else {
			b.WriteString(sec)
		}
		b.WriteString(indent(strings.TrimRight(body, "\n")))
		b.WriteString("\t}\n")
	} else {
		b.WriteString(body)
	}
	if s.Extra != "" {
		b.WriteString("\n\t# Zusatz\n")
		b.WriteString(indent(s.Extra))
	}
	b.WriteString("}\n")
	return b.String()
}

// renderBody is the site's handler part, indented one level.
func renderBody(s Site) string {
	var b strings.Builder
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
	case ModeWebDAV:
		// route keeps the third-party directive out of caddy's global order.
		fmt.Fprintf(&b, "\troute {\n\t\twebdav {\n\t\t\troot %s\n\t\t}\n\t}\n", s.Root)
	case ModeRaw:
		b.WriteString(indent(s.Raw))
	}
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

// normalizeUpstreams moves a scheme typed into an address onto the TLS switch,
// so "https://192.168.10.5:8006/" and "192.168.10.5:8006" + "Ziel spricht
// HTTPS" end up identical. Mixing the two forms otherwise makes caddy refuse
// the config ("scheme is HTTP but transport is configured for TLS").
func (s *Site) normalizeUpstreams() {
	for i, u := range s.Upstreams {
		lower := strings.ToLower(u)
		switch {
		case strings.HasPrefix(lower, "https://"):
			s.UpstreamTLS = true
			u = u[len("https://"):]
		case strings.HasPrefix(lower, "http://"):
			u = u[len("http://"):]
		}
		s.Upstreams[i] = strings.TrimRight(u, "/")
	}
	if s.UpstreamInsecure {
		s.UpstreamTLS = true
	}
}
