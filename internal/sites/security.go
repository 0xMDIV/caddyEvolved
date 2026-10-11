package sites

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// WAF switches the Coraza WAF with the OWASP Core Rule Set on for a site.
// The plugin itself only takes SecLang directives; every option here is a
// CRS or Coraza setting rendered into them.
type WAF struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode,omitempty"` // block | detect
	// Paranoia is the CRS blocking paranoia level 1–4; 0 means the default 1.
	// Higher levels catch more and misfire more. DetectParanoia runs higher
	// levels for the log only.
	Paranoia       int `json:"paranoia,omitempty"`
	DetectParanoia int `json:"detectParanoia,omitempty"`
	// Threshold is the inbound anomaly score that blocks; 0 means the CRS
	// default 5. Raising it is the usual first step against false positives.
	// OutThreshold is the same for responses (default 4).
	Threshold    int `json:"threshold,omitempty"`
	OutThreshold int `json:"outThreshold,omitempty"`
	// EarlyBlocking refuses after the headers when the score is already
	// reached, before the body arrives.
	EarlyBlocking bool `json:"earlyBlocking,omitempty"`
	// Methods replace the CRS default GET HEAD POST OPTIONS; REST APIs and
	// WebDAV need PUT, DELETE, PATCH, PROPFIND and friends.
	Methods []string `json:"methods,omitempty"`
	// ContentTypes are request content types allowed on top of the CRS list.
	ContentTypes []string `json:"contentTypes,omitempty"`
	// BodyLimitMB caps request bodies (default 12.5 MB); BodyPartial inspects
	// the first part of larger bodies instead of refusing them.
	BodyLimitMB int  `json:"bodyLimitMb,omitempty"`
	BodyPartial bool `json:"bodyPartial,omitempty"`
	// NoResponse skips the inspection of responses (data leakage rules).
	NoResponse bool `json:"noResponse,omitempty"`
	// GroupsOff are CRS rule groups switched off (WAFGroups keys).
	GroupsOff []string `json:"groupsOff,omitempty"`
	// Exclude are CRS rule IDs switched off for this site.
	Exclude []int `json:"exclude,omitempty"`
	// SkipPaths switch the WAF off below these path prefixes.
	SkipPaths []string `json:"skipPaths,omitempty"`
	// PathExcludes switch single rules off below a path prefix only.
	PathExcludes []WAFPathExclude `json:"pathExcludes,omitempty"`
	// Custom are further SecLang directives, after the rule set.
	Custom string `json:"custom,omitempty"`
}

// WAFPathExclude switches rules off for one path prefix.
type WAFPathExclude struct {
	Path string `json:"path"`
	IDs  []int  `json:"ids"`
}

// WAFGroup is one CRS rule file, identified by its ID block.
type WAFGroup struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Block int    `json:"block"` // rule IDs Block*1000 … Block*1000+999
}

// WAFGroups are the request rule groups of CRS v4 that can be switched off.
var WAFGroups = []WAFGroup{
	{"scanner", "Scanner-Erkennung (Nikto, sqlmap, …)", 913},
	{"protocol", "Protokoll-Prüfung (Header, Kodierung)", 920},
	{"protocol-attack", "Protokoll-Angriffe (Request Smuggling, Header-Injection)", 921},
	{"multipart", "Multipart-Angriffe (Uploads)", 922},
	{"lfi", "Local File Inclusion (../, Systemdateien)", 930},
	{"rfi", "Remote File Inclusion", 931},
	{"rce", "Befehlsausführung (Shell, RCE)", 932},
	{"php", "PHP-Angriffe", 933},
	{"generic", "Generische Angriffe (Node.js, SSRF, Prototype Pollution)", 934},
	{"xss", "Cross-Site-Scripting (XSS)", 941},
	{"sqli", "SQL-Injection", 942},
	{"session", "Session-Fixation", 943},
	{"java", "Java-Angriffe (Log4Shell, Deserialisierung)", 944},
}

func wafGroup(key string) (WAFGroup, bool) {
	for _, g := range WAFGroups {
		if g.Key == key {
			return g, true
		}
	}
	return WAFGroup{}, false
}

// crsContentTypes is the CRS default of tx.allowed_request_content_type.
const crsContentTypes = "|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json|"

// Defender filters requests from known bot and cloud ranges (caddy-defender).
type Defender struct {
	Enabled   bool     `json:"enabled"`
	Responder string   `json:"responder,omitempty"`
	Ranges    []string `json:"ranges,omitempty"`
	// Message and StatusCode answer for the "custom" responder, URL is the
	// target of "redirect".
	Message    string `json:"message,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	URL        string `json:"url,omitempty"`
	// Whitelist are addresses inside the ranges that still pass.
	Whitelist []string `json:"whitelist,omitempty"`
	// ServeIgnore answers /robots.txt with "disallow everything".
	ServeIgnore bool `json:"serveIgnore,omitempty"`
	// Tarpit settings: how long and how slowly the tarpit answers.
	TarpitTimeout string `json:"tarpitTimeout,omitempty"`
	TarpitBPS     int    `json:"tarpitBps,omitempty"`
}

// RateLimit caps requests per client (caddy-ratelimit). Rules add stricter
// limits for single paths, e.g. a login form.
type RateLimit struct {
	Enabled bool   `json:"enabled"`
	Events  int    `json:"events,omitempty"`
	Window  string `json:"window,omitempty"`
	// Key counts per client IP ("ip", default) or per IP and path ("ip-path").
	Key   string     `json:"key,omitempty"`
	Rules []RateRule `json:"rules,omitempty"`
}

// RateRule is an extra zone for some paths and methods.
type RateRule struct {
	Paths   []string `json:"paths"`
	Methods []string `json:"methods,omitempty"`
	Events  int      `json:"events"`
	Window  string   `json:"window"`
}

// DefenderRanges are the range keys caddy-defender ships (ranges/data).
var DefenderRanges = []string{
	"openai", "deepseek", "githubcopilot", "mistral", "aws", "aws-us-east-1", "aws-us-west-1", "gcloud",
	"azurepubliccloud", "oci", "aliyun", "huawei", "digitalocean", "linode", "vultr", "cloudflare",
	"datadog", "vpn", "private", "all",
}

var (
	reWindow    = regexp.MustCompile(`^[0-9]{1,5}(ms|s|m|h)$`)
	reRangeKey  = regexp.MustCompile(`^[a-z0-9_-]{2,40}$`)
	reMethod    = regexp.MustCompile(`^[A-Z][A-Z-]{1,19}$`)
	reCType     = regexp.MustCompile(`^[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+*-]*$`)
	reWAFPath   = regexp.MustCompile(`^/[A-Za-z0-9._~!$&()+,;=:@%/-]*$`)
	reRatePath  = regexp.MustCompile(`^/[A-Za-z0-9._~!$&()+,;=:@%/*-]*$`)
	responders  = map[string]bool{"block": true, "tarpit": true, "garbage": true, "drop": true, "custom": true, "redirect": true}
	wafModes    = map[string]bool{"block": true, "detect": true}
	rateKeys    = map[string]bool{"ip": true, "ip-path": true}
	defaultBots = []string{"openai", "deepseek", "githubcopilot"}
)

func (s *Site) normalizeSecurity() {
	if s.WAF != nil {
		if !s.WAF.Enabled {
			s.WAF = nil
		} else {
			w := s.WAF
			if w.Mode == "" {
				w.Mode = "block"
			}
			// Sorted and unique, so the rendered snippet stays stable.
			slices.Sort(w.Exclude)
			w.Exclude = slices.Compact(w.Exclude)
			w.Methods = upper(cleanList(w.Methods))
			w.ContentTypes = cleanList(w.ContentTypes)
			for i := range w.ContentTypes {
				w.ContentTypes[i] = strings.ToLower(w.ContentTypes[i])
			}
			w.GroupsOff = cleanList(w.GroupsOff)
			slices.Sort(w.GroupsOff)
			w.GroupsOff = slices.Compact(w.GroupsOff)
			w.SkipPaths = cleanList(w.SkipPaths)
			var pe []WAFPathExclude
			for _, p := range w.PathExcludes {
				p.Path = strings.TrimSpace(p.Path)
				slices.Sort(p.IDs)
				p.IDs = slices.Compact(p.IDs)
				if p.Path != "" || len(p.IDs) > 0 {
					pe = append(pe, p)
				}
			}
			w.PathExcludes = pe
			w.Custom = strings.TrimSpace(strings.ReplaceAll(w.Custom, "\r", ""))
		}
	}
	if s.Defender != nil {
		if !s.Defender.Enabled {
			s.Defender = nil
		} else {
			d := s.Defender
			if d.Responder == "" {
				d.Responder = "block"
			}
			d.Ranges = cleanList(d.Ranges)
			if len(d.Ranges) == 0 {
				d.Ranges = append([]string(nil), defaultBots...)
			}
			d.Whitelist = cleanList(d.Whitelist)
			d.Message = strings.TrimSpace(d.Message)
			d.URL = strings.TrimSpace(d.URL)
			d.TarpitTimeout = strings.TrimSpace(d.TarpitTimeout)
		}
	}
	if s.RateLimit != nil {
		if !s.RateLimit.Enabled {
			s.RateLimit = nil
		} else {
			rl := s.RateLimit
			if rl.Window == "" {
				rl.Window = "1m"
			}
			if rl.Key == "" {
				rl.Key = "ip"
			}
			var rules []RateRule
			for _, r := range rl.Rules {
				r.Paths = cleanList(r.Paths)
				r.Methods = upper(cleanList(r.Methods))
				if r.Window == "" {
					r.Window = "1m"
				}
				if len(r.Paths) > 0 || len(r.Methods) > 0 {
					rules = append(rules, r)
				}
			}
			rl.Rules = rules
		}
	}
}

func (s Site) validateSecurity() []string {
	var problems []string
	if w := s.WAF; w != nil {
		problems = append(problems, w.validate()...)
	}
	if d := s.Defender; d != nil {
		if !responders[d.Responder] {
			problems = append(problems, "Bot-Abwehr: Reaktion block, tarpit, garbage, drop, custom oder redirect")
		}
		for _, r := range d.Ranges {
			if _, err := netip.ParsePrefix(r); err == nil {
				continue
			}
			if !reRangeKey.MatchString(r) {
				problems = append(problems, fmt.Sprintf("Bot-Abwehr: Bereich %q ungültig", r))
			}
		}
		for _, r := range d.Whitelist {
			if r == "private_ranges" || !validRange(r) {
				problems = append(problems, fmt.Sprintf("Bot-Abwehr: Ausnahme %q ist keine IP und kein Bereich", r))
			}
		}
		if d.Responder == "custom" {
			if d.Message == "" || len(d.Message) > 300 || strings.ContainsAny(d.Message, "\"\\`{}\n\r") {
				problems = append(problems, "Bot-Abwehr: Antworttext fehlt oder enthält \" \\ ` { } bzw. Zeilenumbrüche")
			}
			if d.StatusCode != 0 && (d.StatusCode < 200 || d.StatusCode > 599) {
				problems = append(problems, "Bot-Abwehr: Statuscode zwischen 200 und 599")
			}
		}
		if d.Responder == "redirect" {
			if u, err := url.Parse(d.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(d.URL, " \"`{}") {
				problems = append(problems, "Bot-Abwehr: Weiterleitungsziel wie https://example.com")
			}
		}
		if d.TarpitTimeout != "" && !reWindow.MatchString(d.TarpitTimeout) {
			problems = append(problems, "Bot-Abwehr: Tarpit-Dauer wie 30s oder 5m")
		}
		if d.TarpitBPS < 0 || d.TarpitBPS > 1000000 {
			problems = append(problems, "Bot-Abwehr: Tarpit-Bytes pro Sekunde zwischen 1 und 1000000")
		}
	}
	if rl := s.RateLimit; rl != nil {
		if rl.Events < 1 || rl.Events > 1000000 {
			problems = append(problems, "Rate Limit: Anzahl zwischen 1 und 1000000")
		}
		if !reWindow.MatchString(rl.Window) {
			problems = append(problems, "Rate Limit: Zeitfenster wie 30s, 1m oder 1h")
		}
		if !rateKeys[rl.Key] {
			problems = append(problems, "Rate Limit: Zählung pro ip oder ip-path")
		}
		for i, r := range rl.Rules {
			n := i + 1
			if len(r.Paths) == 0 {
				problems = append(problems, fmt.Sprintf("Rate Limit Regel %d: mindestens ein Pfad wie /login*", n))
			}
			for _, p := range r.Paths {
				if !reRatePath.MatchString(p) {
					problems = append(problems, fmt.Sprintf("Rate Limit Regel %d: Pfad %q muss mit / beginnen, ohne Leer- und Anführungszeichen", n, p))
				}
			}
			for _, m := range r.Methods {
				if !reMethod.MatchString(m) {
					problems = append(problems, fmt.Sprintf("Rate Limit Regel %d: Methode %q ungültig", n, m))
				}
			}
			if r.Events < 1 || r.Events > 1000000 {
				problems = append(problems, fmt.Sprintf("Rate Limit Regel %d: Anzahl zwischen 1 und 1000000", n))
			}
			if !reWindow.MatchString(r.Window) {
				problems = append(problems, fmt.Sprintf("Rate Limit Regel %d: Zeitfenster wie 30s, 1m oder 1h", n))
			}
		}
	}
	return problems
}

func (w WAF) validate() []string {
	var problems []string
	if !wafModes[w.Mode] {
		problems = append(problems, "WAF-Modus: block oder detect")
	}
	if w.Paranoia < 0 || w.Paranoia > 4 {
		problems = append(problems, "WAF: Paranoia-Level 1 bis 4")
	}
	if w.DetectParanoia < 0 || w.DetectParanoia > 4 {
		problems = append(problems, "WAF: Paranoia-Level fürs Log 1 bis 4")
	}
	if w.Threshold < 0 || w.Threshold > 1000 || w.OutThreshold < 0 || w.OutThreshold > 1000 {
		problems = append(problems, "WAF: Schwellwert zwischen 1 und 1000")
	}
	for _, id := range w.Exclude {
		if id < 1 || id > 9999999 {
			problems = append(problems, fmt.Sprintf("WAF: Regel-ID %d ungültig", id))
		}
	}
	for _, m := range w.Methods {
		if !reMethod.MatchString(m) {
			problems = append(problems, fmt.Sprintf("WAF: HTTP-Methode %q ungültig", m))
		}
	}
	for _, c := range w.ContentTypes {
		if !reCType.MatchString(c) {
			problems = append(problems, fmt.Sprintf("WAF: Content-Type %q – z. B. application/octet-stream", c))
		}
	}
	if w.BodyLimitMB < 0 || w.BodyLimitMB > 10240 {
		problems = append(problems, "WAF: Body-Limit zwischen 1 und 10240 MB")
	}
	for _, g := range w.GroupsOff {
		if _, ok := wafGroup(g); !ok {
			problems = append(problems, fmt.Sprintf("WAF: unbekannte Regelgruppe %q", g))
		}
	}
	for _, p := range w.SkipPaths {
		if !reWAFPath.MatchString(p) {
			problems = append(problems, fmt.Sprintf("WAF: Pfad %q muss mit / beginnen, ohne Leer-, Anführungszeichen und *", p))
		}
	}
	for _, p := range w.PathExcludes {
		if !reWAFPath.MatchString(p.Path) {
			problems = append(problems, fmt.Sprintf("WAF: Pfad %q muss mit / beginnen, ohne Leer-, Anführungszeichen und *", p.Path))
		}
		if len(p.IDs) == 0 {
			problems = append(problems, fmt.Sprintf("WAF: für %s fehlen die Regel-IDs", p.Path))
		}
		for _, id := range p.IDs {
			if id < 1 || id > 9999999 {
				problems = append(problems, fmt.Sprintf("WAF: Regel-ID %d ungültig", id))
			}
		}
	}
	if len(w.SkipPaths)+len(w.PathExcludes) > 200 {
		problems = append(problems, "WAF: höchstens 200 Pfad-Ausnahmen")
	}
	// The directives sit in a backtick string in the Caddyfile.
	if strings.Contains(w.Custom, "`") || len(w.Custom) > 20000 {
		problems = append(problems, "WAF: eigene Regeln ohne ` (Backtick) und höchstens 20000 Zeichen")
	}
	return problems
}

// needsRoute reports whether handlers must run in written order.
func (s Site) needsRoute(acl *AccessList, opt Options) bool {
	return acl != nil || s.WAF != nil || s.Defender != nil || s.RateLimit != nil || s.crowdsec(opt) || s.firewallOn(opt)
}

// crowdsec reports whether the bouncer runs on this site.
func (s Site) crowdsec(opt Options) bool { return opt.crowdsecOn() && !s.NoCrowdSec }

// renderSecurity emits the protection handlers, already indented for the
// route block. Order: CrowdSec (known attackers, a map lookup), rate limit,
// bot filter, WAF.
func renderSecurity(s Site, opt Options) string {
	var b strings.Builder
	if s.crowdsec(opt) {
		b.WriteString("\t\tcrowdsec\n")
		if opt.Global.CrowdSec.AppSecURL != "" && opt.Caps.AppSec {
			b.WriteString("\t\tappsec\n")
		}
	}
	if rl := s.RateLimit; rl != nil {
		renderRateLimit(&b, s.ID, rl)
	}
	if d := s.Defender; d != nil {
		renderDefender(&b, d)
	}
	if w := s.WAF; w != nil {
		renderWAF(&b, w)
	}
	return b.String()
}

func renderRateLimit(b *strings.Builder, id string, rl *RateLimit) {
	zone := "cf_" + strings.ReplaceAll(id, "-", "_")
	key := "{client_ip}"
	if rl.Key == "ip-path" {
		key = "{client_ip}{path}"
	}
	b.WriteString("\t\trate_limit {\n")
	fmt.Fprintf(b, "\t\t\tzone %s {\n\t\t\t\tkey %s\n\t\t\t\tevents %d\n\t\t\t\twindow %s\n\t\t\t}\n", zone, key, rl.Events, rl.Window)
	for i, r := range rl.Rules {
		fmt.Fprintf(b, "\t\t\tzone %s_%d {\n\t\t\t\tmatch {\n", zone, i+1)
		fmt.Fprintf(b, "\t\t\t\t\tpath %s\n", strings.Join(r.Paths, " "))
		if len(r.Methods) > 0 {
			fmt.Fprintf(b, "\t\t\t\t\tmethod %s\n", strings.Join(r.Methods, " "))
		}
		fmt.Fprintf(b, "\t\t\t\t}\n\t\t\t\tkey {client_ip}\n\t\t\t\tevents %d\n\t\t\t\twindow %s\n\t\t\t}\n", r.Events, r.Window)
	}
	b.WriteString("\t\t}\n")
}

func renderDefender(b *strings.Builder, d *Defender) {
	fmt.Fprintf(b, "\t\tdefender %s {\n\t\t\tranges %s\n", d.Responder, strings.Join(d.Ranges, " "))
	if len(d.Whitelist) > 0 {
		fmt.Fprintf(b, "\t\t\twhitelist %s\n", strings.Join(d.Whitelist, " "))
	}
	switch d.Responder {
	case "custom":
		fmt.Fprintf(b, "\t\t\tmessage \"%s\"\n", d.Message)
		if d.StatusCode != 0 {
			fmt.Fprintf(b, "\t\t\tstatus_code %d\n", d.StatusCode)
		}
	case "redirect":
		fmt.Fprintf(b, "\t\t\turl %s\n", d.URL)
	case "tarpit":
		if d.TarpitTimeout != "" || d.TarpitBPS > 0 {
			b.WriteString("\t\t\ttarpit_config {\n")
			if d.TarpitTimeout != "" {
				fmt.Fprintf(b, "\t\t\t\ttimeout %s\n", d.TarpitTimeout)
			}
			if d.TarpitBPS > 0 {
				fmt.Fprintf(b, "\t\t\t\tbytes_per_second %d\n", d.TarpitBPS)
			}
			b.WriteString("\t\t\t}\n")
		}
	}
	if d.ServeIgnore {
		b.WriteString("\t\t\tserve_ignore\n")
	}
	b.WriteString("\t\t}\n")
}

func renderWAF(b *strings.Builder, w *WAF) {
	const in = "\t\t\t\t"
	engine := "On"
	if w.Mode == "detect" {
		engine = "DetectionOnly"
	}
	b.WriteString("\t\tcoraza_waf {\n\t\t\tload_owasp_crs\n\t\t\tdirectives `\n")
	b.WriteString(in + "Include @coraza.conf-recommended\n")
	if w.BodyLimitMB > 0 {
		fmt.Fprintf(b, in+"SecRequestBodyLimit %d\n", w.BodyLimitMB<<20)
	}
	if w.BodyPartial {
		b.WriteString(in + "SecRequestBodyLimitAction ProcessPartial\n")
	}
	if w.NoResponse {
		b.WriteString(in + "SecResponseBodyAccess Off\n")
	}
	b.WriteString(in + "Include @crs-setup.conf.example\n")
	// The setup file only carries these as comments; set before the rules load.
	action := func(id int, setvars ...string) {
		fmt.Fprintf(b, in+"SecAction \"id:%d,phase:1,pass,t:none,nolog", id)
		for _, s := range setvars {
			fmt.Fprintf(b, ",setvar:'%s'", s)
		}
		b.WriteString("\"\n")
	}
	if w.Paranoia > 1 {
		action(900000, fmt.Sprintf("tx.blocking_paranoia_level=%d", w.Paranoia))
	}
	if w.DetectParanoia > max(w.Paranoia, 1) {
		action(900001, fmt.Sprintf("tx.detection_paranoia_level=%d", w.DetectParanoia))
	}
	if w.Threshold > 0 || w.OutThreshold > 0 {
		var sv []string
		if w.Threshold > 0 {
			sv = append(sv, fmt.Sprintf("tx.inbound_anomaly_score_threshold=%d", w.Threshold))
		}
		if w.OutThreshold > 0 {
			sv = append(sv, fmt.Sprintf("tx.outbound_anomaly_score_threshold=%d", w.OutThreshold))
		}
		action(900110, sv...)
	}
	if w.EarlyBlocking {
		action(900120, "tx.early_blocking=1")
	}
	if len(w.Methods) > 0 {
		action(900200, "tx.allowed_methods="+strings.Join(w.Methods, " "))
	}
	if len(w.ContentTypes) > 0 {
		ct := crsContentTypes
		for _, c := range w.ContentTypes {
			ct += " |" + c + "|"
		}
		action(900220, "tx.allowed_request_content_type="+ct)
	}
	if w.NoResponse {
		action(900500, "tx.crs_skip_response_analysis=1")
	}
	// Path exceptions act in phase 1, before any rule inspects the request.
	for i, p := range w.SkipPaths {
		fmt.Fprintf(b, in+"SecRule REQUEST_FILENAME \"@beginsWith %s\" \"id:%d,phase:1,pass,t:none,nolog,ctl:ruleEngine=Off\"\n", p, 10000+i)
	}
	for i, p := range w.PathExcludes {
		ctl := make([]string, 0, len(p.IDs))
		for _, id := range p.IDs {
			ctl = append(ctl, fmt.Sprintf("ctl:ruleRemoveById=%d", id))
		}
		fmt.Fprintf(b, in+"SecRule REQUEST_FILENAME \"@beginsWith %s\" \"id:%d,phase:1,pass,t:none,nolog,%s\"\n", p.Path, 10300+i, strings.Join(ctl, ","))
	}
	b.WriteString(in + "Include @owasp_crs/*.conf\n")
	var removals []string
	for _, key := range w.GroupsOff {
		g, _ := wafGroup(key)
		removals = append(removals, fmt.Sprintf("%d-%d", g.Block*1000, g.Block*1000+999))
	}
	for _, id := range w.Exclude {
		removals = append(removals, fmt.Sprint(id))
	}
	if len(removals) > 0 {
		fmt.Fprintf(b, in+"SecRuleRemoveById %s\n", strings.Join(removals, " "))
	}
	if w.Custom != "" {
		b.WriteString(in + "# Eigene Regeln\n")
		for _, l := range strings.Split(w.Custom, "\n") {
			b.WriteString(in + strings.TrimRight(l, " \t") + "\n")
		}
	}
	fmt.Fprintf(b, in+"SecRuleEngine %s\n", engine)
	b.WriteString("\t\t\t`\n\t\t}\n")
}
