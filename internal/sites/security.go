package sites

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// WAF switches the Coraza WAF with the OWASP Core Rule Set on for a site.
type WAF struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode,omitempty"` // block | detect
	// Paranoia is the CRS blocking paranoia level 1–4; 0 means the default 1.
	// Higher levels catch more and misfire more.
	Paranoia int `json:"paranoia,omitempty"`
	// Threshold is the inbound anomaly score that blocks; 0 means the CRS
	// default 5. Raising it is the usual first step against false positives.
	Threshold int `json:"threshold,omitempty"`
	// Exclude are CRS rule IDs switched off for this site.
	Exclude []int `json:"exclude,omitempty"`
}

// Defender filters requests from known bot and cloud ranges (caddy-defender).
type Defender struct {
	Enabled   bool     `json:"enabled"`
	Responder string   `json:"responder,omitempty"`
	Ranges    []string `json:"ranges,omitempty"`
}

// RateLimit caps requests per client IP (caddy-ratelimit).
type RateLimit struct {
	Enabled bool   `json:"enabled"`
	Events  int    `json:"events,omitempty"`
	Window  string `json:"window,omitempty"`
}

// DefenderRanges are the range keys caddy-defender ships by default.
var DefenderRanges = []string{"openai", "aws", "gcloud", "azurepubliccloud", "deepseek", "githubcopilot", "cloudflare", "vpn", "private", "all"}

var (
	reWindow    = regexp.MustCompile(`^[0-9]{1,5}(ms|s|m|h)$`)
	reRangeKey  = regexp.MustCompile(`^[a-z0-9_-]{2,40}$`)
	responders  = map[string]bool{"block": true, "tarpit": true, "garbage": true, "drop": true}
	wafModes    = map[string]bool{"block": true, "detect": true}
	defaultBots = []string{"openai", "deepseek", "githubcopilot"}
)

func (s *Site) normalizeSecurity() {
	if s.WAF != nil {
		if !s.WAF.Enabled {
			s.WAF = nil
		} else {
			if s.WAF.Mode == "" {
				s.WAF.Mode = "block"
			}
			// Sorted and unique, so the rendered snippet stays stable.
			slices.Sort(s.WAF.Exclude)
			s.WAF.Exclude = slices.Compact(s.WAF.Exclude)
		}
	}
	if s.Defender != nil {
		if !s.Defender.Enabled {
			s.Defender = nil
		} else {
			if s.Defender.Responder == "" {
				s.Defender.Responder = "block"
			}
			s.Defender.Ranges = cleanList(s.Defender.Ranges)
			if len(s.Defender.Ranges) == 0 {
				s.Defender.Ranges = append([]string(nil), defaultBots...)
			}
		}
	}
	if s.RateLimit != nil {
		if !s.RateLimit.Enabled {
			s.RateLimit = nil
		} else if s.RateLimit.Window == "" {
			s.RateLimit.Window = "1m"
		}
	}
}

func (s Site) validateSecurity() []string {
	var problems []string
	if w := s.WAF; w != nil {
		if !wafModes[w.Mode] {
			problems = append(problems, "WAF-Modus: block oder detect")
		}
		if w.Paranoia < 0 || w.Paranoia > 4 {
			problems = append(problems, "WAF: Paranoia-Level 1 bis 4")
		}
		if w.Threshold < 0 || w.Threshold > 1000 {
			problems = append(problems, "WAF: Schwellwert zwischen 1 und 1000")
		}
		for _, id := range w.Exclude {
			if id < 1 || id > 9999999 {
				problems = append(problems, fmt.Sprintf("WAF: Regel-ID %d ungültig", id))
			}
		}
	}
	if d := s.Defender; d != nil {
		if !responders[d.Responder] {
			problems = append(problems, "Bot-Abwehr: Reaktion block, tarpit, garbage oder drop")
		}
		for _, r := range d.Ranges {
			if _, err := netip.ParsePrefix(r); err == nil {
				continue
			}
			if !reRangeKey.MatchString(r) {
				problems = append(problems, fmt.Sprintf("Bot-Abwehr: Bereich %q ungültig", r))
			}
		}
	}
	if rl := s.RateLimit; rl != nil {
		if rl.Events < 1 || rl.Events > 1000000 {
			problems = append(problems, "Rate Limit: Anzahl zwischen 1 und 1000000")
		}
		if !reWindow.MatchString(rl.Window) {
			problems = append(problems, "Rate Limit: Zeitfenster wie 30s, 1m oder 1h")
		}
	}
	return problems
}

// needsRoute reports whether handlers must run in written order.
func (s Site) needsRoute(acl *AccessList, opt Options) bool {
	return acl != nil || s.WAF != nil || s.Defender != nil || s.RateLimit != nil || s.crowdsec(opt)
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
		fmt.Fprintf(&b, "\t\trate_limit {\n\t\t\tzone cf_%s {\n\t\t\t\tkey {client_ip}\n\t\t\t\tevents %d\n\t\t\t\twindow %s\n\t\t\t}\n\t\t}\n",
			strings.ReplaceAll(s.ID, "-", "_"), rl.Events, rl.Window)
	}
	if d := s.Defender; d != nil {
		fmt.Fprintf(&b, "\t\tdefender %s {\n\t\t\tranges %s\n\t\t}\n", d.Responder, strings.Join(d.Ranges, " "))
	}
	if w := s.WAF; w != nil {
		engine := "On"
		if w.Mode == "detect" {
			engine = "DetectionOnly"
		}
		b.WriteString("\t\tcoraza_waf {\n\t\t\tload_owasp_crs\n\t\t\tdirectives `\n")
		b.WriteString("\t\t\t\tInclude @coraza.conf-recommended\n")
		b.WriteString("\t\t\t\tInclude @crs-setup.conf.example\n")
		// The setup file only carries these as comments; set before the rules load.
		if w.Paranoia > 1 {
			fmt.Fprintf(&b, "\t\t\t\tSecAction \"id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d\"\n", w.Paranoia)
		}
		if w.Threshold > 0 {
			fmt.Fprintf(&b, "\t\t\t\tSecAction \"id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", w.Threshold)
		}
		b.WriteString("\t\t\t\tInclude @owasp_crs/*.conf\n")
		if len(w.Exclude) > 0 {
			ids := make([]string, 0, len(w.Exclude))
			for _, id := range w.Exclude {
				ids = append(ids, fmt.Sprint(id))
			}
			fmt.Fprintf(&b, "\t\t\t\tSecRuleRemoveById %s\n", strings.Join(ids, " "))
		}
		fmt.Fprintf(&b, "\t\t\t\tSecRuleEngine %s\n", engine)
		b.WriteString("\t\t\t`\n\t\t}\n")
	}
	return b.String()
}
