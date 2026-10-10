package sites

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// WAF switches the Coraza WAF with the OWASP Core Rule Set on for a site.
type WAF struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode,omitempty"` // block | detect
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
		} else if s.WAF.Mode == "" {
			s.WAF.Mode = "block"
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
	if s.WAF != nil && !wafModes[s.WAF.Mode] {
		problems = append(problems, "WAF-Modus: block oder detect")
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
func (s Site) needsRoute(acl *AccessList) bool {
	return acl != nil || s.WAF != nil || s.Defender != nil || s.RateLimit != nil
}

// renderSecurity emits the protection handlers, already indented for the
// route block. Order: rate limit (cheapest refusal), bot filter, WAF.
func renderSecurity(s Site) string {
	var b strings.Builder
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
		b.WriteString("\t\t\t\tInclude @owasp_crs/*.conf\n")
		fmt.Fprintf(&b, "\t\t\t\tSecRuleEngine %s\n", engine)
		b.WriteString("\t\t\t`\n\t\t}\n")
	}
	return b.String()
}
