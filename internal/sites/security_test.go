package sites

import (
	"strings"
	"testing"
)

func TestSecurityRender(t *testing.T) {
	s := Site{
		ID: "shop-1", Domains: []string{"shop.example.com"}, Upstreams: []string{"10.0.0.9:3000"},
		WAF:       &WAF{Enabled: true, Mode: "detect"},
		Defender:  &Defender{Enabled: true},
		RateLimit: &RateLimit{Enabled: true, Events: 50},
	}
	s.Normalize()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	got := Render(s)
	for _, want := range []string{
		"\troute {",
		"zone cf_shop_1 {",
		"window 1m",
		"defender block {",
		"ranges openai deepseek githubcopilot",
		"coraza_waf {",
		"SecRuleEngine DetectionOnly",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("fehlt %q in\n%s", want, got)
		}
	}
	rl := strings.Index(got, "rate_limit")
	waf := strings.Index(got, "coraza_waf")
	proxy := strings.Index(got, "reverse_proxy")
	if !(rl < waf && waf < proxy) {
		t.Errorf("Reihenfolge rate_limit < coraza_waf < reverse_proxy verletzt:\n%s", got)
	}
	if !balanced(got) {
		t.Errorf("Klammern unausgeglichen:\n%s", got)
	}
}

func TestSecurityDisabledIsDropped(t *testing.T) {
	s := Site{ID: "a", Domains: []string{"a.lan"}, Upstreams: []string{"x:1"}, WAF: &WAF{Enabled: false}}
	s.Normalize()
	if s.WAF != nil || strings.Contains(Render(s), "route") {
		t.Errorf("deaktivierte WAF wird trotzdem gerendert:\n%s", Render(s))
	}
}

func TestSecurityValidate(t *testing.T) {
	bad := []Site{
		{ID: "a", Domains: []string{"a.lan"}, Upstreams: []string{"x:1"}, WAF: &WAF{Enabled: true, Mode: "on }"}},
		{ID: "a", Domains: []string{"a.lan"}, Upstreams: []string{"x:1"}, Defender: &Defender{Enabled: true, Responder: "nuke"}},
		{ID: "a", Domains: []string{"a.lan"}, Upstreams: []string{"x:1"}, Defender: &Defender{Enabled: true, Ranges: []string{"aws}"}}},
		{ID: "a", Domains: []string{"a.lan"}, Upstreams: []string{"x:1"}, RateLimit: &RateLimit{Enabled: true, Events: 0}},
		{ID: "a", Domains: []string{"a.lan"}, Upstreams: []string{"x:1"}, RateLimit: &RateLimit{Enabled: true, Events: 5, Window: "1 min"}},
	}
	for i, s := range bad {
		s.Normalize()
		if s.Validate() == nil {
			t.Errorf("Fall %d hätte abgelehnt werden müssen", i)
		}
	}
}
