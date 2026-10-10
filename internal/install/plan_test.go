package install

import (
	"context"
	"strings"
	"testing"
)

func baseAnswers() Answers {
	return Answers{
		BinarySource: "official",
		Email:        "hostmaster@example.org",
		HTTPPort:     80,
		HTTPSPort:    443,
		AdminPort:    2019,
		UIPort:       8484,
		UIBind:       "0.0.0.0",
	}
}

func TestValidateAcceptsDefaults(t *testing.T) {
	a := baseAnswers()
	a.Defaults()
	if err := a.Validate(); err != nil {
		t.Fatalf("Defaults invalid: %v", err)
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	a := baseAnswers()
	a.Managed = true
	a.Email = ""
	a.UIPort = 2019
	a.SiteDomain = "proxy.example.org"
	err := a.Validate()
	if err == nil {
		t.Fatal("erwartete Ablehnung blieb aus")
	}
	msg := err.Error()
	for _, want := range []string{"ports must be distinct", "siteDomain and siteTarget come in pairs", "managed HTTPS needs an email"} {
		if !strings.Contains(msg, want) {
			t.Errorf("Meldung %q enthält %q nicht", msg, want)
		}
	}
}

func TestValidateRejectsPortCollisionAndBadSource(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Answers)
		want   string
	}{
		{
			name:   "http gleich admin",
			mutate: func(a *Answers) { a.AdminPort = 80 },
			want:   "ports must be distinct",
		},
		{
			name:   "unbekannte Quelle",
			mutate: func(a *Answers) { a.BinarySource = "apt" },
			want:   "unknown binary source",
		},
		{
			name:   "Site ohne Ziel",
			mutate: func(a *Answers) { a.SiteDomain = "x.example.org" },
			want:   "come in pairs",
		},
		{
			name:   "Ziel ohne Schema",
			mutate: func(a *Answers) { a.SiteDomain, a.SiteTarget = "x.example.org", "localhost:8080" },
			want:   "must be an http(s)://",
		},
		{
			name:   "Modulauswahl mit official-Quelle",
			mutate: func(a *Answers) { a.Plugins = []string{"github.com/example/neu"} },
			want:   "needs a custom build",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := baseAnswers()
			c.mutate(&a)
			err := a.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("Fehler = %v, wollen Anteil %q", err, c.want)
			}
		})
	}
}

func TestDefaultsFillsEveryPort(t *testing.T) {
	var a Answers
	a.Defaults()
	if a.BinarySource != "official" || a.HTTPPort != 80 || a.HTTPSPort != 443 ||
		a.AdminPort != 2019 || a.UIPort != 8484 || a.UIBind != "0.0.0.0" {
		t.Errorf("Defaults = %+v", a)
	}
	if a.Credentials == nil {
		t.Error("Credentials müssen initialisiert sein, sonst kann der Wizard nichts schreiben")
	}
}

// TestRenderCaddyfilePorts is the regression that the answered ports actually
// reach caddy: without the global options it binds 80/443 regardless of answers.
func TestRenderCaddyfilePorts(t *testing.T) {
	got := render(t, Answers{
		BinarySource: "official", Email: "hostmaster@example.org", Managed: true,
		HTTPPort: 8080, HTTPSPort: 8443, AdminPort: 2020, UIPort: 8484, UIBind: "127.0.0.1",
	})
	for _, want := range []string{"admin localhost:2020", "https_port 8443", "http_port 8080", "email hostmaster@example.org"} {
		if !strings.Contains(got, want) {
			t.Errorf("Caddyfile enthält %q nicht:\n%s", want, got)
		}
	}

	// Default ports must NOT emit the options, or every install would pin them.
	std := render(t, baseAnswers())
	if strings.Contains(std, "http_port") || strings.Contains(std, "https_port") {
		t.Errorf("Default-Ports schreiben überflüssige Global-Optionen:\n%s", std)
	}
}

func TestRenderCaddyfileSiteBlockUsesDNS01WhenChosen(t *testing.T) {
	a := baseAnswers()
	a.Plugins = []string{"hetzner"}
	a.SiteDomain = "proxy.example.org"
	a.SiteTarget = "http://127.0.0.1:3000"
	got := render(t, a)

	// Most caddy-dns modules read no env on their own: the value has to be
	// interpolated explicitly or the config validates and issuance fails later.
	if !strings.Contains(got, "dns hetzner {env.HETZNER_API_TOKEN}") {
		t.Errorf("DNS-01-Block fehlt oder interpoliert nicht:\n%s", got)
	}
	if !strings.Contains(got, "reverse_proxy http://127.0.0.1:3000") {
		t.Errorf("Site-Block ohne reverse_proxy:\n%s", got)
	}
}

func TestRenderCaddyfileWithoutSiteKeepsPlaceholder(t *testing.T) {
	a := baseAnswers()
	a.Email = ""
	a.Managed = false
	got := render(t, a)
	if !strings.Contains(got, "respond ") {
		t.Errorf("ohne Site braucht caddy einen Platzhalter, sonst startet es nicht:\n%s", got)
	}
	if strings.Contains(got, "email ") {
		t.Errorf("unmanaged setzte trotzdem ein ACME-Konto:\n%s", got)
	}
}

// render builds a plan in a throwaway prefix and returns its Caddyfile.
func render(t *testing.T, a Answers) string {
	t.Helper()
	a.Defaults()
	plan, err := NewPlan(context.Background(), Options{Answers: a, Prefix: t.TempDir(), DryRun: true})
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	got, err := plan.renderCaddyfile()
	if err != nil {
		t.Fatalf("renderCaddyfile: %v", err)
	}
	return got
}
