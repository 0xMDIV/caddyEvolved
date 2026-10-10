package caddyctl

import (
	"context"
	"strings"
	"testing"

	"caddyforge/internal/cmdx"
)

// TestVersion parses the shapes caddy actually prints. The output changed between
// releases and a custom build appends "+unknown", so a parser that assumes one
// prefix breaks on the next build.
func TestVersion(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{name: "caddy 2.11 mit Modul-Hash", out: "v2.11.7 h1:yj0Y4fYZGPkSvibBJ1sTWE33xC0fxztVyXEW5iIdUT4=\n", want: "2.11.7"},
		{name: "aeltere Ausgabe", out: "Caddy version v2.11.4 h1:abc=\n", want: "2.11.4"},
		{name: "Custom-Build", out: "v2.11.7+unknown\n", want: "2.11.7"},
		{name: "ohne v", out: "2.11.7 h1:abc=\n", want: "2.11.7"},
		{name: "Vorabversion", out: "v2.12.0-rc.1 h1:abc=\n", want: "2.12.0-rc.1"},
		{name: "mehrzeilig", out: "Caddy\nv2.11.7 h1:x=\n", want: "2.11.7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runner := cmdx.NewFake().Outputs("caddy --version", c.out)
			got, err := New("caddy", runner).Version(context.Background())
			if err != nil {
				t.Fatalf("Version: %v", err)
			}
			if got != c.want {
				t.Errorf("Version = %q, wollen %q (aus %q)", got, c.want, c.out)
			}
		})
	}
}

func TestVersionRejectsGarbage(t *testing.T) {
	runner := cmdx.NewFake().Outputs("caddy --version", "no version here\n")
	if _, err := New("caddy", runner).Version(context.Background()); err == nil {
		t.Fatal("Ausgabe ohne Versionsfeld muss fehlschlagen, nicht als leerer String durchgehen")
	}
}

func TestAdminURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{in: "", want: "http://localhost:2019"},
		{in: "localhost:2019", want: "http://localhost:2019"},
		{in: "0.0.0.0:2020", want: "http://127.0.0.1:2020"},
		{in: ":2021", want: "http://127.0.0.1:2021"},
		{in: "127.0.0.1:0", want: "http://127.0.0.1"},
	}
	for _, c := range cases {
		if got := AdminURL(c.in); got != c.want {
			t.Errorf("AdminURL(%q) = %q, wollen %q", c.in, got, c.want)
		}
	}
}

func TestStartArgs(t *testing.T) {
	got := StartArgs("/etc/caddy/Caddyfile")
	want := "run --config /etc/caddy/Caddyfile"
	line := strings.Join(got, " ")
	if line != want {
		t.Errorf("StartArgs = %q, wollen %q", line, want)
	}
}
