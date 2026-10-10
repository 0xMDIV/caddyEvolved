package cli

import (
	"reflect"
	"strings"
	"testing"

	"caddyforge/internal/config"
)

func TestPartitionFlagsKeepsPositionalsInOrder(t *testing.T) {
	valueFlags := map[string]bool{"port": true, "token": true, "timeout": true, "root": true}
	cases := []struct {
		name      string
		in        []string
		wantFlags []string
		wantRest  []string
	}{
		{
			name:      "Flags hinter Positionen",
			in:        []string{"GET", "/api/status", "--port", "8585", "--token", "abc"},
			wantFlags: []string{"--port", "8585", "--token", "abc"},
			wantRest:  []string{"GET", "/api/status"},
		},
		{
			name:      "Flag vor Positionen",
			in:        []string{"--port", "8585", "GET", "/api/status"},
			wantFlags: []string{"--port", "8585"},
			wantRest:  []string{"GET", "/api/status"},
		},
		{
			name:      "Flag mit Gleichheitszeichen",
			in:        []string{"GET", "/api/x", "--port=9"},
			wantFlags: []string{"--port=9"},
			wantRest:  []string{"GET", "/api/x"},
		},
		{
			name:      "Bool-Flag ohne Wert",
			in:        []string{"GET", "/api/x", "--json"},
			wantFlags: []string{"--json"},
			wantRest:  []string{"GET", "/api/x"},
		},
		{
			name:      "Alles nach dem Trenner ist Position",
			in:        []string{"POST", "/api/state", "--", "--port"},
			wantFlags: nil,
			wantRest:  []string{"POST", "/api/state", "--port"},
		},
		{
			name:      "Body bleibt Position",
			in:        []string{"POST", "/api/state", `{"a":1}`},
			wantFlags: nil,
			wantRest:  []string{"POST", "/api/state", `{"a":1}`},
		},
		{
			name:      "Wert fehlt am Ende",
			in:        []string{"GET", "/x", "--port"},
			wantFlags: []string{"--port"},
			wantRest:  []string{"GET", "/x"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			flags, rest := partitionFlags(c.in, valueFlags)
			if !reflect.DeepEqual(flags, c.wantFlags) {
				t.Errorf("flags = %#v, wollen %#v", flags, c.wantFlags)
			}
			if !reflect.DeepEqual(rest, c.wantRest) {
				t.Errorf("positionals = %#v, wollen %#v", rest, c.wantRest)
			}
		})
	}
}

func TestServeListenPrecedence(t *testing.T) {
	cases := []struct {
		name     string
		bind     string
		port     int
		stBind   string
		stPort   int
		wantBind string
		wantPort int
	}{
		{name: "Flag schlägt State", bind: "10.0.0.5", port: 9000, stBind: "0.0.0.0", stPort: 8484, wantBind: "10.0.0.5", wantPort: 9000},
		{name: "State schlägt Default", stBind: "127.0.0.1", stPort: 8585, wantBind: "127.0.0.1", wantPort: 8585},
		{name: "ohne alles Default", wantBind: "0.0.0.0", wantPort: 8484},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := config.State{UIBind: c.stBind, UIPort: c.stPort}
			gotBind, gotPort := serveListen(c.bind, c.port, st)
			if gotBind != c.wantBind || gotPort != c.wantPort {
				t.Errorf("serveListen = %s:%d, wollen %s:%d", gotBind, gotPort, c.wantBind, c.wantPort)
			}
		})
	}
}

func TestParseEnvPairs(t *testing.T) {
	got, err := parseEnvPairs([]string{"A=1", "B=22", "TOKEN=a=b"})
	if err != nil {
		t.Fatalf("parseEnvPairs: %v", err)
	}
	if want := map[string]string{"A": "1", "B": "22", "TOKEN": "a=b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got = %v, wollen %v", got, want)
	}
	if _, err := parseEnvPairs([]string{"VERKEHR"}); err == nil {
		t.Error("KEY ohne = muss fehlschlagen")
	}
	if v, err := parseEnvPairs(nil); err != nil || v != nil {
		t.Errorf("leere Liste = %v/%v, wollen nil/nil", v, err)
	}
}

func TestSplitIDs(t *testing.T) {
	got := splitIDs([]string{"a,b", " c ", "", "d"})
	if want := []string{"a", "b", "c", "d"}; !reflect.DeepEqual(got, want) {
		t.Errorf("splitIDs = %v, wollen %v", got, want)
	}
}

func TestEnvDefault(t *testing.T) {
	t.Setenv("CADDYFORGE_TEST_VAR", "gesetzte")
	if got := envDefault("CADDYFORGE_TEST_VAR", "standard"); got != "gesetzte" {
		t.Errorf("envDefault = %q", got)
	}
	if got := envDefault("CADDYFORGE_TEST_UNSET", "standard"); got != "standard" {
		t.Errorf("envDefault ohne Umgebung = %q", got)
	}
}

func TestDisplayDistinguishesUnsetRoot(t *testing.T) {
	if got := displayRoot(""); got != "/ (Live-System)" {
		t.Errorf("displayRoot(\"\") = %q", got)
	}
	if got := displayRoot("/tmp/stage"); got != "/tmp/stage" {
		t.Errorf("displayRoot = %q", got)
	}
	if got := orDefault("", "ersatz"); got != "ersatz" {
		t.Errorf("orDefault leer = %q", got)
	}
	if got := orDefault("  ", "ersatz"); got != "ersatz" {
		t.Errorf("orDefault blanks = %q", got)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "  ", "drittes"); got != "drittes" {
		t.Errorf("firstNonEmpty = %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("firstNonEmpty leer = %q", got)
	}
}

func TestRegistrProviderName(t *testing.T) {
	cases := map[string]string{
		"dns.provider cloudflare": "cloudflare",
		"dns.provider hetzner":    "hetzner",
		"http.auth preamble":      "",
		"":                        "",
	}
	for in, want := range cases {
		if got := providerName(in); got != want {
			t.Errorf("providerName(%q) = %q, wollen %q", in, got, want)
		}
	}
}

func TestCommandTableIsComplete(t *testing.T) {
	table := commandTable()
	if len(table) < 15 {
		t.Fatalf("Befehlstabelle hat %d Einträge, erwarten mindestens 15", len(table))
	}
	for name, cmd := range table {
		if cmd.run == nil {
			t.Errorf("%s hat keine Implementierung", name)
		}
		if strings.TrimSpace(cmd.usage) == "" || strings.TrimSpace(cmd.summary) == "" {
			t.Errorf("%s hat keine Nutzung oder Zusammenfassung", name)
		}
		if !strings.HasPrefix(cmd.usage, "caddyforge "+name) {
			t.Errorf("%s: usage %q fängt nicht mit dem Befehl an", name, cmd.usage)
		}
	}
}
