package accesslog

import (
	"regexp"
	"testing"
)

func TestRedactURI(t *testing.T) {
	cases := map[string]string{
		"/a?token=abcdefghij&x=1":       "/a?token=abcd******&x=1",
		"/a?API_KEY=abcdefghij":         "/a?API_KEY=abcd******",
		"/a?key=abc":                    "/a?key=******",
		"/a?q=hello":                    "/a?q=hello",
		"/a?x=1&secret=abcd%2Fefghij#f": "/a?x=1&secret=abcd******#f",
		"/a?monkey=bananabanana":        "/a?monkey=bananabanana",
		"/plain":                        "/plain",
	}
	for in, want := range cases {
		if got := RedactURI(in, DefaultRedactParams); got != want {
			t.Errorf("RedactURI(%q) = %q, want %q", in, got, want)
		}
	}
	if got := RedactURI("/a?mytok=abcdefghij", []string{"mytok"}); got != "/a?mytok=abcd******" {
		t.Errorf("extra param: %q", got)
	}
}

func TestRedactValue(t *testing.T) {
	if got := RedactValue("abcdefghij"); got != "abcd******" {
		t.Errorf("long: %q", got)
	}
	if got := RedactValue("short"); got != "******" {
		t.Errorf("short: %q", got)
	}
}

// The pattern goes into caddy's regexp filter; it must compile in RE2 and
// give the same prefix as RedactURI for long values.
func TestRedactPatternMatchesGo(t *testing.T) {
	re := regexp.MustCompile(RedactPattern(DefaultRedactParams))
	got := re.ReplaceAllString("/a?TOKEN=abcdefghij&b=2", "${1}${2}******")
	if got != "/a?TOKEN=abcd******&b=2" {
		t.Fatalf("pattern: %q", got)
	}
}

func TestParseRedactsURIAndReferer(t *testing.T) {
	raw := `{"msg":"handled request","ts":1,"status":200,"request":{"host":"x","uri":"/cb?code=supersecretvalue","headers":{"Referer":["https://x/?token=abcdefghijkl"]}}}`
	e, ok := Parse([]byte(raw))
	if !ok || e.URI != "/cb?code=supe******" || e.Referer != "https://x/?token=abcd******" {
		t.Fatalf("got %+v", e)
	}
}

// Short values must not keep four characters: neither caddy's filter nor
// the parser reading the filtered line may show a 6-digit code.
func TestShortValueFullyHidden(t *testing.T) {
	re := regexp.MustCompile(RedactPattern(DefaultRedactParams))
	file := re.ReplaceAllString("/a?code=123456&b=2", "${1}${2}******")
	if file != "/a?code=******&b=2" {
		t.Fatalf("Datei: %q", file)
	}
	if got := RedactURI(file, DefaultRedactParams); got != "/a?code=******&b=2" {
		t.Fatalf("Parser: %q", got)
	}
	long := re.ReplaceAllString("/a?token=abcdefghij", "${1}${2}******")
	if got := RedactURI(long, DefaultRedactParams); got != "/a?token=abcd******" {
		t.Fatalf("lang: %q", got)
	}
}
