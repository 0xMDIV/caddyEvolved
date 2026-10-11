package tui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestDecode(t *testing.T) {
	cases := []struct {
		in   string
		kind keyKind
		n    int
	}{
		{"\x1b[A", kUp, 3},
		{"\x1b[B", kDown, 3},
		{"\x1bOC", kRight, 3},
		{"\x1b[3~", kOther, 4},
		{"\r", kEnter, 1},
		{"\x03", kAbort, 1},
		{"\x7f", kBack, 1},
		{" ", kSpace, 1},
		{"ä", kRune, 2},
	}
	for _, c := range cases {
		k, n, ok := decode([]byte(c.in))
		if !ok || k.kind != c.kind || n != c.n {
			t.Errorf("decode(%q) = %v,%d,%v; want kind %v, %d bytes", c.in, k.kind, n, ok, c.kind, c.n)
		}
	}
	// An escape sequence split across reads waits for the rest.
	if _, _, ok := decode([]byte("\x1b[")); ok {
		t.Error("incomplete sequence decoded")
	}
	if _, _, ok := decode([]byte{0xc3}); ok {
		t.Error("incomplete rune decoded")
	}
}

func TestTruncateKeepsEscapes(t *testing.T) {
	s := "\x1b[32mabcdefghij\x1b[0m"
	got := truncate(s, 5)
	if visibleLen(got) != 5 || !strings.HasPrefix(got, "\x1b[32m") || !strings.HasSuffix(got, "\x1b[0m") {
		t.Fatalf("truncate = %q (visible %d)", got, visibleLen(got))
	}
	if truncate("kurz", 10) != "kurz" {
		t.Fatal("short string changed")
	}
}

func TestPlainQuestions(t *testing.T) {
	in := strings.NewReader("3\n2\n\n1, 3\n\nfalsch\nok@beispiel.de\nn\n")
	var out bytes.Buffer
	ui := NewPlain(context.Background(), in, &out)

	opts := []Option{{Label: "Eins"}, {Label: "Zwei"}, {Label: "Drei", Disabled: true}}
	// "3" is disabled and refused, "2" is taken.
	if got, err := ui.Select("Wahl", opts, 0); err != nil || got != 1 {
		t.Fatalf("Select = %d, %v", got, err)
	}
	// Empty line keeps the preselection; "1, 3" toggles both.
	items := []Item{{ID: "a", Selected: true}, {ID: "b"}, {ID: "c"}}
	if got, err := ui.Multi("Plugins", "", items); err != nil || strings.Join(got, ",") != "a" {
		t.Fatalf("Multi #1 = %v, %v", got, err)
	}
	if got, err := ui.Multi("Plugins", "", items); err != nil || strings.Join(got, ",") != "c" {
		t.Fatalf("Multi #2 = %v, %v", got, err)
	}
	mustAt := func(v string) error {
		if !strings.Contains(v, "@") {
			return errors.New("kein @")
		}
		return nil
	}
	if got, err := ui.Input("Mail", InputOpts{Validate: mustAt}); err != nil || got != "ok@beispiel.de" {
		t.Fatalf("Input = %q, %v", got, err)
	}
	if got, err := ui.Confirm("Weiter?", true); err != nil || got {
		t.Fatalf("Confirm = %v, %v", got, err)
	}
	// At EOF a failing validation must not loop forever.
	if _, err := ui.Input("Mail", InputOpts{Validate: mustAt}); err == nil {
		t.Fatal("Input at EOF with invalid default accepted")
	}
}

func TestPlainAbortOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pr, pw := io.Pipe()
	defer pw.Close()
	ui := NewPlain(ctx, pr, io.Discard)
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if _, err := ui.Confirm("Weiter?", true); !errors.Is(err, ErrAborted) {
		t.Fatalf("err = %v, want ErrAborted", err)
	}
}
