// Package tui is the installer's terminal interface: single and multiple
// choice lists, text and secret input, yes/no questions and info boxes.
//
// On a real terminal it switches to raw mode and draws arrow-key menus with
// coloured markers; anywhere else (pipes, tests, TERM=dumb) it falls back to
// numbered line prompts with the same API. Ctrl+C aborts both with ErrAborted.
package tui

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// ErrAborted is returned by every question once the user pressed Ctrl+C (or
// the process got SIGINT/SIGTERM through the context).
var ErrAborted = errors.New("abgebrochen")

// Option is one entry of a single-choice list.
type Option struct {
	Label string
	Desc  string // shown dimmed under the label
	Tag   string // short highlight such as "empfohlen"
	// Disabled entries are shown but cannot be chosen; Reason replaces Tag.
	Disabled bool
	Reason   string
}

// Item is one entry of a multiple-choice list.
type Item struct {
	ID       string
	Label    string
	Desc     string
	Group    string // items are expected sorted by group
	Tag      string
	Selected bool
}

// InputOpts tunes a text question.
type InputOpts struct {
	Default  string
	Help     string
	Secret   bool
	Validate func(string) error
}

// UI is what the installer asks through.
type UI interface {
	// Banner prints the title block.
	Banner(title, sub string)
	// Section starts a new group of questions.
	Section(title string)
	// Note prints an info box; it asks nothing.
	Note(title string, lines ...string)
	// Warn prints a highlighted warning line.
	Warn(text string)
	Select(title string, opts []Option, def int) (int, error)
	Multi(title, help string, items []Item) ([]string, error)
	Input(label string, o InputOpts) (string, error)
	Confirm(label string, def bool) (bool, error)
	// Out is where free text (progress, reports) goes while the UI is open.
	Out() io.Writer
	// Close restores the terminal. Safe to call more than once.
	Close()
}

// New picks the interactive UI when in and out are a terminal.
func New(ctx context.Context, in *os.File, out *os.File) UI {
	if term.IsTerminal(int(in.Fd())) && term.IsTerminal(int(out.Fd())) && os.Getenv("TERM") != "dumb" {
		if t, err := newRaw(ctx, in, out); err == nil {
			return t
		}
	}
	return NewPlain(ctx, in, out)
}

// ---- styling -------------------------------------------------------------

type style struct{ on bool }

func (s style) wrap(code, text string) string {
	if !s.on || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s style) green(t string) string  { return s.wrap("32", t) }
func (s style) red(t string) string    { return s.wrap("31", t) }
func (s style) yellow(t string) string { return s.wrap("33", t) }
func (s style) cyan(t string) string   { return s.wrap("36", t) }
func (s style) dim(t string) string    { return s.wrap("2", t) }
func (s style) bold(t string) string   { return s.wrap("1", t) }

// colorWanted honours the NO_COLOR convention.
func colorWanted() bool { return os.Getenv("NO_COLOR") == "" }

// visibleLen counts runes outside ANSI escape sequences.
func visibleLen(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case esc:
			if r >= '@' && r <= '~' && r != '[' {
				esc = false
			}
		case r == '\x1b':
			esc = true
		default:
			n++
		}
	}
	return n
}

// truncate cuts s to width visible runes, keeping escape sequences intact so
// colours are still reset.
func truncate(s string, width int) string {
	if width <= 0 || visibleLen(s) <= width {
		return s
	}
	var b strings.Builder
	n, esc := 0, false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case esc:
			b.WriteRune(r)
			if r >= '@' && r <= '~' && r != '[' {
				esc = false
			}
		case r == '\x1b':
			esc = true
			b.WriteRune(r)
		default:
			if n < width-1 {
				b.WriteRune(r)
			} else if n == width-1 {
				b.WriteRune('…')
			}
			n++
		}
		i += size
	}
	if strings.Contains(s, "\x1b") {
		b.WriteString("\x1b[0m")
	}
	return b.String()
}
