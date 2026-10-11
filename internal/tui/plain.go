package tui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// plain asks with numbered line prompts. It is what scripts, pipes and tests
// get; Ctrl+C reaches it as SIGINT through the context.
type plain struct {
	ctx   context.Context
	out   io.Writer
	lines chan string
	eof   bool
}

// NewPlain builds the line-based UI over any reader.
func NewPlain(ctx context.Context, in io.Reader, out io.Writer) UI {
	p := &plain{ctx: ctx, out: out, lines: make(chan string)}
	go func() {
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			p.lines <- sc.Text()
		}
		close(p.lines)
	}()
	return p
}

func (p *plain) Out() io.Writer { return p.out }
func (p *plain) Close()         {}

// read returns one line; at EOF it answers "" so defaults apply, as before.
func (p *plain) read(prompt string) (string, error) {
	fmt.Fprint(p.out, prompt)
	select {
	case <-p.ctx.Done():
		fmt.Fprintln(p.out, "\nAbgebrochen – es wurde nichts geändert.")
		return "", ErrAborted
	case l, ok := <-p.lines:
		if !ok {
			p.eof = true
			fmt.Fprintln(p.out)
			return "", nil
		}
		return strings.TrimSpace(l), nil
	}
}

func (p *plain) Banner(title, sub string) {
	fmt.Fprintln(p.out, title)
	if sub != "" {
		fmt.Fprintln(p.out, sub)
	}
}

func (p *plain) Section(title string) { fmt.Fprintf(p.out, "\n== %s ==\n", title) }

func (p *plain) Note(title string, lines ...string) {
	if title != "" {
		fmt.Fprintf(p.out, "| %s\n", title)
	}
	for _, l := range lines {
		fmt.Fprintf(p.out, "| %s\n", l)
	}
}

func (p *plain) Warn(text string) { fmt.Fprintf(p.out, "! %s\n", text) }

func (p *plain) Select(title string, opts []Option, def int) (int, error) {
	if def < 0 || def >= len(opts) || opts[def].Disabled {
		def = firstEnabled(opts)
	}
	fmt.Fprintln(p.out, title+":")
	for i, o := range opts {
		line := fmt.Sprintf("  %d) %s", i+1, o.Label)
		if o.Disabled {
			line += " – nicht wählbar"
			if o.Reason != "" {
				line += " (" + o.Reason + ")"
			}
		} else if o.Tag != "" {
			line += " [" + o.Tag + "]"
		}
		fmt.Fprintln(p.out, line)
		if o.Desc != "" {
			for _, d := range strings.Split(o.Desc, "\n") {
				fmt.Fprintln(p.out, "     "+d)
			}
		}
	}
	for {
		v, err := p.read(fmt.Sprintf("Auswahl [%d]: ", def+1))
		if err != nil {
			return 0, err
		}
		if v == "" {
			return def, nil
		}
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= len(opts) && !opts[n-1].Disabled {
			return n - 1, nil
		}
		// Accept the label itself too, so old answers like "official" still work.
		for i, o := range opts {
			if !o.Disabled && strings.EqualFold(firstWord(o.Label), v) {
				return i, nil
			}
		}
		fmt.Fprintf(p.out, "  bitte eine Nummer von 1 bis %d\n", len(opts))
	}
}

func firstWord(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return s
}

func (p *plain) Multi(title, help string, items []Item) ([]string, error) {
	sel := make([]bool, len(items))
	for i, it := range items {
		sel[i] = it.Selected
	}
	fmt.Fprintln(p.out, title+":")
	if help != "" {
		fmt.Fprintln(p.out, "  "+help)
	}
	group := "\x00"
	for i, it := range items {
		if it.Group != group {
			group = it.Group
			if group != "" {
				fmt.Fprintf(p.out, "  -- %s --\n", group)
			}
		}
		tag := ""
		if it.Tag != "" {
			tag = " [" + it.Tag + "]"
		}
		fmt.Fprintf(p.out, "  %3d) %s%s\n", i+1, it.Label, tag)
	}
	for {
		var cur []string
		for i, s := range sel {
			if s {
				cur = append(cur, strconv.Itoa(i+1))
			}
		}
		v, err := p.read(fmt.Sprintf("Nummern zum An-/Abwählen, leer = fertig [%s]: ", strings.Join(cur, ",")))
		if err != nil {
			return nil, err
		}
		if v == "" {
			break
		}
		for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' }) {
			n, err := strconv.Atoi(tok)
			if err == nil && n >= 1 && n <= len(items) {
				sel[n-1] = !sel[n-1]
				continue
			}
			found := false
			for i, it := range items {
				if it.ID == tok {
					sel[i], found = !sel[i], true
				}
			}
			if !found {
				fmt.Fprintf(p.out, "  %q unbekannt\n", tok)
			}
		}
	}
	var ids []string
	for i, s := range sel {
		if s {
			ids = append(ids, items[i].ID)
		}
	}
	return ids, nil
}

func (p *plain) Input(label string, o InputOpts) (string, error) {
	prompt := label
	if o.Help != "" {
		prompt += " (" + o.Help + ")"
	}
	if o.Default != "" {
		prompt += " [" + o.Default + "]"
	}
	for {
		v, err := p.read(prompt + ": ")
		if err != nil {
			return "", err
		}
		if v == "" {
			v = o.Default
		}
		if o.Validate != nil {
			if verr := o.Validate(v); verr != nil {
				if p.eof {
					return "", fmt.Errorf("%s: %w", label, verr)
				}
				fmt.Fprintf(p.out, "  %v\n", verr)
				continue
			}
		}
		return v, nil
	}
}

func (p *plain) Confirm(label string, def bool) (bool, error) {
	suffix := "j/N"
	if def {
		suffix = "J/n"
	}
	v, err := p.read(fmt.Sprintf("%s [%s]: ", label, suffix))
	if err != nil {
		return false, err
	}
	switch strings.ToLower(v) {
	case "j", "ja", "y", "yes":
		return true, nil
	case "n", "nein", "no":
		return false, nil
	}
	return def, nil
}
