package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"
)

// raw is the interactive UI. The terminal stays in raw mode for the whole
// session, so Ctrl+C arrives as a byte (no SIGINT) and output needs "\r\n".
type raw struct {
	ctx  context.Context
	in   *os.File
	out  *os.File
	fd   int
	old  *term.State
	st   style
	keys chan []byte
	pend []byte
	live int // lines of the block currently being redrawn
	done bool
}

func newRaw(ctx context.Context, in, out *os.File) (*raw, error) {
	fd := int(in.Fd())
	old, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	r := &raw{ctx: ctx, in: in, out: out, fd: fd, old: old, st: style{on: colorWanted()}, keys: make(chan []byte, 16)}
	go r.pump()
	return r, nil
}

// pump is the only reader of stdin; every question takes its keys from here,
// so a cancelled question cannot leave a read behind that eats later input.
func (r *raw) pump() {
	buf := make([]byte, 256)
	for {
		n, err := r.in.Read(buf)
		if n > 0 {
			r.keys <- append([]byte(nil), buf[:n]...)
		}
		if err != nil {
			close(r.keys)
			return
		}
	}
}

func (r *raw) Close() {
	if r.done {
		return
	}
	r.done = true
	io.WriteString(r.out, "\x1b[?25h")
	term.Restore(r.fd, r.old)
}

// ---- output ----------------------------------------------------------------

type crlf struct{ w io.Writer }

func (c crlf) Write(p []byte) (int, error) {
	s := strings.ReplaceAll(strings.ReplaceAll(string(p), "\r\n", "\n"), "\n", "\r\n")
	if _, err := io.WriteString(c.w, s); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (r *raw) Out() io.Writer { return crlf{r.out} }

func (r *raw) width() int {
	if w, _, err := term.GetSize(int(r.out.Fd())); err == nil && w > 10 {
		return w
	}
	return 80
}

func (r *raw) height() int {
	if _, h, err := term.GetSize(int(r.out.Fd())); err == nil && h > 8 {
		return h
	}
	return 24
}

// draw replaces the live block with lines; the cursor stays at the end of the
// last line.
func (r *raw) draw(lines []string) {
	var b strings.Builder
	if r.live > 1 {
		fmt.Fprintf(&b, "\x1b[%dA", r.live-1)
	}
	if r.live > 0 {
		b.WriteString("\r\x1b[J")
	}
	w := r.width() - 1
	for i, l := range lines {
		if i > 0 {
			b.WriteString("\r\n")
		}
		b.WriteString(truncate(l, w))
	}
	io.WriteString(r.out, b.String())
	r.live = len(lines)
}

// commit draws the final form of a question and leaves it on screen.
func (r *raw) commit(lines ...string) {
	r.draw(lines)
	io.WriteString(r.out, "\r\n")
	r.live = 0
}

func (r *raw) println(s string) { fmt.Fprint(r.Out(), s+"\n") }

func (r *raw) Banner(title, sub string) {
	r.println("")
	r.println("  " + r.st.bold(r.st.cyan("◆ "+title)))
	if sub != "" {
		r.println("  " + r.st.dim(sub))
	}
}

func (r *raw) Section(title string) {
	r.println("")
	r.println(r.st.bold(r.st.cyan("── "+title+" ")) + r.st.cyan(strings.Repeat("─", max(0, 40-visibleLen(title)))))
}

func (r *raw) Note(title string, lines ...string) {
	bar := r.st.cyan("│ ")
	if title != "" {
		r.println(bar + r.st.bold("ℹ "+title))
	}
	for _, l := range lines {
		r.println(bar + l)
	}
}

func (r *raw) Warn(text string) { r.println(r.st.yellow("! " + text)) }

// ---- keys --------------------------------------------------------------------

type keyKind int

const (
	kRune keyKind = iota
	kUp
	kDown
	kLeft
	kRight
	kHome
	kEnd
	kEnter
	kSpace
	kBack
	kTab
	kAbort
	kClear
	kOther
)

type key struct {
	kind keyKind
	r    rune
}

// decode reads one key from p; ok is false when p holds an incomplete sequence.
func decode(p []byte) (k key, n int, ok bool) {
	if len(p) == 0 {
		return key{}, 0, false
	}
	switch p[0] {
	case 3, 4: // Ctrl+C, Ctrl+D
		return key{kind: kAbort}, 1, true
	case '\r', '\n':
		return key{kind: kEnter}, 1, true
	case 127, 8:
		return key{kind: kBack}, 1, true
	case '\t':
		return key{kind: kTab}, 1, true
	case 21: // Ctrl+U
		return key{kind: kClear}, 1, true
	case ' ':
		return key{kind: kSpace, r: ' '}, 1, true
	case 27:
		if len(p) == 1 {
			return key{kind: kOther}, 1, true
		}
		if p[1] != '[' && p[1] != 'O' {
			return key{kind: kOther}, 1, true
		}
		for i := 2; i < len(p); i++ {
			if p[i] >= 0x40 && p[i] <= 0x7e {
				switch p[i] {
				case 'A':
					return key{kind: kUp}, i + 1, true
				case 'B':
					return key{kind: kDown}, i + 1, true
				case 'C':
					return key{kind: kRight}, i + 1, true
				case 'D':
					return key{kind: kLeft}, i + 1, true
				case 'H':
					return key{kind: kHome}, i + 1, true
				case 'F':
					return key{kind: kEnd}, i + 1, true
				}
				return key{kind: kOther}, i + 1, true
			}
		}
		return key{}, 0, false
	}
	if p[0] < 32 {
		return key{kind: kOther}, 1, true
	}
	if !utf8.FullRune(p) {
		return key{}, 0, false
	}
	ru, size := utf8.DecodeRune(p)
	return key{kind: kRune, r: ru}, size, true
}

func (r *raw) next() (key, error) {
	for {
		if k, n, ok := decode(r.pend); ok {
			r.pend = r.pend[n:]
			if k.kind == kAbort {
				return k, ErrAborted
			}
			return k, nil
		}
		select {
		case <-r.ctx.Done():
			return key{}, ErrAborted
		case b, ok := <-r.keys:
			if !ok {
				return key{}, ErrAborted
			}
			r.pend = append(r.pend, b...)
		}
	}
}

// abort leaves the screen tidy before the error travels up.
func (r *raw) abort() error {
	r.commit(r.st.red("✖ Abgebrochen – es wurde nichts geändert."))
	return ErrAborted
}

func (r *raw) question(title string) string { return r.st.cyan("?") + " " + r.st.bold(title) }
func (r *raw) answered(title, value string) string {
	return r.st.green("✔") + " " + title + "  " + r.st.cyan(value)
}

// ---- single choice -----------------------------------------------------------

func (r *raw) Select(title string, opts []Option, def int) (int, error) {
	cur := def
	if cur < 0 || cur >= len(opts) || opts[cur].Disabled {
		cur = firstEnabled(opts)
	}
	io.WriteString(r.out, "\x1b[?25l")
	defer io.WriteString(r.out, "\x1b[?25h")
	for {
		lines := []string{r.question(title)}
		for i, o := range opts {
			var line string
			switch {
			case o.Disabled:
				line = "    " + r.st.dim("○ "+o.Label)
				if o.Reason != "" {
					line += "  " + r.st.dim("("+o.Reason+")")
				}
			case i == cur:
				line = "  " + r.st.cyan("❯") + " " + r.st.green("●") + " " + r.st.bold(o.Label)
			default:
				line = "    " + r.st.dim("○") + " " + o.Label
			}
			if o.Tag != "" && !o.Disabled {
				line += "  " + r.st.yellow("★ "+o.Tag)
			}
			lines = append(lines, line)
			if o.Desc != "" {
				for _, d := range strings.Split(o.Desc, "\n") {
					lines = append(lines, "      "+r.st.dim(d))
				}
			}
		}
		lines = append(lines, r.st.dim("  ↑/↓ wählen · Enter bestätigen · Strg+C abbrechen"))
		r.draw(lines)

		k, err := r.next()
		if err != nil {
			return 0, r.abort()
		}
		switch k.kind {
		case kUp:
			cur = step(opts, cur, -1)
		case kDown, kTab:
			cur = step(opts, cur, +1)
		case kRune:
			if k.r == 'k' {
				cur = step(opts, cur, -1)
			} else if k.r == 'j' {
				cur = step(opts, cur, +1)
			} else if n := int(k.r - '1'); n >= 0 && n < len(opts) && !opts[n].Disabled {
				cur = n
			}
		case kEnter, kSpace:
			r.commit(r.answered(title, opts[cur].Label))
			return cur, nil
		}
	}
}

func firstEnabled(opts []Option) int {
	for i, o := range opts {
		if !o.Disabled {
			return i
		}
	}
	return 0
}

func step(opts []Option, cur, dir int) int {
	for i := cur + dir; i >= 0 && i < len(opts); i += dir {
		if !opts[i].Disabled {
			return i
		}
	}
	return cur
}

// ---- multiple choice ---------------------------------------------------------

func (r *raw) Multi(title, help string, items []Item) ([]string, error) {
	sel := make([]bool, len(items))
	for i, it := range items {
		sel[i] = it.Selected
	}
	type row struct {
		header string
		idx    int
	}
	var rows []row
	group := "\x00"
	for i, it := range items {
		if it.Group != group {
			group = it.Group
			if group != "" {
				rows = append(rows, row{header: group, idx: -1})
			}
		}
		rows = append(rows, row{idx: i})
	}
	rowOf := func(idx int) int {
		for n, rw := range rows {
			if rw.idx == idx {
				return n
			}
		}
		return 0
	}

	cur, top := 0, 0
	io.WriteString(r.out, "\x1b[?25l")
	defer io.WriteString(r.out, "\x1b[?25h")
	for {
		visible := max(5, r.height()-8)
		if visible > len(rows) {
			visible = len(rows)
		}
		cr := rowOf(cur)
		if cr < top {
			top = cr
			if top > 0 && rows[top-1].idx < 0 {
				top--
			}
		}
		if cr >= top+visible {
			top = cr - visible + 1
		}

		count := 0
		for _, s := range sel {
			if s {
				count++
			}
		}
		lines := []string{r.question(title) + "  " + r.st.dim(fmt.Sprintf("%d ausgewählt", count))}
		if help != "" {
			lines = append(lines, "  "+r.st.dim(help))
		}
		if top > 0 {
			lines = append(lines, r.st.dim(fmt.Sprintf("    ↑ %d weitere", top)))
		}
		for _, rw := range rows[top : top+visible] {
			if rw.idx < 0 {
				lines = append(lines, "  "+r.st.dim(strings.ToUpper(rw.header)))
				continue
			}
			it := items[rw.idx]
			pointer := "  "
			if rw.idx == cur {
				pointer = r.st.cyan("❯ ")
			}
			mark := r.st.dim("○")
			label := it.Label
			if sel[rw.idx] {
				mark = r.st.green("●")
				label = r.st.green(label)
			}
			if rw.idx == cur {
				label = r.st.bold(label)
			}
			line := "  " + pointer + mark + " " + label
			if it.Tag != "" {
				line += "  " + r.st.yellow("★ "+it.Tag)
			}
			lines = append(lines, line)
		}
		if rest := len(rows) - top - visible; rest > 0 {
			lines = append(lines, r.st.dim(fmt.Sprintf("    ↓ %d weitere", rest)))
		}
		if d := items[cur].Desc; d != "" {
			lines = append(lines, "  "+r.st.dim("› "+d))
		}
		lines = append(lines, r.st.dim("  ↑/↓ bewegen · Leertaste an/aus · Enter fertig · Strg+C abbrechen"))
		r.draw(lines)

		k, err := r.next()
		if err != nil {
			return nil, r.abort()
		}
		switch k.kind {
		case kUp:
			if cur > 0 {
				cur--
			}
		case kDown, kTab:
			if cur < len(items)-1 {
				cur++
			}
		case kHome:
			cur = 0
		case kEnd:
			cur = len(items) - 1
		case kSpace:
			sel[cur] = !sel[cur]
		case kRune:
			switch k.r {
			case 'k':
				if cur > 0 {
					cur--
				}
			case 'j':
				if cur < len(items)-1 {
					cur++
				}
			case 'x':
				sel[cur] = !sel[cur]
			}
		case kEnter:
			var ids, labels []string
			for i, s := range sel {
				if s {
					ids = append(ids, items[i].ID)
					labels = append(labels, items[i].Label)
				}
			}
			summary := "keine"
			if len(labels) > 0 {
				summary = strings.Join(labels, ", ")
			}
			r.commit(r.answered(title, summary))
			return ids, nil
		}
	}
}

// ---- text input --------------------------------------------------------------

func (r *raw) Input(label string, o InputOpts) (string, error) {
	var buf []rune
	var problem string
	for {
		head := r.question(label)
		if o.Help != "" {
			head += "  " + r.st.dim(o.Help)
		}
		lines := []string{head}
		if problem != "" {
			lines = append(lines, "  "+r.st.red("✖ "+problem))
		}
		shown := string(buf)
		if o.Secret {
			shown = strings.Repeat("•", len(buf))
		}
		if len(buf) == 0 && o.Default != "" {
			shown = r.st.dim(o.Default)
			lines = append(lines, "  "+r.st.cyan("›")+" "+shown+"\x1b["+fmt.Sprint(visibleLen(o.Default))+"D")
		} else {
			lines = append(lines, "  "+r.st.cyan("›")+" "+shown)
		}
		r.draw(lines)

		k, err := r.next()
		if err != nil {
			return "", r.abort()
		}
		switch k.kind {
		case kRune, kSpace:
			if unicode.IsPrint(k.r) {
				buf = append(buf, k.r)
			}
		case kBack:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
		case kClear:
			buf = buf[:0]
		case kEnter:
			v := strings.TrimSpace(string(buf))
			if v == "" {
				v = o.Default
			}
			if o.Validate != nil {
				if verr := o.Validate(v); verr != nil {
					problem = verr.Error()
					continue
				}
			}
			shownV := v
			switch {
			case o.Secret && v != "":
				shownV = "•••••• (verborgen)"
			case v == "":
				shownV = "–"
			}
			r.commit(r.answered(label, shownV))
			return v, nil
		}
	}
}

// ---- yes / no ----------------------------------------------------------------

func (r *raw) Confirm(label string, def bool) (bool, error) {
	v := def
	io.WriteString(r.out, "\x1b[?25l")
	defer io.WriteString(r.out, "\x1b[?25h")
	for {
		yes, no := r.st.dim("○")+" Ja", r.st.dim("○")+" Nein"
		if v {
			yes = r.st.green("● Ja")
		} else {
			no = r.st.green("● Nein")
		}
		r.draw([]string{r.question(label) + "   " + yes + "   " + no + "   " + r.st.dim("←/→ · Enter")})
		k, err := r.next()
		if err != nil {
			return false, r.abort()
		}
		switch k.kind {
		case kLeft, kRight, kTab, kSpace, kUp, kDown:
			v = !v
		case kRune:
			switch unicode.ToLower(k.r) {
			case 'j', 'y':
				v = true
			case 'n':
				v = false
			}
		case kEnter:
			ans := "Nein"
			if v {
				ans = "Ja"
			}
			r.commit(r.answered(label, ans))
			return v, nil
		}
	}
}
