// Package aiaudit is the protocol of everything the AI chat asked, proposed
// and changed. It only ever appends: there is no way to edit or delete an
// entry through caddyEvolved, and every entry carries the SHA-256 of the one
// before it, so a line changed or removed on disk shows up as a broken chain.
// That does not stop root from rewriting the whole file, but nobody can do
// it unnoticed by changing a single line.
package aiaudit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"caddyevolved/internal/accesslog"
)

// Kinds of entries.
const (
	KindRequest  = "request"  // the user wrote to the AI
	KindProposal = "proposal" // the AI wants to change something
	KindApproved = "approved" // the user allowed a proposal
	KindRejected = "rejected" // the user refused it
	KindExpired  = "expired"  // nobody decided in time
	KindExecuted = "executed" // a tool ran (reads too), with its result
	KindNote     = "note"     // the AI's own account of what it did
)

const fileName = "ai-audit.jsonl"

// maxSize starts a new file; old files are kept forever. A variable for tests.
var maxSize int64 = 10 << 20

// maxText bounds free text per entry.
const maxText = 4000

// Entry is one line of the protocol.
type Entry struct {
	N      int64           `json:"n"`
	TS     time.Time       `json:"ts"`
	Chat   string          `json:"chat,omitempty"`
	Actor  string          `json:"actor,omitempty"`
	Kind   string          `json:"kind"`
	Text   string          `json:"text,omitempty"`
	Tool   string          `json:"tool,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
	Method string          `json:"method,omitempty"`
	Path   string          `json:"path,omitempty"`
	Status int             `json:"status,omitempty"`
	Result string          `json:"result,omitempty"`
	Model  string          `json:"model,omitempty"`
	Prev   string          `json:"prev"`
	Hash   string          `json:"hash,omitempty"`
}

// Log appends to the protocol in dir.
type Log struct {
	dir string

	mu       sync.Mutex
	lastN    int64
	lastHash string
}

// Open continues the chain found in dir.
func Open(dir string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &Log{dir: dir}
	err := l.each(func(e Entry, _ error) bool {
		if e.N > 0 {
			l.lastN, l.lastHash = e.N, e.Hash
		}
		return true
	})
	return l, err
}

// files lists the protocol in order: rotated files by name, the current last.
func (l *Log) files() []string {
	rotated, _ := filepath.Glob(filepath.Join(l.dir, "ai-audit-*.jsonl"))
	slices.Sort(rotated)
	cur := filepath.Join(l.dir, fileName)
	if _, err := os.Stat(cur); err == nil {
		rotated = append(rotated, cur)
	}
	return rotated
}

// each walks every line in order; a line that does not parse is passed with
// its error and N 0.
func (l *Log) each(fn func(Entry, error) bool) error {
	for _, f := range l.files() {
		fh, err := os.Open(f)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			if len(strings.TrimSpace(sc.Text())) == 0 {
				continue
			}
			var e Entry
			err := json.Unmarshal(sc.Bytes(), &e)
			if !fn(e, err) {
				fh.Close()
				return nil
			}
		}
		err = sc.Err()
		fh.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func hashOf(e Entry) string {
	e.Hash = ""
	data, _ := json.Marshal(e)
	sum := sha256.Sum256(append([]byte(e.Prev), data...))
	return hex.EncodeToString(sum[:])
}

// Append writes one entry; N, TS, Prev and Hash are set here. Free text is
// shortened and secrets in the arguments are cut to four characters.
func (l *Log) Append(e Entry) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.N = l.lastN + 1
	e.TS = time.Now().UTC()
	e.Prev = l.lastHash
	e.Text = cut(e.Text)
	e.Result = cut(e.Result)
	if len(e.Args) > 0 {
		e.Args = redactJSON(e.Args)
	}
	e.Hash = hashOf(e)
	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	cur := filepath.Join(l.dir, fileName)
	f, err := os.OpenFile(cur, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Entry{}, err
	}
	_, err = f.Write(append(line, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Entry{}, err
	}
	l.lastN, l.lastHash = e.N, e.Hash
	if fi, err := os.Stat(cur); err == nil && fi.Size() >= maxSize {
		// The number keeps names unique and sortable within one second.
		name := fmt.Sprintf("ai-audit-%s-%09d.jsonl", e.TS.Format("20060102-150405"), e.N)
		_ = os.Rename(cur, filepath.Join(l.dir, name))
	}
	return e, nil
}

// Verify walks the whole chain. brokenAt is the number of the first entry
// that does not follow from the one before (changed, removed or inserted).
func (l *Log) Verify() (ok bool, brokenAt int64, err error) {
	var prevN int64
	prevHash := ""
	ok = true
	err = l.each(func(e Entry, perr error) bool {
		if perr != nil || e.N != prevN+1 || e.Prev != prevHash || hashOf(e) != e.Hash {
			ok, brokenAt = false, e.N
			if brokenAt == 0 {
				brokenAt = prevN + 1
			}
			return false
		}
		prevN, prevHash = e.N, e.Hash
		return true
	})
	return ok, brokenAt, err
}

// List returns entries newest first, optionally of one chat, and the total.
func (l *Log) List(offset, limit int, chat string) ([]Entry, int, error) {
	var all []Entry
	err := l.each(func(e Entry, perr error) bool {
		if perr == nil && (chat == "" || e.Chat == chat) {
			all = append(all, e)
		}
		return true
	})
	slices.Reverse(all)
	total := len(all)
	if offset > total {
		offset = total
	}
	end := min(offset+limit, total)
	return all[offset:end], total, err
}

// Size is the protocol's total size on disk.
func (l *Log) Size() int64 {
	var n int64
	for _, f := range l.files() {
		if fi, err := os.Stat(f); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// Export writes every file in order, unchanged.
func (l *Log) Export(w io.Writer) error {
	for _, f := range l.files() {
		fh, err := os.Open(f)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, fh)
		fh.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func cut(s string) string {
	r := []rune(s)
	if len(r) <= maxText {
		return s
	}
	return string(r[:maxText]) + "…"
}

// redactJSON shortens string values whose key looks like a credential.
func redactJSON(raw json.RawMessage) json.RawMessage {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return json.RawMessage(`"(keine gültigen Argumente)"`)
	}
	out, err := json.Marshal(redactValue("", v))
	if err != nil {
		return nil
	}
	return out
}

func redactValue(key string, v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = redactValue(k, val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = redactValue(key, val)
		}
		return t
	case string:
		if secretKey(key) && t != "" {
			return accesslog.RedactValue(t)
		}
	}
	return v
}

func secretKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range []string{"key", "token", "secret", "password", "passwd", "credential"} {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}
