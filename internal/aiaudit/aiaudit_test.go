package aiaudit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func open(t *testing.T, dir string) *Log {
	t.Helper()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestAppendChain(t *testing.T) {
	l := open(t, t.TempDir())
	var prev string
	for i, k := range []string{KindRequest, KindProposal, KindApproved} {
		e, err := l.Append(Entry{Chat: "c1", Actor: "session abcd", Kind: k, Text: "x"})
		if err != nil {
			t.Fatal(err)
		}
		if e.N != int64(i+1) || e.Prev != prev || e.Hash == "" || e.TS.IsZero() {
			t.Fatalf("Eintrag %d: %+v", i, e)
		}
		prev = e.Hash
	}
	if ok, at, err := l.Verify(); !ok || at != 0 || err != nil {
		t.Fatalf("Verify: %v %d %v", ok, at, err)
	}
	entries, total, err := l.List(0, 10, "")
	if err != nil || total != 3 || entries[0].N != 3 {
		t.Fatalf("List: %v %d %v", entries, total, err)
	}
	if e, total, _ := l.List(0, 10, "anderer"); total != 0 || len(e) != 0 {
		t.Fatalf("Filter: %d", total)
	}
}

func TestTamperDetected(t *testing.T) {
	dir := t.TempDir()
	l := open(t, dir)
	for i := 0; i < 3; i++ {
		l.Append(Entry{Kind: KindNote, Text: "eintrag"})
	}
	p := filepath.Join(dir, fileName)
	data, _ := os.ReadFile(p)
	lines := strings.Split(string(data), "\n")
	lines[1] = strings.Replace(lines[1], "eintrag", "gefälscht", 1)
	os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o600)
	if ok, at, _ := open(t, dir).Verify(); ok || at != 2 {
		t.Fatalf("Manipulation nicht erkannt: ok=%v at=%d", ok, at)
	}
}

func TestDeletedLineDetected(t *testing.T) {
	dir := t.TempDir()
	l := open(t, dir)
	for i := 0; i < 3; i++ {
		l.Append(Entry{Kind: KindNote, Text: "eintrag"})
	}
	p := filepath.Join(dir, fileName)
	data, _ := os.ReadFile(p)
	lines := strings.Split(string(data), "\n")
	os.WriteFile(p, []byte(lines[0]+"\n"+lines[2]+"\n"), 0o600)
	if ok, at, _ := open(t, dir).Verify(); ok || at != 3 {
		t.Fatalf("Löschung nicht erkannt: ok=%v at=%d", ok, at)
	}
}

func TestRotationKeepsChain(t *testing.T) {
	old := maxSize
	maxSize = 300
	defer func() { maxSize = old }()
	dir := t.TempDir()
	l := open(t, dir)
	for i := 0; i < 6; i++ {
		if _, err := l.Append(Entry{Kind: KindNote, Text: strings.Repeat("x", 80)}); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "ai-audit*.jsonl"))
	if len(files) < 2 {
		t.Fatalf("keine Rotation: %v", files)
	}
	if ok, at, err := open(t, dir).Verify(); !ok {
		t.Fatalf("Kette über Dateien gebrochen bei %d: %v", at, err)
	}
	_, total, _ := l.List(0, 100, "")
	if total != 6 {
		t.Fatalf("total %d", total)
	}
	var buf bytes.Buffer
	if err := l.Export(&buf); err != nil || strings.Count(buf.String(), "\n") != 6 {
		t.Fatalf("Export: %v %q", err, buf.String())
	}
}

func TestConcurrentAppend(t *testing.T) {
	l := open(t, t.TempDir())
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Append(Entry{Kind: KindNote, Text: "parallel"})
		}()
	}
	wg.Wait()
	if ok, at, _ := l.Verify(); !ok {
		t.Fatalf("Kette gebrochen bei %d", at)
	}
	if e, total, _ := l.List(0, 1, ""); total != 50 || e[0].N != 50 {
		t.Fatalf("N nicht lückenlos: %d %v", total, e)
	}
}

func TestReopenContinues(t *testing.T) {
	dir := t.TempDir()
	open(t, dir).Append(Entry{Kind: KindNote, Text: "eins"})
	e, _ := open(t, dir).Append(Entry{Kind: KindNote, Text: "zwei"})
	if e.N != 2 || e.Prev == "" {
		t.Fatalf("nicht fortgesetzt: %+v", e)
	}
	if ok, _, _ := open(t, dir).Verify(); !ok {
		t.Fatal("Kette nach Neustart gebrochen")
	}
}

func TestArgsRedactedAndCut(t *testing.T) {
	l := open(t, t.TempDir())
	e, _ := l.Append(Entry{Kind: KindProposal, Args: json.RawMessage(`{"apiKey":"sk-abcdefghijkl","nested":{"password":"geheimgeheim"},"name":"site1"}`), Text: strings.Repeat("ä", 5000)})
	s := string(e.Args)
	if strings.Contains(s, "abcdefghijkl") || strings.Contains(s, "geheimgeheim") || !strings.Contains(s, "sk-a******") || !strings.Contains(s, "site1") {
		t.Fatalf("Args: %s", s)
	}
	if n := len([]rune(e.Text)); n > maxText+1 {
		t.Fatalf("Text nicht gekürzt: %d", n)
	}
}
