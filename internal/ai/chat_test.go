package ai

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"caddyevolved/internal/aiaudit"
)

type fakeProvider struct {
	replies []Message
	seen    [][]Message
}

func (f *fakeProvider) Turn(_ context.Context, _ string, _ []ToolDef, h []Message) (Message, error) {
	f.seen = append(f.seen, slices.Clone(h))
	if len(f.replies) == 0 {
		return Message{Role: RoleAssistant, Text: "fertig"}, nil
	}
	r := f.replies[0]
	f.replies = f.replies[1:]
	return r, nil
}

func (f *fakeProvider) Models(context.Context) ([]string, error) { return nil, nil }

type fakeExec struct{ ran []string }

func (f *fakeExec) Tools() []ToolSpec {
	return []ToolSpec{{Name: "list_sites", ReadOnly: true}, {Name: "delete_site"}}
}

func (f *fakeExec) Run(_ context.Context, tool string, _ json.RawMessage) RunResult {
	f.ran = append(f.ran, tool)
	return RunResult{Text: "ok " + tool, Method: "GET", Path: "/api/x", Status: 200}
}

func (f *fakeExec) Describe(string, json.RawMessage) (string, string, error) {
	return "DELETE", "/api/sites/x", nil
}

func call(id, name, args string) ToolCall {
	return ToolCall{ID: id, Name: name, Args: json.RawMessage(args)}
}

func setup(t *testing.T, replies ...Message) (*Engine, *fakeProvider, *fakeExec, *Store, *aiaudit.Log) {
	t.Helper()
	log, err := aiaudit.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p, x := &fakeProvider{replies: replies}, &fakeExec{}
	st := NewStore(t.TempDir(), time.Now().Add(-time.Minute))
	return &Engine{Provider: p, Exec: x, Audit: log, Actor: "session abcd", Model: "test"}, p, x, st, log
}

func kinds(l *aiaudit.Log) []string {
	e, _, _ := l.List(0, 100, "")
	var k []string
	for i := len(e) - 1; i >= 0; i-- {
		k = append(k, e[i].Kind)
	}
	return k
}

// toolMessages returns the tool-result messages of the history.
func toolMessages(c *Chat) []Message {
	var out []Message
	for _, m := range c.History {
		if m.Role == RoleTool {
			out = append(out, m)
		}
	}
	return out
}

func TestReadToolRunsWithoutApproval(t *testing.T) {
	e, _, x, st, _ := setup(t, Message{Role: RoleAssistant, Calls: []ToolCall{call("1", "list_sites", `{}`)}})
	c, _ := st.Create()
	if err := e.Send(context.Background(), c, "zeig sites", "/sites"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(x.ran, []string{"list_sites"}) {
		t.Fatalf("ran %v", x.ran)
	}
	tm := toolMessages(c)
	if len(tm) != 1 || tm[0].Results[0].Content != "ok list_sites" || c.History[len(c.History)-1].Text != "fertig" {
		t.Fatalf("history %+v", c.History)
	}
}

func TestWriteToolBecomesProposal(t *testing.T) {
	e, p, x, st, log := setup(t, Message{Role: RoleAssistant, Text: "Ich lösche x.", Calls: []ToolCall{call("1", "delete_site", `{"id":"x"}`)}})
	c, _ := st.Create()
	e.Send(context.Background(), c, "lösch x", "")
	if len(x.ran) != 0 || len(c.Proposals) != 1 || c.Proposals[0].State != StatePending || c.Proposals[0].Method != "DELETE" || c.Proposals[0].Summary != "Ich lösche x." {
		t.Fatalf("ran %v proposals %+v", x.ran, c.Proposals)
	}
	if len(p.seen) != 1 {
		t.Fatalf("Schleife lief ohne Freigabe weiter: %d Runden", len(p.seen))
	}
	if !slices.Contains(kinds(log), aiaudit.KindProposal) {
		t.Fatalf("audit %v", kinds(log))
	}
}

func TestApproveRunsAndContinues(t *testing.T) {
	e, _, x, st, log := setup(t, Message{Role: RoleAssistant, Calls: []ToolCall{call("1", "delete_site", `{"id":"x"}`)}})
	c, _ := st.Create()
	e.Send(context.Background(), c, "lösch x", "")
	if err := e.Decide(context.Background(), c, c.Proposals[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(x.ran, []string{"delete_site"}) || c.Proposals[0].State != StateApproved || c.History[len(c.History)-1].Text != "fertig" {
		t.Fatalf("ran %v state %s last %+v", x.ran, c.Proposals[0].State, c.History[len(c.History)-1])
	}
	k := kinds(log)
	if !slices.Contains(k, aiaudit.KindApproved) || !slices.Contains(k, aiaudit.KindExecuted) {
		t.Fatalf("audit %v", k)
	}
}

func TestRejectSendsErrorResult(t *testing.T) {
	e, _, x, st, _ := setup(t, Message{Role: RoleAssistant, Calls: []ToolCall{call("1", "delete_site", `{"id":"x"}`)}})
	c, _ := st.Create()
	e.Send(context.Background(), c, "lösch x", "")
	e.Decide(context.Background(), c, c.Proposals[0].ID, false)
	tm := toolMessages(c)
	if len(x.ran) != 0 || len(tm) != 1 || !tm[0].Results[0].IsError || tm[0].Results[0].Content != "Vom Nutzer abgelehnt – nicht ausgeführt." {
		t.Fatalf("ran %v tool %+v", x.ran, tm)
	}
}

func TestMixedReadWriteSingleResultMessage(t *testing.T) {
	e, _, x, st, _ := setup(t, Message{Role: RoleAssistant, Calls: []ToolCall{call("a", "list_sites", `{}`), call("b", "delete_site", `{"id":"x"}`)}})
	c, _ := st.Create()
	e.Send(context.Background(), c, "aufräumen", "")
	if !slices.Equal(x.ran, []string{"list_sites"}) || len(toolMessages(c)) != 0 {
		t.Fatalf("vor Freigabe: ran %v tool %d", x.ran, len(toolMessages(c)))
	}
	e.Decide(context.Background(), c, c.Proposals[0].ID, true)
	tm := toolMessages(c)
	if len(tm) != 1 || len(tm[0].Results) != 2 || tm[0].Results[0].ID != "a" || tm[0].Results[1].ID != "b" {
		t.Fatalf("tool messages %+v", tm)
	}
}

func TestDecideTwiceConflict(t *testing.T) {
	e, _, _, st, _ := setup(t, Message{Role: RoleAssistant, Calls: []ToolCall{call("1", "delete_site", `{}`)}})
	c, _ := st.Create()
	e.Send(context.Background(), c, "x", "")
	id := c.Proposals[0].ID
	e.Decide(context.Background(), c, id, true)
	if err := e.Decide(context.Background(), c, id, true); !errors.Is(err, ErrDecided) {
		t.Fatalf("zweites Decide: %v", err)
	}
}

func TestExpiredProposalNotRun(t *testing.T) {
	e, _, x, st, log := setup(t, Message{Role: RoleAssistant, Calls: []ToolCall{call("1", "delete_site", `{}`)}})
	c, _ := st.Create()
	e.Send(context.Background(), c, "x", "")
	st.Save(c)
	later := NewStore(st.dir, time.Now().Add(time.Second)) // daemon restarted
	c2, err := later.Get(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Decide(context.Background(), c2, c2.Proposals[0].ID, true); !errors.Is(err, ErrExpired) {
		t.Fatalf("Decide: %v", err)
	}
	if len(x.ran) != 0 || c2.Proposals[0].State != StateExpired || !slices.Contains(kinds(log), aiaudit.KindExpired) {
		t.Fatalf("ran %v state %s", x.ran, c2.Proposals[0].State)
	}
}

func TestSendAfterExpiryClosesOpenCalls(t *testing.T) {
	e, p, _, st, _ := setup(t, Message{Role: RoleAssistant, Calls: []ToolCall{call("1", "delete_site", `{}`)}})
	c, _ := st.Create()
	e.Send(context.Background(), c, "x", "")
	c.Proposals[0].Created = time.Now().Add(-2 * time.Hour)
	e.Send(context.Background(), c, "neue Frage", "")
	last := p.seen[len(p.seen)-1]
	var sawTool bool
	for _, m := range last {
		if m.Role == RoleTool && m.Results[0].ID == "1" && m.Results[0].IsError {
			sawTool = true
		}
	}
	if !sawTool || c.Proposals[0].State != StateExpired {
		t.Fatalf("offener Aufruf nicht geschlossen: %+v", last)
	}
}

func TestWriteAILogNote(t *testing.T) {
	e, _, _, st, log := setup(t, Message{Role: RoleAssistant, Calls: []ToolCall{call("1", ToolWriteLog, `{"text":"Site x gelöscht, weil ungenutzt"}`)}})
	c, _ := st.Create()
	e.Send(context.Background(), c, "x", "")
	entries, _, _ := log.List(0, 10, c.ID)
	var note string
	for _, en := range entries {
		if en.Kind == aiaudit.KindNote {
			note = en.Text
		}
	}
	if note != "Site x gelöscht, weil ungenutzt" {
		t.Fatalf("note %q", note)
	}
}

func TestUnknownToolIsError(t *testing.T) {
	e, _, x, st, _ := setup(t, Message{Role: RoleAssistant, Calls: []ToolCall{call("1", "rm_rf", `{}`)}})
	c, _ := st.Create()
	e.Send(context.Background(), c, "x", "")
	tm := toolMessages(c)
	if len(x.ran) != 0 || len(tm) != 1 || !tm[0].Results[0].IsError {
		t.Fatalf("unbekanntes Werkzeug: ran %v tool %+v", x.ran, tm)
	}
}

func TestStoreListDelete(t *testing.T) {
	st := NewStore(t.TempDir(), time.Now())
	c, _ := st.Create()
	c.Title = "Hallo"
	st.Save(c)
	l, _ := st.List()
	if len(l) != 1 || l[0].Title != "Hallo" {
		t.Fatalf("list %+v", l)
	}
	if err := st.Delete(c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(c.ID); err == nil {
		t.Fatal("gelöscht, aber noch da")
	}
	if _, err := st.Get("../../etc/passwd"); err == nil {
		t.Fatal("Pfad außerhalb angenommen")
	}
}
