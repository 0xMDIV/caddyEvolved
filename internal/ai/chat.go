package ai

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"caddyevolved/internal/aiaudit"
)

// Proposal states.
const (
	StatePending  = "pending"
	StateApproved = "approved"
	StateRejected = "rejected"
	StateExpired  = "expired"
)

// ToolWriteLog lets the AI write its own account into the protocol. It can
// only append; reading or removing entries is no tool.
const ToolWriteLog = "write_ai_log"

const (
	maxRounds   = 12        // model turns per user message
	proposalTTL = time.Hour // undecided proposals expire
	maxShown    = 2000      // characters of a tool result kept for display
)

var (
	ErrDecided  = errors.New("Über diesen Vorschlag wurde schon entschieden")
	ErrExpired  = errors.New("Der Vorschlag ist verfallen – es wurde nichts ausgeführt")
	ErrNotFound = errors.New("Nicht gefunden")
)

// Proposal is a change the AI wants to make, waiting for the user.
type Proposal struct {
	ID      string          `json:"id"`
	CallID  string          `json:"callId"`
	Tool    string          `json:"tool"`
	Args    json.RawMessage `json:"args,omitempty"`
	Summary string          `json:"summary,omitempty"` // what the AI said along with it
	Method  string          `json:"method"`
	Path    string          `json:"path"`
	Created time.Time       `json:"created"`
	State   string          `json:"state"`
	Result  string          `json:"result,omitempty"`
	Failed  bool            `json:"failed,omitempty"` // approved, but the request was refused
	Decided time.Time       `json:"decided,omitzero"`
}

// DisplayItem is what the chat window shows; the history is for the model.
type DisplayItem struct {
	Kind       string    `json:"kind"` // user | assistant | tool | proposal | error
	Text       string    `json:"text,omitempty"`
	Tool       string    `json:"tool,omitempty"`
	ProposalID string    `json:"proposalId,omitempty"`
	IsError    bool      `json:"isError,omitempty"`
	TS         time.Time `json:"ts"`
}

// Chat is one conversation.
type Chat struct {
	ID        string        `json:"id"`
	Title     string        `json:"title"`
	Created   time.Time     `json:"created"`
	Updated   time.Time     `json:"updated"`
	History   []Message     `json:"history"`
	Proposals []Proposal    `json:"proposals"`
	Display   []DisplayItem `json:"display"`
	// Round holds the call IDs of the last assistant message while some of
	// them wait for a decision; Partial the results collected so far.
	Round   []string     `json:"round,omitempty"`
	Partial []ToolResult `json:"partial,omitempty"`

	boot time.Time // daemon start: proposals from before it expired
}

// ChatSummary is one row of the chat list.
type ChatSummary struct {
	ID      string    `json:"id"`
	Title   string    `json:"title"`
	Updated time.Time `json:"updated"`
	Pending int       `json:"pending"`
}

// Pending counts the proposals waiting for a decision.
func (c *Chat) Pending() int {
	n := 0
	for _, p := range c.Proposals {
		if p.State == StatePending {
			n++
		}
	}
	return n
}

func (c *Chat) expired(p Proposal) bool {
	return p.State == StatePending && (p.Created.Before(c.boot) || time.Since(p.Created) > proposalTTL)
}

func (c *Chat) show(kind, text string, mod func(*DisplayItem)) {
	d := DisplayItem{Kind: kind, Text: text, TS: time.Now().UTC()}
	if mod != nil {
		mod(&d)
	}
	c.Display = append(c.Display, d)
}

func (c *Chat) addResult(callID, content string, isErr bool) {
	c.Partial = append(c.Partial, ToolResult{ID: callID, Content: content, IsError: isErr})
}

// closeRound answers the open calls in one tool message, in call order.
func (c *Chat) closeRound() {
	if len(c.Round) == 0 {
		return
	}
	res := make([]ToolResult, 0, len(c.Round))
	for _, id := range c.Round {
		for _, r := range c.Partial {
			if r.ID == id {
				res = append(res, r)
				break
			}
		}
	}
	c.History = append(c.History, Message{Role: RoleTool, Results: res})
	c.Round, c.Partial = nil, nil
}

// ---------- store ----------

// Store keeps chats as JSON files, one per chat.
type Store struct {
	dir  string
	boot time.Time

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

var reChatID = regexp.MustCompile(`^[a-f0-9]{16}$`)

// NewStore keeps chats in dir; boot is the daemon start.
func NewStore(dir string, boot time.Time) *Store {
	return &Store{dir: dir, boot: boot, locks: map[string]*sync.Mutex{}}
}

// Lock serialises work on one chat; call the returned function to release.
func (s *Store) Lock(id string) func() {
	s.mu.Lock()
	l, ok := s.locks[id]
	if !ok {
		l = &sync.Mutex{}
		s.locks[id] = l
	}
	s.mu.Unlock()
	l.Lock()
	return l.Unlock
}

func (s *Store) path(id string) (string, error) {
	if !reChatID.MatchString(id) {
		return "", ErrNotFound
	}
	return filepath.Join(s.dir, id+".json"), nil
}

// Create starts an empty chat (not yet saved).
func (s *Store) Create() (*Chat, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &Chat{ID: hex.EncodeToString(b), Title: "Neuer Chat", Created: now, Updated: now, boot: s.boot}, nil
}

// Get loads a chat.
func (s *Store) Get(id string) (*Chat, error) {
	p, err := s.path(id)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var c Chat
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	c.boot = s.boot
	return &c, nil
}

// Save writes a chat (0600, the history may quote configuration).
func (s *Store) Save(c *Chat) error {
	p, err := s.path(c.ID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	c.Updated = time.Now().UTC()
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Delete removes a chat. The protocol keeps its entries.
func (s *Store) Delete(id string) error {
	p, err := s.path(id)
	if err != nil {
		return err
	}
	if err := os.Remove(p); errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	} else {
		return err
	}
}

// List returns the chats, most recent first.
func (s *Store) List() ([]ChatSummary, error) {
	files, _ := filepath.Glob(filepath.Join(s.dir, "*.json"))
	out := []ChatSummary{}
	for _, f := range files {
		c, err := s.Get(strings.TrimSuffix(filepath.Base(f), ".json"))
		if err != nil {
			continue
		}
		out = append(out, ChatSummary{ID: c.ID, Title: c.Title, Updated: c.Updated, Pending: c.Pending()})
	}
	slices.SortFunc(out, func(a, b ChatSummary) int { return b.Updated.Compare(a.Updated) })
	return out, nil
}

// ---------- engine ----------

// ToolSpec is a tool the executor offers.
type ToolSpec struct {
	Name        string
	Description string
	Schema      map[string]any
	ReadOnly    bool
}

// RunResult is what one tool call did.
type RunResult struct {
	Text    string
	IsError bool
	Method  string
	Path    string
	Status  int
}

// Executor runs tools against caddyEvolved with the user's own session.
type Executor interface {
	Tools() []ToolSpec
	Run(ctx context.Context, tool string, args json.RawMessage) RunResult
	// Describe names the request a call would make, without making it.
	Describe(tool string, args json.RawMessage) (method, path string, err error)
}

// Engine runs a conversation. Reads run at once; every change becomes a
// proposal and runs only after Decide with approve – nothing else can run
// it. The protocol gets every request, proposal, decision and execution.
type Engine struct {
	Provider Provider
	Exec     Executor
	Audit    *aiaudit.Log
	Actor    string // who sits at the keyboard, for the protocol
	Model    string
	System   string // what the AI should know about caddyEvolved
}

const rules = `Antworte auf Deutsch, knapp und konkret.
Lesende Werkzeuge laufen sofort. Jedes ändernde Werkzeug wird NICHT ausgeführt, sondern dem Nutzer als Vorschlag gezeigt; erst seine Freigabe führt es aus. Sage vor jedem ändernden Aufruf in einem Satz, was du tun willst und warum.
Ein abgelehnter Vorschlag ist eine Entscheidung des Nutzers: versuche ihn nicht auf anderem Weg.
Halte nach Änderungen mit write_ai_log fest, was du getan hast und warum.`

func (e *Engine) system(page string) string {
	s := strings.TrimSpace(e.System + "\n\n" + rules)
	if page != "" {
		s += "\n\nDer Nutzer ist gerade auf der Seite: " + page
	}
	return s
}

func (e *Engine) tools() ([]ToolDef, map[string]ToolSpec) {
	specs := map[string]ToolSpec{}
	var defs []ToolDef
	for _, t := range e.Exec.Tools() {
		specs[t.Name] = t
		desc := t.Description
		if !t.ReadOnly {
			desc += " (Änderung: braucht die Freigabe des Nutzers)"
		}
		defs = append(defs, ToolDef{Name: t.Name, Description: desc, Schema: t.Schema})
	}
	defs = append(defs, ToolDef{
		Name:        ToolWriteLog,
		Description: "Write a short entry into the tamper-evident AI protocol: what you did and why. Append-only.",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"text": map[string]any{"type": "string", "description": "what was done and why"},
		}, "required": []string{"text"}},
	})
	return defs, specs
}

func (e *Engine) audit(c *Chat, en aiaudit.Entry) {
	if e.Audit == nil {
		return
	}
	en.Chat, en.Actor, en.Model = c.ID, e.Actor, e.Model
	_, _ = e.Audit.Append(en)
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// settleOpen expires stale proposals and, when the user writes again while
// some still wait, treats them as declined: the new message takes over.
func (e *Engine) settleOpen(c *Chat) {
	for i := range c.Proposals {
		p := &c.Proposals[i]
		if p.State != StatePending {
			continue
		}
		p.Decided = time.Now().UTC()
		if c.expired(*p) {
			p.State = StateExpired
			e.audit(c, aiaudit.Entry{Kind: aiaudit.KindExpired, Tool: p.Tool, Args: p.Args, Method: p.Method, Path: p.Path})
			c.addResult(p.CallID, "Vorschlag verfallen – nicht ausgeführt.", true)
			continue
		}
		p.State = StateRejected
		e.audit(c, aiaudit.Entry{Kind: aiaudit.KindRejected, Tool: p.Tool, Args: p.Args, Method: p.Method, Path: p.Path, Text: "Nutzer hat stattdessen weitergeschrieben"})
		c.addResult(p.CallID, "Nicht ausgeführt – der Nutzer hat stattdessen weitergeschrieben.", true)
	}
	c.closeRound()
}

// Send adds the user's message and runs the model until it is done or
// waits for a decision.
func (e *Engine) Send(ctx context.Context, c *Chat, text, page string) error {
	e.settleOpen(c)
	text = strings.TrimSpace(text)
	if c.Title == "" || c.Title == "Neuer Chat" {
		c.Title = clip(strings.ReplaceAll(text, "\n", " "), 60)
	}
	c.History = append(c.History, Message{Role: RoleUser, Text: text})
	c.show("user", text, nil)
	e.audit(c, aiaudit.Entry{Kind: aiaudit.KindRequest, Text: text, Path: page})
	return e.loop(ctx, c, page)
}

func (e *Engine) loop(ctx context.Context, c *Chat, page string) error {
	defs, specs := e.tools()
	for range maxRounds {
		msg, err := e.Provider.Turn(ctx, e.system(page), defs, c.History)
		if err != nil {
			c.show("error", err.Error(), nil)
			return err
		}
		c.History = append(c.History, msg)
		if strings.TrimSpace(msg.Text) != "" {
			c.show("assistant", msg.Text, nil)
		}
		if len(msg.Calls) == 0 {
			return nil
		}
		c.Round, c.Partial = nil, nil
		for _, call := range msg.Calls {
			c.Round = append(c.Round, call.ID)
			e.handleCall(ctx, c, call, specs, msg.Text)
		}
		if c.Pending() > 0 {
			return nil
		}
		c.closeRound()
	}
	c.show("error", "Abgebrochen: zu viele Schritte ohne Ergebnis.", nil)
	return nil
}

func (e *Engine) handleCall(ctx context.Context, c *Chat, call ToolCall, specs map[string]ToolSpec, said string) {
	if call.Name == ToolWriteLog {
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(call.Args, &in)
		e.audit(c, aiaudit.Entry{Kind: aiaudit.KindNote, Text: in.Text})
		c.addResult(call.ID, "Im Protokoll festgehalten.", false)
		c.show("tool", "Protokoll: "+clip(in.Text, 200), func(d *DisplayItem) { d.Tool = call.Name })
		return
	}
	spec, ok := specs[call.Name]
	if !ok {
		c.addResult(call.ID, "Unbekanntes Werkzeug "+call.Name, true)
		return
	}
	if spec.ReadOnly {
		r := e.Exec.Run(ctx, call.Name, call.Args)
		e.audit(c, aiaudit.Entry{Kind: aiaudit.KindExecuted, Tool: call.Name, Args: call.Args, Method: r.Method, Path: r.Path, Status: r.Status, Result: r.Text})
		c.addResult(call.ID, r.Text, r.IsError)
		c.show("tool", clip(r.Text, maxShown), func(d *DisplayItem) { d.Tool, d.IsError = call.Name, r.IsError })
		return
	}
	method, path, err := e.Exec.Describe(call.Name, call.Args)
	if err != nil {
		c.addResult(call.ID, "Argumentfehler: "+err.Error(), true)
		c.show("tool", "Argumentfehler: "+err.Error(), func(d *DisplayItem) { d.Tool, d.IsError = call.Name, true })
		return
	}
	id := make([]byte, 6)
	_, _ = rand.Read(id)
	p := Proposal{
		ID: hex.EncodeToString(id), CallID: call.ID, Tool: call.Name, Args: call.Args, Summary: strings.TrimSpace(said),
		Method: method, Path: path, Created: time.Now().UTC(), State: StatePending,
	}
	c.Proposals = append(c.Proposals, p)
	e.audit(c, aiaudit.Entry{Kind: aiaudit.KindProposal, Tool: p.Tool, Args: p.Args, Method: method, Path: path, Text: p.Summary})
	c.show("proposal", p.Summary, func(d *DisplayItem) { d.Tool, d.ProposalID = call.Name, p.ID })
}

// Decide approves or declines one proposal. Once every proposal of the
// round is decided, the results go back to the model and it continues.
func (e *Engine) Decide(ctx context.Context, c *Chat, proposalID string, approve bool) error {
	i := slices.IndexFunc(c.Proposals, func(p Proposal) bool { return p.ID == proposalID })
	if i < 0 {
		return ErrNotFound
	}
	p := &c.Proposals[i]
	if p.State != StatePending {
		return ErrDecided
	}
	p.Decided = time.Now().UTC()
	entry := aiaudit.Entry{Tool: p.Tool, Args: p.Args, Method: p.Method, Path: p.Path}
	switch {
	case c.expired(*p):
		p.State = StateExpired
		entry.Kind = aiaudit.KindExpired
		e.audit(c, entry)
		c.addResult(p.CallID, "Vorschlag verfallen – nicht ausgeführt.", true)
		if c.Pending() == 0 {
			c.closeRound()
		}
		return ErrExpired
	case approve:
		entry.Kind = aiaudit.KindApproved
		e.audit(c, entry)
		r := e.Exec.Run(ctx, p.Tool, p.Args)
		p.State, p.Result, p.Failed = StateApproved, clip(r.Text, maxShown), r.IsError
		entry.Kind, entry.Status, entry.Result = aiaudit.KindExecuted, r.Status, r.Text
		entry.Method, entry.Path = r.Method, r.Path
		e.audit(c, entry)
		c.addResult(p.CallID, r.Text, r.IsError)
	default:
		entry.Kind = aiaudit.KindRejected
		e.audit(c, entry)
		p.State = StateRejected
		c.addResult(p.CallID, "Vom Nutzer abgelehnt – nicht ausgeführt.", true)
	}
	if c.Pending() > 0 {
		return nil
	}
	c.closeRound()
	return e.loop(ctx, c, "")
}
