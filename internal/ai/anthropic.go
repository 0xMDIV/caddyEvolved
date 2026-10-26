package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// anthropicAPI is Claude through the official SDK. Messages and tools are
// set as JSON so the history can carry Claude's own blocks unchanged.
type anthropicAPI struct {
	client anthropic.Client
	model  string
	base   string
}

func newAnthropic(c Config) *anthropicAPI {
	opts := []option.RequestOption{
		// Never pick up the host's ANTHROPIC_* variables or CLI profiles.
		option.WithoutEnvironmentDefaults(),
		option.WithAPIKey(c.APIKey),
		option.WithRequestTimeout(120 * time.Second),
		option.WithMaxRetries(2),
	}
	if c.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(c.BaseURL))
	}
	model := c.Model
	if model == "" {
		model = DefaultModel
	}
	return &anthropicAPI{client: anthropic.NewClient(opts...), model: model, base: c.BaseURL}
}

// useFallbacks: the server-side refusal fallback exists on the Claude API
// itself; gateways in between may reject the field.
func useFallbacks(base string) bool {
	base = strings.TrimRight(base, "/")
	return base == "" || base == "https://api.anthropic.com"
}

// supportsEffort lists the model families that take output_config.effort.
func supportsEffort(model string) bool {
	for _, p := range []string{"claude-opus-5", "claude-sonnet-5", "claude-haiku-5", "claude-fable-5", "claude-mythos-5", "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6", "claude-sonnet-4-6"} {
		if strings.HasPrefix(model, p) {
			return true
		}
	}
	return false
}

type antMsg struct {
	role    string
	content []any
	raw     json.RawMessage
}

// anthropicMessages turns the neutral history into the Messages API form.
// Tool results and a following user text share one user turn.
func anthropicMessages(history []Message) []json.RawMessage {
	var msgs []antMsg
	add := func(role string, blocks ...any) {
		if n := len(msgs); n > 0 && msgs[n-1].role == role && msgs[n-1].raw == nil {
			msgs[n-1].content = append(msgs[n-1].content, blocks...)
			return
		}
		msgs = append(msgs, antMsg{role: role, content: blocks})
	}
	for _, m := range history {
		switch m.Role {
		case RoleUser:
			add("user", map[string]any{"type": "text", "text": m.Text})
		case RoleTool:
			for _, r := range m.Results {
				add("user", map[string]any{"type": "tool_result", "tool_use_id": r.ID, "content": r.Content, "is_error": r.IsError})
			}
		case RoleAssistant:
			if len(m.Raw) > 0 {
				msgs = append(msgs, antMsg{role: "assistant", raw: m.Raw})
				continue
			}
			var blocks []any
			if m.Text != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": m.Text})
			}
			for _, c := range m.Calls {
				input := c.Args
				if len(input) == 0 {
					input = json.RawMessage("{}")
				}
				blocks = append(blocks, map[string]any{"type": "tool_use", "id": c.ID, "name": c.Name, "input": input})
			}
			if len(blocks) > 0 {
				add("assistant", blocks...)
			}
		}
	}
	out := make([]json.RawMessage, 0, len(msgs))
	for _, m := range msgs {
		if m.raw != nil {
			out = append(out, m.raw)
			continue
		}
		data, _ := json.Marshal(map[string]any{"role": m.role, "content": m.content})
		out = append(out, data)
	}
	return out
}

func (a *anthropicAPI) Turn(ctx context.Context, system string, tools []ToolDef, history []Message) (Message, error) {
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(a.model),
		MaxTokens: 16000,
		System:    []anthropic.TextBlockParam{{Text: system}},
	}
	if supportsEffort(a.model) {
		params.OutputConfig = anthropic.OutputConfigParam{Effort: anthropic.OutputConfigEffort("medium")}
	}
	opts := []option.RequestOption{option.WithJSONSet("messages", anthropicMessages(history))}
	if len(tools) > 0 {
		ts := make([]map[string]any, 0, len(tools))
		for _, t := range tools {
			ts = append(ts, map[string]any{"name": t.Name, "description": t.Description, "input_schema": schemaOrEmpty(t.Schema)})
		}
		opts = append(opts, option.WithJSONSet("tools", ts))
	}
	if useFallbacks(a.base) {
		opts = append(opts,
			option.WithHeaderAdd("anthropic-beta", "server-side-fallback-2026-07-01"),
			option.WithJSONSet("fallbacks", "default"))
	}
	resp, err := a.client.Messages.New(ctx, params, opts...)
	if err != nil {
		return Message{}, providerError(err)
	}
	out := Message{Role: RoleAssistant}
	if raw, err := json.Marshal(resp.ToParam()); err == nil {
		out.Raw = raw
	}
	var texts []string
	for _, b := range resp.Content {
		switch b.Type {
		case "text":
			texts = append(texts, b.Text)
		case "tool_use":
			args := json.RawMessage(b.Input)
			if !json.Valid(args) {
				args = json.RawMessage("{}")
			}
			out.Calls = append(out.Calls, ToolCall{ID: b.ID, Name: b.Name, Args: args})
		}
	}
	out.Text = strings.Join(texts, "\n\n")
	if resp.StopReason == anthropic.StopReasonRefusal {
		why := string(resp.StopDetails.Category)
		if why == "" {
			why = "ohne Angabe"
		}
		out.Text = strings.TrimSpace(out.Text + "\n\nDie KI hat die Anfrage abgelehnt (" + why + ").")
		out.Calls = nil
	}
	return out, nil
}

func (a *anthropicAPI) Models(ctx context.Context) ([]string, error) {
	page, err := a.client.Models.List(ctx, anthropic.ModelListParams{})
	if err != nil {
		return nil, providerError(err)
	}
	out := make([]string, 0, len(page.Data))
	for _, m := range page.Data {
		out = append(out, m.ID)
	}
	return out, nil
}

// providerError keeps the status and the API's message, not the SDK dump.
func providerError(err error) error {
	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) {
		msg := apiErr.Error()
		var body struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal([]byte(apiErr.RawJSON()), &body) == nil && body.Error.Message != "" {
			msg = body.Error.Message
		}
		return fmt.Errorf("KI-Anbieter: HTTP %d: %s", apiErr.StatusCode, msg)
	}
	return fmt.Errorf("KI-Anbieter: %w", err)
}
