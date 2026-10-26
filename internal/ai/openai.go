package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// openAI speaks /chat/completions, which OpenRouter, Requesty, Ollama,
// LM Studio and most gateways offer.
type openAI struct {
	base, key, model string
	client           *http.Client
}

func newOpenAI(c Config) *openAI {
	return &openAI{
		base: strings.TrimRight(c.BaseURL, "/"), key: c.APIKey, model: c.Model,
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

type oaFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type oaToolCall struct {
	ID       string     `json:"id"`
	Type     string     `json:"type"`
	Function oaFunction `json:"function"`
}

type oaMessage struct {
	Role       string       `json:"role"`
	Content    *string      `json:"content"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

func strPtr(s string) *string { return &s }

func (o *openAI) messages(system string, history []Message) []oaMessage {
	out := []oaMessage{{Role: "system", Content: strPtr(system)}}
	for _, m := range history {
		switch m.Role {
		case RoleUser:
			out = append(out, oaMessage{Role: "user", Content: strPtr(m.Text)})
		case RoleAssistant:
			am := oaMessage{Role: "assistant"}
			if m.Text != "" || len(m.Calls) == 0 {
				am.Content = strPtr(m.Text)
			}
			for _, c := range m.Calls {
				args := string(c.Args)
				if args == "" {
					args = "{}"
				}
				am.ToolCalls = append(am.ToolCalls, oaToolCall{ID: c.ID, Type: "function", Function: oaFunction{Name: c.Name, Arguments: args}})
			}
			out = append(out, am)
		case RoleTool:
			for _, r := range m.Results {
				out = append(out, oaMessage{Role: "tool", ToolCallID: r.ID, Content: strPtr(r.Content)})
			}
		}
	}
	return out
}

func (o *openAI) do(ctx context.Context, method, path string, body any, into any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, o.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.key != "" {
		req.Header.Set("Authorization", "Bearer "+o.key)
	}
	// OpenRouter shows the app name in its dashboard.
	req.Header.Set("X-Title", "caddyEvolved")
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		msg := strings.TrimSpace(string(data))
		if json.Unmarshal(data, &e) == nil && e.Error.Message != "" {
			msg = e.Error.Message
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("KI-Anbieter: HTTP %d: %s", resp.StatusCode, msg)
	}
	return json.Unmarshal(data, into)
}

func (o *openAI) Turn(ctx context.Context, system string, tools []ToolDef, history []Message) (Message, error) {
	req := map[string]any{"model": o.model, "messages": o.messages(system, history)}
	if len(tools) > 0 {
		var ts []map[string]any
		for _, t := range tools {
			ts = append(ts, map[string]any{"type": "function", "function": map[string]any{
				"name": t.Name, "description": t.Description, "parameters": schemaOrEmpty(t.Schema),
			}})
		}
		req["tools"] = ts
	}
	var resp struct {
		Choices []struct {
			Message oaMessage `json:"message"`
		} `json:"choices"`
	}
	if err := o.do(ctx, http.MethodPost, "/chat/completions", req, &resp); err != nil {
		return Message{}, err
	}
	if len(resp.Choices) == 0 {
		return Message{}, fmt.Errorf("KI-Anbieter: leere Antwort")
	}
	m := resp.Choices[0].Message
	out := Message{Role: RoleAssistant}
	if m.Content != nil {
		out.Text = *m.Content
	}
	for _, c := range m.ToolCalls {
		args := json.RawMessage(c.Function.Arguments)
		if !json.Valid(args) {
			args = json.RawMessage("{}")
		}
		out.Calls = append(out.Calls, ToolCall{ID: c.ID, Name: c.Function.Name, Args: args})
	}
	return out, nil
}

func (o *openAI) Models(ctx context.Context) ([]string, error) {
	var resp struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := o.do(ctx, http.MethodGet, "/models", nil, &resp); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(resp.Data))
	for _, d := range resp.Data {
		out = append(out, d.ID)
	}
	return out, nil
}
