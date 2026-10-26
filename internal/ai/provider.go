// Package ai connects caddyEvolved to a language model: an Anthropic or
// OpenAI-compatible provider, a chat store, and the engine that runs a turn
// and stops at every change until the user approves it.
package ai

import (
	"context"
	"encoding/json"
	"errors"
)

// Roles in the provider-neutral history.
const (
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool" // results of the previous assistant message's calls
)

// ToolCall is one function call the model asked for.
type ToolCall struct {
	ID   string          `json:"id"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

// ToolResult answers one ToolCall.
type ToolResult struct {
	ID      string `json:"id"`
	Content string `json:"content"`
	IsError bool   `json:"isError,omitempty"`
}

// Message is one entry of the conversation, the same for every provider.
type Message struct {
	Role    string       `json:"role"`
	Text    string       `json:"text,omitempty"`
	Calls   []ToolCall   `json:"calls,omitempty"`
	Results []ToolResult `json:"results,omitempty"`
	// Raw is the provider's own form of an assistant message. It goes back
	// unchanged on the next request: Claude's thinking blocks are only
	// valid byte for byte.
	Raw json.RawMessage `json:"raw,omitempty"`
}

// ToolDef describes a tool to the model.
type ToolDef struct {
	Name        string
	Description string
	Schema      map[string]any
}

// Provider runs one model turn.
type Provider interface {
	Turn(ctx context.Context, system string, tools []ToolDef, history []Message) (Message, error)
	Models(ctx context.Context) ([]string, error)
}

// NewProvider builds the client for a configuration.
func NewProvider(c Config) (Provider, error) {
	switch c.Kind {
	case KindAnthropic:
		return newAnthropic(c), nil
	case KindOpenAI:
		return newOpenAI(c), nil
	}
	return nil, errors.New("KI-Anbieter nicht eingerichtet")
}

func schemaOrEmpty(s map[string]any) map[string]any {
	if s == nil {
		return map[string]any{"type": "object", "properties": map[string]any{}}
	}
	return s
}
