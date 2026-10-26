package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIRoundTrip(t *testing.T) {
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer sk-test" {
			t.Errorf("request %s %s", r.URL.Path, r.Header.Get("Authorization"))
		}
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		bodies = append(bodies, b)
		if len(bodies) == 1 {
			io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"list_sites","arguments":"{\"x\":1}"}}]}}]}`)
			return
		}
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"Zwei Sites."}}]}`)
	}))
	defer srv.Close()
	p, _ := NewProvider(Config{Kind: KindOpenAI, BaseURL: srv.URL + "/v1/", APIKey: "sk-test", Model: "m"})
	tools := []ToolDef{{Name: "list_sites", Description: "d", Schema: map[string]any{"type": "object"}}}
	hist := []Message{{Role: RoleUser, Text: "hi"}}
	m, err := p.Turn(context.Background(), "sys", tools, hist)
	if err != nil || len(m.Calls) != 1 || m.Calls[0].ID != "call_1" || string(m.Calls[0].Args) != `{"x":1}` {
		t.Fatalf("turn 1: %+v %v", m, err)
	}
	b := bodies[0]
	msgs := b["messages"].([]any)
	if msgs[0].(map[string]any)["role"] != "system" || b["tools"].([]any)[0].(map[string]any)["type"] != "function" {
		t.Fatalf("body 1: %v", b)
	}
	hist = append(hist, m, Message{Role: RoleTool, Results: []ToolResult{{ID: "call_1", Content: "[a,b]"}}})
	m, err = p.Turn(context.Background(), "sys", tools, hist)
	if err != nil || m.Text != "Zwei Sites." {
		t.Fatalf("turn 2: %+v %v", m, err)
	}
	raw, _ := json.Marshal(bodies[1]["messages"])
	if !strings.Contains(string(raw), `"role":"tool"`) || !strings.Contains(string(raw), `"tool_call_id":"call_1"`) || !strings.Contains(string(raw), `"tool_calls"`) {
		t.Fatalf("body 2: %s", raw)
	}
}

func TestOpenAIErrorMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":{"message":"Invalid API key"}}`)
	}))
	defer srv.Close()
	p, _ := NewProvider(Config{Kind: KindOpenAI, BaseURL: srv.URL, APIKey: "sk-test", Model: "m"})
	if _, err := p.Turn(context.Background(), "s", nil, []Message{{Role: RoleUser, Text: "x"}}); err == nil || !strings.Contains(err.Error(), "Invalid API key") {
		t.Fatalf("err %v", err)
	}
}

func TestAnthropicRawPreserved(t *testing.T) {
	var bodies []map[string]any
	var headers []http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		json.NewDecoder(r.Body).Decode(&b)
		bodies = append(bodies, b)
		headers = append(headers, r.Header.Clone())
		w.Header().Set("Content-Type", "application/json")
		if len(bodies) == 1 {
			io.WriteString(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5-5","stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1},
			"content":[{"type":"thinking","thinking":"","signature":"sig-abc"},{"type":"text","text":"Ich sehe nach."},{"type":"tool_use","id":"toolu_1","name":"list_sites","input":{"a":1}}]}`)
			return
		}
		io.WriteString(w, `{"id":"msg_2","type":"message","role":"assistant","model":"claude-opus-5-5","stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1},"content":[{"type":"text","text":"Fertig."}]}`)
	}))
	defer srv.Close()
	p, _ := NewProvider(Config{Kind: KindAnthropic, BaseURL: srv.URL, APIKey: "sk-ant-x", Model: "claude-opus-5-5"})
	tools := []ToolDef{{Name: "list_sites", Description: "d", Schema: map[string]any{"type": "object", "properties": map[string]any{}}}}
	hist := []Message{{Role: RoleUser, Text: "hi"}}
	m, err := p.Turn(context.Background(), "sys", tools, hist)
	if err != nil || m.Text != "Ich sehe nach." || len(m.Calls) != 1 || m.Calls[0].ID != "toolu_1" || string(m.Calls[0].Args) != `{"a":1}` || len(m.Raw) == 0 {
		t.Fatalf("turn 1: %+v %v", m, err)
	}
	if headers[0].Get("X-Api-Key") != "sk-ant-x" {
		t.Errorf("x-api-key fehlt: %v", headers[0])
	}
	if oc, _ := bodies[0]["output_config"].(map[string]any); oc["effort"] != "medium" {
		t.Errorf("effort: %v", bodies[0]["output_config"])
	}
	if _, ok := bodies[0]["fallbacks"]; ok {
		t.Error("fallbacks bei fremder Basis-URL")
	}
	hist = append(hist, m, Message{Role: RoleTool, Results: []ToolResult{{ID: "toolu_1", Content: "[]"}}})
	if m, err = p.Turn(context.Background(), "sys", tools, hist); err != nil || m.Text != "Fertig." {
		t.Fatalf("turn 2: %+v %v", m, err)
	}
	raw, _ := json.Marshal(bodies[1]["messages"])
	if !strings.Contains(string(raw), `"signature":"sig-abc"`) || !strings.Contains(string(raw), `"tool_use_id":"toolu_1"`) {
		t.Fatalf("Verlauf: %s", raw)
	}
}

func TestAnthropicRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"m","type":"message","role":"assistant","model":"claude-opus-5-5","stop_reason":"refusal","stop_details":{"type":"refusal","category":"cyber","explanation":"x"},"usage":{"input_tokens":1,"output_tokens":1},"content":[]}`)
	}))
	defer srv.Close()
	p, _ := NewProvider(Config{Kind: KindAnthropic, BaseURL: srv.URL, APIKey: "k", Model: "claude-opus-5-5"})
	m, err := p.Turn(context.Background(), "s", nil, []Message{{Role: RoleUser, Text: "x"}})
	if err != nil || !strings.Contains(m.Text, "abgelehnt") || !strings.Contains(m.Text, "cyber") {
		t.Fatalf("refusal: %+v %v", m, err)
	}
}

func TestAnthropicFallbacksOnDirectAPI(t *testing.T) {
	if !useFallbacks("") || !useFallbacks("https://api.anthropic.com") || !useFallbacks("https://api.anthropic.com/") || useFallbacks("https://router.requesty.ai") {
		t.Fatal("useFallbacks")
	}
}
