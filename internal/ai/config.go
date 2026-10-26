package ai

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"caddyevolved/internal/accesslog"
)

// Provider kinds.
const (
	KindAnthropic = "anthropic" // Claude Messages API
	KindOpenAI    = "openai"    // /v1/chat/completions: OpenRouter, Requesty, Ollama, LM Studio …
)

// DefaultModel is used when the Anthropic settings name none.
const DefaultModel = "claude-opus-5-5"

// Config is stored in /etc/caddyevolved/ai.json, readable by the daemon only.
type Config struct {
	Kind    string `json:"kind"`
	BaseURL string `json:"baseUrl"`
	APIKey  string `json:"apiKey,omitempty"`
	Model   string `json:"model"`
}

// Preset fills kind and URL for a known provider.
type Preset struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Kind    string `json:"kind"`
	BaseURL string `json:"baseUrl"`
	Model   string `json:"model,omitempty"`
}

// Presets are offered in the settings card.
var Presets = []Preset{
	{ID: "claude", Label: "Claude (Anthropic)", Kind: KindAnthropic, BaseURL: "https://api.anthropic.com", Model: DefaultModel},
	{ID: "openrouter", Label: "OpenRouter", Kind: KindOpenAI, BaseURL: "https://openrouter.ai/api/v1"},
	{ID: "requesty", Label: "Requesty", Kind: KindOpenAI, BaseURL: "https://router.requesty.ai/v1"},
	{ID: "ollama", Label: "Ollama (lokal)", Kind: KindOpenAI, BaseURL: "http://localhost:11434/v1"},
	{ID: "custom", Label: "Eigener (OpenAI-kompatibel)", Kind: KindOpenAI},
}

// Configured reports whether the chat can run.
func (c Config) Configured() bool { return c.Kind != "" && c.BaseURL != "" && c.Model != "" }

// Validate checks a configuration before it is stored. A key is optional:
// local servers such as Ollama need none.
func (c Config) Validate() error {
	var problems []string
	if c.Kind != KindAnthropic && c.Kind != KindOpenAI {
		problems = append(problems, "Anbieter-Typ: anthropic oder openai")
	}
	if !strings.HasPrefix(c.BaseURL, "https://") && !strings.HasPrefix(c.BaseURL, "http://") {
		problems = append(problems, "Basis-URL muss mit http:// oder https:// beginnen")
	}
	if strings.TrimSpace(c.Model) == "" {
		problems = append(problems, "Modell fehlt")
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// Public is the configuration as the UI sees it: the key only as a hint.
func (c Config) Public() map[string]any {
	hint := ""
	if c.APIKey != "" {
		hint = accesslog.RedactValue(c.APIKey)
	}
	return map[string]any{
		"kind": c.Kind, "baseUrl": c.BaseURL, "model": c.Model,
		"keyHint": hint, "configured": c.Configured(),
	}
}

// LoadConfig reads the settings; a missing file is an empty configuration.
func LoadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(data, &c)
}

// SaveConfig writes the settings with mode 0600.
func SaveConfig(path string, c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
