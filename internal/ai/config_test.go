package ai

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestConfigPublicHidesKey(t *testing.T) {
	c := Config{Kind: KindAnthropic, BaseURL: "https://api.anthropic.com", APIKey: "sk-ant-geheim123", Model: "claude-opus-5-5"}
	p := c.Public()
	if p["keyHint"] != "sk-a******" || p["configured"] != true {
		t.Fatalf("public %v", p)
	}
	for _, v := range p {
		if s, ok := v.(string); ok && s == c.APIKey {
			t.Fatal("Key im Klartext")
		}
	}
}

func TestConfigSaveLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ai.json")
	c := Config{Kind: KindOpenAI, BaseURL: "https://openrouter.ai/api/v1", APIKey: "sk-or-1234567890", Model: "x/y"}
	if err := SaveConfig(p, c); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("Rechte %v", fi.Mode().Perm())
	}
	got, err := LoadConfig(p)
	if err != nil || got != c {
		t.Fatalf("load %+v %v", got, err)
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "fehlt.json")); err != nil {
		t.Fatalf("fehlende Datei: %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	ok := Config{Kind: KindOpenAI, BaseURL: "http://localhost:11434/v1", Model: "llama3"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("ollama ohne Key: %v", err)
	}
	for _, bad := range []Config{
		{Kind: "x", BaseURL: "https://a", Model: "m"},
		{Kind: KindOpenAI, BaseURL: "ftp://a", Model: "m"},
		{Kind: KindAnthropic, BaseURL: "https://a", Model: ""},
	} {
		if bad.Validate() == nil {
			t.Errorf("angenommen: %+v", bad)
		}
	}
}
