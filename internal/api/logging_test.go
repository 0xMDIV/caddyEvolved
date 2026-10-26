package api

import "testing"

func TestLogSettingsRedactParams(t *testing.T) {
	ls := defaultLogSettings()
	ls.RedactParams = []string{"mytok", "x-sig"}
	if err := ls.validate(); err != nil {
		t.Fatalf("valid names refused: %v", err)
	}
	ls.RedactParams = []string{"bad name"}
	if err := ls.validate(); err == nil {
		t.Fatal("name with space accepted")
	}
	if got := ls.roll().RedactParams; len(got) != 1 || got[0] != "bad name" {
		t.Fatalf("roll lost params: %v", got)
	}
}
