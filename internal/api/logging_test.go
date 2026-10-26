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

func TestValidLookupURL(t *testing.T) {
	for _, ok := range []string{"https://ipinfo.io/{ip}", "http://x.local/q?ip={ip}"} {
		if err := validLookupURL(ok); err != nil {
			t.Errorf("%q abgelehnt: %v", ok, err)
		}
	}
	for _, bad := range []string{"ftp://x/{ip}", "https://x/", "javascript:alert('{ip}')", ""} {
		if validLookupURL(bad) == nil {
			t.Errorf("%q angenommen", bad)
		}
	}
	if defaultLogSettings().LookupURL != "https://ipinfo.io/{ip}" {
		t.Error("Standard-Lookup fehlt")
	}
}
