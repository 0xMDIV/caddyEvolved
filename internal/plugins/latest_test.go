package plugins

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
		ok   bool
	}{
		{"v0.2.1", "v0.2.0", 1, true},
		{"v1.10.0", "v1.9.9", 1, true},
		{"v2.11.7", "v2.11.7", 0, true},
		{"v2.11.0-beta.1", "v2.11.0", -1, true},
		{"v2.11.0-beta.10", "v2.11.0-beta.2", 1, true},
		{"v0.0.0-20250101120000-abcdef123456", "v0.0.0-20240101120000-abcdef123456", 1, true},
		{"v1.2.4-0.20240101120000-abcdef123456", "v1.2.3", 1, true},
		{"v1.0.0+incompatible", "v1.0.0", 0, true},
		{"(devel)", "v1.0.0", 0, false},
		{"v1.2", "v1.2.0", 0, false},
	}
	for _, c := range cases {
		got, ok := CompareVersions(c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("CompareVersions(%q, %q) = %d, %v; want %d, %v", c.a, c.b, got, ok, c.want, c.ok)
		}
	}
}

func TestEscapePath(t *testing.T) {
	if got := EscapePath("github.com/Azure/go-autorest"); got != "github.com/!azure/go-autorest" {
		t.Fatal(got)
	}
}
