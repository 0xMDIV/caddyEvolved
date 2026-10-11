package selfupdate

import "testing"

func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"0.5.0", "0.4.1", true},
		{"0.5.0", "0.5.0", false},
		{"0.4.1", "0.5.0", false},
		{"0.10.0", "0.9.3", true},
		{"0.5.0", "0.5.0-dev", true}, // dev build of the same number is older
		{"0.5.0", "0.6.0-dev", false},
		{"0.5.0", "dev", true},
	}
	for _, c := range cases {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}

func TestIsDev(t *testing.T) {
	for v, want := range map[string]bool{"": true, "dev": true, "0.5.0-dev": true, "0.5.0": false} {
		if IsDev(v) != want {
			t.Errorf("IsDev(%q) != %v", v, want)
		}
	}
}
