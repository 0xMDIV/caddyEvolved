package blocklists

import (
	"slices"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := `; Spamhaus DROP List
1.10.16.0/20 ; SBL256894
# FireHOL ships the bogons
0.0.0.0/8
192.168.0.0/16
10.1.2.0/24
2.56.0.1
2.56.0.1
2001:db8::/32
2a06:1280::/29
not-an-ip
`
	got := Parse(strings.NewReader(in))
	want := []string{"1.10.16.0/20", "2.56.0.1/32", "2a06:1280::/29"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("Parse = %v, erwartet %v", got, want)
	}
}

func TestParseSeparators(t *testing.T) {
	got := Parse(strings.NewReader("45.43.60.98\t7\n66.132.224.94,scanner\n# x\n"))
	if len(got) != 2 || got[0] != "45.43.60.98/32" || got[1] != "66.132.224.94/32" {
		t.Fatalf("got %v", got)
	}
}
