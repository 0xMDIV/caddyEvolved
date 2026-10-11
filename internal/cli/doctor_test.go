package cli

import (
	"testing"
)

func TestUfwAllows(t *testing.T) {
	status := `Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       192.168.10.0/24
80/tcp                     ALLOW       Anywhere
443                        ALLOW       Anywhere
8000:8100/tcp              ALLOW       Anywhere
8484/tcp                   DENY        Anywhere
80/tcp (v6)                ALLOW       Anywhere (v6)
`
	for port, want := range map[int]bool{22: true, 80: true, 443: true, 8050: true, 8484: false, 2019: false} {
		if got := ufwAllows(status, port); got != want {
			t.Errorf("ufwAllows(%d) = %v, want %v", port, got, want)
		}
	}
}
