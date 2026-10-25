package systemd

import (
	"context"
	"testing"

	"caddyevolved/internal/cmdx"
)

// journalctl has no --tail; the line count must go through --lines.
func TestJournalUsesLines(t *testing.T) {
	f := cmdx.NewFake()
	f.Outputs("journalctl --no-pager --lines 20 -u caddy", "zeile\n")
	out, err := New(f, t.TempDir()).Journal(context.Background(), "caddy", 20)
	if err != nil || out != "zeile\n" {
		t.Fatalf("Journal = %q, %v; Aufrufe %v", out, err, f.Calls)
	}
}
