package sysstat

import (
	"os"
	"runtime"
	"testing"
	"time"
)

// TestSampleOwnProcess samples twice and checks the plausible ranges; it uses
// this test process as "caddy" so it runs without a caddy.
func TestSampleOwnProcess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	s := New(10, func() int { return os.Getpid() })
	if _, err := s.Sample(); err != nil {
		t.Fatal(err)
	}
	// Burn some CPU so the second sample has something to measure.
	end := time.Now().Add(150 * time.Millisecond)
	for x := 0; time.Now().Before(end); x++ {
		_ = x * x
	}
	smp, err := s.Sample()
	if err != nil {
		t.Fatal(err)
	}
	if smp.CPUs < 1 || smp.MemTotal <= 0 || smp.MemUsed <= 0 || smp.MemUsed > smp.MemTotal {
		t.Fatalf("host: %+v", smp)
	}
	if smp.CPU < 0 || smp.CPU > 100 {
		t.Fatalf("host cpu %.1f", smp.CPU)
	}
	if smp.Evolved == nil || smp.Caddy == nil || smp.Evolved.RSS <= 0 || smp.Evolved.Threads < 1 || smp.Evolved.FDs < 1 {
		t.Fatalf("proc: %+v", smp.Evolved)
	}
	if smp.Evolved.Uptime < 0 || smp.Evolved.Uptime > 3600 {
		t.Fatalf("own uptime %.1f s", smp.Evolved.Uptime)
	}
	if smp.Evolved.CPU <= 0 {
		t.Fatalf("busy loop not measured: %.1f", smp.Evolved.CPU)
	}
	if d := Disks("/", "/tmp"); len(d) == 0 || d[0].Total <= 0 {
		t.Fatalf("disks: %+v", d)
	}
}
