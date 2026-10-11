// Package sysstat samples the host and the two processes that matter here –
// caddy and caddyEvolved – from /proc, so the WebUI can show how much of the
// machine the proxy actually uses. No external tools, Linux only; elsewhere
// Sample returns an error and the UI says so.
package sysstat

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// clkTck is USER_HZ; 100 on every mainstream Linux build.
const clkTck = 100

// Proc is one process at one moment.
type Proc struct {
	PID      int     `json:"pid"`
	CPU      float64 `json:"cpu"`     // percent of one core
	CPUShare float64 `json:"cpuHost"` // percent of the whole machine
	RSS      int64   `json:"rss"`     // bytes
	Threads  int     `json:"threads"`
	FDs      int     `json:"fds"`
	ReadBps  float64 `json:"readBps"`  // disk read bytes/s
	WriteBps float64 `json:"writeBps"` // disk write bytes/s
	Uptime   float64 `json:"uptime"`   // seconds since start
}

// Sample is one measurement of the host and both processes.
type Sample struct {
	T         time.Time `json:"t"`
	CPU       float64   `json:"cpu"` // host CPU busy, percent of all cores
	CPUs      int       `json:"cpus"`
	Load1     float64   `json:"load1"`
	Load5     float64   `json:"load5"`
	Load15    float64   `json:"load15"`
	MemTotal  int64     `json:"memTotal"`
	MemUsed   int64     `json:"memUsed"` // total minus available
	RxBps     float64   `json:"rxBps"`   // all non-loopback interfaces
	TxBps     float64   `json:"txBps"`
	Uptime    float64   `json:"uptime"`
	Caddy     *Proc     `json:"caddy,omitempty"`
	Evolved   *Proc     `json:"caddyevolved,omitempty"`
	GoHeap    uint64    `json:"goHeap"`
	GoRoutine int       `json:"goroutines"`
}

// Disk is the usage of one mount.
type Disk struct {
	Path  string `json:"path"`
	Total int64  `json:"total"`
	Free  int64  `json:"free"`
}

// raw counters kept between samples for rates.
type counters struct {
	at          time.Time
	cpuTotal    uint64
	cpuIdle     uint64
	rx, tx      uint64
	procTicks   map[int]uint64
	procRead    map[int]uint64
	procWritten map[int]uint64
}

// Sampler keeps a ring of recent samples.
type Sampler struct {
	mu      sync.Mutex
	prev    *counters
	ring    []Sample
	keep    int
	caddyFn func() int
}

// New returns a sampler keeping keep samples. caddyPID finds caddy's process.
func New(keep int, caddyPID func() int) *Sampler {
	if caddyPID == nil {
		caddyPID = CaddyPID
	}
	return &Sampler{keep: keep, caddyFn: caddyPID}
}

// Run samples every interval until ctx ends.
func (s *Sampler) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if smp, err := s.Sample(); err == nil {
			s.mu.Lock()
			s.ring = append(s.ring, smp)
			if len(s.ring) > s.keep {
				s.ring = s.ring[len(s.ring)-s.keep:]
			}
			s.mu.Unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// History returns the kept samples, oldest first.
func (s *Sampler) History() []Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Sample(nil), s.ring...)
}

// ErrUnsupported is returned off Linux.
var ErrUnsupported = errors.New("Systemwerte gibt es nur unter Linux")

// Sample measures now; rates are relative to the previous call.
func (s *Sampler) Sample() (Sample, error) {
	if runtime.GOOS != "linux" {
		return Sample{}, ErrUnsupported
	}
	now := time.Now()
	c := &counters{at: now, procTicks: map[int]uint64{}, procRead: map[int]uint64{}, procWritten: map[int]uint64{}}
	smp := Sample{T: now.UTC(), CPUs: runtime.NumCPU()}

	total, idle, err := cpuTimes()
	if err != nil {
		return smp, err
	}
	c.cpuTotal, c.cpuIdle = total, idle
	smp.Load1, smp.Load5, smp.Load15 = loadAvg()
	smp.MemTotal, smp.MemUsed = memInfo()
	c.rx, c.tx = netBytes()
	smp.Uptime = uptime()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	smp.GoHeap, smp.GoRoutine = ms.HeapAlloc, runtime.NumGoroutine()

	s.mu.Lock()
	prev := s.prev
	s.prev = c
	s.mu.Unlock()

	var dt float64
	if prev != nil {
		dt = now.Sub(prev.at).Seconds()
		if dTotal := float64(c.cpuTotal - prev.cpuTotal); dTotal > 0 {
			smp.CPU = round1(100 * (1 - float64(c.cpuIdle-prev.cpuIdle)/dTotal))
		}
		if dt > 0 {
			smp.RxBps = float64(c.rx-prev.rx) / dt
			smp.TxBps = float64(c.tx-prev.tx) / dt
		}
	}
	proc := func(pid int) *Proc {
		if pid <= 0 {
			return nil
		}
		p, ticks, read, written, ok := readProc(pid, now)
		if !ok {
			return nil
		}
		c.procTicks[pid], c.procRead[pid], c.procWritten[pid] = ticks, read, written
		if prev != nil && dt > 0 {
			if old, ok := prev.procTicks[pid]; ok && ticks >= old {
				p.CPU = round1(float64(ticks-old) / clkTck / dt * 100)
				p.CPUShare = round1(p.CPU / float64(smp.CPUs))
			}
			if old, ok := prev.procRead[pid]; ok && read >= old {
				p.ReadBps = float64(read-old) / dt
			}
			if old, ok := prev.procWritten[pid]; ok && written >= old {
				p.WriteBps = float64(written-old) / dt
			}
		}
		return &p
	}
	smp.Evolved = proc(os.Getpid())
	smp.Caddy = proc(s.caddyFn())
	return smp, nil
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// cpuTimes returns the summed and the idle jiffies of all CPUs.
func cpuTimes() (total, idle uint64, err error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	line, _, _ := strings.Cut(string(data), "\n")
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, errors.New("/proc/stat unerwartet")
	}
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		if i >= 8 { // guest time is already in user/nice
			break
		}
		total += n
		if i == 3 || i == 4 { // idle, iowait
			idle += n
		}
	}
	return total, idle, nil
}

func loadAvg() (a, b, c float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	f := strings.Fields(string(data))
	if len(f) >= 3 {
		a, _ = strconv.ParseFloat(f[0], 64)
		b, _ = strconv.ParseFloat(f[1], 64)
		c, _ = strconv.ParseFloat(f[2], 64)
	}
	return
}

// memInfo honours the container's view (LXCFS shows the container limits).
func memInfo() (total, used int64) {
	fh, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer fh.Close()
	var avail int64
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseInt(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = v * 1024
		case "MemAvailable:":
			avail = v * 1024
		}
	}
	return total, total - avail
}

func netBytes() (rx, tx uint64) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "lo" || name == "" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(f[0], 10, 64)
		t, _ := strconv.ParseUint(f[8], 10, 64)
		rx += r
		tx += t
	}
	return
}

func uptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseFloat(strings.Fields(string(data))[0], 64)
	return v
}

// readProc reads one process; ticks are utime+stime, read/written disk bytes.
func readProc(pid int, now time.Time) (p Proc, ticks, read, written uint64, ok bool) {
	dir := "/proc/" + strconv.Itoa(pid)
	stat, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return p, 0, 0, 0, false
	}
	// The command name may contain spaces; fields start after the last ")".
	s := string(stat)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return p, 0, 0, 0, false
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return p, 0, 0, 0, false
	}
	utime, _ := strconv.ParseUint(f[11], 10, 64)
	stime, _ := strconv.ParseUint(f[12], 10, 64)
	threads, _ := strconv.Atoi(f[17])
	start, _ := strconv.ParseFloat(f[19], 64)
	p.PID, p.Threads, ticks = pid, threads, utime+stime
	// Start ticks count from the host's boot (btime). In a container
	// /proc/uptime is the container's, so it must not be the reference.
	if bt := bootTime(); bt > 0 {
		p.Uptime = float64(now.Unix()) - (float64(bt) + start/clkTck)
		if p.Uptime < 0 { // btime has whole-second precision
			p.Uptime = 0
		}
	}

	if status, err := os.ReadFile(dir + "/status"); err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				if ff := strings.Fields(line); len(ff) >= 2 {
					kb, _ := strconv.ParseInt(ff[1], 10, 64)
					p.RSS = kb * 1024
				}
			}
		}
	}
	if io, err := os.ReadFile(dir + "/io"); err == nil {
		for _, line := range strings.Split(string(io), "\n") {
			k, v, _ := strings.Cut(line, ": ")
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			switch k {
			case "read_bytes":
				read = n
			case "write_bytes":
				written = n
			}
		}
	}
	if fds, err := os.ReadDir(dir + "/fd"); err == nil {
		p.FDs = len(fds)
	}
	return p, ticks, read, written, true
}

// CaddyPID asks systemd for caddy's main PID and falls back to scanning /proc.
func CaddyPID() int {
	if out, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", "caddy.service").Output(); err == nil {
		if pid, _ := strconv.Atoi(strings.TrimSpace(string(out))); pid > 0 {
			return pid
		}
	}
	matches, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, m := range matches {
		if data, err := os.ReadFile(m); err == nil && strings.TrimSpace(string(data)) == "caddy" {
			pid, _ := strconv.Atoi(filepath.Base(filepath.Dir(m)))
			return pid
		}
	}
	return 0
}

// Disks reports usage of the mounts relevant to caddyEvolved.
func Disks(paths ...string) []Disk {
	var out []Disk
	seen := map[[2]int64]bool{}
	for _, p := range paths {
		var st syscall.Statfs_t
		if err := syscall.Statfs(p, &st); err != nil {
			continue
		}
		d := Disk{Path: p, Total: int64(st.Blocks) * int64(st.Bsize), Free: int64(st.Bavail) * int64(st.Bsize)}
		// Paths on the same filesystem report the same numbers; show it once.
		key := [2]int64{d.Total, d.Free}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, d)
	}
	return out
}

// bootTime is the host's boot time (epoch seconds) from /proc/stat.
func bootTime() int64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			return n
		}
	}
	return 0
}
