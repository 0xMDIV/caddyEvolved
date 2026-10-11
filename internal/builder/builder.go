// Package builder compiles custom caddy binaries on this host.
//
// Caddy modules are compiled in, so "install a plugin" means "build a new
// binary". The builder keeps a private Go toolchain and xcaddy under the state
// directory, runs one build at a time with a streamed log, verifies the result
// against the requested modules and the live Caddyfile, and swaps the binary
// with an automatic rollback when caddy does not come back healthy.
package builder

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"caddyevolved/internal/caddyctl"
	"caddyevolved/internal/secrets"
)

// Status of a build.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusPreparing Status = "preparing"
	StatusBuilding  Status = "building"
	StatusVerifying Status = "verifying"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Done reports whether the build will not change any more.
func (s Status) Done() bool {
	return s == StatusSucceeded || s == StatusFailed || s == StatusCancelled
}

// Build is one compile job and, once finished, one candidate binary.
type Build struct {
	ID           string `json:"id"`
	Status       Status `json:"status"`
	Stage        string `json:"stage,omitempty"`
	CaddyVersion string `json:"caddyVersion"`
	// Plugins is what the operator asked for: catalog ids or module paths.
	Plugins []string `json:"plugins"`
	// Modules are the resolved go module paths passed to xcaddy.
	Modules         []string  `json:"modules"`
	CreatedAt       time.Time `json:"createdAt"`
	StartedAt       time.Time `json:"startedAt,omitzero"`
	FinishedAt      time.Time `json:"finishedAt,omitzero"`
	DurationSec     int       `json:"durationSec,omitempty"`
	Error           string    `json:"error,omitempty"`
	Size            int64     `json:"size,omitempty"`
	SHA256          string    `json:"sha256,omitempty"`
	BinaryVersion   string    `json:"binaryVersion,omitempty"`
	DetectedModules []string  `json:"detectedModules,omitempty"`
	// ValidateOK says whether the new binary accepts the live Caddyfile; an
	// activation is refused otherwise, because caddy would not start.
	ValidateOK     bool      `json:"validateOk"`
	ValidateOutput string    `json:"validateOutput,omitempty"`
	Active         bool      `json:"active"`
	ActivatedAt    time.Time `json:"activatedAt,omitzero"`
}

// Spec is a build request after plugin resolution.
type Spec struct {
	CaddyVersion string
	Plugins      []string
	Modules      []string
}

// Msg is one item of a build's live feed.
type Msg struct {
	Kind  string // "line", "status", "done"
	Line  string
	Build Build
}

// Hooks connect activation to the service layer, which this package does not
// know: systemd on a real host, the supervisor in a prefix test.
type Hooks struct {
	Restart func(ctx context.Context) error
	Healthy func(ctx context.Context) error
}

// Config locates everything the builder touches.
type Config struct {
	Dir       string // state directory, e.g. /var/lib/caddyevolved
	CaddyBin  string // the live binary, e.g. /usr/local/bin/caddy
	Caddyfile string
	EnvFile   string
	// Keep is how many finished builds stay on disk besides the active one.
	Keep int
}

// ErrBusy means a build is already running.
var ErrBusy = errors.New("es läuft bereits ein Build")

// Manager owns the build directory.
type Manager struct {
	dir       string
	caddyBin  string
	caddyfile string
	envFile   string
	keep      int

	mu      sync.Mutex
	builds  map[string]*Build
	running *job
	// actMu serialises activation and rollback; both restart caddy.
	actMu sync.Mutex
}

type job struct {
	id     string
	cancel context.CancelFunc
	lines  []string
	subs   map[chan Msg]struct{}
	logf   *os.File
}

const maxMemLines = 4000

// New loads earlier builds. A build that was running when the daemon stopped
// cannot be resumed and is marked failed.
func New(c Config) (*Manager, error) {
	if c.Keep <= 0 {
		c.Keep = 5
	}
	m := &Manager{
		dir: c.Dir, caddyBin: c.CaddyBin, caddyfile: c.Caddyfile, envFile: c.EnvFile, keep: c.Keep,
		builds: map[string]*Build{},
	}
	for _, d := range []string{m.buildsDir(), m.tmpDir()} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	entries, _ := os.ReadDir(m.buildsDir())
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "previous" {
			continue
		}
		b, err := readBuild(filepath.Join(m.buildsDir(), e.Name(), "build.json"))
		if err != nil {
			continue
		}
		if !b.Status.Done() {
			b.Status, b.Error = StatusFailed, "caddyEvolved wurde während des Builds neu gestartet"
			m.save(b)
		}
		m.builds[b.ID] = b
	}
	return m, nil
}

func (m *Manager) buildsDir() string           { return filepath.Join(m.dir, "builds") }
func (m *Manager) buildDir(id string) string   { return filepath.Join(m.buildsDir(), id) }
func (m *Manager) binaryPath(id string) string { return filepath.Join(m.buildDir(id), "caddy") }
func (m *Manager) logPath(id string) string    { return filepath.Join(m.buildDir(id), "build.log") }
func (m *Manager) previousBin() string         { return filepath.Join(m.buildsDir(), "previous", "caddy") }
func (m *Manager) previousMeta() string        { return filepath.Join(m.buildsDir(), "previous", "meta.json") }

// List returns all builds, newest first.
func (m *Manager) List() []Build {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Build, 0, len(m.builds))
	for _, b := range m.builds {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Running returns the id of the build in progress, if any.
func (m *Manager) Running() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running == nil {
		return ""
	}
	return m.running.id
}

// ActiveID is the build whose binary is installed right now.
func (m *Manager) ActiveID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.builds {
		if b.Active {
			return b.ID
		}
	}
	return ""
}

// PreviousAvailable reports whether a rollback target exists.
func (m *Manager) PreviousAvailable() bool {
	_, err := os.Stat(m.previousBin())
	return err == nil
}

// Get returns a build and its log.
func (m *Manager) Get(id string) (Build, []string, error) {
	m.mu.Lock()
	b, ok := m.builds[id]
	var lines []string
	if ok && m.running != nil && m.running.id == id {
		lines = append(lines, m.running.lines...)
	}
	m.mu.Unlock()
	if !ok {
		return Build{}, nil, fmt.Errorf("Build %s: %w", id, os.ErrNotExist)
	}
	if lines == nil {
		lines = readLines(m.logPath(id), maxMemLines)
	}
	return *b, lines, nil
}

// Subscribe follows a running build. The returned backlog holds every line so
// far, so a late subscriber renders the full log without a gap.
func (m *Manager) Subscribe(id string) (backlog []string, ch <-chan Msg, cancel func(), err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.builds[id]; !ok {
		return nil, nil, nil, fmt.Errorf("Build %s: %w", id, os.ErrNotExist)
	}
	if m.running == nil || m.running.id != id {
		return readLines(m.logPath(id), maxMemLines), nil, func() {}, nil
	}
	c := make(chan Msg, 256)
	j := m.running
	j.subs[c] = struct{}{}
	backlog = append(backlog, j.lines...)
	return backlog, c, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if _, ok := j.subs[c]; ok {
			delete(j.subs, c)
			close(c)
		}
	}, nil
}

// Start queues a build and runs it in the background.
func (m *Manager) Start(spec Spec) (Build, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running != nil {
		return Build{}, ErrBusy
	}
	b := &Build{
		ID:           newID(),
		Status:       StatusQueued,
		CaddyVersion: spec.CaddyVersion,
		Plugins:      spec.Plugins,
		Modules:      spec.Modules,
		CreatedAt:    time.Now().UTC(),
	}
	if err := os.MkdirAll(m.buildDir(b.ID), 0o750); err != nil {
		return Build{}, err
	}
	logf, err := os.OpenFile(m.logPath(b.ID), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return Build{}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.running = &job{id: b.ID, cancel: cancel, subs: map[chan Msg]struct{}{}, logf: logf}
	m.builds[b.ID] = b
	m.saveLocked(b)
	go m.run(ctx, b.ID)
	return *b, nil
}

// Cancel stops a running build.
func (m *Manager) Cancel(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running == nil || m.running.id != id {
		return fmt.Errorf("Build %s läuft nicht", id)
	}
	m.running.cancel()
	return nil
}

// Delete removes a finished build and its binary.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.builds[id]
	if !ok {
		return fmt.Errorf("Build %s: %w", id, os.ErrNotExist)
	}
	if !b.Status.Done() {
		return fmt.Errorf("Build %s läuft noch", id)
	}
	if b.Active {
		return fmt.Errorf("Build %s ist die aktive Binary und kann nicht gelöscht werden", id)
	}
	delete(m.builds, id)
	return os.RemoveAll(m.buildDir(id))
}

// run is the build goroutine.
func (m *Manager) run(ctx context.Context, id string) {
	log := func(line string) { m.emitLine(id, line) }
	setStage := func(st Status, stage string) {
		m.update(id, func(b *Build) {
			b.Status, b.Stage = st, stage
			if b.StartedAt.IsZero() {
				b.StartedAt = time.Now().UTC()
			}
		})
		log("==> " + stage)
	}

	err := func() error {
		setStage(StatusPreparing, "Go-Toolchain prüfen")
		if err := m.ensureGo(ctx, log); err != nil {
			return err
		}
		setStage(StatusPreparing, "xcaddy prüfen")
		if err := m.ensureXcaddy(ctx, log); err != nil {
			return err
		}
		b := m.snapshot(id)
		setStage(StatusBuilding, "caddy "+b.CaddyVersion+" mit "+fmt.Sprint(len(b.Modules))+" Modul(en) kompilieren")
		out := m.binaryPath(id)
		args := []string{"build", b.CaddyVersion, "--output", out}
		for _, mod := range b.Modules {
			args = append(args, "--with", mod)
		}
		log("$ xcaddy " + strings.Join(args, " "))
		cmd := exec.CommandContext(ctx, m.xcaddyBin(), args...)
		cmd.Env = m.buildEnv()
		cmd.Dir = m.buildDir(id)
		if err := m.stream(cmd, log); err != nil {
			return fmt.Errorf("xcaddy build: %w", err)
		}
		setStage(StatusVerifying, "Binary prüfen")
		return m.verify(ctx, id, log)
	}()

	m.update(id, func(b *Build) {
		b.FinishedAt = time.Now().UTC()
		if !b.StartedAt.IsZero() {
			b.DurationSec = int(b.FinishedAt.Sub(b.StartedAt).Seconds())
		}
		switch {
		case ctx.Err() != nil:
			b.Status, b.Error, b.Stage = StatusCancelled, "abgebrochen", ""
		case err != nil:
			b.Status, b.Error = StatusFailed, err.Error()
		default:
			b.Status, b.Stage = StatusSucceeded, ""
		}
	})
	final := m.snapshot(id)
	if final.Status == StatusSucceeded {
		log(fmt.Sprintf("==> fertig in %ds: %s, %d MB", final.DurationSec, final.BinaryVersion, final.Size>>20))
	} else {
		log("==> " + string(final.Status) + ": " + final.Error)
		os.Remove(m.binaryPath(id))
	}

	// Take the subscribers out under the lock: a subscriber's cancel func
	// closes its channel only while it is still listed, so each channel is
	// closed exactly once.
	m.mu.Lock()
	j := m.running
	m.running = nil
	var subs map[chan Msg]struct{}
	if j != nil {
		subs, j.subs = j.subs, map[chan Msg]struct{}{}
	}
	m.mu.Unlock()
	if j != nil {
		j.cancel()
		j.logf.Close()
		for c := range subs {
			c <- Msg{Kind: "done", Build: final}
			close(c)
		}
	}
	m.prune()
}

// verify checks the fresh binary: it runs, it contains every requested module,
// and it accepts the live Caddyfile.
func (m *Manager) verify(ctx context.Context, id string, log func(string)) error {
	bin := m.binaryPath(id)
	st, err := os.Stat(bin)
	if err != nil {
		return fmt.Errorf("xcaddy hat keine Binary erzeugt: %w", err)
	}
	sum, err := fileSHA256(bin)
	if err != nil {
		return err
	}
	vctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	version, err := exec.CommandContext(vctx, bin, "version").Output()
	if err != nil {
		return fmt.Errorf("neue Binary startet nicht: %w", err)
	}
	mods, err := ListModules(vctx, bin)
	if err != nil {
		return err
	}
	b := m.snapshot(id)
	var missing []string
	for _, want := range b.Modules {
		path, _, _ := strings.Cut(want, "@")
		if !HasPackage(mods, path) {
			missing = append(missing, path)
		}
	}
	var ids []string
	for _, mod := range mods {
		ids = append(ids, mod.ID)
	}
	log(fmt.Sprintf("Nicht-Standard-Module in der Binary: %d", len(mods)))
	for _, mod := range mods {
		log("  " + mod.ID + "  " + mod.Package + " " + mod.Version)
	}
	if len(missing) > 0 {
		return fmt.Errorf("Module fehlen in der Binary: %s", strings.Join(missing, ", "))
	}

	validateOK, validateOut := true, ""
	if _, err := os.Stat(m.caddyfile); err == nil {
		cmd := exec.CommandContext(vctx, bin, "validate", "--config", m.caddyfile, "--adapter", "caddyfile")
		cmd.Env = append(os.Environ(), envFileVars(m.envFile)...)
		scratch, _ := os.MkdirTemp(m.tmpDir(), "validate-")
		cmd.Env = append(cmd.Env, caddyctl.ScratchEnv(scratch)...)
		out, err := cmd.CombinedOutput()
		os.RemoveAll(scratch)
		validateOut = tail(string(out), 4000)
		if err != nil {
			validateOK = false
			log("WARNUNG: die neue Binary lehnt das aktuelle Caddyfile ab – Aktivierung gesperrt")
			for _, l := range strings.Split(strings.TrimSpace(validateOut), "\n") {
				log("  " + l)
			}
		} else {
			log("Aktuelles Caddyfile mit der neuen Binary validiert: ok")
		}
	}
	m.update(id, func(b *Build) {
		b.Size, b.SHA256 = st.Size(), sum
		b.BinaryVersion = strings.TrimSpace(strings.SplitN(string(version), "\n", 2)[0])
		b.DetectedModules = ids
		b.ValidateOK, b.ValidateOutput = validateOK, validateOut
	})
	return nil
}

// stream runs cmd and forwards every output line. Stdout and stderr share one
// pipe so the log keeps go's interleaving.
func (m *Manager) stream(cmd *exec.Cmd, log func(string)) error {
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	prepareCmd(cmd)
	if err := cmd.Start(); err != nil {
		pw.Close()
		return err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			log(sc.Text())
		}
		io.Copy(io.Discard, pr)
	}()
	err := cmd.Wait()
	pw.Close()
	<-done
	return err
}

func (m *Manager) emitLine(id, line string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j := m.running
	if j == nil || j.id != id {
		return
	}
	stamped := time.Now().Format("15:04:05") + "  " + line
	j.lines = append(j.lines, stamped)
	if len(j.lines) > maxMemLines {
		j.lines = j.lines[len(j.lines)-maxMemLines:]
	}
	fmt.Fprintln(j.logf, stamped)
	for c := range j.subs {
		select {
		case c <- Msg{Kind: "line", Line: stamped}:
		default: // a stalled browser must not block the build
		}
	}
}

func (m *Manager) update(id string, fn func(*Build)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.builds[id]
	if !ok {
		return
	}
	fn(b)
	m.saveLocked(b)
	if m.running != nil && m.running.id == id {
		for c := range m.running.subs {
			select {
			case c <- Msg{Kind: "status", Build: *b}:
			default:
			}
		}
	}
}

func (m *Manager) snapshot(id string) Build {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.builds[id]; ok {
		return *b
	}
	return Build{}
}

func (m *Manager) save(b *Build) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveLocked(b)
}

func (m *Manager) saveLocked(b *Build) {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return
	}
	p := filepath.Join(m.buildDir(b.ID), "build.json")
	tmp := p + ".tmp"
	if os.WriteFile(tmp, data, 0o640) == nil {
		os.Rename(tmp, p)
	}
}

// prune keeps the newest finished builds plus the active one.
func (m *Manager) prune() {
	builds := m.List()
	kept := 0
	for _, b := range builds {
		if b.Active || !b.Status.Done() {
			continue
		}
		if b.Status == StatusSucceeded && kept < m.keep {
			kept++
			continue
		}
		if b.Status != StatusSucceeded && kept < m.keep*2 {
			// Failed builds are small (log only) – keep them a while for the log.
			continue
		}
		m.Delete(b.ID)
	}
}

func readBuild(path string) (*Build, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Build
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if b.ID == "" {
		return nil, errors.New("build ohne id")
	}
	return &b, nil
}

func readLines(path string, max int) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{}
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > max {
		lines = lines[len(lines)-max:]
	}
	return lines
}

func newID() string {
	var b [3]byte
	rand.Read(b[:])
	return time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// envFileVars returns the credential file as KEY=VALUE pairs so validate sees
// the same {env.*} values the service gets through EnvironmentFile.
func envFileVars(path string) []string {
	vars, err := secrets.New(path).Read()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(vars))
	for k, v := range vars {
		out = append(out, k+"="+v)
	}
	return out
}
