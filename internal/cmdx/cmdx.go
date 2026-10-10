// Package cmdx abstracts external command execution so install steps can be
// tested without touching a real system.
package cmdx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Cmd describes one invocation of an external program.
type Cmd struct {
	Name  string
	Args  []string
	Env   []string // KEY=VALUE pairs appended to the current environment
	Dir   string
	Stdin []byte
	// InheritStdio passes stdout/stderr through instead of capturing.
	InheritStdio bool
}

// Line is the identity used to match a command against scripted results.
func (c Cmd) Line() string {
	return strings.Join(append([]string{c.Name}, c.Args...), " ")
}

// Runner executes Cmd values.
type Runner interface {
	Output(ctx context.Context, c Cmd) ([]byte, error)
	Run(ctx context.Context, c Cmd) error
}

// ExecRunner runs commands as real child processes.
type ExecRunner struct{}

func (ExecRunner) Output(ctx context.Context, c Cmd) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Dir = c.Dir
	if len(c.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}
	var out, errb bytes.Buffer
	if c.InheritStdio {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return nil, cmd.Run()
	}
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil && len(errb.String()) > 0 {
		return out.Bytes(), fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), err
}

func (r ExecRunner) Run(ctx context.Context, c Cmd) error {
	_, err := r.Output(ctx, c)
	return err
}

// Result is a scripted reply for FakeRunner.
type Result struct {
	Out string
	Err error
}

// FakeRunner records calls and replies from a script keyed by Cmd.Line().
// A missing key yields zero output and no error, which keeps step tests short.
type FakeRunner struct {
	Calls   []Cmd
	Results map[string]Result
}

func NewFake() *FakeRunner { return &FakeRunner{Results: map[string]Result{}} }

// Script registers the reply for cmd's exact line.
func (f *FakeRunner) Script(cmd string, out string, err error) *FakeRunner {
	f.Results[cmd] = Result{Out: out, Err: err}
	return f
}

// Outputs registers a successful reply.
func (f *FakeRunner) Outputs(cmd, out string) *FakeRunner { return f.Script(cmd, out, nil) }

func (f *FakeRunner) Output(_ context.Context, c Cmd) ([]byte, error) {
	f.Calls = append(f.Calls, c)
	r := f.Results[c.Line()]
	return []byte(r.Out), r.Err
}

func (f *FakeRunner) Run(ctx context.Context, c Cmd) error {
	_, err := f.Output(ctx, c)
	return err
}

// Called reports whether a command line was executed.
func (f *FakeRunner) Called(cmd string) bool {
	for _, c := range f.Calls {
		if c.Line() == cmd {
			return true
		}
	}
	return false
}
