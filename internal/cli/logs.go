package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"caddyforge/internal/supervisor"
)

// unitNames maps the friendly --unit value onto a systemd unit.
var unitNames = map[string]string{
	"caddy":      "caddy.service",
	"caddyforge": "caddyforge.service",
}

func cmdLogs(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", envDefault("CADDYFORGE_ROOT", ""), "Installation in diesem Baum")
	unit := fs.String("unit", "caddy", "caddy oder caddyforge")
	lines := fs.Int("lines", 50, "letzte N Zeilen")
	follow := fs.Bool("follow", false, "fortlaufen, bis Strg-C")
	if err := fs.Parse(args); err != nil {
		return err
	}

	name, ok := unitNames[strings.TrimSpace(*unit)]
	if !ok {
		return fmt.Errorf("bekannte Einheiten sind caddy und caddyforge, bekommen %q", *unit)
	}
	l := newLayout(ctx, *root)

	if l.hasSystemd(ctx) {
		if *follow {
			return followJournal(ctx, l, name, *lines, stdout, stderr)
		}
		out, err := l.units().Journal(ctx, name, *lines)
		if out != "" {
			fmt.Fprint(stdout, out)
		}
		if err != nil {
			return fmt.Errorf("journalctl %s: %w", name, err)
		}
		if strings.TrimSpace(out) == "" {
			fmt.Fprintf(stdout, "%s hat noch keine Protokollzeilen\n", name)
		}
		return nil
	}

	// Without systemd only caddy has a file we wrote; the daemon logs to whatever
	// launched it, so asking for its unit must say so instead of printing nothing.
	if name != "caddy.service" {
		return fmt.Errorf("ohne systemd gibt es kein Protokoll für %s – `caddyforge serve` schreibt auf stdout", name)
	}
	if *follow {
		return followFile(ctx, l.paths.LogFile, *lines, stdout)
	}
	tail, err := supervisor.TailFile(l.paths.LogFile, *lines)
	if err != nil {
		return err
	}
	for _, line := range tail {
		fmt.Fprintln(stdout, line)
	}
	return nil
}

// followJournal streams journalctl until the context ends. It writes straight to
// the command's stdout, so `caddyforge logs -f | grep` behaves like journalctl.
func followJournal(ctx context.Context, l *layout, unit string, lines int, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, "journalctl", "--no-pager", "--lines", fmt.Sprint(lines), "--follow", "-u", unit)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("journalctl %s: %w", unit, err)
	}
	return nil
}

// followFile tails a log file the way inotify-lite does it: seek to the end, then
// poll. A container without inotify access still gets working output.
func followFile(ctx context.Context, path string, lines int, stdout io.Writer) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("Protokoll %s: %w", path, err)
	}
	tail, err := supervisor.TailFile(path, lines)
	if err != nil {
		return err
	}
	for _, line := range tail {
		fmt.Fprintln(stdout, line)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	var partial []byte
	emit := func(chunk []byte) {
		for _, line := range strings.Split(string(chunk), "\n") {
			if line != "" {
				fmt.Fprintln(stdout, line)
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			if len(partial) > 0 {
				emit(partial)
			}
			return nil
		case <-time.After(500 * time.Millisecond):
		}
		for {
			n, err := f.Read(buf)
			if n > 0 {
				chunk := append(partial, buf[:n]...)
				if end := strings.LastIndexByte(string(chunk), '\n'); end >= 0 {
					emit([]byte(chunk[:end]))
					partial = append([]byte(nil), chunk[end+1:]...)
				} else {
					partial = chunk
				}
			}
			if err != nil {
				break
			}
		}
	}
}
