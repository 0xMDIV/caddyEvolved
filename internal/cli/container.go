package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"caddyevolved/internal/install"
	"caddyevolved/internal/platform"
)

// bundledCaddy is the official caddy the image ships. It is copied into the
// data volume on first start; from then on the volume copy is the one that
// runs, so a binary built with plugins survives a new image.
const bundledCaddy = "/usr/local/share/caddyevolved/caddy"

// cmdContainer is the image's entrypoint: first-run setup, then caddy under
// our supervision and the WebUI in the foreground. Settings come from the
// environment (see docker/README).
func cmdContainer(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("container", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !platform.InContainer() {
		return errors.New("nur im caddyEvolved-Docker-Image (CADDYEVOLVED_CONTAINER=1) – auf einem normalen Server `caddyevolved install` verwenden")
	}
	// The image links /etc/caddy, /var/lib/caddy … into /data; a fresh
	// volume is empty, so the link targets have to exist first.
	for _, link := range []string{"/etc/caddy", "/etc/caddyevolved", "/var/lib/caddy", "/var/lib/caddyevolved", "/var/log/caddy"} {
		if target, err := os.Readlink(link); err == nil {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("%s: %w", target, err)
			}
		}
	}
	l := newLayout(ctx, "")
	logf := func(format string, a ...any) { fmt.Fprintf(stdout, "caddyevolved: "+format+"\n", a...) }

	if err := seedCaddy(l.paths.CaddyBin); err != nil {
		return err
	}
	// PIDs start over in a new container; a pid file from the last run may
	// name an unrelated process now.
	os.Remove(l.paths.PIDFile)

	st, _ := l.state()
	if !st.Installed {
		logf("Erster Start – richte caddyEvolved ein")
		if err := containerInstall(ctx, stdout, stderr); err != nil {
			return fmt.Errorf("Einrichtung: %w", err)
		}
		// The install report names the container's own address, which is
		// only reachable from the host itself in bridge mode.
		logf("WebUI: https://<IP des Docker-Hosts>:%d – mit Port-Mapping der dort gemappte Port", envInt("CADDYEVOLVED_UI_PORT", 8484))
	} else if _, err := l.manager().Start(ctx); err != nil {
		logf("caddy startet nicht: %v – Details in der WebUI unter Logs", err)
	}

	sup := l.manager()
	go sup.Watch(ctx, 10*time.Second, logf)

	err := cmdServe(ctx, nil, stdout, stderr)
	stopCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Not Stop(): its marker would keep caddy down after the next start.
	if pid, running := sup.PID(); running {
		if p, e := os.FindProcess(pid); e == nil {
			_ = p.Signal(os.Interrupt)
		}
		for i := 0; i < 50; i++ {
			if _, running := sup.PID(); !running {
				break
			}
			select {
			case <-stopCtx.Done():
				i = 50
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	return err
}

// seedCaddy puts the bundled caddy into the volume when none is there yet.
func seedCaddy(dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	src, err := os.Open(bundledCaddy)
	if err != nil {
		return fmt.Errorf("mitgelieferte caddy-Binary fehlt: %w", err)
	}
	defer src.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".caddy-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

// containerInstall runs the normal install engine unattended with answers
// from the environment.
func containerInstall(ctx context.Context, stdout, stderr io.Writer) error {
	a := install.Answers{
		BinarySource: "official",
		Email:        os.Getenv("CADDYEVOLVED_EMAIL"),
		UIPort:       envInt("CADDYEVOLVED_UI_PORT", 8484),
		UIBind:       "0.0.0.0",
		HTTPPort:     80,
		HTTPSPort:    443,
		AdminPort:    2019,
	}
	a.Managed = a.Email != ""
	data, _ := json.Marshal(a)
	f, err := os.CreateTemp("", "caddyevolved-answers-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	f.Close()

	args := []string{"--unattended", f.Name(), "--yes"}
	if pw := os.Getenv("CADDYEVOLVED_PASSWORD"); pw != "" {
		args = append(args, "--ui-password", pw)
	}
	return cmdInstall(ctx, args, stdout, stderr)
}

func envInt(key string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil && v > 0 {
		return v
	}
	return def
}
