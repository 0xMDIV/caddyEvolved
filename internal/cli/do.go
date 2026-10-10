package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"caddyforge/internal/api"
	"caddyforge/internal/config"
)

// doFlagArgs are the flags that consume a following value, so the partitioner
// below can tell them from a positional argument.
var doFlagArgs = map[string]bool{"port": true, "token": true, "timeout": true, "root": true}

// cmdDo calls the daemon's own HTTP API. It exists because the API is the real
// interface: whatever works here works from the WebUI, and an operator can debug
// a fresh LXC without a browser.
func cmdDo(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	// Go's flag package stops at the first positional, which would make
	// `do GET /api/status --port 8585` silently ignore --port. The call reads
	// better with trailing flags, so they are pulled out first.
	flags, rest := partitionFlags(args, doFlagArgs)
	fs := flag.NewFlagSet("do", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", envDefault("CADDYFORGE_ROOT", ""), "Installation in diesem Baum")
	port := fs.Int("port", 0, "Port des Dienstes (Standard: aus state.json)")
	token := fs.String("token", os.Getenv("CADDYFORGE_SESSION"), "Sitzungs-Token für die Authorization")
	timeout := fs.Duration("timeout", 30*time.Second, "Zeit für die Anfrage")
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		rest = append(fs.Args(), rest...)
	}
	if len(rest) < 2 {
		return fmt.Errorf("Aufruf: caddyforge do METHODE PFAD [BODY], z. B. do GET /api/status")
	}
	method := strings.ToUpper(rest[0])
	path := rest[1]
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	var body []byte
	if len(rest) > 2 {
		body = []byte(strings.Join(rest[2:], " "))
	}

	l := newLayout(ctx, *root)
	st, err := l.state()
	if err != nil {
		return err
	}
	listenPort := *port
	if listenPort == 0 {
		listenPort = st.UIPort
	}
	if listenPort == 0 {
		listenPort = 8484
	}

	reqCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	status, payload, err := callLocalAPI(reqCtx, net.JoinHostPort("127.0.0.1", fmt.Sprint(listenPort)), method, path, body, *token)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "%s %s -> %s\n", method, path, status)
	var pretty bytes.Buffer
	var doc any
	if json.Unmarshal(payload, &doc) == nil {
		enc := json.NewEncoder(&pretty)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(doc); encErr == nil {
			fmt.Fprint(stdout, pretty.String())
			if strings.HasPrefix(status, "2") {
				return nil
			}
			return fmt.Errorf("HTTP %s", status)
		}
	}
	stdout.Write(payload)
	if len(payload) > 0 && payload[len(payload)-1] != '\n' {
		fmt.Fprintln(stdout)
	}
	if !strings.HasPrefix(status, "2") {
		return fmt.Errorf("HTTP %s", status)
	}
	return nil
}

// callLocalAPI talks to our own daemon over loopback. TLS is verified off: the
// certificate is the self-signed one the daemon generates, and a hostname check
// against 127.0.0.1 would fail even for a correct certificate.
func callLocalAPI(ctx context.Context, addr, method, path string, body []byte, token string) (string, []byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
	}
	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		var rdr io.Reader
		if body != nil {
			rdr = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, scheme+"://"+addr+path, rdr)
		if err != nil {
			return "", nil, err
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		// The API refuses unsafe methods without this marker; a CLI call is
		// deliberately same-origin, not a cross-site form post.
		req.Header.Set(api.HeaderGate, "1")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		payload, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if rerr != nil {
			return resp.Status, payload, rerr
		}
		return resp.Status, payload, nil
	}
	return "", nil, fmt.Errorf("kein HTTP-Antwort auf %s: %w", addr, lastErr)
}

// cmdProxy is the M5 surface; it stays a refusal rather than a half-command.
func cmdProxy(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	return fmt.Errorf("proxy %s ist für M5 geplant und noch nicht implementiert", strings.Join(orPlaceholder(args), " "))
}

// cmdUninstall is destructive, so it is not stubbed into a partial deletion.
func cmdUninstall(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Bool("yes", false, "Rückfrage überspringen")
	fs.Bool("keep-config", false, "Caddyfile und Zugangsdaten behalten")
	root := fs.String("root", envDefault("CADDYFORGE_ROOT", ""), "Installation in diesem Baum")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return fmt.Errorf("uninstall für %s entfernt absichtlich noch nichts: Einheiten, Daten und Binary löscht erst M7 – "+
		"bis dahin systemctl disable --now caddy caddyforge, dann /etc/caddyforge, /etc/caddy, /var/lib/caddyforge und /var/log/caddy von Hand entfernen",
		displayRoot(config.NewPaths(*root).Root))
}

func orPlaceholder(args []string) []string {
	if len(args) == 0 {
		return []string{"(ohne Befehl)"}
	}
	return args
}
