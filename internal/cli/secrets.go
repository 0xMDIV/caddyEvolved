package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"caddyforge/internal/auth"
)

// cmdToken mints a session id for the CLI or a script, so an operator can drive
// the HTTP API without typing the password into curl each time.
//
// A running daemon owns the live session table, so the daemon is asked first and
// the file is only written when nothing is listening.
func cmdToken(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", envDefault("CADDYFORGE_ROOT", ""), "Installation in diesem Baum")
	ttlHours := fs.Float64("ttl", 24, "Gültigkeit in Stunden (nur ohne laufenden Daemon)")
	port := fs.Int("port", 0, "Port des Dienstes (Standard: aus state.json)")
	jsonOut := fs.Bool("json", false, "JSON ausgeben")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ttlHours <= 0 || *ttlHours > 24*30 {
		return fmt.Errorf("--ttl erwartet 1 bis %d Stunden, bekommen %g", 24*30, *ttlHours)
	}

	l := newLayout(ctx, *root)
	st, err := l.state()
	if err != nil {
		return err
	}
	store, err := auth.LoadStore(l.paths.AuthFile)
	if err != nil {
		return fmt.Errorf("Auth-Store %s: %w", l.paths.AuthFile, err)
	}
	if !store.HasPassword() {
		return fmt.Errorf("kein UI-Passwort gesetzt – zuerst `caddyforge install` oder `caddyforge passwd`")
	}
	password, err := readPassword(stderr, "UI-Passwort")
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

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]any{"password": password})
	if status, payload, lerr := callLocalAPI(reqCtx, net.JoinHostPort("127.0.0.1", fmt.Sprint(listenPort)),
		http.MethodPost, "/api/login", body, ""); lerr == nil && strings.HasPrefix(status, "2") {
		var out struct {
			SessionID string    `json:"sessionId"`
			Expires   time.Time `json:"expires"`
		}
		if json.Unmarshal(payload, &out) == nil && out.SessionID != "" {
			if *jsonOut {
				return encode(stdout, map[string]any{"token": out.SessionID, "expires": out.Expires, "source": "daemon"})
			}
			fmt.Fprintf(stdout, "Token (gültig bis %s):\n  %s\n\nBeispiel:\n  caddyforge do GET /api/status --token %s\n",
				out.Expires.Format(time.RFC3339), out.SessionID, out.SessionID)
			return nil
		}
		return fmt.Errorf("Login-Antwort des Dienstes nicht verstanden: %s", strings.TrimSpace(string(payload)))
	}

	// Nothing is listening: the token has to come from the store, and the daemon
	// will accept it as soon as it starts.
	sess, err := store.Login(password, "caddyforge-cli", "cli", time.Duration(*ttlHours*float64(time.Hour)))
	if err != nil {
		return err
	}
	if *jsonOut {
		return encode(stdout, map[string]any{
			"token": sess.ID, "expires": sess.Expires, "ttlHours": *ttlHours, "source": "store",
		})
	}
	fmt.Fprintf(stderr, "Hinweis: kein Dienst auf Port %d erreichbar – Token aus der Datei; ein laufender Dienst liest sie nicht nachträglich.\n", listenPort)
	fmt.Fprintf(stdout, "Token (einmalig, gültig bis %s):\n  %s\n\nBeispiel:\n  caddyforge do GET /api/status --token %s\n",
		sess.Expires.Format(time.RFC3339), sess.ID, sess.ID)
	return nil
}

// cmdPasswd sets the UI password and drops every session, because a reset
// usually follows "someone else knows it".
func cmdPasswd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", envDefault("CADDYFORGE_ROOT", ""), "Installation in diesem Baum")
	fromFile := fs.String("password-file", "", "neues Passwort aus dieser Datei (0600 empfohlen)")
	generate := fs.Bool("generate", false, "sicheres Passwort erzeugen und ausgeben")
	if err := fs.Parse(args); err != nil {
		return err
	}

	l := newLayout(ctx, *root)
	store, err := auth.LoadStore(l.paths.AuthFile)
	if err != nil {
		return fmt.Errorf("Auth-Store %s: %w", l.paths.AuthFile, err)
	}

	var password string
	switch {
	case *generate:
		password, err = auth.GeneratePassword()
		if err != nil {
			return err
		}
	case *fromFile != "":
		data, rerr := os.ReadFile(*fromFile)
		if rerr != nil {
			return fmt.Errorf("Passwort-Datei: %w", rerr)
		}
		password = strings.TrimRight(string(data), "\r\n")
	default:
		password, err = readPasswordTwice(stderr)
		if err != nil {
			return err
		}
	}

	if err := store.SetPassword(password); err != nil {
		if errors.Is(err, auth.ErrWeakPassword) {
			return fmt.Errorf("%w – Vorschlag: %s", err, auth.GeneratePasswordHint())
		}
		return err
	}
	if *generate {
		fmt.Fprintf(stdout, "Neues UI-Passwort (einmalig, nicht wiederholbar):\n  %s\n", password)
	} else {
		fmt.Fprintln(stdout, "UI-Passwort gesetzt.")
	}
	fmt.Fprintln(stdout, "Alle Sitzungen sind abgemeldet – die WebUI braucht einen neuen Login.")
	// A running daemon keeps its own copy of the store, so the file we just wrote
	// does not reach it until restart. Saying so beats "the password is wrong".
	if st, serr := l.state(); serr == nil {
		listenPort := st.UIPort
		if listenPort == 0 {
			listenPort = 8484
		}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if _, _, err := callLocalAPI(probeCtx, net.JoinHostPort("127.0.0.1", fmt.Sprint(listenPort)),
			http.MethodGet, "/api/version", nil, ""); err == nil {
			fmt.Fprintln(stderr, "Der Dienst läuft noch: systemctl restart caddyforge (ohne systemd: `caddyforge serve` neu starten), sonst gilt das alte Passwort.")
		}
	}
	return nil
}

// readPassword reads one line from the terminal. The standard library has no
// hidden-input primitive, so the prompt states plainly that the value is shown.
func readPassword(stderr io.Writer, label string) (string, error) {
	if v := os.Getenv("CADDYFORGE_UI_PASSWORD"); v != "" {
		return v, nil
	}
	fmt.Fprintf(stderr, "%s (Eingabe ist sichtbar): ", label)
	p := newPrompt(stderr)
	v := p.ask("", "")
	if v == "" {
		return "", errors.New("leere Eingabe")
	}
	return v, nil
}

func readPasswordTwice(stderr io.Writer) (string, error) {
	first, err := readPassword(stderr, "Neues Passwort")
	if err != nil {
		return "", err
	}
	second, err := readPassword(stderr, "Passwort wiederholen")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("die beiden Eingaben unterscheiden sich")
	}
	return first, nil
}
