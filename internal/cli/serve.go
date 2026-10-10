package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"time"

	"caddyevolved/internal/analytics"
	"caddyevolved/internal/api"
	"caddyevolved/internal/auth"
	"caddyevolved/internal/caddyctl"
	"caddyevolved/internal/config"
	"caddyevolved/internal/events"
)

func cmdServe(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("root", envDefault("CADDYEVOLVED_ROOT", ""), "Installation in diesem Baum verwalten")
	bind := fs.String("bind", "", "Bind-Adresse (Standard: aus state.json, sonst 0.0.0.0)")
	port := fs.Int("port", 0, "Port (Standard: aus state.json, sonst 8484)")
	insecure := fs.Bool("insecure-dev", false, "ohne TLS ausliefern (nur Loopback oder hinter caddy)")
	if err := fs.Parse(args); err != nil {
		return err
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
	ev := events.Open(l.paths.EventsFile)

	bindAddr, listenPort := serveListen(*bind, *port, st)
	if !store.HasPassword() {
		// Every request would be refused: the login path needs a stored hash.
		// Say it before binding a port, because "401 forever" is otherwise the
		// only symptom an operator sees.
		fmt.Fprintln(stderr, "Warnung: kein UI-Passwort gesetzt – Login unmöglich. `caddyevolved passwd` oder `caddyevolved install` ausführen.")
	}

	srv := api.New(&api.Server{
		Paths:     l.paths,
		Runner:    l.runner,
		Auth:      store,
		Events:    ev,
		Caddy:     caddyctl.New(l.paths.CaddyBin, l.runner),
		Analytics: analytics.New(l.paths.AnalyticsFile),
		Bind:      bindAddr,
		Port:      listenPort,
		Insecure:  *insecure,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()
	go srv.StartBackground(ctx)
	fmt.Fprintf(stderr, "caddyevolved serve auf %s (root %s)\n", net.JoinHostPort(bindAddr, fmt.Sprint(listenPort)), displayRoot(l.paths.Root))

	select {
	case err := <-errCh:
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("Abschließen: %w", err)
		}
		ev.Record(events.Event{Kind: events.KindService, Step: "serve", OK: true, Summary: "caddyEvolved stopped"})
		return nil
	}
}

// serveListen resolves the bind/port precedence: flag, then install state, then
// the default. A daemon that ignores state.json would come up on the wrong port
// after an install moved it.
func serveListen(bind string, port int, st config.State) (string, int) {
	if bind == "" {
		bind = st.UIBind
	}
	if bind == "" {
		bind = "0.0.0.0"
	}
	if port == 0 {
		port = st.UIPort
	}
	if port == 0 {
		port = 8484
	}
	return bind, port
}
