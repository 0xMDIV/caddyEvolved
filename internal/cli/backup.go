package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"caddyevolved/internal/backup"
	"caddyevolved/internal/buildinfo"
	"caddyevolved/internal/caddyctl"
	"caddyevolved/internal/secrets"
	"caddyevolved/internal/tui"
)

// readPassphrase takes the backup passphrase from a file, the environment or
// a hidden prompt – never from argv, where it would land in shell history.
func readPassphrase(file string, prompt string, stderr io.Writer, required bool) (string, error) {
	switch {
	case file != "":
		data, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	case os.Getenv("CADDYEVOLVED_BACKUP_PASSPHRASE") != "":
		return os.Getenv("CADDYEVOLVED_BACKUP_PASSPHRASE"), nil
	case !required:
		return "", nil
	case term.IsTerminal(int(os.Stdin.Fd())):
		fmt.Fprint(stderr, prompt+": ")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(stderr)
		return string(pw), err
	}
	return "", errors.New("Passwort nötig: --passphrase-file oder CADDYEVOLVED_BACKUP_PASSPHRASE")
}

func cmdBackup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "Datei schreiben statt im Backup-Verzeichnis ablegen")
	certs := fs.Bool("certs", false, "Zertifikate, Schlüssel und ACME-Konten mitsichern")
	encrypt := fs.Bool("encrypt", false, "mit Passwort verschlüsseln (Abfrage, --passphrase-file oder CADDYEVOLVED_BACKUP_PASSPHRASE)")
	passFile := fs.String("passphrase-file", "", "Passwort aus dieser Datei")
	root := fs.String("root", envDefault("CADDYEVOLVED_ROOT", ""), "Installation in diesem Baum")
	if err := fs.Parse(args); err != nil {
		return err
	}
	l := newLayout(ctx, *root)
	pass, err := readPassphrase(*passFile, "Passwort für das Backup", stderr, *encrypt || *passFile != "")
	if err != nil {
		return err
	}
	if pass != "" && len(pass) < 8 {
		return errors.New("Passwort: mindestens 8 Zeichen")
	}

	var buf bytes.Buffer
	m, err := backup.Create(l.paths, &buf, backup.Options{Certs: *certs, Passphrase: pass, Version: buildinfo.Version, Reason: "CLI"})
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	target := *out
	if target == "" {
		store := backup.Store{Dir: filepath.Join(l.paths.StateDir, "backups")}
		name := backup.FileName("manual", host, m.CreatedAt, pass != "")
		if err := store.Save(name, buf.Bytes()); err != nil {
			return err
		}
		target = filepath.Join(store.Dir, name)
	} else if err := os.WriteFile(target, buf.Bytes(), 0o600); err != nil {
		return err
	}
	notes := []string{}
	if m.Secrets && pass == "" {
		notes = append(notes, "Enthält Zugangsdaten unverschlüsselt – sicher aufbewahren oder mit --encrypt erstellen.")
	}
	tui.Done(stdout, "Backup erstellt", []tui.Row{
		{Label: "Datei", Value: target},
		{Label: "Inhalt", Value: fmt.Sprintf("%d Sites, %d Dateien%s%s", m.Sites, m.Files, map[bool]string{true: ", Zertifikate"}[m.Certs], map[bool]string{true: ", verschlüsselt"}[pass != ""])},
	}, notes...)
	return nil
}

func cmdRestore(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	certs := fs.Bool("certs", false, "auch Zertifikate wiederherstellen, falls im Backup")
	passFile := fs.String("passphrase-file", "", "Passwort aus dieser Datei")
	yes := fs.Bool("yes", false, "ohne Rückfrage")
	root := fs.String("root", envDefault("CADDYEVOLVED_ROOT", ""), "Installation in diesem Baum")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("Aufruf: caddyevolved restore [--certs] DATEI")
	}
	l := newLayout(ctx, *root)
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	pass := ""
	if backup.IsEncrypted(data) {
		if pass, err = readPassphrase(*passFile, "Passwort des Backups", stderr, true); err != nil {
			return err
		}
	}
	m, _, err := backup.Inspect(data, pass)
	if err != nil {
		return err
	}
	p := tui.PaintFor(stdout)
	fmt.Fprintf(stdout, "Backup vom %s (%s, caddyEvolved %s): %d Sites, %d Dateien%s\n",
		m.CreatedAt.Local().Format("02.01.2006 15:04"), m.Host, m.Version, m.Sites, m.Files, map[bool]string{true: ", mit Zertifikaten"}[m.Certs])
	if !*yes {
		ui := openUI(ctx, stdout)
		ok, err := ui.Confirm("Aktuelle Konfiguration ersetzen? (Der jetzige Stand wird vorher gesichert)", false)
		ui.Close()
		if err != nil || !ok {
			fmt.Fprintln(stdout, "Nichts geändert.")
			return err
		}
	}

	// Safety copy of the current state first.
	var safety bytes.Buffer
	if _, err := backup.Create(l.paths, &safety, backup.Options{Certs: *certs && m.Certs, Version: buildinfo.Version, Reason: "vor Wiederherstellung"}); err != nil {
		return fmt.Errorf("aktuellen Stand sichern: %w – nichts geändert", err)
	}
	host, _ := os.Hostname()
	store := backup.Store{Dir: filepath.Join(l.paths.StateDir, "backups")}
	safetyName := backup.FileName("pre-restore", host, time.Now(), false)
	if err := store.Save(safetyName, safety.Bytes()); err != nil {
		return err
	}
	if _, err := backup.Restore(l.paths, data, pass, backup.RestoreOptions{Certs: *certs}); err != nil {
		backup.Restore(l.paths, safety.Bytes(), "", backup.RestoreOptions{Certs: *certs})
		return fmt.Errorf("Wiederherstellen: %w – alter Stand ist zurück", err)
	}

	c := caddyctl.New(l.paths.CaddyBin, l.runner)
	if vars, err := secrets.New(l.paths.EnvFile).Read(); err == nil {
		for k, v := range vars {
			c.Env = append(c.Env, k+"="+v)
		}
	}
	if c.Exists() {
		if out, err := c.Validate(ctx, l.paths.Caddyfile, "caddyfile"); err != nil {
			backup.Restore(l.paths, safety.Bytes(), "", backup.RestoreOptions{Certs: *certs})
			return fmt.Errorf("Caddy lehnt die wiederhergestellte Konfiguration ab – alter Stand ist zurück:\n%s", out)
		}
	}
	if l.hasSystemd(ctx) {
		svc := l.units()
		if *certs && m.Certs {
			_ = svc.Restart(ctx, "caddy.service")
		} else {
			_ = svc.ReloadOrRestart(ctx, "caddy.service")
		}
		_ = svc.Restart(ctx, "caddyevolved.service")
	}
	tui.Done(stdout, "Konfiguration wiederhergestellt", []tui.Row{
		{Label: "Stand vom", Value: m.CreatedAt.Local().Format("02.01.2006 15:04")},
		{Label: "Vorher gesichert", Value: filepath.Join(store.Dir, safetyName)},
	}, p.Dim("Caddy wurde neu geladen, die WebUI neu gestartet – bitte neu anmelden."))
	return nil
}
