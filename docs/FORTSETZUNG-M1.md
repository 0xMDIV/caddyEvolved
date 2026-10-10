# M1 fortsetzen — Wo wir stehen und was als nächstes kommt

Handoff-Stand: Commit `0e6a2d6` auf `main`. **Der Build ist rot, und das ist der
dokumentierte Zustand, nicht ein Versehen.** Diese Datei ist der Wiedereinstieg
ohne erneutes Analysieren.

## 1. Umgebungs-Realität (nicht nochmal suchen)

| Fakt | Konsequenz |
|---|---|
| Kein Go auf Windows, nur in WSL (`~/.local/go`, User `dev`) | Alle Build-/Testbefehle über `wsl -d Ubuntu-24.04` |
| `sudo` in WSL verlangt Passwort | Kein `/usr/local`, kein apt; keine sudo-Befehle einbauen |
| Repo liegt in WSL unter `/mnt/p/code/caddyEvolved` | Pfade in Scripts so schreiben |
| Docker-CLI da, **Daemon aus** (Docker Desktop gestoppt) | Kein Container-Build, bis der User ihn startet |
| `make` fehlt auf Windows | Scripts als `.sh` in WSL oder als Go-Task |

Arbeitsbefehl:

```bash
wsl -d Ubuntu-24.04 -- bash -c "export PATH=\$HOME/.local/go/bin:\$PATH; cd /mnt/p/code/caddyEvolved && go build ./... 2>&1 | head -40"
```

## 2. Arbeitsreihenfolge bis M1 grün

Die Pakete `supervisor`, `plugins`, `auth` bauen bereits fehlerfrei. Der Rest ist
kaskadiert — `api` ist aktuell unsichtbar, weil `install` vorher fällt. In dieser
Reihenfolge abarbeiten, sonst Errors erfinden:

### Schritt 1 — `internal/install` (5 echte Fehler)

```
runtime.go:167:80  not enough arguments in call to supervisor.New
                   have (string, string, string, string)
                   want (string, string, string, string, string)
steps.go:209:26    e.Registers undefined (plugins.Entry has no field Registers)
steps.go:275:5     st.UIBind undefined (config.State has no field UIBind)
units.go:7:2       "fmt" imported and not used
units.go:8:2       "path/filepath" imported and not used
```

- `supervisor.New(bin, config, envFile, logPath, pidFile)` — das `envFile`-Argument
  fehlt an der Aufrufstelle; `p.paths.EnvFile` durchreichen.
- Feld heißt `Registr`, nicht `Registers`.
- `UIBind` lebt in `Answers`/`api.stateView`, **nicht** in `config.State`.
  Entscheidung nötig: entweder `State.UIBind` ergänzen (sinnvoll, die UI braucht es
  nach jedem Reload), oder den Write in `steps.go` löschen. Ich würde ergänzen.
- Imports aufräumen.

### Schritt 2 — `internal/api` (jetzt erst sichtbar)

Nach Schritt 1 neu bauen; die dortigen Fehler sind noch unbekannt. Erwartete
Kandidaten aus dem Schreiben: `handlers_install.go` (`runs`-Feld initialisieren?),
`middleware.go` (Session-Struktur), `handlers_status.go` (`pluginStates` braucht
`config.State`-Feld `Enabled` ✓ vorhanden).

### Schritt 3 — `internal/cli` (Hauptblock, 14 fehlende Funktionen)

`cli.go:30-43` referenziert:

```
cmdInstall cmdServe cmdStatus cmdStart cmdStop cmdRestart cmdReload
cmdValidate cmdLogs cmdProxy cmdToken cmdPasswd cmdDo cmdUninstall
```

Unterschätzt das nicht — das ist die halbe M1-Arbeit, nicht ein Nachziehen.
Sinnvolle Aufteilung in Dateien: `install.go`, `service.go` (start/stop/restart/
reload/validate), `serve.go`, `status.go`, `secrets.go` (token/passwd), `do.go`,
`proxy.go`, `uninstall.go`. Alle haben Signatur
`func(ctx context.Context, args []string, stdout, stderr io.Writer) error`.

Für M1 **Pflicht**: `install` (Wizard + `--unattended`), `serve`, `status`,
`start/stop/reload`, `version`, `validate`.
Für M1 **zurückstellbar** (Stub mit "noch nicht in M1" ist okay, damit der Build
grün wird): `proxy` (M5), `do` (M2+), `logs` (M2), `token`/`passwd` (M7),
`uninstall` (M7).

### Schritt 4 — Formatierung

```bash
gofmt -l .   # aktuell 19 Dateien
gofmt -w .
```

Vor jedem Commit ausführen, nicht als separater "format only"-Commit.

### Schritt 5 — Verifikation von M1

Erstes echtes Ziel: **eine Installation in einen `--prefix`-Staging-Baum**, die
Caddy startet und die Admin-API antworten lässt, ohne root und ohne LXC:

```bash
./caddyforge install --prefix /tmp/stage --unattended answers.json --dry-run
```

Dann `go vet ./...` und Tests für die Stellen, die ohne System auskommen:
`plugins.Resolve`, `fetch.ParseChecksumFile`, `secrets.Apply`, `auth` Hash/Roundtrip,
`install.Answers.Validate`. Diese fünf sind reine Funktion und ohne Container testbar.

## 3. Was schon verifiziert ist (nicht erneut prüfen)

Der Plugin-Katalog (`internal/plugins/catalog.json`) ist gegen `proxy.golang.org`
geprüft; Importpfade sind byte-genau. Vier Punkte, die beim Bauen still falsch
wären und es jetzt nicht sind:

- `github.com/caddy-dns/hetzner/v2` — **ohne `/v2` baut xcaddy gegen v1.0.0 (2025-05)**.
  Feld `versionSuffix: true` markiert genau diese Fallen.
- Cloudflare: `CF_API_TOKEN` (lego liest es direkt) — nicht `CLOUDFLARE_API_TOKEN`.
- `all-inkl` existiert, Caddyfile-Name ist aber `allinkl` (ohne Bindestrich).
- Die meisten `caddy-dns`-Module lesen **keine** Env-Variablen selbst, sie erwarten
  Argument/Option. Deshalb interpoliert `install/caddyfile.go` jeden Wert explizit
  als `{env.X}` — sonst validiert die Config und die Cert-Ausstellung scheitert
  Minuten später, ohne nachvollziehbare Fehlerquelle.

Nicht verifiziert, bewusst als `note` markiert: Konfigurationsschlüssel von
`storage-postgresql`, `transip`-gleiche Pfade, `caddy-security`-Direktivnamen pro
Site. Vor M6/M3 gezielt nachlesen.

## 4. Anschluss an M2 (damit der Übergang nicht überrascht)

- UI bindet `0.0.0.0`, Login mit Passwort (PBKDF2-HMAC-SHA256, 600k Iterationen,
  bewusst stdlib statt `x/crypto`, damit `go build` ohne Netzwerkmodule läuft).
  Das erste Passwort generiert der Installer und gibt es **einmal** im Report aus.
- SSE-Vertrag steht schon: `GET /api/events/stream` mit `Last-Event-ID`, `id:`- und
  `event:`-Feldern; REST-Endpunkte in `internal/api/server.go` verdrahtet.
- Der Build ist ohne Internet nicht möglich? Doch: **keine externen Go-Dependencies**
  in `go.mod`. Das ist eine Eigenschaft, die wir halten wollen (LXC ohne Toolchain).
- Caddy-Validierung läuft immer über die **installierte** Binary, nicht über
  einkompilierte Caddy-Pakete — keine Versionskopplung, kein cgo.

## 5. Offene Entscheidungen (brauchen Input, nicht Code)

1. **Echter Proxmox-LXC**: Zu welcher Zeit kann auf eine echte LXC deployt werden?
   Ein `--prefix`-Test in WSL belegt die Engine, aber nicht systemd + CAP_NET_BIND_SERVICE
   + DNS-01 in einem unprivilegierten Container. Diese Lücke ist real.
2. **Docker Desktop**: nur nötig, wenn wir `xcaddy`-Builds lokal (statt im CI) bauen
   wollen. Bis M8 nicht nötig.
3. **Lizenz des Projekts** selbst (Repo ist öffentlich, bisher ohne LICENSE).
4. **`caddy-security` in der Standard-Variante**: vergrößert die Binary spürbar.
   Wenn die UI es nicht wirklich konfigurieren kann (große Fläche), lieber opt-in.

## 6. Fallstricke, die schon einmal wehgetan haben

- **Mehrzeilige Commit-Bodies per `-m` schneidet cmd.exe bei der ersten leeren Zeile
  ab.** Immer `git commit -F datei`. Zwei Mal passiert, einmal per amend +
  `--force-with-lease` repariert.
- **`.gitignore` muss Binary-Muster gewurzelt schreiben** (`/caddyforge`, nicht
  `caddyforge`) — sonst verschluckt das Muster `cmd/caddyforge/` komplett. Ist
  passiert und war still (Datei einfach nicht im Commit).
- **CRLF ist für uns ein Function-Bug, nicht Style**: systemd-Units parsen CRLF
  falsch, Shell-Scripts sterben mit "bad interpreter". `.gitattributes` erzwingt LF,
  `core.autocrlf=input` ist repo-lokal gesetzt.
- **Kein Feature vor grünem Build**: M2 beginnt erst nach Schritt 5.
