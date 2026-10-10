# Stand: läuft auf dem LXC (Builder + WebUI + Sites)

**2026-10-10, nach M1.** Ziel-LXC `192.168.10.27` (Ubuntu 26.04, 2 vCPU, 4 GB, systemd).
Zugang per SSH-Key `~/.ssh/caddyforge_lxc` **in WSL** (nicht im Windows-Profil).

## Was jetzt auf dem LXC verifiziert ist

- `caddyforge install --unattended` auf echtem systemd: alle Schritte `ok`, caddy als User
  `caddy` mit `CAP_NET_BIND_SERVICE` auf 80/443, `Type=notify` startet sauber.
- WebUI auf `https://192.168.10.27:8484` (self-signed), Login aus dem LAN.
- **Sites:** anlegen → validate → reload, HTTPS mit `tls internal` erreichbar; ungültige
  Raw-Site wird abgelehnt und vollständig zurückgerollt; Injection über Domain/Upstream
  wird vor caddy abgefangen.
- **Lokaler Build:** erster Build (inkl. Go-Download von go.dev mit SHA-256, xcaddy-Install)
  caddy v2.11.7 + `caddy-dns/cloudflare` in **108 s**, 48 MB; `list-modules` bestätigt das
  Modul, aktuelles Caddyfile mit neuer Binary validiert.
- **Aktivieren** (Backup → atomarer Tausch → Restart → Admin-API-Check) und **Rollback**
  in beide Richtungen; die Site antwortete bei jedem Schritt mit 200.

## Auf dem Server gefundene und behobene Fehler

| Fehler | Folge | Fix |
|---|---|---|
| `caddy validate` provisioniert die lokale CA und schreibt nach `$HOME/.local` | im gehärteten Daemon (`ProtectSystem`, read-only `/root`) scheitert jede Validierung mit `tls internal`; in caddys Datenverzeichnis hätte es root-eigene Dateien hinterlassen | `caddyctl.ScratchEnv`: validate läuft mit eigenem Wegwerf-`XDG_DATA_HOME` |
| `caddyforge.service` hat `UMask=0077` | vom Daemon geschriebene Snippets/Caddyfile wären `0600`, caddy (User `caddy`) könnte sie nicht lesen | explizites `chmod 0644` / Verzeichnisse `0755` |
| `ProtectSystem=full` ohne `/usr/local/bin` in `ReadWritePaths` | Binary-Tausch nach Build unmöglich | `ReadWritePaths` erweitert |
| `install --dry-run` legte den System-User `caddy` an | Trockenlauf verändert das System | Dry-Run-Guard in `stepSystemUser` |
| `list-modules --nonstandard` (gibt es nicht) | Plugin-Erkennung immer leer | `--skip-standard`, Parser ignoriert die eingerückte Zusammenfassung |

## Runde 2 (2026-10-10 abends): Sicherheit, Analytics, Import, KI – auf dem LXC verifiziert

Laufende Binary auf dem LXC: caddy 2.11.7 + cloudflare, coraza, caddy-defender,
caddy-ratelimit, maxmind-geolocation (Build 38 s dank Modul-Cache).

| Feature | Live-Test |
|---|---|
| Access List | ohne Login 401, mit Login 200, fremde IP trotz Login 403 (`route` hält die Reihenfolge) |
| `caddy hash-password` per stdin | funktioniert, Klartext nie in argv |
| WAF (Coraza/CRS) | normal 200, SQLi/XSS 403; Modus `detect` lässt durch |
| Rate Limit | 5/10 s → ab der 6. Anfrage 429 |
| Plugin-Sidebar | `/api/nav` meldet WAF, Bot-Abwehr, Geo, Rate Limit nach dem Binary-Tausch |
| Coraza + caddy-waf | vor dem Build abgelehnt (gleiche Modul-ID) |
| Analytics | 24 Anfragen, 3 geblockt, Top-Pfade, p95, Live-Liste; überlebt Neustart und Log-Rotation (Test) |
| Import | Traefik-YAML → Site live; kaputte Raw-Site einzeln abgelehnt, Rest übernommen |
| Tokens | read: GET 200, DELETE 403; Token kann keine Tokens erzeugen |
| MCP | legacy `initialize` + modern `server/discover`; read 14 Tools, write 25; `create_site` über MCP live, Audit: `token ki-schreiben (mcp)` |

Gefunden und behoben:
- `caddy validate` (als root) legte `/var/log/caddy/access.log` als root 0600 an → caddy
  konnte nicht loggen. Fix: Daemon legt die Datei vorher als `caddy` an (`ensureAccessLog`),
  Verzeichnis gehört `caddy`.
- caddy versuchte bei jedem Start per sudo seine lokale CA zu installieren →
  `skip_install_trust` im globalen Block (Installer + live gesetzt).

Neue Abhängigkeiten (erste außerhalb der stdlib): `gopkg.in/yaml.v3`, `github.com/BurntSushi/toml`
für den Traefik-Import.

## Offen

- UI ist nur gebaut und über die API getestet, nicht im Browser durchgeklickt.
- MCP antwortet nur JSON (kein SSE-Stream); reicht für alle Tools, die sofort antworten.
- Bestehende Installationen bekommen die neue `caddyforge.service` (ReadWritePaths) nur durch
  erneutes `caddyforge install --force` bzw. manuelles Anpassen der Unit.
- Rollback bei *ungesundem* Start ist implementiert, aber nur der Erfolgspfad ist auf dem LXC
  getestet.
- Builds laufen als root im Daemon (Go-Toolchain unter `/var/lib/caddyforge`). Ein eigener
  Build-User wäre sauberer.
- Caddyfile-Revisionsverlauf (M4), Zertifikatsübersicht (Admin-API-Endpunkt prüfen), Auth-Hardening (M7).
- `internal/forge` (externer Build-Service) ist durch `internal/builder` ersetzt und kann weg.

---

# M1-Status: Build grün, CLI fertig, lokal verifiziert

Stand nach dieser Runde (vorher: `df19599`). Der Build ist **grün**, `go vet` sauber,
`gofmt -l .` leer, und die Installation ist in WSL **ohne root end-to-end durchgelaufen**.
M1 fehlt nur noch die Verifikation auf echtem systemd (Proxmox-LXC).

## 0. Kurzfassung

**Gebaut und verifiziert (M1):**
- Statische Go-Binary `caddyforge`, alle 14 CLI-Befehle implementiert; `proxy` (M5) und
  `uninstall` (M7) sind bewusste Absagen statt halber Pfade.
- Installation end-to-end in WSL als uid 1000 gegen einen `--prefix`-Baum: alle zwölf
  Schritte `ok`/`skipped`, caddy 2.11.7 geladen und Digest geprüft, Caddyfile validiert,
  UI-Zugang gesetzt, per Supervisor gestartet, Admin-API antwortet.
- `status`, `validate`, `version`, `logs`, `stop`, `serve`, `token`, `do` gegen genau
  diese Installation durchgetestet.
- Build grün, `go vet` sauber, `gofmt -l .` leer, Tests in 7 Paketen (kein Netz, kein
  root). Statisches Binary: `dist/caddyforge` (10 MB).
- Sieben Fehler, die nur die echte Ausführung zeigen konnte, sind gefixt — siehe
  Tabelle 3.

**Offen (Exit-Kriterien für M1):** siehe Abschnitt 6 als Checkliste. Einzige echte
Lücke ist die systemd-/LXC-Verifikation; der Prefix-Test in WSL kann sie nicht belegen.

## 1. Was jetzt funktioniert (verifiziert, nicht nur gebaut)

Verifikation lief in WSL Ubuntu-24.04 als uid 1000 gegen einen Prefix-Baum
(`--prefix`), also ohne root, ohne systemd-Berührung:

```
caddyforge install --prefix ~/caddytest/stage \
  --unattended docs/examples/answers.official.json \
  --http-port 8080 --https-port 8443 --ui-port 8585 --ui-bind 127.0.0.1 --yes
```

Alle zwölf Schritte `ok`/`skipped`, darunter:

- caddy 2.11.7 von GitHub geladen, **Digest-Prüfung bestanden**, entpackt, ausführbar
- Caddyfile mit `caddy validate` geprüft, dann geschrieben (Atomic: erst prüfen, dann rennen)
- UI-Passwort generiert und **einmal** ausgegeben
- `state.json`, `env` (0600), beide Unit-Dateien gerendernt
- caddy per Supervisor gestartet, Admin-API auf `localhost:2019` antwortet
- `status`, `validate`, `version`, `logs`, `stop`, `serve`, `token`, `do` gegen diese
  Installation ausgeführt; `do POST /api/cert` mit Token 200, ohne Token 401

Tests: `go test ./...` deckt `auth`, `caddyctl`, `cli`, `fetch`, `install`, `plugins`,
`secrets` ab (7 Pakete, reine Funktion + `httptest`, kein Netz, kein root).

### 1a. self-signed-Pfad nachgetestet (`managed: false`)

Der obige Lauf nutzte `managed: true` mit echtem ACME-Issuer. Die Variante ohne Modul und
ohne ACME (`docs/examples/answers.selfsigned.json`) war ungeprüft und läuft jetzt ebenfalls
in WSL gegen einen Prefix-Baum (`--http-port 8080 --https-port 8443 --ui-port 8585`):

- Caddyfile rendert `tls internal` und **kein** `email` in den globalen Options.
- `caddy` startet, `verify` wird `ok`, das Local-CA-Zertifikat wird ausgestellt:
  `issuer=CN = Caddy Local Authority - ECC Intermediate`, Laufzeit 12 h.
- Site antwortet: `HTTP 502` (der Beispiel-Backend `127.0.0.1:18080` läuft bewusst nicht)
  und `HTTP 308` Redirect von http nach https — der Proxy-Pfad ist also durch.

Drei Beobachtungen, die der Lauf gezeigt hat:

1. **Ports 80/443 sind in WSL als uid 1000 nicht bindbar.** Mit `answers.selfsigned.json`
   unverändert (80/443) wird `verify` `failed` mit `admin-API nicht erreichbar`, während die
   eigentliche Ursache im caddy-Log steht: `listen tcp :443: bind: permission denied`.
   Die Diagnose ist damit an der falschen Stelle – der Fehler ist ein Bind-Problem, gemeldet
   wird ein Health-Check. Auf dem LXC (root + `CAP_NET_BIND_SERVICE`) tritt es nicht auf.
   `preflight` warnt in diesem Fall nur in `s.Reason` (`Ports <1024: als uid …`), es ist kein
   Abbruch. Für Prefix-Tests immer Hochports geben.
2. **Nicht-Standard-Ports und Redirect-Ziel:** bei `https_port 8443` in den globalen Options
   antwortet der Auto-HTTPS-Redirect mit `Location: https://caddytest.local/` (also :443).
   Nicht verifiziert, ob das caddy-Verhalten oder unsere Konfiguration ist; für M1 egal
   (Live-Installation nutzt 443), für M5 relevant.
3. **`--prefix` gibt es nur bei `install`.** Alle anderen Befehle nehmen denselben Baum über
   `--root DIR` (`newLayout(firstNonEmpty(prefix, root))`), `stop --prefix` ist ein
   Flag-Fehler. Absichtliche Benennungsasymmetrie, aber gewöhnungsbedürftig.

## 2. Die Befehle, die die Arbeit getragen haben

```bash
# Alles über WSL, Windows hat kein Go.
wsl -d Ubuntu-24.04 -- bash -c "export PATH=\$HOME/.local/go/bin:\$PATH; \
  cd /mnt/p/code/caddyEvolved && gofmt -w . && go vet ./... && go test ./..."
```

Staging-Baum **nicht** in `/tmp` anlegen: WSL fährt die Distro zwischen Aufrufen herunter,
`/tmp` ist tmpfs und weg. `~/caddytest` überlebt.

## 3. Was diese Runde gefunden und gefixt wurde

Nicht nur Compile-Errors nachziehen – die echte Ausführung hat sechs Fehler zu Tage
gefördert, die der Build nicht sehen konnte:

| Fehler | Folge ohne Fix | Fix |
|---|---|---|
| `caddy_<ver>_checksums.txt` enthält **SHA-512**, wir prüften hart gegen SHA-256 | jede Official-Installation bricht mit "checksum mismatch" | `fetch.ParseDigest` leitet den Algorithmus aus Präfix **oder Länge** ab; `Options.SHA256` → `Options.Digest`; `ToFile` hasht beides |
| `caddy --version` liefert `v2.11.7 h1:...` (kein "Caddy version"-Präfix mehr) | Versionsvergleich mit `"h1:yj0Y..."`, Installation bricht | Feldsuche per Regex statt Präfix-Annahme (`caddyctl.Version`) |
| `caddy validate` lief gegen die **noch nicht geschriebene** Caddyfile | Erstinstallation scheitert immer | Inhalt nach `.caddyforge-new` schreiben, prüfen, dann `rename` |
| `--dry-run` schrieb `env` und Verzeichnisse, und gab ein Passwort aus, das nie entstand | Sicherheitsnetz lügt | Dry-Run-Guard in `directories`, `credentials`; Passwort-Generierung hinter den Dry-Run-Zweig |
| Prefix-Installation rief `systemctl daemon-reload`/`enable` und `status` auf dem **Live-System** | Non-root bricht ab; im Ernstfall würdest du den echten caddy steuern | `systemd.Service.Write()` ohne Reload; Prefix-Zweige in `stepUnits`, `stepEnableStart`, `stepVerify`; `layout.hasSystemd()` knows prefix |
| `p.resolved.started` blieb ohne systemd false | `verify` übersprungen, nie ein Health-Check | `enable-start` setzt `started` auch im Supervisor-Pfad |

Dazu die im alten Stand dokumentierten Signaturen (`supervisor.New` mit 5 Argumenten,
`Entry.Registr`, `config.State.UIBind`) und die 14 fehlenden CLI-Funktionen.

Zwei Entscheidungen, die ich getroffen habe – bitte gegenlesen:

1. **`caddyforge.service` ist `Type=simple`, nicht `Type=notify`.** Das Binary spricht
   `sd_notify` nicht, also hätte systemd den Start nach `TimeoutStartSec` abgebrochen.
   `caddy.service` bleibt `notify` (caddy kann das). sd_notify für uns wäre ein eigene
   Kleinigkeit, aber kein M1-Gewinn.
2. **`token` fragt den laufenden Daemon** (`POST /api/login`) und fällt nur zurück, wenn
   nichts lauscht. Der Daemon hält die Session-Tabelle im Speicher; ein direkt in
   `auth.json` geschriebener Token wäre von einem laufenden Dienst ignoriert worden.
   `passwd` kann das nicht umgehen und weist deshalb auf den nötigen Neustart hin.

## 4. CLI-Fläche (M1)

| Befehl | Status |
|---|---|
| `install` | Wizard (interaktiv) + `--unattended answers.json`, `--prefix`, `--dry-run`, `--force`, `--yes`, `--json`, Flags für Quelle/Version/Module/Ports/ Site/Passwort |
| `serve` | Daemon, Bind/Port aus `state.json`, Flag schlägt State; Shutdown auf SIGTERM |
| `status` | Text + `--json`; State, Binary, Dienst, Admin-API, WebUI-Probe, Modulprüfung, Ports; Probleme im Exit-Code |
| `start` `stop` `restart` `reload` | systemd **oder** Supervisor; `reload` validiert vorher |
| `validate` | `caddy validate` gegen Datei oder installiertes Caddyfile, `--json` |
| `logs` | `journalctl` bzw. Tail-Datei, `--follow` für beide Pfade |
| `token` `passwd` | funktionierend (siehe oben) |
| `do` | HTTP gegen die eigene API, Trailing-Flags werden erkannt |
| `version` `commands` `help` | vorhanden |
| `proxy` | bewusste Absage (M5) |
| `uninstall` | bewusste Absage (M7) – destruktiv, deshalb kein halber Pfad |

Beispieldateien: `docs/examples/answers.official.json`,
`docs/examples/answers.dns-hetzner.json` (DNS-01 mit `custom`-Quelle),
`docs/examples/answers.selfsigned.json` (Basis-System ohne Module und ohne ACME – die
Test-Datei für die LXC-Verifikation; `siteTarget` auf `127.0.0.1:18080`, damit der
Proxy-Pfad ohne echten Backend durchgetestet werden kann).

## 5. Nächster Schritt: Verifikation auf dem LXC

Der Prefix-Test belegt die Engine, aber **nicht** systemd + `CAP_NET_BIND_SERVICE` +
Ports 80/443 in einem unprivilegierten Container. Diese Lücke ist offen.

Bauen (statisch, damit die LXC keine Toolchain braucht):

```bash
wsl -d Ubuntu-24.04 -- bash -c "export PATH=\$HOME/.local/go/bin:\$PATH; \
  cd /mnt/p/code/caddyEvolved && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags '-s -w' -o dist/caddyforge ./cmd/caddyforge && sha256sum dist/caddyforge"
```

Auf dem LXC (Debian 12 / Ubuntu 24.04, systemd als Init, root):

```bash
# 1) Binary ablegen
install -m 0755 caddyforge /usr/local/bin/caddyforge

# 2) Trockenlauf: schreibt nichts, zeigt den Plan
caddyforge install --unattended antworten.json --dry-run

# 3) Echte Installation (DNS-01-Variante: Token in antworten.json eintragen)
caddyforge install --unattended antworten.json
# 4) Das ausgegebenene UI-Passwort notieren, dann:
caddyforge status
systemctl status caddy caddyforge
journalctl -u caddyforge -n 30
caddyforge token            # API-Token für die Kommandozeile
caddyforge do GET /api/status --token <TOKEN>
```

Worauf der LXC-Lauf besonders achtet (alles Punkte, die WSL nicht abdeckt):

- `useradd --system caddy` und `chown` auf `/var/lib/caddy`, `/etc/caddy`
- `AmbientCapabilities=CAP_NET_BIND_SERVICE` mit `httpPort 80`/`httpsPort 443`
- `Type=notify` für caddy: startet und bleibt der Dienst, wenn systemd auf READY=1 wartet?
- `ProtectSystem=full` + `ReadWritePaths` in `caddyforge.service`: kann der Daemon
  trotzdem `/etc/caddy/Caddyfile` und `/etc/caddyforge/env` schreiben?
- HTTPS-Bindung der UI auf `0.0.0.0` mit self-signed Cert, Login vom LAN aus
- DNS-01: Zertifikatsausstellung für eine echte Domain (Der-Fluss dauert 1–3 Minuten
  bei `binarySource: custom`, weil caddyserver.com den Build kompiliert)

## 6. Was vor M2 noch offen bleibt

Exit-Kriterien, Reihenfolge egal bis auf den ersten Punkt:

- [ ] **LXC-Verifikation (Abschnitt 5)** — blockiert den M1-Abschluss als einziger Punkt.
      Belegen muss sie: `useradd --system caddy` + `chown`, `CAP_NET_BIND_SERVICE` auf
      80/443, `Type=notify` für caddy, `ProtectSystem=full` mit `ReadWritePaths`,
      UI-Login vom LAN auf `0.0.0.0`.
- [x] `LICENSE` — **MIT**, Copyright 2026 `0xMDIV` (Repo-Inhaber, wie in `git config`).
      Andere Inhaber-Zeile → `LICENSE` ändern und neu committen, bevor das breit genutzt wird.
      Caddy selbst ist **Apache-2.0** (verifiziert über die GitHub-API), wir bündeln es aber
      nur zur Installationszeit über den Download. **Sobald M8 Bundle-Releases mit
      caddy-Binary ausliefert, verlangt Apache-2.0 Lizenz- und NOTICE-Texte im Bundle.**
- [ ] Install-Report nennt die WebUI-URL mit `<host-ip>` statt einer anklickbaren Adresse
      (`displayHost` in `install/runtime.go`); schön wäre die tatsächliche LAN-Adresse.
- [ ] `caddy-security` in der Standard-Variante: Fläche groß, Binary größer – eher opt-in.
- [ ] Doku soll auf die Dateirechte für `Answers.Credentials` hinweisen: es landet in
      `env` (0600) **und** in `answers.json`. Die Beispiele enthalten Absichtswerte.

Erledigt: Commit `aba04ba` ist gepusht (`origin/main`).

## 7. Fallstricke (aktualisiert)

- **SHA-512 in Caddys Checksums-Datei** – siehe Tabelle 3. Ein Digest ist nie "die
  Hash-Funktion, die wir gerade haben", sondern Präfix oder Länge.
- **`caddy --version`-Format ist nicht stabil.** Feld-Matching, kein Präfix-Parser.
- **`flag` stoppt am ersten Positionsargument.** `do GET /x --port 85` schluckt `--port`
  still; `partitionFlags` in `internal/cli/root.go` zieht die Flags vorher heraus.
- **`--prefix` ist kein Live-System.** Jeder Pfad, der `systemctl` aufruft, braucht den
  Prefix-Zweig – sonst steuert ein Test die echte Maschine.
- **`/tmp` in WSL ist flüchtig**, Staging-Bäume dort verschwinden zwischen Aufrufen
  (und hinterlassen caddy-Prozesse ohne PID-Datei, die Ports belegen).
- **Mehrzeilige Commit-Bodies per `-m` schneidet cmd.exe ab** → immer `git commit -F datei`.
- **`.gitignore`-Muster gewurzelt schreiben** (`/caddyforge`, nicht `caddyforge`).
- **CRLF ist ein Function-Bug**: systemd-Units und Shell-Scripts brauchen LF
  (`.gitattributes` erzwingt das, `core.autocrlf=input` repo-lokal).
- **Kein Feature vor grüner Verifikation**: M2 beginnt erst nach Punkt 5.
