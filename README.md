# caddyforge

Advanced Caddy installer + modern web admin UI. Ein einzelnes Go-Binary, das auf einem
Proxmox-LXC Caddy installiert, die bekannten Caddy-Module mit einrichtet und alles über
eine WebGUI verwaltbar macht.

**Status: läuft auf dem Ziel-LXC.** Installation, WebUI, Sites-Verwaltung und der
lokale Custom-Build sind auf echtem systemd (Ubuntu 26.04, Proxmox-LXC) verifiziert.
API-Vertrag: [`docs/API.md`](docs/API.md), Stand und Fallstricke:
[`docs/FORTSETZUNG-M1.md`](docs/FORTSETZUNG-M1.md).

## Warum

Caddy ist ein hervorragender Reverse Proxy mit automatischem HTTPS — aber:

- Die Konfiguration ist eine Textdatei, was für Homelabs und kleine Teams unnötig Hürde ist.
- Caddy-"Plugins" sind **keine** Runtime-Plugins. Community-Module (DNS-Provider, SSO,
  Layer-4-Proxy, ACME-Storage) werden mit `xcaddy` in die Binary **hineinkompiliert**.
  "Ein Plugin installieren" heißt also "eine neue Binary bauen".
- Der offizielle Weg (`caddyserver.com/api/download`) kompiliert serverseitig auf
  Bestellung — im Test **~114 Sekunden** pro Anfrage. Für einen Installer, der "sofort
  läuft", unbrauchbar.

caddyforge löst das mit drei Schichten statt mit einem Kompromiss.

## Plugin-Modell: Caddy wird auf dem Server gebaut

Caddy-Module werden einkompiliert. caddyforge baut die Binary deshalb **auf dem
Server selbst**: In der WebUI unter *Plugins & Build* Module ankreuzen (oder einen
freien Go-Modulpfad angeben), Caddy-Version wählen, Build starten.

1. Beim ersten Build lädt caddyforge Go von go.dev (**SHA-256 gegen den offiziellen
   Index geprüft**) und installiert xcaddy – alles unter `/var/lib/caddyforge/`,
   nichts systemweit.
2. `xcaddy build` läuft mit Live-Log in der UI (SSE). Modul-Cache bleibt erhalten,
   Folge-Builds sind deutlich schneller.
3. Die neue Binary wird geprüft: startet sie, enthält sie jedes gewünschte Modul
   (`list-modules --packages`), akzeptiert sie das aktuelle Caddyfile?
4. **Aktivieren** sichert die laufende Binary, tauscht atomar, startet caddy neu und
   wartet auf die Admin-API. Wird caddy nicht gesund, kommt die alte Binary
   automatisch zurück. *Rollback* ist jederzeit ein Klick.

## Sites (Reverse Proxy)

Jede Site ist eine Datei `/etc/caddy/sites/<id>.caddy`, das Caddyfile bindet sie mit
`import /etc/caddy/sites/*.caddy` ein. Änderungen in der UI laufen als Transaktion:
schreiben → `caddy validate` → reload; lehnt caddy ab, wird der alte Stand
wiederhergestellt und die Fehlermeldung angezeigt. Modi: Reverse Proxy (mehrere
Upstreams, Load-Balancing, Health-Check, Upstream-TLS), Weiterleitung, statische
Dateien, Raw. TLS: automatisch (ACME), intern (lokale CA), DNS-01 über ein
eingebautes DNS-Plugin, oder nur HTTP. Das Caddyfile selbst bleibt im
Expertenmodus der UI editierbar.

## Sicherheit, Analytics, Import, KI

- **Access Lists:** IP-Freigabe/-Sperre, Länder (Plugin `maxmind-geolocation`) und
  Basic-Auth-Benutzer (bcrypt über `caddy hash-password`, Klartext nie auf Platte). Pro
  Site zuweisbar; die Prüfungen laufen in einem `route`-Block vor dem Login.
- **Schutz pro Site** (nur sichtbar, wenn das Plugin eingebaut ist): WAF (Coraza + OWASP
  CRS, Modus blockieren/nur protokollieren), Bot-Abwehr (`caddy-defender`, z. B. KI-Crawler),
  Rate Limit (`caddy-ratelimit`). Plugins mit eigener Seite erscheinen automatisch in der
  Sidebar, sobald sie in der laufenden Binary stecken.
- **Zertifikate:** Übersicht aus caddys Speicher (die Admin-API listet keine ACME-Zertifikate),
  Download der internen Root-CA.
- **Analytics:** alle Sites schreiben ein JSON-Access-Log; caddyforge aggregiert Minuten
  (48 h) und Stunden (35 Tage): Anfragen nach Statusklasse, Geblockt, Latenz (Ø/p95),
  Top-Pfade/-IPs/-Agents/-Referer, Live-Liste.
- **Audit Log:** jeder ändernde API-Aufruf mit Session bzw. Token-Name.
- **Import:** Caddyfile, Zoraxy (Backup-ZIP), Traefik (YAML/TOML, docker-compose-Labels),
  Nginx Proxy Manager (API-JSON oder `sqlite3 -json`) – mit Vorschau, Warnungen und
  Einzelübernahme.
- **API-Tokens + MCP:** gehashte Tokens mit Scope `read`/`write`; `POST /mcp` ist ein
  MCP-Server (Spezifikation 2026-07-28, abwärtskompatibel), über den eine KI Sites,
  Access Lists, Builds, Logs und Analytics bedienen kann.

## Architektur

- **Ein statisches Go-Binary** (`caddyforge`): Installer, Daemon, REST-API, SSE-Streams und
  das per `embed.FS` eingebaute React-Frontend. Im LXC braucht es danach kein Node, kein
  Docker und keine Internet-Abhängigkeit.
- **Caddyfile bleibt Source of Truth.** Validierung und Formatierung laufen über die
  *installierte* `caddy`-Binary (`caddy validate`, `caddy fmt --stdin`), deshalb keine
  Versionskopplung an Caddy. Reload ohne Downtime.
- **Auth:** UI bindet `0.0.0.0` mit Login (PBKDF2-HMAC-SHA256, 600k Iterationen —
  bewusst stdlib statt `x/crypto`, damit `go build` ohne Netzwerkmodule läuft),
  HttpOnly-Session-Cookie, Lockout nach 5 Fehlversuchen, Session-Revocation.
- **FHS-Layout:** `/usr/local/bin/caddyforge`, `/etc/caddyforge/{state.json,auth.json,env,ui.crt}`,
  `/var/lib/caddyforge/`, UI-Port Standard `8484`.
- **Testbarkeit:** Jeder Pfad geht über `config.Paths`, das mit `--root <prefix>` complete
  in einen Staging-Baum umgebogen wird. Damit ist die Install-Engine unprivileged in einem
  Temp-Verzeichnis testbar, ohne ein echtes System anzufassen.

## Installation (Zielzustand)

```bash
sudo ./caddyforge install                      # interaktiver Wizard
sudo ./caddyforge install --unattended a.json  # headless, für Cloud-Init
```

Ablauf: Preflight (root/systemd/LXC-Detect, Ports 80/443/2019/8484, bestehendes Caddy) →
Variante + Modul-Häkchen → Credentials pro Provider → User/Group `caddy` + Verzeichnisse →
Binary-Download **mit SHA256-Abgleich gegen das offizielle `checksums.txt`** → Caddyfile →
UI-Zugang (generiertes Passwort, wird genau einmal ausgegeben) → systemd-Units (Basis:
offizielles Vorbild aus `caddyserver/dist@master:init/caddy.service`, plus
`EnvironmentFile`) → `enable --now` → Health-Check über die Admin-API → Report.

LXC-spezifisch berücksichtigt: `CAP_NET_BIND_SERVICE` für Ports < 1024, kein `--resume`
(das Caddyfile gewinnt beim Neustart), `Type=notify`, unprivileged-Container-Erkennung.

## Bauen

Go 1.27+ (Backend, in WSL Ubuntu-24.04), Node 24 (Frontend):

```bash
cd ui && npm ci && npm run build        # Frontend nach internal/webui/dist (eingecheckt)
go vet ./... && go test ./...           # Prüfung
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o dist/caddyforge ./cmd/caddyforge   # statisches Binary für den LXC
```

Frontend-Entwicklung: `npm run dev` in `ui/` proxyt `/api` auf `https://127.0.0.1:8484`.

## Struktur

```
cmd/caddyforge/        Einstiegspunkt
internal/cli/          Befehle: install, serve, status, start/stop/reload, proxy, token, do
internal/install/      Schritt-Engine (idempotent, dry-run), Preflight, Units, Caddyfile
internal/config/       FHS-Layout mit --root-Prefix, state.json
internal/platform/     Host-Erkennung: Distro, systemd, LXC, Portbelegung
internal/caddyctl/     caddy-Binary (validate/fmt/reload/list-modules) + Admin-API
internal/systemd/      systemctl-Aktionen, Unit-Installation
internal/supervisor/     Prozessverwaltung ohne systemd (--root-Tests)
internal/fetch/          Download, Digest-Prüfung (SHA-256/SHA-512), tar.gz-Extraktion, atomarer Write
internal/releases/     GitHub-Releases, Asset-Namen, Custom-Build-URL
internal/plugins/      kuratierter Modul-Katalog + Go-Proxy-Validierung freier Pfade
internal/secrets/      EnvironmentFile-Verwaltung (Namen-only Reports)
internal/builder/      lokaler xcaddy-Build: Go-Toolchain, Jobs, Live-Log, Aktivierung + Rollback
internal/sites/        Reverse-Proxy-Sites, Access Lists, WAF/Bot/Rate-Limit-Rendering, transaktional
internal/certs/        Zertifikate aus caddys Storage lesen
internal/analytics/    Access-Log-Follower und Aggregation (Minute/Stunde, Top-Listen)
internal/importer/     Import aus Caddyfile, Zoraxy, Traefik, Nginx Proxy Manager
internal/forge/        (alt) Client für einen externen Build-Service, ungenutzt
ui/                    React + Vite + TypeScript, Build landet in internal/webui/dist
internal/api/          HTTP-Routen, Auth-Middleware, SSE, self-signed TLS
internal/auth/         PBKDF2-Passwort, Sessions, Lockout
internal/events/       events.jsonl + Live-Fan-out für die UI
internal/webui/        embed.FS für das gebaute Frontend
```

## Roadmap

- [x] **M1** Gerüst, Install-Engine, systemd — auf dem LXC verifiziert
- [x] **M2** WebUI-Shell + Dashboard
- [x] **M3** Plugin-Katalog + Credentials + **lokaler Custom-Build mit Rollback**
- [~] **M4** Caddyfile-Editor + Validate/Reload — *Revisionsverlauf offen*
- [x] **M5** Reverse-Proxy-Sites
- [~] **M6** Zertifikate — *Übersicht + DNS-01 fertig; manuelles Erneuern/Hochladen offen*
- [x] Access Lists, WAF/Bot-Abwehr/Rate Limit, Plugin-Seiten in der Sidebar
- [x] Analytics, Audit Log, Import (Caddyfile/Zoraxy/Traefik/NPM), API-Tokens, MCP
- [ ] **M7** Auth/Hardening (Mehrbenutzer, 2FA)
- [ ] **M8** CI für Bundle-Varianten + Releases, LXC-Testharness

## Verifizierte Faktengrundlage

- Caddy aktuell: **v2.11.7** (2026-10-03)
- Offizielle systemd-Unit: `caddyserver/dist@master:init/caddy.service`
- DNS-Provider unter `github.com/caddy-dns/*` sind meist unterrepräsentiert: `all-inkl` hat
  **keinen** caddy-dns-Ableger (nur `gregormuehlberger/caddy-dns-all-inkl`, 5 ★),
  `servercow` ebenso. `caddy-dns/google-domains` ist archiviert *und* v0.0.2 (pre-semver) →
  als nicht wählbar markiert.
- Katalog-Importpfade werden gegen `proxy.golang.org` geprüft, nicht geraten.

## Lizenz

MIT — siehe [LICENSE](LICENSE).
