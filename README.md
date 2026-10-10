# caddyforge

Advanced Caddy installer + modern web admin UI. Ein einzelnes Go-Binary, das auf einem
Proxmox-LXC Caddy installiert, die bekannten Caddy-Module mit einrichtet und alles über
eine WebGUI verwaltbar macht.

**Status: Arbeitsprototyp, Meilenstein M1.** Der Code kompiliert noch nicht
(`internal/cli` ist unvollständig). Der konkrete Wiedereinstieg — Fehlerliste,
Reihenfolge, verifizierte Fakten, offene Entscheidungen — steht in
[`docs/FORTSETZUNG-M1.md`](docs/FORTSETZUNG-M1.md). Siehe auch
[Struktur](#struktur) und [Roadmap](#roadmap).

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

## Plugin-Modell

| Schicht | Was passiert | Zeit |
|---|---|---|
| **Varianten** `caddy` / `standard` / `custom` | Vorgebaute Binaries; der Installer wählt die passende | Sekunden |
| **Profile** (Häkchen in der UI) | Steuert, welche Module **konfiguriert** werden und welche Credentials in `/etc/caddyforge/env` landen | sofort |
| **Custom-Build** | Gewünschtes Modul outside Bundle → Build-Job (xcaddy), mit Live-Log und Digest-Prüfung | Minuten, asynchron |

Ehrliche Randbedingung: Ein Abwählen häkelt nur die Konfiguration ab — es macht die Binary
nicht kleiner. Und ein Modul outside der Variante ist erst nach einem Build benutzbar.

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

Go 1.27+ (Entwicklung auf diesem Rechner in WSL Ubuntu-24.04):

```bash
go build ./...                 # Backend
go vet ./... && go test ./...  # Prüfung
cd ui && npm install && npm run build   # Frontend nach internal/webui/dist
```

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
internal/forge/        Client für den Build-Service (asynchrone Custom-Builds)
internal/api/          HTTP-Routen, Auth-Middleware, SSE, self-signed TLS
internal/auth/         PBKDF2-Passwort, Sessions, Lockout
internal/events/       events.jsonl + Live-Fan-out für die UI
internal/webui/        embed.FS für das gebaute Frontend
```

## Roadmap

- [~] **M1** Gerüst, Install-Engine, systemd — *gebaut, lokal verifiziert; LXC-Verifikation offen*
- [ ] **M2** WebUI-Shell + Dashboard
- [ ] **M3** Plugin-Katalog + Credentials
- [ ] **M4** Caddyfile-Editor + Validate/Reload + Revisionen
- [ ] **M5** Reverse-Proxy-Wizard
- [ ] **M6** Zertifikate (ACME, DNS-Provider, Renew)
- [ ] **M7** Auth/Hardening
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
