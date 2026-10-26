# caddyEvolved

**Caddy als Reverse Proxy – mit WebUI, Plugins per Klick und allem, was ein Homelab
oder kleines Team braucht.** caddyEvolved installiert [Caddy](https://caddyserver.com),
baut es mit den gewünschten Plugins und macht alles über den Browser verwaltbar –
Sites, Zertifikate, Schutz, Logs, Backups.

## Installation

| Wo | Befehl / Weg | Anleitung |
|---|---|---|
| **Linux-Server** (Debian, Ubuntu, Proxmox-LXC, Raspberry Pi OS …) | `curl -fsSL https://raw.githubusercontent.com/0xMDIV/caddyEvolved/main/install.sh \| sudo sh` | [INSTALLATION.md](INSTALLATION.md) |
| **Docker** (auch Synology, TrueNAS & Co.) | `curl -fsSL https://raw.githubusercontent.com/0xMDIV/caddyEvolved/main/install_docker.sh \| sudo sh` | [docs/DOCKER.md](docs/DOCKER.md) |
| **Unraid** | Docker → Template Repositories: `https://github.com/0xMDIV/caddyEvolved`, dann Vorlage „caddyEvolved“ | [docs/DOCKER.md#unraid](docs/DOCKER.md#unraid) |

Danach `https://<server-ip>:8484` öffnen – Passwort zeigt der Installer am Ende (im
Container: im Log). Router, DNS und Übernahme bestehender Seiten:
[INSTALLATION.md](INSTALLATION.md).

## Funktionen

| | |
|---|---|
| **Sites** | Reverse Proxy, Weiterleitung, statische Dateien oder eigene Konfiguration. Mehrere Upstreams mit Lastverteilung und Health-Check, Upstreams mit HTTPS. Jede Änderung prüft Caddy, bevor sie live geht – sonst bleibt der alte Stand. Ein Klick testet eine Site wie ein Besucher (DNS, Cloudflare-Proxy, Zertifikat, Weg zum Ziel). |
| **Automatisches HTTPS** | Zertifikat pro Domain über Let's Encrypt/ZeroSSL, DNS-Challenge mit 41 DNS-Anbietern (auch Wildcards, auch hinter dem Cloudflare-Proxy), interne CA fürs LAN. Domains, die noch auf ein Zertifikat warten, zeigen den Grund aus dem Caddy-Log und den passenden Knopf zur Lösung. |
| **Plugins per Klick** | Caddy-Plugins werden einkompiliert – caddyEvolved baut die Binary direkt auf dem Server bzw. im Container, mit Live-Log, Prüfung, sofortiger Aktivierung und automatischem Rollback. Einstellungen aller eingebauten Plugins (z. B. API-Token für Cloudflare-DNS) an einer Stelle, nach Thema geordnet. |
| **Sensible Dateien** | `.env`, `.git`, Schlüssel, Datenbank-Dumps, Backups, `docker-compose.yml` und Ähnliches sind bei jeder Site **immer gesperrt** (404), bevor die Anfrage den Dienst erreicht – nicht abschaltbar, eigene Muster ergänzbar. |
| **Firewall** | Für alle Sites: Whitelist und Blacklist (IPs und Bereiche), 11 öffentliche Sperrlisten (Spamhaus, FireHOL, blocklist.de, CINS, IPsum, Tor-Exits …) nach Strenge sortiert plus eigene Listen per URL mit Test, Länder und Netzbetreiber (ASN) mit kostenlosen DB-IP-Geodaten ohne Account. Blockierte Anfragen mit Grund, WAF-Treffer mit Regel-ID – sperren, freigeben oder Regel ausschalten per Klick. **Auto-Bann:** Fallen-Pfade (z. B. `/phpmyadmin*`) und Zugriffe auf `.env` & Co. sperren sofort, zu viele Abweisungen oder 404-Scans ebenso; Sperrdauer mit Eskalation bis dauerhaft, IPv6 als /64. |
| **Access Lists** | IPs erlauben/sperren, Länder, Benutzer mit Passwort – pro Site. |
| **Schutz** | WAF (Coraza + OWASP Core Rule Set) mit allen CRS-Optionen: Paranoia-Level, Schwellwerte, erlaubte Methoden und Content-Types, Body-Limit, Regelgruppen, Ausnahmen pro Regel und Pfad, eigene SecLang-Regeln. CrowdSec-Bouncer mit AppSec, Bot-Abwehr mit allen Reaktionen und Netzen, Rate Limit mit eigenen Grenzen pro Pfad. |
| **Netzwerk** | Echte Besucher-IPs hinter Cloudflare, Fastly, Bunny CDN, AWS CloudFront (zum Anhaken, Adresslisten bleiben aktuell) oder eigenen Proxys (ein CDN gleichzeitig, `trusted_proxies_strict`), DynDNS für Anschlüsse ohne feste IP, Sites nur im Tailnet (Tailscale), Brotli, HTTP-Cache (Souin), WebDAV als Site-Art. |
| **Analytics** | Anfragen, Fehler, Geblockte und Antwortzeiten; Traffic rein und raus, gesamt und pro Site; Top-Pfade, IPs, User-Agents, Markierungen; Live-Liste. |
| **System** | Wie stark Caddy und caddyEvolved den Server belasten: CPU, RAM, Platte und Netzwerk im Verhältnis zum ganzen System, letzte Stunde. |
| **Toolbox** | Netzwerk-Werkzeuge vom Server aus: CIDR-Rechner und IP-Bereich → CIDR, Ping, Traceroute, Port-Scan, IP-Scan des LANs (Name, MAC), mDNS-Browser, DNS-Abfrage. |
| **Logs** | Zugriffe aller Sites mit Filtern (Zeitraum, Site, Status, IP, Pfad, User-Agent, Dauer, Freitext) und Markierungen für Torrent, KI-Crawler, Bots, Scanner, Geblockte und Fehler; liest auch rotierte, komprimierte Dateien. Rotation einstellbar. Neben jeder IP Land und Netzbetreiber (DB-IP, ohne externen Dienst), Kopieren und „IP prüfen“ (Lookup-Seite einstellbar). Tokens in URLs und API-Key-Header stehen nur gekürzt im Log. |
| **Audit Log** | Wer hat wann was geändert – per Login, API-Token oder KI. |
| **Backup** | Sites, Access Lists, Einstellungen, Zugangsdaten und optional Zertifikate – verschlüsselt mit Passwort, täglich automatisch, Wiederherstellung mit Vorschau und Rollback. |
| **Import** | aus Caddyfile, Zoraxy, Traefik (inkl. docker-compose-Labels) und Nginx Proxy Manager, mit Vorschau. |
| **Diagnose & Update** | `caddyevolved doctor` prüft Ports, Firewall, Weiterleitung, DNS und Zertifikate mit Lösungshinweisen; Selbst-Update per Knopf oder `caddyevolved update` (im Container: neues Image). |
| **API und KI** | REST-API mit Tokens (lesen/schreiben) und eingebauter **MCP-Server**: Claude & Co. können Sites anlegen, Logs lesen und Builds starten. **KI-Chat** direkt in der WebUI (Claude oder jeder OpenAI-kompatible Anbieter wie OpenRouter, Requesty, Ollama): eigene Seite und Chat-Knopf auf jeder Seite; die KI fragt vor jeder Änderung, ausgeführt wird nur, was du freigibst. Alles landet im nicht löschbaren **KI-Protokoll** mit Prüfsummen-Kette. |

Plugins mit eigener Seite (WAF, Bot-Abwehr, Geo-Blocking, Rate Limit) erscheinen
automatisch in der Sidebar, sobald sie in der laufenden Caddy-Binary stecken.

## Voraussetzungen

- **Server:** Linux mit systemd auf **amd64** oder **arm64**, root-Rechte, Ports 80 und 443.
  Kein Docker, kein Node, keine Datenbank – caddyEvolved ist ein statisches Go-Programm mit
  eingebauter WebUI.
- **Docker:** Docker mit Compose auf amd64 oder arm64. Ein Container, ein Datenordner.

## Warum

Caddy ist ein hervorragender Reverse Proxy mit automatischem HTTPS, aber:

- Die Konfiguration ist eine Textdatei.
- Caddy-„Plugins“ sind keine Laufzeit-Plugins. Module (DNS-Provider, WAF, Rate Limit, …)
  werden mit `xcaddy` in die Binary **hineinkompiliert** – ein Plugin installieren heißt
  eine neue Binary bauen.
- Der offizielle Download mit Zusatzmodulen kompiliert serverseitig auf Bestellung und
  braucht im Test rund zwei Minuten pro Anfrage.

caddyEvolved baut deshalb lokal: Beim ersten Build lädt es Go von go.dev (SHA-256 gegen den
offiziellen Index geprüft) und xcaddy nach `/var/lib/caddyevolved/`. Die neue Binary wird
geprüft – startet sie, enthält sie jedes Modul, akzeptiert sie das Caddyfile? – und erst
dann atomar getauscht. Wird Caddy danach nicht gesund, kommt die alte Binary automatisch
zurück.

## Wie es arbeitet

- **Caddyfile bleibt die Quelle der Wahrheit.** Jede Site ist eine Datei
  `/etc/caddy/sites/<id>.caddy`, eingebunden per `import`. Änderungen laufen als
  Transaktion: schreiben → `caddy validate` → Reload ohne Unterbrechung; bei Fehlern wird
  der alte Stand wiederhergestellt. Das Caddyfile bleibt im Expertenmodus editierbar.
- **Sperre sensibler Dateien** steht als erster `handle`-Block in jeder Site und greift
  damit vor Access Lists, Schutz-Plugins und Proxy – auch bei eigener Konfiguration.
  Gematcht wird auf Caddys bereinigten Pfad (`%2e`, `//`, `../`, Groß-/Kleinschreibung).
- **Validierung über die installierte Caddy-Binary** – keine Versionskopplung.
- **Server oder Container:** Auf einem Server laufen Caddy und caddyEvolved als
  systemd-Dienste. Im Container startet und überwacht caddyEvolved Caddy selbst; Caddy-Binary,
  Zertifikate und Einstellungen liegen im Volume `/data` und überstehen Image-Updates.
- **Sicherheit:** WebUI nur mit Login (PBKDF2-HMAC-SHA256, 600k Iterationen), HttpOnly-Session,
  Sperre nach Fehlversuchen, CSRF-Schutz, selbstsigniertes TLS. API-Tokens werden nur
  gehasht gespeichert. Basic-Auth-Passwörter gehen als bcrypt-Hash an Caddy, nie im Klartext
  auf die Platte. Plugin-Zugangsdaten liegen in `/etc/caddyevolved/env` (0600). Der Dienst
  läuft mit systemd-Härtung.
- **MCP:** `POST /mcp` spricht das Model Context Protocol (Spezifikation 2026-07-28,
  abwärtskompatibel bis 2024-11-05); Anleitung und fertige Client-Konfiguration auf der
  Seite *KI / MCP* der WebUI.

API-Referenz: [`docs/API.md`](docs/API.md).

## Entwicklung

Go 1.27+ für das Backend, Node 24 für das Frontend.

```bash
cd ui && npm ci && npm run build      # Frontend nach internal/webui/dist (eingecheckt)
go vet ./... && go test ./...         # Prüfung
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags '-s -w' -o dist/caddyevolved ./cmd/caddyevolved
docker build -t caddyevolved:test .   # Container-Image
```

Frontend-Entwicklung: `npm run dev` in `ui/` leitet `/api` an `https://127.0.0.1:8484` weiter.

Jeder Dateipfad läuft über `config.Paths`, das sich mit `--root <prefix>` in einen
Staging-Baum umbiegen lässt – die Install-Engine ist so ohne root in einem Temp-Verzeichnis
testbar (`caddyevolved install --prefix /tmp/x --dry-run`).

**Release:** `git tag v0.x.y && git push origin v0.x.y`. Der Workflow
`.github/workflows/release.yml` testet, baut über `scripts/release.sh` die Archive für
amd64/arm64 samt `SHA256SUMS`, veröffentlicht sie und schiebt das Image
`ghcr.io/0xmdiv/caddyevolved` (Tags `x.y.z`, `x.y`, `latest`). Lokal:
`scripts/release.sh v0.x.y` → `dist/release/`.

### Struktur

```
cmd/caddyevolved/     Einstiegspunkt
internal/cli/         Befehle: install, serve, container, status, start/stop/reload, update, backup, doctor …
internal/install/     Schritt-Engine (idempotent, dry-run), Preflight, Units, Caddyfile
internal/config/      FHS-Layout mit --root-Prefix, state.json
internal/platform/    Host-Erkennung: Distro, systemd, LXC, Container, Portbelegung
internal/caddyctl/    caddy-Binary (validate/fmt/reload/list-modules) + Admin-API
internal/systemd/     systemctl-Aktionen, Unit-Installation
internal/supervisor/  Caddy ohne systemd starten und überwachen (Container, --root-Tests)
internal/fetch/       Download, Digest-Prüfung, tar.gz-Extraktion
internal/releases/    GitHub-Releases, Asset-Namen
internal/selfupdate/  Selbst-Update aus den Releases
internal/plugins/     kuratierter Modul-Katalog + Go-Proxy-Validierung freier Pfade
internal/secrets/     EnvironmentFile-Verwaltung (Plugin-Zugangsdaten)
internal/builder/     lokaler xcaddy-Build: Go-Toolchain, Jobs, Live-Log, Aktivierung + Rollback
internal/sites/       Sites, Firewall, Access Lists, Schutz-Rendering, Sperre sensibler Dateien, globale Optionen, transaktional
internal/certs/       Zertifikate aus Caddys Speicher lesen
internal/probe/       Site-Test, Cloudflare-Erkennung, ACME-Fehler mit Lösungshinweis
internal/analytics/   Access-Log-Follower und Aggregation (Minute/Stunde, Top-Listen)
internal/accesslog/   Zugriffs-Log lesen, filtern, markieren (auch rotiert/gzip), Tokens kürzen
internal/geo/         Land und Netzbetreiber zu einer IP (DB-IP Lite)
internal/ai/          KI-Anbindung (Anthropic, OpenAI-kompatibel), Chats, Freigabe-Schleife
internal/aiaudit/     KI-Protokoll: nur anhängen, Hash-Kette
internal/sysstat/     CPU/RAM/Netz/Platte von System, Caddy und caddyEvolved
internal/toolbox/     Netzwerk-Werkzeuge: CIDR, Ping/Traceroute (ICMP), Port- und Host-Scan, mDNS, DNS
internal/backup/      Backup/Restore, Verschlüsselung, Zeitplan
internal/importer/    Import aus Caddyfile, Zoraxy, Traefik, Nginx Proxy Manager
internal/api/         HTTP-Routen, Auth-Middleware, SSE, MCP, self-signed TLS
internal/auth/        PBKDF2-Passwort, Sessions, API-Tokens, Lockout
internal/events/      events.jsonl + Live-Fan-out für die UI
internal/tui/         Pfeiltasten-Assistent des Installers
internal/webui/       embed.FS für das gebaute Frontend
ui/                   React + Vite + TypeScript + Tabler Icons
docker/, Dockerfile   Container-Image und Compose-Datei
unraid/               Unraid-Vorlage und Symbol
```

## Roadmap

- [x] Install-Engine, systemd, WebUI, Dashboard
- [x] Plugin-Katalog, Zugangsdaten, lokaler Custom-Build mit Rollback
- [x] Reverse-Proxy-Sites, Caddyfile-Editor mit Validate/Reload
- [x] Access Lists, WAF/Bot-Abwehr/Geo-Blocking/Rate Limit, Plugin-Seiten in der Sidebar
- [x] Firewall mit Sperrlisten, Länder- und ASN-Regeln, Block-Log und WAF-Treffern
- [x] Auto-Bann: Fallen, Schwellwerte, wachsende Sperrliste
- [x] Analytics, Audit Log, Import, API-Tokens, MCP
- [x] Releases für amd64/arm64 mit Installationsskript, Pfeiltasten-Assistent
- [x] `caddyevolved doctor`, Site-Test mit Zertifikatsansicht und Cloudflare-Erkennung
- [x] Selbst-Update per `caddyevolved update` oder Knopf in der WebUI
- [x] Backup/Restore, Logger mit Filtern, Traffic- und Systemlast-Anzeige, Toolbox
- [x] Plugin-Einstellungen an einer Stelle, Diagnose wartender Zertifikate
- [x] Sensible Dateien immer gesperrt
- [x] Docker-Image und Unraid-Vorlage
- [x] Globale Optionen aus der WebUI: echte Client-IPs, DynDNS, CrowdSec, Tailscale, Cache, Brotli, WebDAV
- [x] 41 DNS-Anbieter, jeder gegen die aktuelle Caddy-Version gebaut und geprüft
- [x] KI-Chat mit Freigabe pro Änderung und KI-Protokoll, IP-Herkunft im Log, CDN-Proxys zum Anhaken
- [ ] Eigener MMDB-Leser statt `maxminddb-golang` (weniger Abhängigkeiten)
- [ ] Oberfläche für Storage (Redis/Postgres) und Layer 4
- [ ] Anzeige „Update verfügbar“ für Plugins
- [ ] Zugangsdaten verschlüsselt ablegen (`systemd-creds`)
- [ ] Caddyfile-Revisionsverlauf
- [ ] Zertifikate manuell erneuern und hochladen
- [ ] Mehrbenutzer, 2FA
- [ ] `caddyevolved uninstall`

## Lizenz

MIT – siehe [LICENSE](LICENSE).
