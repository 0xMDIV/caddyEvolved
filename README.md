# caddyEvolved

**Caddy als Reverse Proxy – mit WebUI, Plugins per Klick und allem, was ein Homelab
oder kleines Team braucht.** Ein einzelnes Programm installiert
[Caddy](https://caddyserver.com) auf einem Linux-Server, baut es mit den gewünschten
Plugins und macht alles über den Browser verwaltbar.

```bash
curl -fsSL https://raw.githubusercontent.com/0xMDIV/caddyEvolved/main/install.sh | sudo sh
```

Danach `https://<server-ip>:8484` öffnen. Ausführlich, inklusive Router, DNS und Übernahme
bestehender Seiten: **[INSTALLATION.md](INSTALLATION.md)**.

## Funktionen

| | |
|---|---|
| **Sites** | Reverse Proxy, Weiterleitung, statische Dateien oder eigene Konfiguration. Mehrere Upstreams mit Lastverteilung und Health-Check, Upstreams mit HTTPS. Jede Änderung wird von Caddy geprüft, bevor sie live geht – sonst bleibt der alte Stand. |
| **Automatisches HTTPS** | Zertifikat pro Domain über Let's Encrypt/ZeroSSL, DNS-Challenge für Wildcards, interne CA fürs LAN. Zertifikatsübersicht mit Ablaufdaten. |
| **Plugins per Klick** | Caddy-Plugins werden einkompiliert – caddyEvolved baut die Binary direkt auf dem Server, mit Live-Log, Prüfung und automatischem Rollback. Caddy-Version ebenso wählbar. |
| **Access Lists** | IPs erlauben/sperren, Länder (GeoIP), Benutzer mit Passwort – pro Site. |
| **Schutz** | WAF (Coraza + OWASP Core Rule Set), Bot- und KI-Crawler-Abwehr, Rate Limit. |
| **Analytics** | Graphen für Anfragen, Fehler, Geblockte und Antwortzeiten; Traffic rein und raus über Caddy, gesamt und pro Site; Top-Pfade, IPs, User-Agents, Markierungen; Live-Liste. |
| **System** | Wie stark Caddy und caddyEvolved den Server belasten: CPU, RAM, Platte und Netzwerk im Verhältnis zum ganzen System, letzte Stunde. |
| **Toolbox** | Netzwerk-Werkzeuge, die vom Server aus laufen: CIDR-Rechner und IP-Bereich → CIDR, Ping, Traceroute, Port-Scan, IP-Scan des LANs (Name, MAC), mDNS-Browser, DNS-Abfrage. |
| **Logs** | Zugriffe aller Sites mit Filtern (Zeitraum, Site, Status, IP, Pfad, User-Agent, Dauer, Freitext) und Markierungen für Torrent, KI-Crawler, Bots, Scanner, Geblockte und Fehler; liest auch rotierte, komprimierte Dateien. Rotation und gzip-Kompression einstellbar. |
| **Audit Log** | Wer hat wann was geändert – per Login, API-Token oder KI. |
| **Backup** | Sites, Access Lists, Einstellungen, Zugangsdaten und optional Zertifikate sichern – verschlüsselt mit Passwort, täglich automatisch, Wiederherstellung mit Vorschau und automatischem Rollback. |
| **Import** | aus Caddyfile, Zoraxy, Traefik (inkl. docker-compose-Labels) und Nginx Proxy Manager, mit Vorschau. |
| **API und KI** | REST-API mit Tokens (lesen/schreiben) und eingebauter **MCP-Server**: Claude & Co. können Sites anlegen, Logs lesen und Builds starten. |

Plugins mit eigener Seite (WAF, Bot-Abwehr, Geo-Blocking, Rate Limit) erscheinen
automatisch in der Sidebar, sobald sie in der laufenden Caddy-Binary stecken.

## Voraussetzungen

Linux mit systemd (Debian, Ubuntu, Proxmox-LXC, Raspberry Pi OS, …) auf **amd64** oder
**arm64**, root-Rechte, Ports 80 und 443. Kein Docker, kein Node, keine Datenbank –
caddyEvolved ist ein statisches Go-Programm mit eingebauter WebUI.

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
- **Validierung über die installierte Caddy-Binary** – keine Versionskopplung.
- **Sicherheit:** WebUI nur mit Login (PBKDF2-HMAC-SHA256, 600k Iterationen), HttpOnly-Session,
  Sperre nach Fehlversuchen, CSRF-Schutz, selbstsigniertes TLS. API-Tokens werden nur
  gehasht gespeichert. Basic-Auth-Passwörter gehen als bcrypt-Hash an Caddy, nie im Klartext
  auf die Platte. Der Dienst läuft mit systemd-Härtung.
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
```

Frontend-Entwicklung: `npm run dev` in `ui/` leitet `/api` an `https://127.0.0.1:8484` weiter.

Jeder Dateipfad läuft über `config.Paths`, das sich mit `--root <prefix>` in einen
Staging-Baum umbiegen lässt – die Install-Engine ist so ohne root in einem Temp-Verzeichnis
testbar (`caddyevolved install --prefix /tmp/x --dry-run`).

**Release:** `git tag v0.x.y && git push origin v0.x.y`. Der Workflow
`.github/workflows/release.yml` testet, baut über `scripts/release.sh` die Archive für
amd64/arm64 samt `SHA256SUMS` und veröffentlicht sie. Lokal: `scripts/release.sh v0.x.y`
→ `dist/release/`.

### Struktur

```
cmd/caddyevolved/     Einstiegspunkt
internal/cli/         Befehle: install, serve, status, start/stop/reload, passwd, token, do
internal/install/     Schritt-Engine (idempotent, dry-run), Preflight, Units, Caddyfile
internal/config/      FHS-Layout mit --root-Prefix, state.json
internal/platform/    Host-Erkennung: Distro, systemd, LXC, Portbelegung
internal/caddyctl/    caddy-Binary (validate/fmt/reload/list-modules) + Admin-API
internal/systemd/     systemctl-Aktionen, Unit-Installation
internal/supervisor/  Prozessverwaltung ohne systemd (--root-Tests)
internal/fetch/       Download, Digest-Prüfung, tar.gz-Extraktion, atomarer Write
internal/releases/    GitHub-Releases, Asset-Namen
internal/plugins/     kuratierter Modul-Katalog + Go-Proxy-Validierung freier Pfade
internal/secrets/     EnvironmentFile-Verwaltung
internal/builder/     lokaler xcaddy-Build: Go-Toolchain, Jobs, Live-Log, Aktivierung + Rollback
internal/sites/       Sites, Access Lists, WAF/Bot/Rate-Limit-Rendering, transaktional
internal/certs/       Zertifikate aus Caddys Speicher lesen
internal/analytics/   Access-Log-Follower und Aggregation (Minute/Stunde, Top-Listen)
internal/toolbox/    Netzwerk-Werkzeuge: CIDR, Ping/Traceroute (ICMP), Port- und Host-Scan, mDNS, DNS
internal/importer/    Import aus Caddyfile, Zoraxy, Traefik, Nginx Proxy Manager
internal/api/         HTTP-Routen, Auth-Middleware, SSE, MCP, self-signed TLS
internal/auth/        PBKDF2-Passwort, Sessions, API-Tokens, Lockout
internal/events/      events.jsonl + Live-Fan-out für die UI
internal/webui/       embed.FS für das gebaute Frontend
ui/                   React + Vite + TypeScript + Tabler Icons
```

## Roadmap

- [x] Install-Engine, systemd, WebUI, Dashboard
- [x] Plugin-Katalog, Zugangsdaten, lokaler Custom-Build mit Rollback
- [x] Reverse-Proxy-Sites, Caddyfile-Editor mit Validate/Reload
- [x] Access Lists, WAF/Bot-Abwehr/Rate Limit, Plugin-Seiten in der Sidebar
- [x] Analytics, Audit Log, Import, API-Tokens, MCP
- [x] Releases für amd64/arm64 mit Installationsskript, Pfeiltasten-Assistent
- [x] `caddyevolved doctor`: Ports, Firewall, Weiterleitung, DNS, Zertifikate, Erreichbarkeit jeder Site
- [x] Selbst-Update per `caddyevolved update` oder Knopf in der WebUI
- [ ] Caddyfile-Revisionsverlauf
- [ ] Zertifikate manuell erneuern und hochladen
- [ ] Mehrbenutzer, 2FA
- [ ] `caddyevolved uninstall`, vorgebaute Bundle-Varianten

## Lizenz

MIT – siehe [LICENSE](LICENSE).
