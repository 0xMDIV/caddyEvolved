# Fortsetzung – Stand 11.10.2026

Übergabe für die nächste Sitzung. Älterer Stand: [`FORTSETZUNG-M1.md`](FORTSETZUNG-M1.md).

## Wo wir stehen

Letztes Release: **v0.10.0** (läuft auf dem Test-LXC 192.168.10.27). Release-Weg:
`git tag vX.Y.Z && git push origin vX.Y.Z` → GitHub Actions baut amd64/arm64 →
auf dem Server `sudo caddyevolved update` oder Knopf unter Einstellungen → Updates.

Erledigt aus der Wunschliste:

| Release | Inhalt |
|---|---|
| v0.4.x | Installer mit Pfeiltasten-UI (`internal/tui`), Strg+C, Empfehlungen, echte IP und Passwort am Ende |
| v0.5.0 | `caddyevolved doctor`, Site-Formular mit HTTP/HTTPS-Schalter, Host/Port, Schnellwahl, Hilfe |
| v0.6.x | Selbst-Update (`caddyevolved update`, Knopf in den Einstellungen) |
| v0.7.0 | Site-Test-Knopf + Zertifikatsansicht, Cloudflare-Erkennung (`internal/probe`) |
| v0.8.0 | Backup/Restore (`internal/backup`, Seite Backup, CLI `backup`/`restore`) |
| v0.9.0 | Logger: Zugriffs-Log mit Filtern + Markierungen (Torrent, KI-Crawler, Bot, Scanner, Geblockt, Fehler), Rotation/gzip einstellbar (`internal/accesslog`) |
| v0.10.0 | Traffic rein/raus pro Site (Analytics), Seite System mit CPU/RAM/Netz von Caddy und caddyEvolved (`internal/sysstat`) |

## In Arbeit: Toolbox (noch kein Release)

**Backend fertig, getestet, committet – UI fehlt.**

- `internal/toolbox/cidr.go` – CIDR-Rechner (v4/v6, Maske, Broadcast, nutzbare Hosts), IP-Bereich → CIDR-Liste
- `internal/toolbox/icmp.go` – Ping und Traceroute über ICMP (raw Socket als root, sonst ping_group_range)
- `internal/toolbox/scan.go` – Port-Scanner (TCP connect, Banner), Host-Scanner (ICMP-Sweep + TCP-Fallback, rDNS, MAC aus ARP), `LocalNetworks()`
- `internal/toolbox/mdns.go` – mDNS-Browser (Legacy-Unicast-Abfrage, kein Konflikt mit avahi), DNS-Lookup
- `internal/api/handlers_tools.go` – Endpunkte:
  - `GET /api/tools` (lokale Netze, Standard-Ports), `GET /api/tools/cidr?q=` bzw. `?from=&to=`, `GET /api/tools/dns?name=`
  - `POST /api/tools/ping {host,count}`, `/traceroute {host,maxHops}`, `/ports {host,ports}`, `/hosts {cidr}`, `/mdns {seconds}`
  - Scanner nur mit Login (nicht per API-Token), ein Scan gleichzeitig (409 sonst)
- Neue Abhängigkeit: `golang.org/x/net v0.30.0` (icmp, ipv4/ipv6, dnsmessage)

**Nächste Schritte Toolbox:**

1. `ui/src/pages/Toolbox.tsx`: Karten bzw. Tabs für CIDR-Rechner (live beim Tippen), Bereich→CIDR,
   Ping, Traceroute, Port-Scan (Vorgabe „häufige Ports“), IP-Scan (Netz aus `/api/tools` vorschlagen),
   mDNS, DNS-Lookup. Nav-Eintrag „Toolbox“ (Icon z. B. `IconTool`) in `App.tsx`, Route `/toolbox`.
2. Auf dem LXC live testen: Ping/Traceroute zu 1.1.1.1, IP-Scan 192.168.10.0/24, mDNS im LAN,
   Port-Scan auf 192.168.10.132. Im unprivilegierten LXC prüfen, ob raw ICMP geht.
3. Doku (README-Tabelle, INSTALLATION.md), Release v0.11.0.

## Danach offen

- **Plugin-Updates:** Anzeige „Update verfügbar“ für eingebaute Plugins (Angebot steht noch aus).
- **Zugangsdaten verschlüsseln** mit `systemd-creds` (TPM der VM) – nur angeboten, nicht beauftragt.
- Hinweis des Nutzers (Vaultwarden hinter Cloudflare): Lösung war DNS-Challenge mit Cloudflare-Plugin
  oder Full (strict) + „Always Use HTTPS“ aus; Ziel war fälschlich Port 8006 (Proxmox).
- Ältere Punkte: Caddyfile-Revisionsverlauf, Zertifikat manuell erneuern/hochladen, Mehrbenutzer/2FA,
  `caddyevolved uninstall`, Bundle-Variante.

## Arbeitsweise (bewährt)

- Go baut in WSL Ubuntu-24.04 (`~/.local/go/bin`), Node 24 unter Windows (`cd ui && npm run build`
  schreibt nach `internal/webui/dist`, wird eingecheckt).
- Prüfen: gofmt, `go vet ./...`, `go test ./...` (Skript im Scratchpad: `check.sh`).
- Live-Test: Dev-Build per scp auf den LXC (`deploy.sh`), dann `systemctl restart caddyevolved`.
  Test-Sites über die API anlegen und danach wieder löschen; auf dem LXC gibt es kein `curl`, nur `wget`.
- Browser-Tests mit puppeteer-core gegen das installierte Chrome (Login, Klickpfade, Screenshots,
  400-px-Breite auf Überlauf prüfen).
- Vor jedem Commit: `git grep` nach Passwörtern – keine Zugangsdaten ins Repo.
- Commit-Nachrichten auf Deutsch, mit `Co-Authored-By`-Zeile.
