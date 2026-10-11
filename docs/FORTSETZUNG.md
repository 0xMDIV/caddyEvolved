# Fortsetzung – Stand 11.10.2026

Übergabe für die nächste Sitzung. Älterer Stand: [`FORTSETZUNG-M1.md`](FORTSETZUNG-M1.md).

## Wo wir stehen

Letztes Release: **v0.11.0** (läuft auf dem Test-LXC 192.168.10.27). Release-Weg:
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
| v0.11.0 | Toolbox: CIDR-Rechner, Ping, Traceroute, Port-Scan, IP-Scan, mDNS, DNS (`internal/toolbox`) |

## Toolbox (v0.11.0)

- Backend: `internal/toolbox` (CIDR, ICMP-Ping/Traceroute, Port-/Host-Scan, mDNS, DNS), Endpunkte in
  `internal/api/handlers_tools.go`, beschrieben in `docs/API.md` → Toolbox.
- UI: `ui/src/pages/Toolbox.tsx`, Route `/toolbox`, Tabs (auch per `#ping` usw. in der URL).
  IP-Scan und mDNS öffnen per Knopf Port-Scan bzw. Ping für ein Gerät.
- Live auf dem LXC geprüft: raw ICMP geht im unprivilegierten LXC; Ping/Traceroute 1.1.1.1,
  IP-Scan 192.168.10.0/24 (25 Geräte, ~11 s), mDNS (~20 Dienste), Port-Scan .132 (12 offen).
  Binäre TXT-Werte (Thread-Router) werden als Hex angezeigt.

## Danach offen

- **Plugin-Updates:** Anzeige „Update verfügbar“ für eingebaute Plugins (Angebot steht noch aus).
- **Zugangsdaten verschlüsseln** mit `systemd-creds` (TPM der VM) – nur angeboten, nicht beauftragt.
- **Vaultwarden auf der VM 192.168.10.28** (vault.m0ses.de → 192.168.10.132:8006, HTTP – das Ziel
  stimmt, 8006 ist dort Vaultwarden, nicht Proxmox): Cloudflare-Proxy an, Caddy hat kein Zertifikat
  → Cloudflare 525. HTTP-01 scheitert mit **403 von Cloudflare** (Firewall/Länder-/Bot-Regel blockt
  die Let's-Encrypt-Prüfer), TLS-ALPN geht hinter Cloudflare nie. Lösung: DNS-Challenge mit
  Cloudflare-Plugin oder Ausnahme für `/.well-known/acme-challenge/*` in Cloudflare.
- caddyEvolved fragt alle 15 s `/pki/certificates/local` ab, obwohl keine interne CA aktiv ist →
  404-Fehler im Caddy-Journal. Abfrage nur bei `tls internal` oder 404 still behandeln.
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
