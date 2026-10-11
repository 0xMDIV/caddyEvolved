# caddyEvolved mit Docker und Unraid

Das Image `ghcr.io/0xmdiv/caddyevolved` enthält caddyEvolved und das offizielle Caddy
(amd64 und arm64). Ein Container reicht: caddyEvolved startet und überwacht Caddy selbst,
eine Datenbank oder einen zweiten Container gibt es nicht.

- [Schnellstart](#schnellstart)
- [Docker Compose von Hand](#docker-compose-von-hand)
- [Unraid](#unraid)
- [Netzwerk: host oder bridge](#netzwerk-host-oder-bridge)
- [Daten, Update, Backup](#daten-update-backup)
- [Unterschiede zur Server-Installation](#unterschiede-zur-server-installation)

## Schnellstart

```bash
curl -fsSL https://raw.githubusercontent.com/0xMDIV/caddyEvolved/main/install_docker.sh | sudo sh
```

Das Skript installiert auf Nachfrage Docker (über get.docker.com), legt
`/opt/caddyevolved/compose.yml` an, startet den Container und zeigt Adresse und Passwort
der WebUI. Varianten:

```bash
# Ports einzeln mappen statt host-Netz, E-Mail für Let's Encrypt, ohne Rückfragen
curl -fsSL …/install_docker.sh | sudo CADDYEVOLVED_NETWORK=bridge CADDYEVOLVED_EMAIL=ich@example.com CADDYEVOLVED_YES=1 sh
```

## Docker Compose von Hand

[`docker/compose.yml`](../docker/compose.yml) in einen leeren Ordner legen, dann:

```bash
docker compose up -d
docker compose logs caddyevolved | grep Passwort
```

`https://<IP des Servers>:8484` öffnen und die Warnung zum selbstsignierten Zertifikat
einmal bestätigen.

| Variable | Bedeutung |
|---|---|
| `CADDYEVOLVED_EMAIL` | E-Mail für das ACME-Konto (Ablaufwarnungen) – optional |
| `CADDYEVOLVED_PASSWORD` | WebUI-Passwort für den **ersten** Start; leer = erzeugt, steht im Log |
| `CADDYEVOLVED_UI_PORT` | Port der WebUI im Container, Standard 8484 |
| `TZ` | Zeitzone für Logs und Analytics |

Ohne Compose:

```bash
docker run -d --name caddyevolved --restart unless-stopped --network host \
  -v /opt/caddyevolved/data:/data ghcr.io/0xmdiv/caddyevolved:latest
```

## Unraid

Unraid installiert Dienste als Docker-Container über Vorlagen, dafür gibt es
[`unraid/caddyevolved.xml`](../unraid/caddyevolved.xml).

1. **Docker → Template Repositories** (ganz unten auf der Docker-Seite) um
   `https://github.com/0xMDIV/caddyEvolved` ergänzen, speichern.
2. **Docker → Add Container → Template** „caddyEvolved“ wählen.
3. Pfad *Daten* bleibt `/mnt/user/appdata/caddyevolved`; E-Mail und Passwort sind optional.
4. **Apply.** Das Passwort steht – falls keins gesetzt – im Log des Containers (Symbol → Logs).

**Ports auf Unraid:** Die Unraid-Oberfläche belegt selbst 80 und 443. Die Vorlage nimmt
deshalb **1880** (HTTP) und **18443** (HTTPS) auf dem Unraid-Server; im Router
Port 80 → Unraid:1880 und 443 → Unraid:18443 weiterleiten. Wer dem Container lieber eine
eigene IP gibt: Netzwerk **br0** und eine freie IP eintragen – dann gelten 80/443 direkt
auf dieser IP.

Update: auf der Docker-Seite „apply update“ am Container; alles unter
`/mnt/user/appdata/caddyevolved` bleibt.

## Netzwerk: host oder bridge

| | `network_mode: host` (Vorgabe in compose.yml) | Ports mappen (bridge) |
|---|---|---|
| Client-IPs in Logs/Access Lists | echt | echt (IPv4), bei IPv6 je nach Docker-Setup die des Hosts |
| Toolbox (IP-Scan, mDNS) | sieht das LAN | nur eingeschränkt |
| Ports | 80, 443, 8484 direkt auf dem Host | frei wählbar |

Ziele auf demselben Docker-Host: mit host-Netz `127.0.0.1:<port>` bzw. die LAN-IP; im
bridge-Netz die LAN-IP des Hosts oder `host.docker.internal` (mit
`extra_hosts: ["host.docker.internal:host-gateway"]`).

## Daten, Update, Backup

Alles Veränderliche liegt in **einem** Ordner (`/data` im Container):

| Unter `/data` | Inhalt |
|---|---|
| `etc/caddy` | Caddyfile und Site-Dateien |
| `etc/caddyevolved` | Einstellungen, Sites, Passwort-Hash, Zugangsdaten (`env`) |
| `var/lib/caddy` | Zertifikate und ACME-Konten |
| `var/lib/caddyevolved` | Caddy-Binary (auch selbst gebaute), Builds, Go-Toolchain, Analytics |
| `var/log/caddy` | Zugriffs- und Prozess-Logs |

- **Update:** `docker compose pull && docker compose up -d`. Der Knopf „Update“ in der
  WebUI zeigt im Container nur diesen Hinweis – das Programm steckt im Image.
- **Plugins** (Cloudflare-DNS, WAF, …) baut caddyEvolved wie auf einem Server direkt im
  Container. Die gebaute Binary liegt im Volume und übersteht Updates des Images.
- **Backup:** WebUI → Backup, oder den Ordner `data` sichern.

## Unterschiede zur Server-Installation

- Kein systemd: caddyEvolved startet Caddy selbst und startet es nach einem Absturz neu
  (nach höchstens 10 s). Ein „Stopp“ aus der WebUI bleibt bestehen.
- Caddy-Logs stehen in der WebUI unter Logs → Prozess, nicht in `docker logs`.
- `caddyevolved doctor` prüft Ports und Firewall aus Sicht des Containers.
