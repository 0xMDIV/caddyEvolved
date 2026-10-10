# Installation

caddyEvolved installiert [Caddy](https://caddyserver.com) als Reverse Proxy und richtet
dazu eine WebUI ein. Diese Anleitung führt von einem leeren Linux-Server bis zur
ersten erreichbaren Seite.

- [1. Voraussetzungen](#1-voraussetzungen)
- [2. Installieren](#2-installieren)
- [3. Anmelden](#3-anmelden)
- [4. Router und DNS](#4-router-und-dns)
- [5. Bestehende Seiten übernehmen](#5-bestehende-seiten-übernehmen)
- [6. Plugins einbauen](#6-plugins-einbauen)
- [7. Prüfen und Fehlersuche](#7-prüfen-und-fehlersuche)
- [8. Update, Passwort, Deinstallation](#8-update-passwort-deinstallation)

## 1. Voraussetzungen

| | |
|---|---|
| System | Linux mit **systemd** – Debian, Ubuntu, Proxmox-LXC, Raspberry Pi OS, … |
| Architektur | **amd64** (x86_64) oder **arm64** (aarch64) |
| Rechte | root bzw. `sudo` |
| Ports | **80** und **443** frei (Caddy), **8484** für die WebUI |
| Werkzeuge | `curl` oder `wget`, `tar`, `sha256sum` – auf fast jedem System vorhanden |

Proxmox-LXC: unprivilegierte Container funktionieren, die Ports < 1024 bekommt Caddy
über `CAP_NET_BIND_SERVICE`.

Läuft schon ein anderer Proxy (Zoraxy, Traefik, Nginx Proxy Manager) auf 80/443, kann
caddyEvolved auf einer **zweiten Maschine** daneben laufen: erst alles übernehmen
(Schritt 5), dann den alten Proxy stoppen und die Weiterleitung im Router umstellen.

## 2. Installieren

```bash
curl -fsSL https://raw.githubusercontent.com/0xMDIV/caddyEvolved/main/install.sh | sudo sh
```

Ohne `curl`:

```bash
wget -qO- https://raw.githubusercontent.com/0xMDIV/caddyEvolved/main/install.sh | sudo sh
```

Das Skript

1. erkennt die Architektur und lädt das neueste
   [Release](https://github.com/0xMDIV/caddyEvolved/releases),
2. prüft die **SHA-256-Summe** gegen `SHA256SUMS` des Releases,
3. legt `caddyevolved` nach `/usr/local/bin` und
4. startet den **Assistenten**. Der fragt nach Caddy-Version, Ports, E-Mail für
   Let's Encrypt und optional einer ersten Site. Die Vorgaben passen für die meisten Fälle –
   einfach mit Enter bestätigen.

Am Ende stehen die Adresse der WebUI und das **UI-Passwort**. Das Passwort wird nur
dieses eine Mal angezeigt – notieren.

### Varianten

| Zweck | Befehl |
|---|---|
| bestimmte Version | `curl -fsSL …/install.sh \| sudo CADDYEVOLVED_VERSION=v0.3.0 sh` |
| nur das Programm, später einrichten | `curl -fsSL …/install.sh \| sudo CADDYEVOLVED_NO_SETUP=1 sh`, danach `sudo caddyevolved install` |
| ohne Rückfragen (Skripte, cloud-init) | `curl -fsSL …/install.sh \| sudo sh -s -- --unattended /root/answers.json` |
| nur ansehen, nichts ändern | `sudo caddyevolved install --dry-run` |

Beispiel `answers.json` für die unbeaufsichtigte Installation:

```json
{
  "binarySource": "official",
  "email": "admin@example.com",
  "httpPort": 80,
  "httpsPort": 443,
  "adminPort": 2019,
  "uiPort": 8484,
  "uiBind": "0.0.0.0",
  "managed": false,
  "siteDomain": "cloud.example.com",
  "siteTarget": "192.168.10.40:80"
}
```

Das UI-Passwort lässt sich dabei mit `--ui-password` vorgeben oder mit
`--password-file /root/ui-pw` in eine Datei schreiben.

### Manuell, ohne `curl | sh`

Wer kein Skript aus dem Netz direkt ausführen will: das passende Archiv
`caddyevolved_<version>_linux_<arch>.tar.gz` und `SHA256SUMS` von der
[Release-Seite](https://github.com/0xMDIV/caddyEvolved/releases) laden und:

```bash
sha256sum -c --ignore-missing SHA256SUMS
tar -xzf caddyevolved_*_linux_amd64.tar.gz
sudo install -m 0755 caddyevolved_*_linux_amd64/caddyevolved /usr/local/bin/
sudo caddyevolved install
```

Der Assistent lädt Caddy anschließend von GitHub – der Server braucht dafür
Internetzugang.

### Was installiert wird

| Pfad | Inhalt |
|---|---|
| `/usr/local/bin/caddyevolved` | Programm (WebUI, API, Verwaltung) |
| `/usr/local/bin/caddy` | Caddy |
| `/etc/caddy/Caddyfile`, `/etc/caddy/sites/` | Caddy-Konfiguration, eine Datei pro Site |
| `/etc/caddyevolved/` | Zustand, UI-Passwort (gehasht), Zugangsdaten für Plugins, UI-Zertifikat |
| `/var/lib/caddyevolved/` | Builds, Go-Toolchain, Analytics |
| `/var/log/caddy/access.log` | Access-Log aller Sites |
| `caddy.service`, `caddyevolved.service` | systemd-Dienste |

## 3. Anmelden

Im Browser `https://<server-ip>:8484` öffnen. Die WebUI nutzt ein selbstsigniertes
Zertifikat – die Browser-Warnung einmal bestätigen. Anmelden mit dem Passwort aus
Schritt 2.

> Port **8484 nie ins Internet weiterleiten.** Die WebUI gehört ins LAN oder hinter
> VPN. Wer sie von außen braucht, veröffentlicht sie als eigene Site mit Access List
> (siehe Tabelle in Schritt 5).

## 4. Router und DNS

1. **Router:** TCP-Port **80** und **443** auf die IP des caddyEvolved-Servers
   weiterleiten. Port 80 ist nötig – Let's Encrypt prüft darüber, und Caddy leitet
   HTTP automatisch auf HTTPS um.
2. **DNS:** Für jede Domain einen A-Eintrag (IPv6: AAAA) auf die öffentliche IP. Bei
   wechselnder IP einen DynDNS-Dienst nutzen. Für viele Subdomains reicht ein
   Wildcard-Eintrag `*.example.com`.
3. **Nur im LAN:** Kein Router-Eintrag nötig. Lokales DNS (Pi-hole, AdGuard, Router)
   lässt die Namen auf den caddyEvolved-Server zeigen, TLS steht dann auf *Intern*.

## 5. Bestehende Seiten übernehmen

### Weg A: Import – für viele Seiten aus einem anderen Proxy

WebUI → **Import**. Quelle wählen, Datei hochladen, Vorschau prüfen, übernehmen.

| Quelle | Was hochladen |
|---|---|
| Caddyfile | das alte `Caddyfile` – jeder Site-Block wird eine Site |
| Zoraxy | Backup-ZIP: Zoraxy → Einstellungen → Backup & Restore → Export |
| Traefik | statische/dynamische Konfiguration (YAML/TOML) oder `docker-compose.yml` mit Labels |
| Nginx Proxy Manager | JSON aus der NPM-API oder `sqlite3 -json database.sqlite "select * from proxy_host"` – die genauen Befehle stehen auf der Import-Seite |

In der Vorschau hat jede Seite eine Checkbox und gegebenenfalls Warnungen, etwa „Passwort
nicht übernehmbar“. Nur angehakte Seiten werden angelegt. Caddy prüft jede Seite
einzeln – eine fehlerhafte blockiert die anderen nicht.

Passwörter für Basic-Auth: Zoraxy und NPM geben sie nicht heraus, Traefik nur als
bcrypt-Hash. Fehlende Passwörter danach unter **Access Lists** neu setzen.

### Weg B: Von Hand

WebUI → **Sites** → **Neue Site**:

1. **ID** leer lassen – wird aus der Domain gebildet.
2. **Art:** *Reverse Proxy*.
3. **Domains:** eine pro Zeile, z. B. `cloud.example.com`.
4. **Upstreams:** Adresse des Dienstes im LAN, z. B. `192.168.10.40:80`. Mehrere Zeilen
   verteilen die Last.
5. **TLS:** *Automatisch* für öffentliche Domains.
6. **Speichern.**

Beim Speichern prüft Caddy die Konfiguration. Ist sie fehlerhaft, bleibt der alte Stand
aktiv und die Fehlermeldung erscheint. Die **Vorschau** zeigt den erzeugten
Caddyfile-Block.

### Typische Fälle

| Dienst / Ziel | Einstellung |
|---|---|
| normaler Webdienst (Nextcloud, Jellyfin, Vaultwarden, Home Assistant, …) | Upstream `ip:port`, TLS *Automatisch*. WebSockets funktionieren ohne Zusatz. |
| Dienst spricht selbst HTTPS mit eigenem Zertifikat (Proxmox `:8006`, UniFi `:8443`, TrueNAS) | Upstream `192.168.10.5:8006`, Haken **Upstream spricht HTTPS** und **Zertifikat des Upstreams nicht prüfen** |
| nur im LAN, ohne öffentliche Domain | Domain z. B. `nas.lan`, TLS **Intern**. Die Root-CA unter **Zertifikate** herunterladen und auf den Geräten als vertrauenswürdig importieren. |
| Wildcard-Zertifikat oder Server nicht aus dem Internet erreichbar | TLS **DNS-Challenge** – braucht ein DNS-Plugin (Schritt 6) und dessen API-Token |
| alte Domain umziehen | Art **Weiterleitung**, Ziel `https://neu.example.com{uri}` |
| nur bestimmte IPs, Länder oder mit Login | erst unter **Access Lists** anlegen, dann in der Site auswählen |
| Schutz vor Angriffen und Bots | Schalter **WAF**, **Bot-Abwehr**, **Rate Limit** – erscheinen, sobald das Plugin eingebaut ist |
| caddyEvolved-WebUI selbst von außen | Upstream `127.0.0.1:8484` mit HTTPS und ohne Zertifikatsprüfung, **unbedingt** mit Access List |
| Sonderfall, den das Formular nicht abdeckt | Art **Eigene Konfiguration** oder Feld *Zusätzliche Direktiven* – roher Caddyfile-Inhalt |

## 6. Plugins einbauen

Caddy-Plugins werden in die Binary einkompiliert. caddyEvolved baut sie direkt auf dem
Server:

1. WebUI → **Plugins & Build**.
2. Plugins anhaken – z. B. ein DNS-Provider (Cloudflare, Hetzner, …), Coraza-WAF,
   Bot-Abwehr, Rate Limit, Geo-Blocking.
3. Bei DNS-Plugins die Zugangsdaten eintragen.
4. **Build starten.** Beim ersten Mal lädt caddyEvolved Go herunter (geprüft per
   SHA-256), das dauert ein bis zwei Minuten; spätere Builds gehen schneller.
5. **Aktivieren.** Die alte Binary wird gesichert. Startet Caddy mit der neuen nicht,
   kommt automatisch die alte zurück; *Rollback* geht jederzeit von Hand.

Plugins mit eigener Seite (WAF, Bot-Abwehr, Geo-Blocking, Rate Limit) erscheinen danach
in der Sidebar unter *Plugins*.

## 7. Prüfen und Fehlersuche

- **Dashboard:** Caddy läuft, keine Warnungen.
- **Zertifikate:** Nach dem ersten Aufruf einer Domain erscheint ihr Zertifikat.
- **Logs:** Hier steht, warum Caddy kein Zertifikat bekommt oder ein Upstream nicht
  antwortet.
- **Analytics:** zeigt, ob Anfragen ankommen.
- Auf dem Server: `caddyevolved status` fasst alles zusammen.

| Symptom | Ursache und Lösung |
|---|---|
| Zertifikat kommt nicht, Log zeigt `timeout` oder `connection refused` | Port 80/443 nicht weitergeleitet oder DNS zeigt woandershin |
| `502 Bad Gateway` | Upstream falsch, Dienst aus, oder er lauscht nur auf `127.0.0.1` |
| Endlos-Weiterleitung | Der Dienst erzwingt selbst HTTPS → *Upstream spricht HTTPS* aktivieren oder im Dienst den Proxy als vertrauenswürdig eintragen |
| Nextcloud, Vaultwarden u. Ä. melden eine falsche Adresse | im Dienst die öffentliche Domain als vertrauenswürdig eintragen (`trusted_domains`, `DOMAIN=`) |
| WebUI nicht erreichbar | `systemctl status caddyevolved`, Firewall für Port 8484 prüfen |
| Seite lädt, aber `403` | Access List, WAF oder Bot-Abwehr hat geblockt – unter **Analytics → Geblockt** nachsehen |

## 8. Update, Passwort, Deinstallation

**Update:** dasselbe Kommando wie bei der Installation. Ist caddyEvolved schon
eingerichtet, wird nur das Programm getauscht und neu gestartet – Sites, Passwort und
Caddy bleiben unverändert.

```bash
curl -fsSL https://raw.githubusercontent.com/0xMDIV/caddyEvolved/main/install.sh | sudo sh
```

Installationen unter dem alten Namen **caddyforge** zieht dasselbe Kommando automatisch
um (`/etc/caddyforge` → `/etc/caddyevolved`, Dienst `caddyforge` → `caddyevolved`).
Danach einmal neu anmelden; vorhandene API-Tokens müssen neu erstellt werden.

**Caddy-Version wechseln:** WebUI → **Plugins & Build** → Version wählen → Build →
Aktivieren.

**UI-Passwort vergessen oder ändern:**

```bash
sudo caddyevolved passwd            # neues Passwort eingeben
sudo caddyevolved passwd --generate # neues zufälliges Passwort
```

Alle Sitzungen werden dabei abgemeldet. In der WebUI geht es auch unter
**Einstellungen**.

**Deinstallieren** (von Hand, solange `caddyevolved uninstall` noch fehlt):

```bash
sudo systemctl disable --now caddyevolved caddy
sudo rm -f /etc/systemd/system/caddyevolved.service /etc/systemd/system/caddy.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/caddyevolved /usr/local/bin/caddy
# Konfiguration und Daten, nur wenn sie wirklich weg sollen:
sudo rm -rf /etc/caddyevolved /var/lib/caddyevolved /etc/caddy /var/lib/caddy /var/log/caddy
```
