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

> Lieber als Docker-Container oder auf Unraid? → [docs/DOCKER.md](docs/DOCKER.md). Der Rest
> dieser Anleitung (Router, DNS, Plugins, Fehlersuche) gilt dort genauso.

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
4. startet den **Assistenten**. Bedienung mit **↑/↓**, **Leertaste** (an/aus) und
   **Enter**; **Strg+C** bricht jederzeit ab, ohne etwas zu ändern. Die Vorgaben passen für
   die meisten Fälle – einfach mit Enter bestätigen.

### Die Fragen des Assistenten

| Frage | Empfehlung |
|---|---|
| **Welches Caddy?** | **Offizielles Caddy** – Original von GitHub, Prüfsumme geprüft, in Sekunden da. Plugins baust du danach in der WebUI dazu. *Caddy mit Plugins (custom)* lässt dich Plugins schon jetzt wählen; caddyserver.com baut die Binary dann (1–3 Minuten, ohne veröffentlichte Prüfsumme). *Fertiges Paket (bundle)* kommt in einer späteren Version. |
| **Plugins** (nur bei custom) | Die empfohlenen – Coraza WAF, Caddy Defender, Rate Limit – sind vorausgewählt (grüner Punkt). Ein DNS-Plugin nur, wenn du Wildcard-Zertifikate brauchst oder Port 80 nicht offen ist. Plugins lassen sich **jederzeit** in der WebUI unter *Plugins & Build* hinzufügen oder entfernen. |
| **Zugangsdaten** | Eingabe bleibt verborgen. Leer lassen und später in der WebUI eintragen geht auch. |
| **Zertifikate** | *Let's Encrypt* für Domains aus dem Internet (braucht eine echte E-Mail-Adresse), *Interne CA* nur fürs LAN. |
| **Standard-Ports?** | Ja (80/443, WebUI 8484). |
| **Erste Site?** | Nein – Sites legst du bequemer in der WebUI an. |

Zum Schluss zeigt der Assistent eine Zusammenfassung und installiert erst nach „Ja“.

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

WebUI → **Sites** → **Neue Site**. Oben im Formular klappt **„Hilfe: Was trage ich wo ein?“**
eine Legende mit Beispiel auf.

1. **Art:** *Reverse Proxy*. Die **ID** leer lassen – sie wird aus der Domain gebildet.
2. **Aufgerufen unter → Domains:** eine pro Zeile, ohne `https://`, z. B. `pve.deinedomain.de`.
3. **Weiterleiten an:**
   - **Ziel spricht HTTP / HTTPS** – so, wie du den Dienst im LAN aufrufst.
   - **Host** und **Port** in die zwei Felder, z. B. `192.168.10.132` und `8006`. Eine
     komplette URL wie `https://192.168.10.132:8006/` einfügen geht auch – sie wird
     zerlegt und der Schalter gesetzt.
   - **Zertifikat des Ziels nicht prüfen** – an, wenn das Ziel ein selbstsigniertes
     Zertifikat hat.
   - **Schnellwahl** setzt Port und Protokoll für bekannte Dienste (Proxmox, Home Assistant,
     UniFi, …).
   - *+ weiteres Ziel* verteilt die Last auf mehrere Server.
4. **HTTPS für Besucher:** *Automatisch* für öffentliche Domains, *Intern* fürs LAN.
5. **Speichern & anwenden.**

**Beispiel Proxmox** (`pve.deinedomain.de` → `https://192.168.10.132:8006`): Domain
`pve.deinedomain.de`, Schnellwahl *Proxmox VE* (setzt HTTPS, Port 8006, Zertifikat nicht
prüfen), Host `192.168.10.132`, HTTPS für Besucher *Automatisch*.

Beim Speichern prüft Caddy die Konfiguration. Ist sie fehlerhaft, bleibt der alte Stand
aktiv und die Fehlermeldung erscheint. Die **Vorschau** zeigt den erzeugten
Caddyfile-Block.

### Typische Fälle

| Dienst / Ziel | Einstellung |
|---|---|
| normaler Webdienst (Nextcloud, Jellyfin, Vaultwarden, Home Assistant, …) | Ziel spricht **HTTP**, Host und Port des Dienstes, HTTPS für Besucher *Automatisch*. WebSockets funktionieren ohne Zusatz. |
| Dienst spricht selbst HTTPS mit eigenem Zertifikat (Proxmox `:8006`, UniFi `:8443`, TrueNAS) | Ziel spricht **HTTPS**, Host `192.168.10.132`, Port `8006`, Schalter **Zertifikat des Ziels nicht prüfen** – oder einfach die Schnellwahl *Proxmox VE* |
| nur im LAN, ohne öffentliche Domain | Domain z. B. `nas.lan`, TLS **Intern**. Die Root-CA unter **Zertifikate** herunterladen und auf den Geräten als vertrauenswürdig importieren. |
| Wildcard-Zertifikat oder Server nicht aus dem Internet erreichbar | TLS **DNS-Challenge** – braucht ein DNS-Plugin (Schritt 6) und dessen API-Token |
| alte Domain umziehen | Art **Weiterleitung**, Ziel-URL `https://neu.example.com` – der Pfad wird automatisch angehängt |
| nur bestimmte IPs, Länder oder mit Login | erst unter **Access Lists** anlegen, dann in der Site auswählen |
| Schutz vor Angriffen und Bots | Schalter **WAF**, **Bot-Abwehr**, **Rate Limit** – erscheinen, sobald das Plugin eingebaut ist |
| caddyEvolved-WebUI selbst von außen | Ziel `127.0.0.1` : `8484`, Ziel spricht HTTPS, Zertifikat nicht prüfen, **unbedingt** mit Access List |
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

- **Sites → Testen:** prüft eine Site wie ein Besucher – DNS (inkl. Cloudflare-Proxy), Zertifikat,
  Weg über Caddy zum Ziel und den öffentlichen Weg, auf Wunsch von außen. Das Zertifikats-Symbol
  daneben zeigt die ausgelieferte Zertifikatskette.
- **Dashboard:** Caddy läuft, keine Warnungen.
- **Zertifikate:** Nach dem ersten Aufruf einer Domain erscheint ihr Zertifikat.
- **Logs:** Hier steht, warum Caddy kein Zertifikat bekommt oder ein Upstream nicht
  antwortet.
- **Analytics:** zeigt, ob Anfragen ankommen.
- Auf dem Server: **`sudo caddyevolved doctor`** prüft Dienste, Ports, Firewall, Portweiterleitung,
  DNS und Zertifikate und sagt bei jedem Problem, was zu tun ist. Mit `--extern` testet es
  die Ports 80/443 zusätzlich von außen (über check-host.net, übermittelt nur IP und Port).
- `caddyevolved status` zeigt den Zustand der Installation kompakt.
- **Toolbox:** Ping, Traceroute, Port-Scan und DNS-Abfrage laufen auf dem Server – also aus Sicht
  von Caddy. Antwortet das Ziel einer Site dort nicht, liegt es nicht an Caddy. Der IP-Scan findet
  Geräte im LAN samt Name und MAC; von dort öffnet „Ports“ den Port-Scan für das Gerät.

| Symptom | Ursache und Lösung |
|---|---|
| Zertifikat kommt nicht, Log zeigt `timeout` oder `connection refused` | Port 80/443 nicht weitergeleitet oder DNS zeigt woandershin |
| `502 Bad Gateway` | Ziel (Host/Port oder HTTP/HTTPS) falsch, Dienst aus, oder er lauscht nur auf `127.0.0.1` |
| Endlos-Weiterleitung | Der Dienst erzwingt selbst HTTPS → *Ziel spricht HTTPS* wählen oder im Dienst den Proxy als vertrauenswürdig eintragen |
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

**Backup und Umzug:** WebUI → **Backup** oder auf dem Server:

```bash
sudo caddyevolved backup --encrypt --certs --out /root/cev.cevbak   # Passwort wird abgefragt
sudo caddyevolved restore --certs /root/cev.cevbak                # auf dem neuen Server
```

Vor jeder Wiederherstellung wird der aktuelle Stand gesichert; lehnt Caddy die Konfiguration ab,
kommt er automatisch zurück. Damit lässt sich auch ein Server auf einen anderen umziehen.

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
