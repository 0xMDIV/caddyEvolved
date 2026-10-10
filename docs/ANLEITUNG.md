# Anleitung: installieren und bestehende Seiten übernehmen

## 1. Auf einer neuen Linux-Maschine installieren

Voraussetzung: Linux mit systemd (Debian, Ubuntu, Proxmox-LXC, …), amd64 oder arm64,
root-Rechte, Ports 80 und 443 frei.

```bash
curl -fsSL https://raw.githubusercontent.com/0xMDIV/caddyEvolved/main/install.sh | sudo sh
```

Das Skript lädt das neueste Release, prüft die SHA-256-Summe und startet den
Assistenten. Am Ende steht die Adresse der WebUI (`https://<server-ip>:8484`) und das
UI-Passwort – **das wird nur einmal angezeigt**, also notieren.

Varianten:

| Zweck | Befehl |
|---|---|
| bestimmte Version | `curl -fsSL …/install.sh \| sudo CADDYFORGE_VERSION=v0.2.0 sh` |
| ohne Rückfragen | `curl -fsSL …/install.sh \| sudo sh -s -- --unattended /root/answers.json` |
| nur Binary, später einrichten | `curl -fsSL …/install.sh \| sudo CADDYFORGE_NO_SETUP=1 sh` |
| **Update** | dasselbe Kommando erneut – ist caddyforge eingerichtet, wird nur das Binary getauscht und der Dienst neu gestartet |

Ohne Internet am Zielserver: das passende `caddyforge_<version>_linux_<arch>.tar.gz`
von der [Release-Seite](https://github.com/0xMDIV/caddyEvolved/releases) kopieren,
entpacken, `sudo ./caddyforge install`.

## 2. Netzwerk vorbereiten

1. **Router:** Port **80** und **443** (TCP) auf die IP des caddy-Servers weiterleiten.
   Port **8484** (WebUI) **nicht** weiterleiten – die UI bleibt im LAN.
2. **DNS:** für jede Domain einen A-Eintrag (bzw. AAAA) auf deine öffentliche IP. Bei
   wechselnder IP DynDNS nutzen. Für Subdomains reicht oft ein Wildcard-Eintrag
   `*.example.com`.
3. Läuft bisher ein anderer Proxy (Zoraxy, Traefik, NPM) auf 80/443: erst übernehmen
   (Schritt 3), dann den alten stoppen und die Weiterleitung umstellen.

## 3. Bestehende Seiten übernehmen

### Weg A: Import (empfohlen bei vielen Seiten)

WebUI → **Import**. Quelle wählen, Datei hochladen, Vorschau prüfen, übernehmen.

| Quelle | Was hochladen |
|---|---|
| Caddyfile | das alte `Caddyfile` (ein Block pro Site wird eine Site) |
| Zoraxy | Backup-ZIP: Zoraxy → Einstellungen → Backup & Restore → Export |
| Traefik | `traefik.yml`/dynamische Config (YAML/TOML) oder `docker-compose.yml` mit Labels |
| Nginx Proxy Manager | JSON aus der NPM-API oder `sqlite3 -json database.sqlite "select * from proxy_host"` – die genauen Befehle stehen auf der Import-Seite |

In der Vorschau hat jede Seite Warnungen (z. B. „Passwort nicht übernehmbar“) und eine
Checkbox. Nur was angehakt ist, wird angelegt. Jede Seite wird einzeln von caddy
geprüft – eine fehlerhafte blockiert die anderen nicht.

### Weg B: Von Hand

WebUI → **Sites** → **Neue Site**:

1. **ID**: leer lassen (wird aus der Domain gebildet) oder z. B. `nextcloud`.
2. **Art**: *Reverse Proxy* für fast alles.
3. **Domains**: eine pro Zeile, z. B. `cloud.example.com`.
4. **Upstreams**: Adresse des Dienstes im LAN, z. B. `192.168.10.40:80`.
   Mehrere Zeilen = Lastverteilung.
5. **TLS**: *Automatisch* für öffentliche Domains. Fertig → **Speichern**.

Beim Speichern prüft caddy die Konfiguration; ist sie fehlerhaft, bleibt der alte Stand
aktiv und die Fehlermeldung wird angezeigt. Rechts zeigt die **Vorschau** den
erzeugten Caddyfile-Block.

### Typische Fälle

| Dienst | Einstellung |
|---|---|
| normaler Webdienst (Nextcloud, Jellyfin, Vaultwarden, Home Assistant …) | Upstream `ip:port`, TLS automatisch. WebSockets funktionieren ohne Zusatz. |
| Dienst spricht selbst HTTPS mit eigenem Zertifikat (Proxmox `:8006`, UniFi `:8443`, TrueNAS) | Upstream `192.168.10.5:8006`, Haken **Upstream spricht HTTPS** und **Zertifikat des Upstreams nicht prüfen** |
| nur im LAN erreichbar, keine öffentliche Domain | Domain z. B. `nas.lan`, TLS **Intern**. Die Root-CA unter **Zertifikate** herunterladen und auf den Geräten importieren. Lokales DNS (Pi-hole, Router) muss `nas.lan` auf den caddy-Server zeigen. |
| Wildcard-Zertifikat oder Server nicht aus dem Internet erreichbar | TLS **DNS-Challenge**. Braucht ein DNS-Plugin (z. B. Cloudflare) unter **Plugins & Build** und dessen API-Token. |
| alte Domain umziehen | Art **Weiterleitung**, Ziel `https://neu.example.com{uri}` |
| nur bestimmte IPs / mit Login | erst unter **Access Lists** anlegen, dann in der Site auswählen |
| Schutz vor Angriffen / Bots | Schalter **WAF**, **Bot-Abwehr**, **Rate Limit** (erscheinen, wenn das Plugin eingebaut ist) |
| Spezialfall, den das Formular nicht abdeckt | Art **Eigene Konfiguration** oder Feld *Zusätzliche Direktiven* – roher Caddyfile-Inhalt |

## 4. Prüfen

- **Dashboard**: caddy läuft, keine Fehler.
- **Zertifikate**: nach dem ersten Aufruf jeder Domain erscheint dort ihr Zertifikat
  (Let's Encrypt braucht offene Ports 80/443 und korrektes DNS).
- **Logs**: bei Problemen steht hier, warum caddy kein Zertifikat bekommt.
- **Analytics**: zeigt, ob Anfragen ankommen.

Häufige Fehler:

| Symptom | Ursache |
|---|---|
| Zertifikat kommt nicht, Log zeigt `timeout` / `connection refused` | Port 80/443 nicht weitergeleitet oder DNS zeigt woandershin |
| `502 Bad Gateway` | Upstream falsch oder Dienst lauscht nur auf `127.0.0.1` |
| Endlos-Weiterleitung | Dienst erzwingt selbst HTTPS → *Upstream spricht HTTPS* aktivieren oder im Dienst die Proxy-Einstellung (`trusted proxies`) setzen |
| Nextcloud/Vaultwarden meckern über die Adresse | im Dienst die öffentliche Domain als vertrauenswürdig eintragen |
