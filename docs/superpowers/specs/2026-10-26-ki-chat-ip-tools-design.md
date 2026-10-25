# KI-Chat, KI-Protokoll, IP-Werkzeuge im Log, Token-Schwärzung, Proxy-Anbieter

Stand: 2026-10-26. Fünf Teile, unabhängig baubar. Empfohlene Reihenfolge:
1 → 2 → 3 → 4 → 5 (klein zuerst, KI zuletzt, weil sie das Protokoll braucht).

Bereits vorhanden und **nicht** Teil dieser Arbeit: Geo-Blocking (Firewall,
Access Lists, DB-IP Lite), `trusted_proxies`/`client_ip_headers` für
Cloudflare (`internal/sites/global.go`, `RealIPCard`), MCP-Endpunkt mit
Tools (`internal/api/handlers_mcp.go`). Erledigt vorab: `get_logs` rief
`journalctl --tail` auf (gibt es nicht) → jetzt `--lines`.

---

## Teil 1 – IP-Werkzeuge im Log-Viewer

**Warum:** Beim Durchsehen der Logs will man eine auffällige IP sofort
einordnen (Land, wem gehört sie) und weitergeben, ohne abzutippen.

- Neben jeder IP in den Logs (Access-Log-Ansicht, Blockiert-Log der
  Firewall, Auto-Bann-Liste, wo immer IPs tabellarisch stehen):
  - **Land**: Flagge + ISO-Kürzel, aus der DB-IP-Country-DB, die
    caddyEvolved schon herunterlädt (`blocklists.GeoPath`/`GeoCountry`).
    Kein externer Dienst. Heute liest nur Caddy die `.mmdb`; der Daemon braucht
    einen MMDB-Leser (siehe „Entscheidung MMDB-Leser“). `Entry.Country`
    existiert im Parser, wird aber nirgends gefüllt – beim Ausliefern an die
    UI füllen (mit kleinem Cache). Fehlt die DB: nichts anzeigen, keinen Fehler.
  - Optional ASN/Netzbetreiber als Tooltip, falls die ASN-DB vorhanden ist
    (Builder-Entscheidung, nicht Pflicht).
  - **Kopieren**-Button (Clipboard, kurze Bestätigung „kopiert“).
  - **„IP prüfen“**-Button: öffnet die konfigurierte Lookup-URL im neuen Tab.
- **Einstellung** (Einstellungen-Seite, neue kleine Karte „IP-Lookup“):
  URL-Vorlage mit Platzhalter `{ip}`. Standard `https://ipinfo.io/{ip}`.
  Vorlagen zum Auswählen: ipinfo, AbuseIPDB (`https://www.abuseipdb.com/check/{ip}`),
  whois (`https://who.is/whois-ip/ip-address/{ip}`), bgp.he.net. Freie Eingabe
  erlaubt; Validierung: muss `http(s)://` sein und `{ip}` enthalten.
- Nicht-Ziel: automatischer Lookup bei externen Diensten im Hintergrund.

## Teil 2 – Vertrauenswürdige Proxys: Anbieter zum Anhaken

**Warum:** Steht ein CDN/Proxy vor Caddy, sehen Logs, Firewall und Auto-Bann
sonst dessen IP. Heute gibt es nur Cloudflare als Schalter plus Freitext.

- `RealIPCard` wird zu einer Liste von Anbietern mit Häkchen, Freitext für
  eigene Proxys bleibt.
- Anbieter (Startumfang): **Cloudflare** (vorhanden), **Bunny CDN**,
  **Fastly**, **AWS CloudFront**. Builder darf weitere mit offiziell
  veröffentlichter IP-Liste ergänzen (z. B. Google Cloud CDN, Gcore).
- Jeder Anbieter hat: offizielle URL der IP-Bereiche, eingebaute Fallback-
  Liste, Header für die Besucher-IP.
- Bereichslisten werden wie die Sperrlisten periodisch geholt und gecacht
  (Muster aus `internal/blocklists`), Fallback auf eingebaute Liste. Ändert
  sich eine Liste, wird die globale Caddyfile neu gerendert.
- Cloudflare mit Plugin `http.ip_sources.cloudflare` wird nur genutzt, wenn
  Cloudflare der einzige Eintrag ist (keine anderen Anbieter, kein Freitext);
  sonst `static` mit allen Bereichen – entspricht `global.go:233`.
- `client_ip_headers`: Caddy kennt nur eine globale Header-Liste. Reihenfolge:
  anbieterspezifische Header (`Cf-Connecting-Ip`, `Fastly-Client-Ip`, …) zuerst,
  `X-Forwarded-For` zuletzt. Bunny/CloudFront → `X-Forwarded-For`.
- Datenmodell: `RealIP.Providers []string` (IDs), `Cloudflare bool` wird beim
  Laden nach `Providers` migriert (rückwärtskompatibel lesen).

## Teil 3 – Tokens nicht im Klartext loggen

**Warum:** Tokens in URLs (`?token=…`, `?api_key=…`) und eigenen Headern
(`X-Api-Key`) landen heute im Klartext im Access-Log. Caddy schwärzt
nur `Authorization`, `Cookie`, `Set-Cookie`.

- **Beim Schreiben** (Caddy-Log-Konfiguration, `format filter`):
  - Query-Parameter mit Namen aus einer Liste (`token`, `access_token`,
    `api_key`, `apikey`, `key`, `secret`, `password`, `pass`, `auth`, `sig`,
    `signature`, `code`, `session`) – Groß/Klein egal – werden auf die
    **ersten 4 Zeichen + `******`** gekürzt. Umsetzung als Builder-Entscheidung;
    naheliegend `regexp`-Filter auf `request>uri` mit Capture-Gruppe, da der
    `query`-Filter kein Präfix behalten kann. Werte unter 8 Zeichen: komplett `******`.
  - Header `X-Api-Key`, `X-Auth-Token`, `Proxy-Authorization` gleich behandeln.
  - Liste in den Einstellungen erweiterbar (Karte „Logging“ oder bei IP-Lookup),
    Standardliste immer aktiv.
- **Beim Lesen**: der Parser (`accesslog.Parse`) schwärzt dieselben Muster
  zusätzlich, damit ältere Logzeilen von vor der Änderung auch nicht im
  Klartext in der UI erscheinen.
- **In der UI**: der gekürzte Teil (`abcd******`) wird unscharf (CSS blur)
  dargestellt, Klick hebt den Blur auf. Klartext ist ja nicht mehr vorhanden.
- Das gilt ebenso für das Audit-Log und das KI-Protokoll: der KI-API-Key und
  API-Tokens erscheinen dort nur als Präfix (so wie Tokens heute schon als
  Name/ID statt Wert im Audit stehen).
- Nicht-Ziel: Request-Bodies schwärzen (werden nicht geloggt).

## Teil 4 – KI-Protokoll (nicht löschbar)

**Warum:** Wenn eine KI Einstellungen ändert, muss nachvollziehbar sein, wer
was angefragt, was die KI vorgeschlagen, wer zugestimmt hat und was passiert
ist. Die KI soll dort selbst hineinschreiben, aber nichts entfernen können.

- Eigene Datei unter dem Datenverzeichnis, z. B. `/var/lib/caddyevolved/ai-audit.jsonl`,
  nur Anhängen (`O_APPEND`), Rechte 0600.
- **Keine** API, kein UI-Element, kein Tool zum Löschen, Kürzen oder Bearbeiten.
  Auch nicht für Admins über die UI. Rotation bei 10 MB → `ai-audit-<datum>.jsonl`,
  alte Dateien bleiben liegen (nie löschen). Die Kette läuft über Dateigrenzen
  weiter (erstes `prev` = Hash des letzten Eintrags der Vordatei) und wird über
  alle Dateien geprüft. Die UI zeigt die Gesamtgröße. Unbegrenztes Wachstum ist
  bei Text-Einträgen praktisch kein Problem. *(meine Entscheidung)*
- Backup: Backups umfassen nur `/etc/caddyevolved` und `/etc/caddy`, nicht
  das Datenverzeichnis. Das Protokoll liegt im Datenverzeichnis und ist damit
  **nicht** Teil des Backups – ein Restore kann es also auch nicht
  überschreiben. Gesichert wird es über den JSONL-Export. *(meine Entscheidung)*
- Jeder Eintrag: Zeit, Chat-ID, Benutzer (Session/Login), Art
  (`request`, `proposal`, `approved`, `rejected`, `executed`, `note`),
  Inhalt (Nutzeranfrage gekürzt, vorgeschlagene Aktion = Tool + Argumente,
  API-Methode/Pfad, Statuscode/Ergebnis-Kurzfassung), Modell/Anbieter,
  Begründung der KI.
- **Hash-Kette**: jeder Eintrag enthält `prev` (SHA-256 des vorigen) und
  `hash`. Die UI zeigt „Kette intakt“ / „Kette gebrochen ab Eintrag N“.
  Schützt nicht gegen Root, macht Manipulation aber sichtbar.
- Die KI bekommt ein Tool `write_ai_log` (nur anhängen, Art `note`), um
  festzuhalten, was sie getan hat und warum. Lesen/Löschen des Protokolls ist
  **kein** KI-Tool.
- Ausführungs-Einträge (`approved`/`executed`) schreibt der **Server**, nicht
  die KI – die KI kann also nicht verschweigen, was ausgeführt wurde.
- Ansicht: Reiter „Protokoll“ auf der KI-Seite, nur lesen, filterbar nach
  Chat/Datum, Export als JSONL.
- Zusätzlich landen ausgeführte KI-Aktionen wie heute im normalen Audit
  (Actor z. B. `ai (chat abcd1234, user …)`).

## Teil 5 – KI-Chat

**Warum:** Einstellungen per Sprache abfragen und ändern („sperr diese IP“,
„warum ist Site X langsam“), ohne einen externen MCP-Client.

### Anbindung
- Einstellungen → Karte „KI“: Anbieter-Typ, Basis-URL, API-Key, Modell.
  - Typ **Anthropic** über das offizielle Go-SDK `github.com/anthropics/anthropic-sdk-go`
    (mit `option.WithBaseURL` für abweichende URLs). Standardmodell
    `claude-opus-5-5`, Effort ausdrücklich `medium`. Beim direkten Claude-API-Endpunkt
    serverseitiger Refusal-Fallback (`fallbacks: "default"`, Beta
    `server-side-fallback-2026-07-01`); bei fremder Basis-URL weggelassen.
    Thinking-Blöcke werden unverändert im Verlauf mitgeführt (nie bearbeiten).
    *(meine Entscheidung: SDK ist die offizielle Anbindung; zweite Abhängigkeit)*
  - Typ **OpenAI-kompatibel** (`/v1/chat/completions`, Bearer) – deckt
    OpenRouter, Requesty, Ollama, LM Studio, „other“ ab.
  - Vorlagen füllen Typ + URL: Claude direkt, OpenRouter, Requesty, Ollama
    lokal, Eigene.
  - Modell: Freitext; falls der Anbieter eine Modellliste liefert
    (`/v1/models`), Auswahl daraus.
  - „Verbindung testen“-Button.
- Einstellungen samt Key in `/etc/caddyevolved/ai.json` (0600, nur der Daemon
  liest sie). Kommt wie `auth.json` ins Backup und setzt dort das
  „enthält Geheimnisse“-Kennzeichen. **Nicht** `internal/secrets` –
  das ist Caddys EnvironmentFile, und Caddy braucht den Key nicht.
  In UI/API/Logs nur als Präfix.
- Alle Anfragen an den Anbieter gehen vom **Server** aus; der Browser
  sieht den Key nie.

### Werkzeuge
- Dieselben Tools wie der MCP-Endpunkt (Tool-Liste und `runTool` wieder-
  verwenden), plus `write_ai_log`. Ausführung in-process mit der Session des
  Admins, der den Chat führt – Validierung, Rollback und Audit gelten wie bei
  jeder anderen Änderung. Anpassung nötig: `internalCall` reicht heute nur den
  `Authorization`-Header weiter (Tokens); für eine Browser-Session muss es
  Cookie und CSRF-Header mitgeben bzw. die Session direkt übernehmen, und
  `audit()` braucht einen Zweig für den Actor `ai (chat <id>, session <id>)`
  (z. B. über `X-CaddyEvolved-Via: ai`).
- Systemprompt auf Basis von `mcpInstructions`, plus: aktuelle Seite des
  Nutzers, Hinweis auf Rückfrage-Pflicht und Protokoll.

### Rückfrage vor jeder Änderung (serverseitig erzwungen)
- Lese-Tools (GET) laufen ohne Rückfrage.
- Jedes schreibende Tool wird **nicht** ausgeführt, sondern als Vorschlag
  gespeichert (Protokoll: `proposal`) und im Chat als Karte angezeigt:
  „Was ich tun will“ (Text der KI), konkrete Änderung (Tool, Argumente,
  bei Sites wenn möglich Vorher/Nachher bzw. Caddyfile-Vorschau),
  Buttons **Ausführen** / **Ablehnen**.
- Erst der Klick (eigener API-Aufruf mit Session des Nutzers) führt aus;
  Ergebnis geht zurück an die KI, die dann weitermacht.
- Mehrere Änderungen in einer Antwort = mehrere Karten, jede einzeln.
- Kein „immer erlauben“ in dieser Version.

### Oberfläche
- Eigener Eintrag **„KI“** in der Seitenleiste: Chat als ganze Seite,
  Liste vergangener Chats, Reiter „Protokoll“.
- **Schwebender Button** unten rechts auf jeder Seite (nicht auf der KI-Seite
  selbst und nicht auf Login): öffnet Chat als Panel.
- Panel und Seite zeigen **denselben** aktiven Chat (gemeinsamer Verlauf);
  die aktuelle Seite (Route + ggf. ausgewählte Site/IP) geht als Kontext mit.
- Antworten kommen schrittweise: der Server führt die Runde aus, bis die KI
  fertig ist oder auf eine Freigabe wartet, und liefert dann den neuen Stand;
  die UI zeigt solange „denkt nach …“. Kein Token-Streaming in dieser Version.
  *(meine Entscheidung – halbiert den Aufwand für zwei Anbieter-Protokolle)*
- Ist keine KI konfiguriert: Button zeigt Hinweis mit Link zu den Einstellungen.

### Speicherung und Benutzer
- caddyEvolved hat einen Admin (ein Passwort, mehrere Sessions), keine
  Benutzer/Rollen. Chats sind daher **gemeinsam für alle Admin-Sessions**,
  serverseitig im Datenverzeichnis. Im Protokoll steht als Benutzer die
  Session-Kurz-ID plus Client-IP. *(meine Entscheidung)*
- Der Chat ist nur für Browser-Sessions; API-Tokens nutzen weiter den
  MCP-Endpunkt. *(meine Entscheidung)*
- Chats löschen ist erlaubt – das Protokoll bleibt davon unberührt.
- Offene Vorschläge werden mit dem Chat gespeichert und verfallen nach
  1 Stunde oder beim Neustart des Daemons. Ein Klick auf einen verfallenen
  Vorschlag führt nichts aus; der Chat bittet die KI, neu vorzuschlagen.
  Gespeichert wird nur der Chatverlauf, kein laufender Anbieter-Stream.
  *(meine Entscheidung)*

### Nicht-Ziele
- Kein autonomes Handeln ohne Klick, keine geplanten KI-Aufgaben.
- Kein eigener MCP-Client für fremde MCP-Server.

---

## Entscheidung MMDB-Leser (Nutzer, 2026-10-26)
- Erst einmal die Bibliothek `oschwald/maxminddb-golang`. **Für später
  vorgemerkt:** durch einen eigenen Leser ersetzen (weniger Abhängigkeiten).
  Den Zugriff deshalb hinter einer kleinen Schnittstelle kapseln
  (z. B. `geo.Country(ip) string`), damit der Tausch lokal bleibt.

## Dem Builder überlassen
- Genaue Gestaltung der Karten, Panelgröße, Flaggen-Darstellung.
- Ob Teil 1 ASN anzeigt.
- Technik der Token-Schwärzung in Caddy (regexp-Filter o. ä.), solange das
  Ergebnis „4 Zeichen + `******`“ im Log steht.
- Weitere Proxy-Anbieter über die vier genannten hinaus.
- Umgang mit Anbieter-Fehlern (Timeouts, Rate Limits) – sinnvolle Meldung im Chat.

## Erledigt vorab
- `internal/systemd/systemd.go`: `journalctl --tail` → `--lines`, Test
  `internal/systemd/systemd_test.go`.
