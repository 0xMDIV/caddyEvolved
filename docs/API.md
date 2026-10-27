# caddyevolved HTTP-API (v1)

Alle Routen unter `/api`. Antworten sind JSON. Fehler haben immer die Form
`{"error": "Text", "code": "stabiler_code", "details": ["…"]}`.

**Auth:** Session-Cookie `cev_session` (HttpOnly) aus `POST /api/login`, alternativ
`Authorization: Bearer <id>`. **Jede nicht-GET-Anfrage braucht den Header
`X-CaddyEvolved: 1`** (CSRF-Schutz), sonst 403 `csrf`. 401 `unauthenticated` → Login-Seite.

## Bestehend (M1)

| Route | Zweck |
|---|---|
| `GET /api/version` | öffentlich: `{name, version, commit, api, setup, serverTime}` |
| `POST /api/login` `{password, keepMeLoggedIn}` | `{expires, sessionId}` + Cookie |
| `POST /api/logout` | |
| `GET /api/session` | `{sessionId, remote, sessions[]}` |
| `POST /api/password` `{current, new}` | |
| `GET /api/status` | Dashboard-Daten (siehe `handlers_status.go`) |
| `GET /api/plugins` | Katalog mit `detected`, `active`, `credentialState`, `complete` |
| `POST /api/plugins/check` `{module}` | freien Modulpfad gegen proxy.golang.org prüfen |
| `POST /api/plugins/credentials` | Credentials in `/etc/caddyevolved/env` schreiben (siehe Handler) |
| `GET /api/logs?unit=caddy|caddyevolved&lines=200&grep=` | `{unit, lines[], count, source}` |
| `POST /api/service/{start|stop|restart|reload}?unit=caddy.service` | |
| `GET /api/events` / `GET /api/events/stream` (SSE) | Ereignisprotokoll |

## Builds (lokaler xcaddy-Build auf dem Server)

`Build`:

```json
{
  "id": "20261010-183012-ab12",
  "status": "queued|preparing|building|verifying|succeeded|failed|cancelled",
  "stage": "Go-Toolchain laden",
  "caddyVersion": "v2.11.7",
  "plugins": ["cloudflare", "github.com/foo/bar@v1.2.3"],
  "modules": ["github.com/caddy-dns/cloudflare"],
  "createdAt": "…", "startedAt": "…", "finishedAt": "…",
  "durationSec": 184,
  "error": "",
  "size": 52428800,
  "sha256": "…",
  "detectedModules": ["dns.providers.cloudflare"],
  "active": false,
  "activatedAt": "…"
}
```

| Route | Antwort |
|---|---|
| `GET /api/build/toolchain` | `{go:{installed,version}, xcaddy:{installed,version}, cacheBytes, busy, runningId}` |
| `GET /api/build/versions` | `{latest:"v2.11.7", installed:"2.11.7", recent:["v2.11.7",…]}` |
| `GET /api/builds` | `{builds:[Build…] (neueste zuerst), activeId, runningId, previousAvailable}` |
| `POST /api/builds` `{caddyVersion:"latest"\|"v2.11.7", plugins:[id\|modulpfad[@ver]]}` | 202 `{build}`; 409 `busy` wenn schon einer läuft |
| `GET /api/builds/{id}` | `{build, log:[Zeilen]}` |
| `GET /api/builds/{id}/stream` (SSE) | Events `line` (data = Textzeile), `status` (data = Build-JSON), `done` (data = Build-JSON) |
| `POST /api/builds/{id}/cancel` | `{build}` |
| `POST /api/builds/{id}/activate` | Binary tauschen + caddy neu starten + Health-Check, bei Fehler automatischer Rollback. `{build, caddyVersion, rolledBack:false}`; Fehler 502 `activate_failed` mit Rollback-Info |
| `POST /api/builds/rollback` | vorherige Binary zurück; `{caddyVersion}` |
| `DELETE /api/builds/{id}` | nicht für den aktiven Build |

## Sites (Reverse-Proxy-Verwaltung)

Jede Site ist eine Datei `/etc/caddy/sites/<id>.caddy`, das Caddyfile enthält
`import /etc/caddy/sites/*.caddy`. Jede Änderung: schreiben → `caddy validate` →
reload; bei Fehler wird der alte Stand wiederhergestellt und 422 `invalid_config`
mit `details` (caddy-Ausgabe) geliefert.

`Site`:

```json
{
  "id": "nextcloud",
  "domains": ["cloud.example.com"],
  "mode": "proxy|redirect|static|raw",
  "upstreams": ["192.168.10.40:80"],
  "upstreamTls": false,
  "upstreamInsecure": false,
  "lbPolicy": "",
  "healthUri": "",
  "tls": "auto|internal|dns|off",
  "dnsProvider": "cloudflare",
  "compress": true,
  "redirectTo": "",
  "root": "",
  "extra": "",
  "raw": "",
  "enabled": true,
  "updatedAt": "…"
}
```

Zusätzliche Site-Felder (alle optional):

```json
{
  "accessList": "nur-lan",
  "waf":       {"enabled": true, "mode": "block|detect"},
  "defender":  {"enabled": true, "responder": "block|tarpit|garbage|drop", "ranges": ["openai","aws","deepseek"]},
  "rateLimit": {"enabled": true, "events": 100, "window": "1m"}
}
```

- `waf` braucht das Plugin `coraza` (OWASP Core Rule Set, `detect` = nur protokollieren).
- `defender` braucht `caddy-defender`. Bekannte Bereiche: `openai, aws, gcloud, azurepubliccloud,
  deepseek, githubcopilot, cloudflare, vpn, private, all` oder CIDRs.
- `rateLimit` braucht `caddy-ratelimit`; Schlüssel ist die Client-IP, `window` z. B. `30s`, `1m`, `1h`.
- Ist das Plugin nicht in der Binary, lehnt caddy die Site ab (422 `invalid_config`). Die UI
  zeigt diese Abschnitte deshalb nur, wenn das Plugin laut `/api/nav` bzw. `/api/plugins`
  (`detected`) eingebaut ist.

- `tls: off` → Site lauscht nur auf `http://`.
- `dns` braucht ein im Binary enthaltenes DNS-Plugin mit gesetzten Credentials.
- `extra`: zusätzliche Direktiven innerhalb des Site-Blocks (Expertenfeld).
- `raw` (nur `mode: raw`): kompletter Blockinhalt.

| Route | Antwort |
|---|---|
| `GET /api/sites` | `{sites:[Site…], importOk, sitesDir, dnsProviders:[{id,name,ready}]}` |
| `POST /api/sites/preview` `Site` | `{caddyfile}` (gerendert, nichts geschrieben) |
| `POST /api/sites` `Site` | 201 `{site, reloaded}` |
| `PUT /api/sites/{id}` `Site` | `{site, reloaded}` |
| `DELETE /api/sites/{id}` | `{ok, reloaded}` |
| `POST /api/sites/{id}/enabled` `{enabled:bool}` | `{site, reloaded}` |

## Access Lists

Wirkt pro Site über `Site.accessList` (ID). Reihenfolge im gerenderten Block:
IP-Sperre → IP-Freigabe → Länder (nur mit Plugin `maxmind-geolocation`) → Basic-Auth → Handler.

Eingabe (`POST`/`PUT`):

```json
{
  "name": "Nur LAN",
  "allow": ["private_ranges", "203.0.113.0/24"],
  "deny": ["192.168.10.99"],
  "allowCountries": ["DE", "AT"],
  "denyCountries": [],
  "geoDb": "/var/lib/caddyevolved/GeoLite2-Country.mmdb",
  "users": [{"username": "nico", "password": "neu, oder leer = unverändert"}]
}
```

Ausgabe (Hashes werden nie zurückgegeben):

```json
{"id":"nur-lan","name":"Nur LAN","allow":[…],"deny":[…],"allowCountries":[],"denyCountries":[],"geoDb":"",
 "users":[{"username":"nico","hasPassword":true}],"usedBy":["app"],"needsGeo":false,"updatedAt":"…"}
```

| Route | Antwort |
|---|---|
| `GET /api/access-lists` | `{accessLists:[…], geoAvailable}` (`geoAvailable` = maxmind-Plugin in der Binary) |
| `POST /api/access-lists` | 201 `{accessList, reloaded}` |
| `PUT /api/access-lists/{id}` | `{accessList, reloaded}` |
| `DELETE /api/access-lists/{id}` | `{ok, reloaded}`; 422 `invalid_site` wenn noch von Sites benutzt |

Fehler wie bei Sites: 422 `invalid_site` (Feldfehler in `details`) oder 422 `invalid_config`.

## Zertifikate

| Route | Antwort |
|---|---|
| `GET /api/certificates` | `{certificates:[{name, domains[], issuer, issuerKey, source: letsencrypt\|zerossl\|internal\|other, staging, notBefore, notAfter, daysLeft, hoursLeft, serial, keyType, sites:[siteIds]}], storage, internalCA}` (sortiert nach Ablauf) |
| `GET /api/certificates/root.crt` | Root-Zertifikat der internen CA (Download, `application/x-x509-ca-cert`); 404 solange keine Site `tls internal` nutzt |

Caddy erneuert ACME-Zertifikate selbst (~30 Tage vor Ablauf), interne alle paar Stunden.

## Plugin-Navigation

`GET /api/nav` → `{plugins:[{page, label, icon, pluginId, plugin}], caddyVersion}`: Seiten
von Plugins, die **in der installierten Binary** stecken. `page` ist der Routen-Schlüssel
(`waf`, `defender`, `ratelimit`, `security`, `geo`). Katalog-Einträge in `/api/plugins`
tragen dasselbe Feld als `ui: {page, label, icon}`.

## Analytics

Alle Sites schreiben ein JSON-Access-Log nach `/var/log/caddy/access.log` (pro Site
abschaltbar mit `Site.noLog`). caddyevolved liest es mit und aggregiert pro Minute (48 h)
und pro Stunde (35 Tage). `blocked` zählt 403 und 429 (Access List, WAF, Bot-Abwehr, Rate Limit).

| Route | Antwort |
|---|---|
| `GET /api/analytics?range=15m\|1h\|6h\|24h\|7d\|30d&site=<siteId>` | `{range, accessLog, report}` |
| `GET /api/analytics/recent?limit=100&site=<siteId>` | `{requests:[{ts, host, method, uri, status, size, durationMs, ip, agent}]}` neueste zuerst |

`report`:

```json
{
  "from": "…", "to": "…", "step": "1m|1h",
  "series": [{"t":"…","requests":12,"s2xx":10,"s3xx":0,"s4xx":1,"s5xx":1,"blocked":1,"bytes":4096,
              "durSum":0.4,"durMax":0.2,"lat":[…],"avgMs":33.3,"p95Ms":100}],
  "totals": {…wie ein series-Punkt…},
  "hosts": [{"key":"app.example.com","count":120}],
  "top": {"paths":[{"key":"/","count":50}], "ips":[…], "agents":[…], "status":[{"key":"200","count":40}], "referers":[…]}
}
```

`series` ist lückenlos (auch leere Minuten/Stunden), `p95Ms` ist eine Histogramm-Schätzung.

## Audit Log

Jeder ändernde API-Aufruf (POST/PUT/DELETE) wird protokolliert, dazu Logins.

| Route | Antwort |
|---|---|
| `GET /api/audit?limit=200` | `{entries:[{id, ts, kind:"audit"\|"auth", step, ok, summary, error, meta:{method, path, status, remote, actor, ms}}]}` neueste zuerst |

## Import

Zweistufig: Vorschau (schreibt nichts) → Auswahl → Übernahme. Dateien gehen base64-kodiert
im JSON (ZIP wird entpackt).

| Format | Was hochladen |
|---|---|
| `caddyfile` | ein oder mehrere Caddyfiles. Einfache Sites (nur `reverse_proxy`/`encode`/`tls internal`) werden strukturiert, alles andere Raw-Site |
| `zoraxy` | Zoraxy-Backup-ZIP oder einzelne Dateien aus `conf/proxy/*.config`, `conf/access/*.json`, `conf/redirect/*.json` |
| `traefik` | dynamische Konfiguration (`.yml`/`.yaml`/`.toml`) und/oder `docker-compose.yml` mit `traefik.*`-Labels |
| `npm` | Nginx Proxy Manager als JSON: API-Export (`GET /api/nginx/proxy-hosts?expand=access_list`, `/api/nginx/redirection-hosts`) oder `sqlite3 -json /data/database.sqlite "select * from proxy_host where is_deleted=0"` |

| Route | Antwort |
|---|---|
| `POST /api/import/preview` `{format, files:[{name, content(base64)}]}` | `{format, sites:[{site, source, warnings[], problems[]}], accessLists:[{accessList, source, warnings[]}], warnings[]}`; 422 `import_failed` bei unlesbaren Dateien |
| `POST /api/import/apply` `{accessLists:[AccessList], sites:[Site]}` | `{imported, results:[{kind: site\|accessList, id, ok, error, details[]}]}` – Access Lists zuerst, dann jede Site einzeln (eine abgelehnte Site blockiert die anderen nicht) |

- `problems` ≠ leer: so nicht übernehmbar (z. B. Domain existiert schon, ID belegt, Feld ungültig) – in der Vorschau editierbar machen (Domain, ID, Ziel) oder abwählen.
- `warnings`: übernehmbar, aber mit Abweichung (z. B. Pfad-Regel ignoriert, Plugin nötig, Passwort neu setzen).
- `accessLists[].accessList.users` kann bcrypt-Hashes aus Traefik enthalten; unverändert zurückschicken.

## API-Tokens

Für Skripte und KI-Clients: `Authorization: Bearer cev_…`. Gespeichert wird nur der
SHA-256-Hash; der Klartext kommt genau einmal bei der Erstellung zurück. Mit Bearer-Auth
entfällt der `X-CaddyEvolved`-Header. Scope `read` darf nur GET, `write` alles außer
Token-Verwaltung (die geht nur mit Login-Session).

| Route | Antwort |
|---|---|
| `GET /api/tokens` | `{tokens:[{id, name, scope, prefix, created, lastUsed, expires}]}` |
| `POST /api/tokens` `{name, scope: read\|write, ttlDays: 0 = unbegrenzt}` | 201 `{token: "cev_…" (einmalig), info}` |
| `DELETE /api/tokens/{id}` | `{ok}` |

Im Audit Log erscheinen Token-Aufrufe als `actor: "token <name>"`, über MCP als `"token <name> (mcp)"`.

## MCP (KI-Anbindung)

`POST /mcp` – Model Context Protocol, Streamable HTTP, nur JSON-Antworten (kein SSE).
Auth: `Authorization: Bearer cev_…` (API-Token). Dual-era: moderne Clients (2026-07-28,
`server/discover`, `_meta` pro Request) und ältere (`initialize`, 2025-11-25 … 2024-11-05).

Tools (Lese-Token sehen nur die lesenden): `get_status`, `list_sites`, `get_site_preview`,
`create_site`, `update_site`, `set_site_enabled`, `delete_site`, `list_access_lists`,
`create_access_list`, `update_access_list`, `delete_access_list`, `list_certificates`,
`get_analytics`, `recent_requests`, `get_logs`, `get_caddyfile`, `validate_caddyfile`,
`list_plugins`, `list_builds`, `get_build`, `start_build`, `activate_build`,
`rollback_build`, `service_action`, `get_audit_log`.

Client-Konfiguration (Beispiel Claude Code):

```bash
claude mcp add --transport http caddyevolved https://<host>:8484/mcp \
  --header "Authorization: Bearer cev_…"
```

Das UI-Zertifikat ist selbstsigniert: entweder dem Client vertrauen
(`NODE_EXTRA_CA_CERTS=/pfad/ui.crt` für Node-basierte Clients, Datei liegt unter
`/etc/caddyevolved/ui.crt`, Download über die UI) oder caddyevolved als eigene Site hinter caddy
veröffentlichen (Upstream `https://127.0.0.1:8484`, `upstreamInsecure: true`, mit Access List).

| Route | Antwort |
|---|---|
| `GET /api/mcp/info` | `{endpoint, tools:[{name, description, readOnly}], uiCertAvailable}` für die UI-Seite |
| `GET /api/ui.crt` | das selbstsignierte UI-Zertifikat (PEM) zum Vertrauen im Client |

## Caddyfile (Expertenmodus)

| Route | Antwort |
|---|---|
| `GET /api/caddyfile` | `{path, content, sitesDir}` |
| `POST /api/caddyfile/validate` `{content}` | `{ok, output}` |
| `POST /api/caddyfile/fmt` `{content}` | `{content}` |
| `PUT /api/caddyfile` `{content}` | validieren, schreiben, reload. `{ok, output, reloaded}`; 422 `invalid_config` |

## Toolbox (Netzwerk-Werkzeuge)

Laufen auf dem Server. Die POST-Werkzeuge nur mit Login (nicht per API-Token) und eines nach dem
anderen – läuft schon eines, kommt 409 `tool_busy`. Antwort: `{result, error, seconds}`; `error`
kann bei einem Teilergebnis gesetzt sein.

| Route | Antwort |
|---|---|
| `GET /api/tools` | `{networks:["192.168.10.0/24"], commonPorts:[…]}` |
| `GET /api/tools/cidr?q=192.168.1.17/24` | `{network, version, address, broadcast, first, last, netmask, wildcard, bits, total, usable, private, contains}` |
| `GET /api/tools/cidr?from=A&to=B` | `{cidrs:[…]}` kleinste CIDR-Liste für den Bereich |
| `GET /api/tools/dns?name=` | `{records:[{type, value}]}` – A/AAAA/CNAME/MX/NS/TXT, bei einer IP PTR |
| `POST /api/tools/ping` `{host, count}` | `{host, addr, sent, received, loss, minMs, avgMs, maxMs, replies:[{seq, rttMs, ttl}]}` (`rttMs` −1 = verloren) |
| `POST /api/tools/traceroute` `{host, maxHops}` | `{addr, hops:[{ttl, addr, name, rttMs[], reached}]}` |
| `POST /api/tools/ports` `{host, ports:"22,80,8000-8100"}` | `{addr, scanned, open:[{port, service, rttMs, banner}]}`; leere `ports` = häufige Ports |
| `POST /api/tools/hosts` `{cidr}` | `{hosts:[{ip, rttMs, via:"icmp"\|"tcp", name, mac, self, openOn[]}]}` – höchstens /22 |
| `POST /api/tools/mdns` `{seconds}` | `{services:[{instance, type, host, port, addrs[], txt[], from}]}` |

## Sensible Dateien

Jede Site beantwortet Pfade mit Zugangsdaten (Punkt-Dateien außer `/.well-known`, `*.env`, Schlüssel,
Dumps, Backups, `docker-compose.yml` …) mit 404, bevor ein anderer Handler läuft. Nicht abschaltbar.

| Route | Antwort |
|---|---|
| `GET /api/protect` | `{rules[], extra[]}` – eingebaute Regeln (Text) und eigene Muster |
| `PUT /api/protect` `{extra:["/backup/*","*.xlsx"]}` | speichert, schreibt alle Sites neu (validate + reload); 400 `bad_pattern` |
| `GET /api/protect/check?path=` | `{path, blocked}` – Pfad oder ganze URL |

## Globale Optionen

Gespeichert in `/etc/caddyevolved/global.json`, gerendert nach `/etc/caddy/caddyevolved-global.caddy`, das
die Caddyfile im globalen Block importiert (wird bei Bedarf eingefügt). Nur Funktionen, deren Modul in der
laufenden Binary steckt, werden gerendert (`caps`).

| Route | Antwort |
|---|---|
| `GET /api/global` | `{global, caps, dnsProviders:[{id,name,ready}], file, proxyProviders:[{id,label,ranges,builtin,updated}]}` |
| `PUT /api/global` `{realIp:{providers:["cloudflare", "fastly", "bunny", "cloudfront"], proxies[]}, dynDns:{enabled, provider, domains:[{zone, names[]}], interval, ipv6}, crowdsec:{enabled, apiUrl, appsecUrl}, tailscale:{enabled, ephemeral}, cache:{enabled, ttl}}` | validieren, Zugangsdaten prüfen, schreiben, reload; 422 mit `details` |

Site-Felder dazu: `noCrowdsec`, `cache`, `tailnet`, Modus `webdav` (mit `root`), `waf.paranoia` (1–4),
`waf.threshold`, `waf.exclude` (CRS-Regel-IDs).

`realIp.providers` schaltet die Adressbereiche bekannter CDNs als `trusted_proxies` frei; die Listen werden beim
Speichern und alle 6 Stunden vom Anbieter geladen (bei Ausfall bleibt die alte). `client_ip_headers` setzt die
Header der aktiven Anbieter vor `X-Forwarded-For`. Ältere Dateien mit `realIp.cloudflare: true` werden beim
Lesen übernommen.

## Logs: IP-Herkunft, Lookup und Token-Schwärzung

| Route | Antwort |
|---|---|
| `GET /api/logs/access?…` | wie bisher plus `ipGeo:{"<ip>":{country, asn, asnOrg}}` aus DB-IP Lite (nur bekannte IPs) |
| `GET /api/firewall/log` | plus `ipGeo` für Blockiert-Log und WAF-Treffer |
| `GET /api/firewall` | plus `ipGeo` für die Auto-Bann-Liste |
| `GET /api/analytics/recent` | plus `ipGeo` |
| `GET /api/logging` / `PUT /api/logging` | Einstellungen zusätzlich `lookupUrl` (http(s) mit `{ip}`, Standard `https://ipinfo.io/{ip}`) und `redactParams[]` |

Caddy schreibt Werte der Query-Parameter `token access_token api_key apikey key secret password pass auth sig
signature code session` (plus `redactParams`) sowie der Header `X-Api-Key`, `X-Auth-Token`,
`Proxy-Authorization` und Tokens im `Referer` nur mit den ersten vier Zeichen und `******` ins Log
(`format filter`, `regexp`). Der Parser kürzt ältere Zeilen beim Lesen ebenso.

## Cloudflare-DNS

Sites mit `"cloudflare": {"proxied": true|false}` bekommen bei `POST /api/sites`, `PUT /api/sites/{id}` und
beim Aktivieren ihren DNS-Eintrag bei Cloudflare. Pro Domain: passende Zone suchen (längstes Suffix), gibt es
dort schon A/AAAA/CNAME, bleibt das Ziel und nur `proxied` wird angeglichen; sonst wird ein Eintrag angelegt
(A/AAAA/CNAME je nach Ziel, TTL auto, Kommentar „angelegt von caddyEvolved“). Gelöscht wird nie etwas.
Das Speichern der Site scheitert nicht an DNS: die Antwort enthält zusätzlich
`dns: [{name, action:"created"|"updated"|"exists"|"skipped"|"error", zone, type, content, proxied, message}]`,
Änderungen und Fehler stehen im Audit Log (`cloudflare`).

Token: der eigene aus den Einstellungen, sonst `CF_API_TOKEN` des Cloudflare-DNS-Plugins. Er braucht
Zone: Lesen und DNS: Bearbeiten. Mit `email` gilt er als Global API Key.

| Route | Antwort |
|---|---|
| `GET /api/cloudflare` | `{keyHint, email, target, proxied, source:"own"\|"plugin"\|"", configured}` |
| `PUT /api/cloudflare` `{apiToken?, email, target, proxied}` | speichert `/etc/caddyevolved/cloudflare.json` (0600); ohne `apiToken` bleibt der alte. `target` leer = öffentliche IPv4 |
| `DELETE /api/cloudflare/token` | entfernt den eigenen Token (der des Plugins bleibt) |
| `POST /api/cloudflare/test` | `{zones[], target, type, targetError}` |

## KI-Chat

Der Chat läuft in der Browser-Sitzung (API-Tokens und CLI bekommen 403 `ai_session_only`; sie nutzen `/mcp`).
Lesende Werkzeuge laufen sofort, jedes ändernde wird zum Vorschlag und erst mit
`POST …/proposals/{pid} {approve:true}` ausgeführt – als normaler API-Aufruf mit dieser Sitzung, im Audit Log
als `ai (chat <id>, session <id>)`. Offene Vorschläge verfallen nach 1 Stunde oder beim Neustart.

| Route | Antwort |
|---|---|
| `GET /api/ai/settings` | `{kind, baseUrl, model, keyHint, configured, presets[], defaultModel}` – der Key nie im Klartext |
| `PUT /api/ai/settings` `{kind:"anthropic"\|"openai", baseUrl, model, apiKey?}` | speichert `/etc/caddyevolved/ai.json` (0600); ohne `apiKey` bleibt der alte |
| `POST /api/ai/test` | `{reply, ms}` – kurze Testanfrage an den Anbieter |
| `GET /api/ai/models` | `{models[]}` vom Anbieter |
| `GET /api/ai/chats` / `POST /api/ai/chats` | `{chats:[{id,title,updated,pending}], configured}` / neuer Chat |
| `GET /api/ai/chats/{id}` / `DELETE` | `{id, title, display[], proposals[], pending}` / löschen (das Protokoll bleibt) |
| `POST /api/ai/chats/{id}/messages` `{text, context}` | Chat nach der Runde (fertig oder wartet auf Freigabe), ggf. `error` |
| `POST /api/ai/chats/{id}/proposals/{pid}` `{approve}` | Chat; 409 `decided`, wenn schon entschieden oder verfallen |

## KI-Protokoll

`/var/lib/caddyevolved/ai-audit.jsonl` (0600): Anfragen, Vorschläge, Freigaben, Ablehnungen, Ausführungen und
Notizen der KI (`write_ai_log`). Nur Anhängen, Rotation ab 10 MB ohne Löschen, jeder Eintrag mit SHA-256 des
vorigen. Es gibt keine Route zum Ändern oder Löschen.

| Route | Antwort |
|---|---|
| `GET /api/ai/audit?offset&limit&chat` | `{entries[], total, ok, brokenAt, sizeBytes}` neueste zuerst; `ok:false` mit der Nummer des ersten Eintrags, der nicht zur Kette passt |
| `GET /api/ai/audit/export` | alle Dateien als JSONL-Download |
