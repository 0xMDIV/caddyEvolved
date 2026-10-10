# caddyforge HTTP-API (v1)

Alle Routen unter `/api`. Antworten sind JSON. Fehler haben immer die Form
`{"error": "Text", "code": "stabiler_code", "details": ["…"]}`.

**Auth:** Session-Cookie `cfx_session` (HttpOnly) aus `POST /api/login`, alternativ
`Authorization: Bearer <id>`. **Jede nicht-GET-Anfrage braucht den Header
`X-Caddyforge: 1`** (CSRF-Schutz), sonst 403 `csrf`. 401 `unauthenticated` → Login-Seite.

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
| `POST /api/plugins/credentials` | Credentials in `/etc/caddyforge/env` schreiben (siehe Handler) |
| `GET /api/logs?unit=caddy|caddyforge&lines=200&grep=` | `{unit, lines[], count, source}` |
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

## Caddyfile (Expertenmodus)

| Route | Antwort |
|---|---|
| `GET /api/caddyfile` | `{path, content, sitesDir}` |
| `POST /api/caddyfile/validate` `{content}` | `{ok, output}` |
| `POST /api/caddyfile/fmt` `{content}` | `{content}` |
| `PUT /api/caddyfile` `{content}` | validieren, schreiben, reload. `{ok, output, reloaded}`; 422 `invalid_config` |
