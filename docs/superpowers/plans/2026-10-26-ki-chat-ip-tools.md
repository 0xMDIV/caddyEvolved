# KI-Chat, KI-Protokoll, IP-Werkzeuge, Token-Schwärzung, Proxy-Anbieter – Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** IP-Werkzeuge im Log, schaltbare Proxy-Anbieter, Token-Schwärzung, ein append-only KI-Protokoll und einen KI-Chat mit Freigabe pro Änderung.

**Architecture:** Go-Daemon (`internal/api`) mit neuen Paketen `internal/geo`, `internal/aiaudit`, `internal/ai`; React-UI (`ui/src`), gebaut nach `internal/webui/dist` (wird mit eingecheckt). Der Chat nutzt die MCP-Tool-Tabelle (`mcpTools`) und führt Aufrufe in-process über `s.mux` aus.

**Tech Stack:** Go 1.27, `github.com/oschwald/maxminddb-golang/v2`, `github.com/anthropics/anthropic-sdk-go`, React 18 + Vite, Caddy-Caddyfile.

**Spec:** `docs/superpowers/specs/2026-10-26-ki-chat-ip-tools-design.md`

## Global Constraints

- Kein Go lokal: Toolchain liegt in `C:/Users/MDIV/AppData/Local/Temp/claude/P--code-caddyEvolved/<session>/scratchpad/go/bin/go`; prüfen mit `GOOS=linux go vet ./...` und `go test ./...` (api/sysstat bauen nur unter Linux → `GOOS=linux go vet`, Tests der übrigen Pakete nativ).
- UI-Texte deutsch, Stil der bestehenden Karten (`card stack`, `toggle-row`, `SaveRow`, `Badge`).
- Neue Abhängigkeiten nur: `maxminddb-golang/v2`, `anthropic-sdk-go`. MMDB-Zugriff hinter `geo.Resolver` kapseln (später eigener Leser).
- Token-Präfix: 4 Zeichen + `******`. Standard-Parameter: `token access_token api_key apikey key secret password pass auth sig signature code session`. Standard-Header: `X-Api-Key X-Auth-Token Proxy-Authorization`.
- KI-Protokoll: `<StateDir>/ai-audit.jsonl`, 0600, Rotation bei 10 MB → `ai-audit-<YYYYMMDD-HHMMSS>.jsonl`, nie löschen, SHA-256-Kette über Dateigrenzen.
- KI-Einstellungen: `<Etc>/ai.json`, 0600. Key nie vollständig in API-Antworten (`keyHint`: 4 Zeichen + `******`).
- Standardmodell Anthropic `claude-opus-5-5`, `output_config.effort = "medium"`, `max_tokens` 16000.
- Schreibende Tools (`!ReadOnly`) werden nie ohne Klick ausgeführt; Vorschläge verfallen nach 1 h oder beim Neustart.
- Lookup-URL Standard `https://ipinfo.io/{ip}`; muss `http(s)://` sein und `{ip}` enthalten.

## Review Focus

- Kaputte/fehlende Geo-DB oder IPv6/ungültige IP → Land leer, kein Fehler, kein Panic (Test in Task 2).
- Token-Werte mit `&`, `#`, URL-Encoding oder Groß-/Kleinschreibung des Parameternamens (`?API_KEY=`) → trotzdem geschwärzt (Test in Task 1).
- Gleichzeitige Protokoll-Schreiber (zwei Chats parallel) → Kette bleibt gültig (Mutex; Test in Task 4).
- KI liefert in einer Antwort Lese- und Schreib-Tool gemischt → Lese-Tools laufen, alle `tool_result` gehen gesammelt in einer Nachricht zurück, sobald alle Vorschläge entschieden sind (Test in Task 6).
- Freigabe-Klick auf bereits entschiedenen oder verfallenen Vorschlag → keine Ausführung, 409 (Test in Task 6).

---

### Task 1: Token-Schwärzung (Log-Datei und Parser)

**Files:**
- Create: `internal/accesslog/redact.go`, `internal/accesslog/redact_test.go`
- Modify: `internal/accesslog/accesslog.go` (`Parse`: URI schwärzen), `internal/sites/render.go:165-201` (`LogRoll`, `renderLog`), `internal/api/handlers_logging.go` (`logSettings`, `roll()`)
- Test: `internal/sites/render_test.go` (bestehende Log-Block-Erwartungen anpassen)

**Interfaces:**
- Produces: `accesslog.DefaultRedactParams []string`, `accesslog.DefaultRedactHeaders []string`, `accesslog.RedactURI(uri string, params []string) string`, `accesslog.RedactValue(v string) string`, `accesslog.RedactPattern(params []string) string` (RE2-Muster für Caddy), `sites.LogRoll.RedactParams []string`, `logSettings.RedactParams []string` (`json:"redactParams"`, nur Zusätze zur Standardliste).

- [ ] **Step 1: Tests schreiben** – `TestRedactURI`: `/a?token=abcdefghij&x=1` → `/a?token=abcd******&x=1`; `/a?API_KEY=abcdefghij` → `/a?API_KEY=abcd******`; `/a?key=abc` → `/a?key=******` (unter 8 Zeichen komplett); `/a?q=hello` unverändert; `/a?token=abcd%2Fefghij#frag` → Wert bis `&`/`#` behandelt. `TestRedactValue`: `"abcdefghij"` → `"abcd******"`, `"short"` → `"******"`. Render-Test: `renderLog` enthält `format filter {`, `wrap json`, `request>uri regexp`, `request>headers>X-Api-Key regexp`.
- [ ] **Step 2:** `go test ./internal/accesslog/ ./internal/sites/` → FAIL.
- [ ] **Step 3: Implementieren.** `RedactURI` arbeitet auf dem Rohstring (nicht `url.Parse`, damit Reihenfolge/Encoding erhalten bleiben), Parametername case-insensitiv. `renderLog` schreibt statt `format json`:
  ```
  format filter {
      wrap json
      request>uri regexp <RedactPattern> ${1}${2}******
      request>headers>X-Api-Key regexp ^(.{0,4}).* ${1}******
      … (je Header aus DefaultRedactHeaders)
  }
  ```
  `RedactPattern` = `(?i)([?&](?:token|access_token|…)=)([^&#]{0,4})[^&#]*` (Liste `regexp.QuoteMeta`, Standard + `RedactParams`). In der Datei behalten auch kurze Werte bis zu 4 Zeichen – das ist der dokumentierte Kompromiss (RE2 ohne Lookahead); der Parser schwärzt beim Lesen zusätzlich nach `RedactValue`-Regel. `Parse` wendet `RedactURI(…, DefaultRedactParams)` auf `URI` an. `roll()` reicht `RedactParams` durch; `validate()` lehnt Namen außerhalb `[A-Za-z0-9_.-]{1,40}` ab.
- [ ] **Step 4:** Tests → PASS; `GOOS=linux go vet ./...` sauber.
- [ ] **Step 5: Commit** `Logs: Tokens in URLs und Headern nur gekürzt schreiben`

### Task 2: Geo-Resolver (Land/ASN aus DB-IP)

**Files:**
- Create: `internal/geo/geo.go`, `internal/geo/geo_test.go`
- Modify: `go.mod`/`go.sum` (`github.com/oschwald/maxminddb-golang/v2`), `internal/api/server.go` (Feld `Geo *geo.Resolver`, in `New` anlegen), `internal/api/handlers_logging.go` (`handleAccessLog`: `Country` füllen), `internal/api/handlers_firewall.go` (Blockiert-Log), `internal/api/handlers_autoban.go` (Bann-Liste), `internal/api/handlers_analytics.go` (`handleAnalyticsRecent`)

**Interfaces:**
- Produces: `geo.New(paths func() (country, asn string)) *Resolver`; `(*Resolver).Country(ip string) string` (ISO-2 oder `""`); `(*Resolver).ASN(ip string) (num uint, org string)`. Öffnet die DB lazy, öffnet neu, wenn sich der Pfad ändert; Cache `map[string]string` max. 10 000 Einträge (bei Überlauf leeren). JSON-Felder in API-Antworten: `country`, `asn`, `asnOrg` (omitempty).
- Consumes: `blocklists.GeoPath(s.geoDir(), blocklists.GeoCountry|GeoASN)`.

- [ ] **Step 1: Tests** – `TestCountryNoDB`: Pfad `""` → `""`; `TestCountryBadFile`: Datei mit Müll → `""`, kein Panic; `TestCountryInvalidIP`: `"nope"` → `""`. (Kein echtes MMDB im Repo; Lookup-Pfad über eine im Test mit `maxminddb`-Writer erzeugte DB nur, wenn der Writer ohne weitere Abhängigkeit verfügbar ist – sonst manuell auf dem Test-LXC prüfen und im Commit vermerken.)
- [ ] **Step 2:** FAIL.
- [ ] **Step 3: Implementieren.** DB-IP-Country-Feld: `country.iso_code`; ASN-DB: `autonomous_system_number`, `autonomous_system_organization`.
- [ ] **Step 4:** PASS, `GOOS=linux go vet ./...`.
- [ ] **Step 5: Commit** `Logs: Land und Netzbetreiber zu jeder IP (DB-IP Lite)`

### Task 3: IP-Werkzeuge in der UI + Lookup-Einstellung

**Files:**
- Create: `ui/src/components/ip.tsx`
- Modify: `internal/api/handlers_logging.go` (`logSettings.LookupURL string \`json:"lookupUrl"\``, Default, Validierung), `ui/src/api.ts` (Typen `country?`, `asn?`, `asnOrg?`; `LogSettings.lookupUrl`, `redactParams`), `ui/src/pages/Logs.tsx:286` (IP-Spalte `IPCell`, URI-Spalte über `Redacted`), `ui/src/pages/Firewall.tsx:123,161`, `ui/src/components/autoban.tsx:210`, `ui/src/pages/Analytics.tsx:228`, Logging-Einstellungskarte (dort, wo heute `PUT /api/logging` bedient wird) um „IP-Lookup“ und „Weitere Token-Parameter“, `ui/src/styles.css`

**Interfaces:**
- Produces: `export function IPCell(props: { ip: string; country?: string; asnOrg?: string; onFilter?: () => void })` – Flagge (Regional-Indicator-Emoji aus ISO-2) + Kürzel mit Tooltip `countryName()`, IP (klickbar wenn `onFilter`), Button Kopieren (`navigator.clipboard.writeText`, Fallback `execCommand`, 1,5 s „kopiert“), Button „IP prüfen“ (`window.open(lookupUrl.replace("{ip}", encodeURIComponent(ip)), "_blank", "noopener")`). `export function useLookupUrl(): string` (einmal `GET /api/logging` pro Sitzung, Modul-Cache). `export function Redacted({ text }: { text: string })` – blendet Teile mit `******` per CSS `filter: blur(4px)` aus, Klick hebt auf.
- Vorlagen im Einstellungsfeld: ipinfo `https://ipinfo.io/{ip}`, AbuseIPDB `https://www.abuseipdb.com/check/{ip}`, who.is `https://who.is/whois-ip/ip-address/{ip}`, bgp.he.net `https://bgp.he.net/ip/{ip}`.

- [ ] **Step 1: Go-Test** `TestLogSettingsLookupURL` in `internal/api` (nur unter Linux lauffähig → `GOOS=linux go vet`, Logik als reine Funktion `validLookupURL(string) error` in einer Datei ohne Linux-Abhängigkeit testen): `"https://x/{ip}"` ok, `"ftp://x/{ip}"` Fehler, `"https://x/"` Fehler.
- [ ] **Step 2:** FAIL → **Step 3:** implementieren (Go + UI) → **Step 4:** Test PASS, `cd ui && npm run build` ohne Fehler.
- [ ] **Step 5: Commit** `Logs: IP kopieren, IP prüfen und Land neben jeder IP`

### Task 4: Vertrauenswürdige Proxys – Anbieter zum Anhaken

**Files:**
- Create: `internal/sites/proxies.go`, `internal/sites/proxies_test.go`
- Modify: `internal/sites/global.go:26-31,107-125,225-249` (`RealIP`, Migration, Render), `internal/api/handlers_firewall.go:279` (`firewallLoop` holt Bereiche), `ui/src/api.ts:792`, `ui/src/components/globalcards.tsx:75-110`

**Interfaces:**
- Produces: `type ProxyProvider struct { ID, Label string; URLs []string; Header string; Builtin []string }`; `var ProxyProviders = []ProxyProvider{cloudflare, bunny, fastly, cloudfront}`; `RealIP.Providers []string \`json:"providers,omitempty"\``; `RealIP.Cloudflare` bleibt nur zum Lesen (Normalize: `Cloudflare==true` → `"cloudflare"` in `Providers`, dann `Cloudflare=false`); `sites.ProxyRanges(dir string, id string) []string` (Cache-Datei `<dir>/proxy-<id>.txt`, sonst `Builtin`); `sites.UpdateProxyRanges(ctx, dir, id) error`.
- Quellen: Cloudflare `https://www.cloudflare.com/ips-v4`, `…/ips-v6`, Header `Cf-Connecting-Ip`; Bunny `https://bunnycdn.com/api/system/edgeserverlist/plain` + `…/IPv6`, Header `X-Forwarded-For`; Fastly `https://api.fastly.com/public-ip-list` (JSON `addresses`, `ipv6_addresses`), Header `Fastly-Client-Ip`; CloudFront `https://ip-ranges.amazonaws.com/ip-ranges.json` (`prefixes[].ip_prefix` bzw. `ipv6_prefixes[].ipv6_prefix` mit `service=="CLOUDFRONT"`), Header `X-Forwarded-For`. Bei leerer/ungültiger Antwort (keine gültigen CIDRs) alte Liste behalten. Download über das vorhandene `get(ctx,url,limit)` aus `internal/blocklists` bzw. `internal/fetch`.
- Render: Plugin-Pfad `trusted_proxies cloudflare` nur wenn `Providers == ["cloudflare"]`, keine `Proxies`, `c.CloudflareIP`; sonst `static` mit allen Bereichen. `client_ip_headers`: spezifische Header der aktiven Anbieter (dedupliziert, Reihenfolge wie `ProxyProviders`), `X-Forwarded-For` zuletzt.

- [ ] **Step 1: Tests** – `TestRealIPMigratesCloudflare`; `TestRenderProxiesStatic` (bunny+fastly → `trusted_proxies static` mit Bereichen beider, `client_ip_headers Fastly-Client-Ip X-Forwarded-For`); `TestRenderCloudflarePlugin` (nur cloudflare + Cap → `trusted_proxies cloudflare`); `TestParseFastlyJSON`, `TestParseCloudFrontJSON`, `TestProxyRangesFallback` (keine Cache-Datei → Builtin).
- [ ] **Step 2:** FAIL → **Step 3:** implementieren; UI: Checkbox-Liste je Anbieter mit Hinweis auf Quelle, Freitext bleibt. → **Step 4:** PASS, vet, `npm run build`.
- [ ] **Step 5: Commit** `Echte Besucher-IP: Cloudflare, Bunny, Fastly und CloudFront zum Anhaken`

### Task 5: KI-Protokoll (append-only, Hash-Kette)

**Files:**
- Create: `internal/aiaudit/aiaudit.go`, `internal/aiaudit/aiaudit_test.go`
- Modify: `internal/api/server.go` (Feld `AIAudit *aiaudit.Log`, Routen), `internal/cli/serve.go` (öffnen mit `Paths.StateDir`)

**Interfaces:**
- Produces:
  ```go
  type Entry struct {
      N int64; TS time.Time; Chat, Actor, Kind string // Kind: request|proposal|approved|rejected|expired|executed|note
      Text string; Tool string; Args json.RawMessage; Method, Path string; Status int
      Result, Model string; Prev, Hash string
  }
  func Open(dir string) (*Log, error)
  func (l *Log) Append(e Entry) (Entry, error) // setzt N, TS, Prev, Hash
  func (l *Log) List(offset, limit int, chat string) ([]Entry, int, error) // neueste zuerst, total
  func (l *Log) Verify() (ok bool, brokenAt int64, err error)
  func (l *Log) Size() int64
  func (l *Log) Export(w io.Writer) error // alle Dateien in Reihenfolge
  ```
  Hash = hex(SHA-256(Prev + kanonisches JSON des Eintrags ohne `Hash`)). Erster Eintrag `Prev = ""`. `Text`/`Result` auf 4000 Zeichen kürzen; `Args` vor dem Schreiben durch `redactJSON` (Schlüssel, deren Name `key|token|secret|password` enthält → `accesslog.RedactValue`).
- Routen (nur GET, nie DELETE/PUT): `GET /api/ai/audit?offset&limit&chat` → `{entries,total,ok,brokenAt,sizeBytes}`; `GET /api/ai/audit/export` → `application/x-ndjson` Download.

- [ ] **Step 1: Tests** – `TestAppendChain` (3 Einträge, `Verify` ok); `TestTamperDetected` (Datei-Zeile 2 ändern → `brokenAt == 2`); `TestRotationKeepsChain` (Rotationsgrenze im Test über Paketvariable `maxSize` auf 200 Bytes → zwei Dateien, `Verify` ok, erstes `Prev` der neuen Datei = letzter Hash der alten); `TestConcurrentAppend` (50 Goroutinen → `Verify` ok, N lückenlos); `TestReopenContinues` (Open, Append, Open erneut, Append → Kette ok); `TestArgsRedacted`.
- [ ] **Step 2:** FAIL → **Step 3:** implementieren (`O_APPEND|O_CREATE|O_WRONLY`, 0600, `sync.Mutex`, beim Open letzten Eintrag lesen) → **Step 4:** PASS, vet.
- [ ] **Step 5: Commit** `KI-Protokoll: nur anhängen, Hash-Kette, keine Löschfunktion`

### Task 6: KI-Anbindung und Chat-Engine

**Files:**
- Create: `internal/ai/config.go` (Einstellungen), `internal/ai/provider.go` (neutrales Format + Interface), `internal/ai/anthropic.go`, `internal/ai/openai.go`, `internal/ai/chat.go` (Store + Schleife), `internal/ai/*_test.go`, `internal/api/handlers_ai.go`
- Modify: `go.mod`, `internal/api/handlers_mcp.go:210-229` (`internalCall` für Sessions), `internal/api/handlers_analytics.go:98-120` (`audit`: Actor für `X-CaddyEvolved-Via: ai`), `internal/api/server.go` (Felder `AI *ai.Store`, Routen), `internal/backup/backup.go:119` (`ai.json` setzt `Secrets`)

**Interfaces:**
- Config (`<Etc>/ai.json`): `type Config struct { Kind string /* anthropic|openai */; BaseURL, APIKey, Model string }`; `LoadConfig(path) (Config, error)`, `SaveConfig(path, Config) error` (0600); `(Config).Public() map[string]any` → `kind, baseUrl, model, keyHint, configured`. Vorlagen (UI und `GET /api/ai/presets`): Claude `anthropic` `https://api.anthropic.com`; OpenRouter `openai` `https://openrouter.ai/api/v1`; Requesty `openai` `https://router.requesty.ai/v1`; Ollama `openai` `http://localhost:11434/v1`; Eigene.
- Neutrales Format:
  ```go
  type ToolCall struct{ ID, Name string; Args json.RawMessage }
  type ToolResult struct{ ID, Content string; IsError bool }
  type Message struct {
      Role string // user|assistant|tool
      Text string; Calls []ToolCall; Results []ToolResult
      Raw json.RawMessage // anbieter-eigener Assistant-Inhalt, unverändert zurückgeben
  }
  type ToolDef struct{ Name, Description string; Schema map[string]any }
  type Provider interface {
      Turn(ctx context.Context, system string, tools []ToolDef, history []Message) (Message, error)
      Models(ctx context.Context) ([]string, error)
  }
  func NewProvider(c Config) (Provider, error)
  ```
  Anthropic: SDK `client.Messages.New` (bzw. `client.Beta.Messages.New` mit Beta `server-side-fallback-2026-07-01` und `Fallbacks: "default"`, nur wenn BaseURL `https://api.anthropic.com`), `MaxTokens: 16000`, `OutputConfig.Effort: "medium"`, kein `thinking`-Feld (Opus 5.5 läuft adaptiv), Tools als `ToolParam`; `Raw` = JSON von `resp.ToParam()`, beim nächsten Request unverändert eingesetzt (Thinking-Blöcke erhalten). `StopReason == refusal` → Text „Die KI hat die Anfrage abgelehnt (<category>)“. Models: `client.Models.List`. OpenAI-kompatibel: `POST {base}/chat/completions` mit `tools: [{type:"function",function:{name,description,parameters}}]`, `tool_calls`, Rolle `tool` mit `tool_call_id`; Models: `GET {base}/models` (`data[].id`). Timeout 120 s.
- Chat-Store (`<StateDir>/ai-chats/<id>.json`):
  ```go
  type Proposal struct{ ID, CallID, Tool string; Args json.RawMessage; Summary, Method, Path string; Created time.Time; State string /* pending|approved|rejected|expired */; Result string }
  type Chat struct{ ID, Title string; Created, Updated time.Time; History []Message; Proposals []Proposal; Display []DisplayItem }
  type DisplayItem struct{ Kind string /* user|assistant|tool|proposal|error */; Text, Tool, ProposalID string; TS time.Time }
  func NewStore(dir string, boot time.Time) *Store // Vorschläge mit Created < boot oder älter 1 h gelten als expired
  func (s *Store) List() ([]ChatSummary, error); Get(id) (*Chat, error); Create() (*Chat, error); Delete(id) error; Save(*Chat) error
  ```
- Engine:
  ```go
  type Executor interface {
      Tools() []ToolSpec // aus mcpTools: Name, Description, Schema, ReadOnly
      Run(ctx context.Context, tool string, args json.RawMessage) (text string, isErr bool, method, path string)
      Describe(tool string, args json.RawMessage) (method, path string, err error) // ohne Ausführung
  }
  type Engine struct{ Provider Provider; Exec Executor; Audit *aiaudit.Log; Actor, Model string }
  func (e *Engine) Send(ctx context.Context, c *Chat, userText, pageContext string) error
  func (e *Engine) Decide(ctx context.Context, c *Chat, proposalID string, approve bool) error // ErrDecided → 409
  ```
  Ablauf `Send`: Audit `request`; Schleife max. 12 Runden: `Turn`; Antwort ohne Calls → fertig. Mit Calls: Lese-Tools sofort ausführen (Audit `executed`), schreibende → `Proposal` + Audit `proposal`, Ergebnis offen. `write_ai_log` (eingebautes Tool, Arg `text`) → Audit `note`, Ergebnis „protokolliert“. Sind Vorschläge offen → Schleife pausiert, Chat speichern. `Decide`: Zustand prüfen (nicht `pending` oder verfallen → `ErrDecided`); approve → `Run` (Audit `approved` + `executed` mit Status), reject → Ergebnis „Vom Nutzer abgelehnt“, `IsError` (Audit `rejected`). Wenn alle Vorschläge der Runde entschieden: alle Results **in einer** `tool`-Nachricht anhängen und Schleife fortsetzen.
  Systemprompt: `mcpInstructions` + „Antworte auf Deutsch. Schreibende Werkzeuge werden erst nach Freigabe des Nutzers ausgeführt; beschreibe vor jedem Vorschlag kurz, was du tun willst und warum. Halte mit write_ai_log fest, was du getan hast.“ + `Aktuelle Seite: <pageContext>`.
- Executor im API-Paket: `internalCall` bekommt Parameter `via string` und übernimmt bei Cookie-Sessions `Cookie` + `X-CaddyEvolved: 1` + `Origin`/`Referer` vom auslösenden Request; MCP ruft weiter mit `"mcp"`. `audit()`: bei `via == "ai"` Actor `ai (chat <id>, session <kurz>)`, Chat-ID über Header `X-CaddyEvolved-Chat`.
- Routen (alle `s.auth`, nur Cookie-Sessions: `sess.Token != ""` → 403 `ai_session_only`):
  `GET/PUT /api/ai/settings` (PUT ohne `apiKey` behält alten Key), `POST /api/ai/test` (kurzer `Turn` „Antworte mit OK“), `GET /api/ai/models`, `GET /api/ai/presets`, `GET/POST /api/ai/chats`, `GET/DELETE /api/ai/chats/{id}`, `POST /api/ai/chats/{id}/messages` `{text, context}` → Chat, `POST /api/ai/chats/{id}/proposals/{pid}` `{approve}` → Chat.

- [ ] **Step 1: Tests** (Paket `internal/ai`, nativ lauffähig) mit Fake-Provider und Fake-Executor:
  `TestReadToolRunsWithoutApproval`; `TestWriteToolBecomesProposal` (Executor.Run nicht aufgerufen, Audit enthält `proposal`); `TestApproveRunsAndContinues`; `TestRejectSendsErrorResult`; `TestMixedReadWriteSingleResultMessage` (eine `tool`-Nachricht mit beiden Results nach Entscheidung); `TestDecideTwiceConflict` (`ErrDecided`); `TestExpiredProposalNotRun` (boot nach Created); `TestWriteAILogNote`; `TestConfigPublicHidesKey` (`keyHint == "sk-a******"`); `TestOpenAIRoundTrip` (httptest-Server prüft Request-Form `tools`, `tool_calls`, `tool_call_id`); `TestAnthropicRawPreserved` (httptest-Server, zweiter Request enthält den ersten Assistant-Inhalt byte-gleich inkl. `thinking`-Block).
- [ ] **Step 2:** FAIL → **Step 3:** implementieren → **Step 4:** `go test ./internal/ai/ ./internal/aiaudit/` PASS, `GOOS=linux go vet ./...`, `go test ./internal/api/` unter Linux-Bedingungen nur vet.
- [ ] **Step 5: Commit** `KI: Anbindung Anthropic/OpenAI-kompatibel, Chat mit Freigabe pro Änderung`

### Task 7: KI-Oberfläche

**Files:**
- Create: `ui/src/pages/Ai.tsx`, `ui/src/components/aichat.tsx`, `ui/src/components/aisettings.tsx`, `ui/src/components/aiaudit.tsx`
- Modify: `ui/src/App.tsx:50-67,238-316` (NAV-Eintrag `{ path: "/ai", label: "KI-Chat", icon: IconMessageChatbot }` vor „KI / MCP“; Route `/ai`; schwebender Button), `ui/src/pages/Settings.tsx` (Karte `AISettingsCard`), `ui/src/api.ts` (Typen + Aufrufe), `ui/src/styles.css`

**Interfaces:**
- Consumes: Routen aus Task 5/6.
- Produces: `export function ChatView({ compact }: { compact?: boolean })` – gemeinsam für Seite und Panel; aktiver Chat-ID in `localStorage["cev.ai.chat"]` (try/catch) und Modul-State, damit Panel und Seite denselben Chat zeigen. Proposal-Karte: Text der KI, Tool, `method path`, Argumente als formatiertes JSON (`Redacted`), Buttons „Ausführen“ / „Ablehnen“; nach Entscheidung Status-Badge. Während eines laufenden Requests „denkt nach …“ mit `Spinner`, Eingabe gesperrt. `pageContext` = `window.location.pathname` + ggf. `?…`.
- Schwebender Button: fest unten rechts (`position: fixed; right: 20px; bottom: 20px`), nicht auf `/ai` und nicht ohne Login; Panel 420×600 px, auf schmalen Bildschirmen volle Breite. Ohne Konfiguration: Hinweis + Link „KI einrichten“ → `/settings`.
- `Ai.tsx`: Reiter „Chat“ (Chat-Liste links, Neu/Löschen) und „Protokoll“ (Tabelle neueste zuerst, Filter nach Chat, Badge „Kette intakt“ / „Kette gebrochen ab Eintrag N“, Größe, Button „Exportieren“; keine Lösch-/Bearbeiten-Elemente).

- [ ] **Step 1:** `cd ui && npm run typecheck` als Ausgangslage grün.
- [ ] **Step 2:** implementieren.
- [ ] **Step 3:** `npm run build` ohne Fehler; Bundle in `internal/webui/dist` aktualisiert.
- [ ] **Step 4: Commit** `KI-Chat: eigene Seite, schwebender Button und Protokoll-Ansicht`

### Task 8: Doku, Release

**Files:**
- Modify: `README.md` (Featureliste), `docs/API.md` (neue Routen), `C:\Users\MDIV\.claude\projects\P--code-caddyEvolved\memory\project-status.md`

- [ ] **Step 1:** Doku ergänzen (Routen aus Task 5/6, Felder `lookupUrl`, `redactParams`, `realIp.providers`). Im README unter „Später“: eigener MMDB-Leser statt `maxminddb-golang`.
- [ ] **Step 2:** Vollständige Prüfung: `GOOS=linux go vet ./...`, `go test ./...` (nativ, Linux-only-Pakete ausgenommen wie bisher), `cd ui && npm run build`.
- [ ] **Step 3:** Commit `Doku: KI-Chat, IP-Werkzeuge, Proxy-Anbieter`; Tag `v0.21.0`; `git push origin main v0.21.0` (Release-Workflow baut und veröffentlicht).
- [ ] **Step 4:** Release-Workflow beobachten (`gh run watch`), bei Fehler beheben und neuen Patch-Tag setzen (Tags nicht verschieben).
