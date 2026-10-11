import { ReactNode, useEffect, useState } from "react";
import {
  api,
  BINARY_CHANGED,
  DEFENDER_RANGES,
  defaultDefender,
  defaultRateLimit,
  defaultWaf,
  PluginsResponse,
  RateRule,
  SiteDefender,
  SiteRateLimit,
  SiteWaf,
  WAF_GROUPS,
} from "../api";
import { Switch } from "./ui";

/** Plugin ids whose site-level sections the UI offers. */
export const FEATURE_PLUGINS = { waf: "coraza", defender: "caddy-defender", rateLimit: "caddy-ratelimit" } as const;

/** Which catalog plugins are compiled into the running binary, by id. */
export function useCompiledPlugins(): Record<string, boolean> {
  const [compiled, setCompiled] = useState<Record<string, boolean>>({});
  useEffect(() => {
    let alive = true;
    const load = async () => {
      try {
        const r = await api.get<PluginsResponse>("/api/plugins");
        const m: Record<string, boolean> = {};
        for (const p of r.plugins ?? []) m[p.id] = p.detected;
        if (alive) setCompiled(m);
      } catch {
        /* sections stay hidden */
      }
    };
    load();
    window.addEventListener(BINARY_CHANGED, load);
    return () => {
      alive = false;
      window.removeEventListener(BINARY_CHANGED, load);
    };
  }, []);
  return compiled;
}

/** splitList turns free text (lines, spaces, commas) into entries. */
export const splitList = (t: string) =>
  t
    .split(/[\s,;]+/)
    .map((x) => x.trim())
    .filter(Boolean);

const splitIds = (t: string) =>
  t
    .split(/[\s,;]+/)
    .map((x) => parseInt(x, 10))
    .filter((n) => Number.isFinite(n) && n > 0);

/**
 * ListArea edits a list as free text. It keeps the typed text while the
 * parent only sees the parsed entries, so typing a space does not jump.
 */
export function ListArea({
  value,
  onChange,
  placeholder,
  rows = 2,
}: {
  value?: string[];
  onChange: (v: string[]) => void;
  placeholder?: string;
  rows?: number;
}) {
  const [text, setText] = useState((value ?? []).join("\n"));
  return (
    <textarea
      className="mono"
      rows={rows}
      value={text}
      placeholder={placeholder}
      spellCheck={false}
      onChange={(e) => {
        setText(e.target.value);
        onChange(splitList(e.target.value));
      }}
    />
  );
}

/** IdInput edits rule IDs as text. */
function IdInput({ value, onChange, placeholder }: { value?: number[]; onChange: (v: number[]) => void; placeholder?: string }) {
  const [text, setText] = useState((value ?? []).join(" "));
  return (
    <input
      className="mono"
      value={text}
      placeholder={placeholder}
      onChange={(e) => {
        setText(e.target.value);
        onChange(splitIds(e.target.value));
      }}
    />
  );
}

function Section({ title, children, open }: { title: string; children: ReactNode; open?: boolean }) {
  return (
    <details className="waf-tuning" open={open}>
      <summary className="small">{title}</summary>
      <div className="form-grid" style={{ marginTop: 8 }}>
        {children}
      </div>
    </details>
  );
}

// ---- WAF ----------------------------------------------------------------------

const CRS_METHODS = ["GET", "HEAD", "POST", "OPTIONS"];
const METHOD_CHOICES = ["GET", "HEAD", "POST", "OPTIONS", "PUT", "PATCH", "DELETE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH"];
const METHOD_PRESETS: Record<string, string[]> = {
  Standard: CRS_METHODS,
  "REST-API": [...CRS_METHODS, "PUT", "PATCH", "DELETE"],
  "WebDAV / Nextcloud": [...CRS_METHODS, "PUT", "PATCH", "DELETE", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH"],
};

export function WafFields({ value, onChange }: { value?: SiteWaf; onChange: (v: SiteWaf | undefined) => void }) {
  const v = value ?? { ...defaultWaf(), enabled: false };
  return (
    <div className="feature">
      <div className="feature-head">
        <Switch checked={v.enabled} onChange={(on) => onChange({ ...v, enabled: on })} label="WAF aktiv" />
        WAF <span className="hint">(Coraza + OWASP Core Rule Set)</span>
      </div>
      {v.enabled && (
        <div className="inline-fields">
          <label className="check">
            <input type="radio" checked={v.mode === "block"} onChange={() => onChange({ ...v, mode: "block" })} /> Blockieren
          </label>
          <label className="check">
            <input type="radio" checked={v.mode === "detect"} onChange={() => onChange({ ...v, mode: "detect" })} /> Nur erkennen (Log)
          </label>
          <span className="hint">Neue Sites erst mit „Nur erkennen“ testen – Treffer stehen unter Firewall → WAF-Treffer.</span>
        </div>
      )}
      {v.enabled && <WafTuning v={v} onChange={onChange} />}
    </div>
  );
}

/** Every Coraza/CRS option the site can set. */
function WafTuning({ v, onChange }: { v: SiteWaf; onChange: (v: SiteWaf) => void }) {
  const set = <K extends keyof SiteWaf>(k: K, val: SiteWaf[K]) => onChange({ ...v, [k]: val });
  const methods = v.methods && v.methods.length > 0 ? v.methods : CRS_METHODS;
  const toggleMethod = (m: string, on: boolean) => {
    const next = on ? [...methods.filter((x) => x !== m), m] : methods.filter((x) => x !== m);
    const same = next.length === CRS_METHODS.length && CRS_METHODS.every((x) => next.includes(x));
    set("methods", same ? [] : METHOD_CHOICES.filter((x) => next.includes(x)));
  };
  const off = new Set(v.groupsOff ?? []);
  const toggleGroup = (k: string, on: boolean) => set("groupsOff", WAF_GROUPS.map((g) => g.key).filter((g) => (g === k ? !on : off.has(g))));
  const pe = v.pathExcludes ?? [];
  return (
    <>
      <Section title="Strenge & Schwellwerte">
        <label className="field">
          Paranoia-Level (blockieren)
          <select value={v.paranoia || 1} onChange={(e) => set("paranoia", Number(e.target.value))}>
            <option value={1}>1 – Standard, kaum Fehlalarme</option>
            <option value={2}>2 – strenger</option>
            <option value={3}>3 – sehr streng</option>
            <option value={4}>4 – maximal, viele Fehlalarme</option>
          </select>
        </label>
        <label className="field">
          Paranoia-Level (nur protokollieren)
          <select value={v.detectParanoia || 0} onChange={(e) => set("detectParanoia", Number(e.target.value))}>
            <option value={0}>wie oben</option>
            {[2, 3, 4].map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
          <span className="hint">Höhere Stufe testweise mitlaufen lassen: Treffer landen im Log, blockiert wird nach der Stufe oben.</span>
        </label>
        <label className="field">
          Blockieren ab Punktzahl (Anfrage)
          <input type="number" min={1} max={1000} value={v.threshold || 5} onChange={(e) => set("threshold", Number(e.target.value))} />
          <span className="hint">Standard 5. Höher (z. B. 10) hilft zuerst gegen Fehlalarme.</span>
        </label>
        <label className="field">
          Blockieren ab Punktzahl (Antwort)
          <input type="number" min={1} max={1000} value={v.outThreshold || 4} onChange={(e) => set("outThreshold", Number(e.target.value))} />
          <span className="hint">Standard 4. Greift bei Datenlecks in Antworten.</span>
        </label>
        <label className="check full">
          <input type="checkbox" checked={!!v.earlyBlocking} onChange={(e) => set("earlyBlocking", e.target.checked)} /> Früh blockieren – schon nach den Headern,
          bevor der Body hochgeladen ist
        </label>
      </Section>

      <Section title="Erlaubte Anfragen (Methoden, Content-Types, Größe)">
        <div className="field full">
          Erlaubte HTTP-Methoden
          <div className="inline-fields" style={{ margin: "4px 0" }}>
            {Object.entries(METHOD_PRESETS).map(([name, ms]) => (
              <button key={name} type="button" className="btn sm" onClick={() => set("methods", name === "Standard" ? [] : ms)}>
                {name}
              </button>
            ))}
          </div>
          <div className="check-grid">
            {METHOD_CHOICES.map((m) => (
              <label key={m} className="check small mono">
                <input type="checkbox" checked={methods.includes(m)} onChange={(e) => toggleMethod(m, e.target.checked)} /> {m}
              </label>
            ))}
          </div>
          <span className="hint">CRS erlaubt nur GET, HEAD, POST, OPTIONS. Vaultwarden, Nextcloud und andere APIs brauchen PUT/DELETE – sonst 403.</span>
        </div>
        <label className="field">
          Weitere Content-Types
          <ListArea value={v.contentTypes} onChange={(x) => set("contentTypes", x)} placeholder={"application/octet-stream\napplication/grpc"} />
          <span className="hint">Zusätzlich zu Formularen, Multipart, JSON und XML.</span>
        </label>
        <label className="field">
          Max. Größe des Anfrage-Body (MB)
          <input type="number" min={1} max={10240} value={v.bodyLimitMb || ""} placeholder="12.5 (Standard)" onChange={(e) => set("bodyLimitMb", Number(e.target.value) || 0)} />
          <label className="check" style={{ fontWeight: 400 }}>
            <input type="checkbox" checked={!!v.bodyPartial} onChange={(e) => set("bodyPartial", e.target.checked)} /> Größere Bodys nur anprüfen statt
            ablehnen (Uploads)
          </label>
        </label>
        <label className="check full">
          <input type="checkbox" checked={!v.noResponse} onChange={(e) => set("noResponse", !e.target.checked)} /> Antworten prüfen (Datenlecks: SQL-Fehler,
          Stacktraces, Webshells) – kostet etwas Leistung
        </label>
      </Section>

      <Section title={`Regelgruppen${off.size ? ` (${off.size} aus)` : ""}`}>
        <div className="check-grid full" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))" }}>
          {WAF_GROUPS.map((g) => (
            <label key={g.key} className="check small">
              <input type="checkbox" checked={!off.has(g.key)} onChange={(e) => toggleGroup(g.key, e.target.checked)} /> {g.label}{" "}
              <span className="muted mono">{g.block}xxx</span>
            </label>
          ))}
        </div>
        <span className="hint full">Ganze Gruppen nur abschalten, wenn die Anwendung sie sicher nicht braucht (z. B. Java-Regeln vor einer PHP-App).</span>
      </Section>

      <Section title="Ausnahmen (Regeln und Pfade)">
        <label className="field full">
          Regeln ausschalten (IDs, überall auf dieser Site)
          <IdInput value={v.exclude} onChange={(x) => set("exclude", x)} placeholder="z. B. 942100 920350" />
          <span className="hint">Die ID steht unter Firewall → WAF-Treffer – dort geht das Ausschalten auch per Klick.</span>
        </label>
        <label className="field">
          WAF aus unter diesen Pfaden
          <ListArea value={v.skipPaths} onChange={(x) => set("skipPaths", x)} placeholder={"/api/upload\n/webhook"} />
          <span className="hint">Präfix, z. B. /api trifft auch /api/v1.</span>
        </label>
        <div className="field">
          Regeln nur unter einem Pfad ausschalten
          {pe.map((p, i) => (
            <div key={i} className="inline-fields">
              <input
                className="mono"
                style={{ width: 140 }}
                value={p.path}
                placeholder="/api"
                onChange={(e) => set("pathExcludes", pe.map((x, j) => (j === i ? { ...x, path: e.target.value } : x)))}
              />
              <IdInput value={p.ids} onChange={(ids) => set("pathExcludes", pe.map((x, j) => (j === i ? { ...x, ids } : x)))} placeholder="942100 941100" />
              <button type="button" className="btn sm" onClick={() => set("pathExcludes", pe.filter((_, j) => j !== i))}>
                ✕
              </button>
            </div>
          ))}
          <button type="button" className="btn sm" style={{ alignSelf: "flex-start" }} onClick={() => set("pathExcludes", [...pe, { path: "", ids: [] }])}>
            + Pfad-Ausnahme
          </button>
        </div>
      </Section>

      <Section title="Eigene Regeln (SecLang, Experten)">
        <label className="field full">
          Zusätzliche Coraza-Direktiven
          <textarea
            className="editor"
            style={{ minHeight: 90 }}
            spellCheck={false}
            value={v.custom ?? ""}
            placeholder={'SecRule REQUEST_HEADERS:User-Agent "@contains badbot" "id:10901,phase:1,deny,status:403"'}
            onChange={(e) => set("custom", e.target.value)}
          />
          <span className="hint">Werden nach dem Core Rule Set geladen. IDs ab 10000 frei wählen (10000–10499 vergibt caddyEvolved für Pfad-Ausnahmen).</span>
        </label>
      </Section>
    </>
  );
}

// ---- Bot-Abwehr -----------------------------------------------------------------

const RANGE_LABEL: Record<string, string> = {
  openai: "OpenAI (GPTBot)",
  deepseek: "DeepSeek",
  githubcopilot: "GitHub Copilot",
  mistral: "Mistral",
  aws: "AWS (alle Regionen)",
  "aws-us-east-1": "AWS us-east-1",
  "aws-us-west-1": "AWS us-west-1",
  gcloud: "Google Cloud",
  azurepubliccloud: "Microsoft Azure",
  oci: "Oracle Cloud",
  aliyun: "Alibaba Cloud",
  huawei: "Huawei Cloud",
  digitalocean: "DigitalOcean",
  linode: "Linode / Akamai",
  vultr: "Vultr",
  cloudflare: "Cloudflare (Vorsicht hinter CF-Proxy!)",
  datadog: "Datadog",
  vpn: "VPN-Anbieter",
  private: "Private Netze (sperrt das LAN!)",
  all: "Alle oben",
};

export function DefenderFields({ value, onChange }: { value?: SiteDefender; onChange: (v: SiteDefender | undefined) => void }) {
  const v = value ?? { ...defaultDefender(), enabled: false };
  const set = <K extends keyof SiteDefender>(k: K, val: SiteDefender[K]) => onChange({ ...v, [k]: val });
  const toggleRange = (r: string, on: boolean) => set("ranges", on ? [...v.ranges.filter((x) => x !== r), r] : v.ranges.filter((x) => x !== r));
  const custom = v.ranges.filter((r) => !DEFENDER_RANGES.includes(r));
  return (
    <div className="feature">
      <div className="feature-head">
        <Switch checked={v.enabled} onChange={(on) => onChange({ ...v, enabled: on })} label="Bot-Abwehr aktiv" />
        Bot-Abwehr <span className="hint">(KI-Crawler und Cloud-Netze aussperren)</span>
      </div>
      {v.enabled && (
        <>
          <label className="field">
            Reaktion
            <select value={v.responder} onChange={(e) => set("responder", e.target.value as SiteDefender["responder"])}>
              <option value="block">Blockieren (403)</option>
              <option value="custom">Eigene Antwort (Text und Statuscode)</option>
              <option value="redirect">Weiterleiten</option>
              <option value="tarpit">Tarpit (extrem langsam antworten)</option>
              <option value="garbage">Müll-Daten ausliefern</option>
              <option value="drop">Verbindung kappen</option>
            </select>
          </label>
          {v.responder === "custom" && (
            <div className="form-grid">
              <label className="field">
                Antworttext
                <input value={v.message ?? ""} placeholder="Kein Zugriff für Bots" onChange={(e) => set("message", e.target.value)} />
              </label>
              <label className="field">
                Statuscode
                <input type="number" min={200} max={599} value={v.statusCode || ""} placeholder="200" onChange={(e) => set("statusCode", Number(e.target.value) || 0)} />
              </label>
            </div>
          )}
          {v.responder === "redirect" && (
            <label className="field">
              Weiterleiten nach
              <input className="mono" value={v.url ?? ""} placeholder="https://example.com" onChange={(e) => set("url", e.target.value)} />
            </label>
          )}
          {v.responder === "tarpit" && (
            <div className="form-grid">
              <label className="field">
                Dauer
                <input className="mono" value={v.tarpitTimeout ?? ""} placeholder="30s (Standard)" onChange={(e) => set("tarpitTimeout", e.target.value)} />
              </label>
              <label className="field">
                Bytes pro Sekunde
                <input type="number" min={1} value={v.tarpitBps || ""} placeholder="24 (Standard)" onChange={(e) => set("tarpitBps", Number(e.target.value) || 0)} />
              </label>
            </div>
          )}
          <div className="check-grid" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))" }}>
            {DEFENDER_RANGES.map((r) => (
              <label key={r} className="check small">
                <input type="checkbox" checked={v.ranges.includes(r)} onChange={(e) => toggleRange(r, e.target.checked)} /> {RANGE_LABEL[r] ?? r}
              </label>
            ))}
          </div>
          {v.ranges.length === 0 && <span className="hint">Mindestens einen Bereich wählen.</span>}
          <Section title="Eigene Bereiche, Ausnahmen, robots.txt">
            <label className="field">
              Weitere IP-Bereiche sperren
              <ListArea
                value={custom}
                onChange={(x) => set("ranges", [...v.ranges.filter((r) => DEFENDER_RANGES.includes(r)), ...x])}
                placeholder="203.0.113.0/24"
              />
            </label>
            <label className="field">
              Ausnahmen (IPs, die trotzdem dürfen)
              <ListArea value={v.whitelist} onChange={(x) => set("whitelist", x)} placeholder="20.1.2.3" />
            </label>
            <label className="check full">
              <input type="checkbox" checked={!!v.serveIgnore} onChange={(e) => set("serveIgnore", e.target.checked)} /> /robots.txt ausliefern, das allen
              Crawlern alles verbietet
            </label>
          </Section>
        </>
      )}
    </div>
  );
}

// ---- Rate Limit -------------------------------------------------------------------

const WINDOWS = ["10s", "30s", "1m", "5m", "15m", "1h"];

function WindowSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}>
      {WINDOWS.map((w) => (
        <option key={w} value={w}>
          {w}
        </option>
      ))}
      {!WINDOWS.includes(value) && <option value={value}>{value}</option>}
    </select>
  );
}

export function RateLimitFields({ value, onChange }: { value?: SiteRateLimit; onChange: (v: SiteRateLimit | undefined) => void }) {
  const v = value ?? { ...defaultRateLimit(), enabled: false };
  const rules = v.rules ?? [];
  const setRule = (i: number, r: Partial<RateRule>) => onChange({ ...v, rules: rules.map((x, j) => (j === i ? { ...x, ...r } : x)) });
  return (
    <div className="feature">
      <div className="feature-head">
        <Switch checked={v.enabled} onChange={(on) => onChange({ ...v, enabled: on })} label="Rate Limit aktiv" />
        Rate Limit <span className="hint">(pro Client-IP)</span>
      </div>
      {v.enabled && (
        <>
          <div className="inline-fields">
            <input type="number" min={1} style={{ width: 100 }} value={v.events} onChange={(e) => onChange({ ...v, events: Math.max(1, Number(e.target.value) || 1) })} />
            <span>Anfragen pro</span>
            <WindowSelect value={v.window} onChange={(w) => onChange({ ...v, window: w })} />
            <select value={v.key ?? "ip"} onChange={(e) => onChange({ ...v, key: e.target.value as SiteRateLimit["key"] })}>
              <option value="ip">je IP</option>
              <option value="ip-path">je IP und Pfad</option>
            </select>
            <span className="hint">Darüber antwortet Caddy mit 429.</span>
          </div>
          <div className="field">
            <span className="small" style={{ fontWeight: 550 }}>
              Strengere Grenzen für einzelne Pfade <span className="hint">(z. B. Login gegen Passwort-Raten)</span>
            </span>
            {rules.map((r, i) => (
              <div key={i} className="inline-fields">
                <PathInput value={r.paths} onChange={(paths) => setRule(i, { paths })} />
                <select value={(r.methods ?? []).join(" ") || ""} onChange={(e) => setRule(i, { methods: e.target.value ? e.target.value.split(" ") : [] })}>
                  <option value="">alle Methoden</option>
                  <option value="POST">nur POST</option>
                  <option value="POST PUT PATCH DELETE">schreibende</option>
                </select>
                <input type="number" min={1} style={{ width: 80 }} value={r.events} onChange={(e) => setRule(i, { events: Math.max(1, Number(e.target.value) || 1) })} />
                <span>pro</span>
                <WindowSelect value={r.window} onChange={(w) => setRule(i, { window: w })} />
                <button type="button" className="btn sm" onClick={() => onChange({ ...v, rules: rules.filter((_, j) => j !== i) })}>
                  ✕
                </button>
              </div>
            ))}
            <button
              type="button"
              className="btn sm"
              style={{ alignSelf: "flex-start" }}
              onClick={() => onChange({ ...v, rules: [...rules, { paths: ["/login*"], methods: ["POST"], events: 5, window: "1m" }] })}
            >
              + Pfad-Regel
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function PathInput({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const [text, setText] = useState(value.join(" "));
  return (
    <input
      className="mono"
      style={{ width: 200 }}
      value={text}
      placeholder="/login* /api/auth*"
      onChange={(e) => {
        setText(e.target.value);
        onChange(splitList(e.target.value));
      }}
    />
  );
}
