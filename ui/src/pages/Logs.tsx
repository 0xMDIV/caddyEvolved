import { Fragment, useEffect, useRef, useState } from "react";
import { IconFileZip, IconFilter, IconRefresh, IconX } from "@tabler/icons-react";
import { api, fmtTime } from "../api";
import { ToggleRow } from "../components/siteform";
import { IPCell, IPGeoMap, LOOKUP_PRESETS, Redacted, setLookupUrl } from "../components/ip";
import { Badge, ErrorBox, PageHead, Spinner, useLoad, useToast } from "../components/ui";

type Tab = "access" | "process" | "settings";

export default function Logs() {
  const [tab, setTab] = useState<Tab>(() => (window.location.hash === "#prozess" ? "process" : window.location.hash === "#rotation" ? "settings" : "access"));
  const go = (t: Tab) => {
    setTab(t);
    history.replaceState(null, "", t === "access" ? "#" : t === "process" ? "#prozess" : "#rotation");
  };
  return (
    <>
      <PageHead title="Logs" sub="Zugriffe aller Sites mit Filtern und Markierungen, Prozess-Logs von Caddy und caddyEvolved, Rotation.">
        <div className="seg">
          <button className={`seg-btn ${tab === "access" ? "active" : ""}`} onClick={() => go("access")}>
            Zugriffe
          </button>
          <button className={`seg-btn ${tab === "process" ? "active" : ""}`} onClick={() => go("process")}>
            Prozess-Logs
          </button>
          <button className={`seg-btn ${tab === "settings" ? "active" : ""}`} onClick={() => go("settings")}>
            Rotation & Speicher
          </button>
        </div>
      </PageHead>
      {tab === "access" && <AccessLog />}
      {tab === "process" && <ProcessLog />}
      {tab === "settings" && <LogSettings />}
    </>
  );
}

// ---------- access log ----------

interface AccessEntry {
  ts: string;
  host: string;
  method: string;
  uri: string;
  proto?: string;
  status: number;
  size: number;
  bytesRead: number;
  durationMs: number;
  ip: string;
  agent?: string;
  referer?: string;
  tags?: string[];
}
interface AccessResult {
  entries: AccessEntry[];
  matched: number;
  scanned: number;
  files: number;
  tags: Record<string, number>;
  partial: boolean;
  ipGeo?: IPGeoMap;
}
interface TagInfo {
  Tag: string;
  Label: string;
  Desc: string;
}

const TAG_KIND: Record<string, "ok" | "err" | "warn" | "info" | undefined> = {
  torrent: "info",
  "ki-crawler": "warn",
  bot: undefined,
  scanner: "err",
  geblockt: "warn",
  fehler: "err",
};

const EMPTY = { since: "24h", host: "", status: "", tag: "", ip: "", path: "", agent: "", q: "", method: "", minMs: "" };
type Filters = typeof EMPTY;

function statusKind(s: number): "ok" | "err" | "warn" | "info" {
  if (s >= 500) return "err";
  if (s >= 400) return "warn";
  if (s >= 300) return "info";
  return "ok";
}

export function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function AccessLog() {
  const [f, setF] = useState<Filters>(EMPTY);
  const [limit, setLimit] = useState(200);
  const [auto, setAuto] = useState(false);
  const [data, setData] = useState<AccessResult | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState<number | null>(null);
  const meta = useLoad(() => api.get<{ tags: TagInfo[] }>("/api/logging"));
  const hosts = useLoad(() => api.get<{ sites: { domains: string[] }[] }>("/api/sites"));
  const set = (k: keyof Filters, v: string) => setF((x) => ({ ...x, [k]: v }));

  async function load() {
    setLoading(true);
    try {
      const q = new URLSearchParams({ limit: String(limit) });
      Object.entries(f).forEach(([k, v]) => v && q.set(k, v));
      setData(await api.get<AccessResult>(`/api/logs/access?${q}`));
      setErr(null);
    } catch (e) {
      setErr(e);
    } finally {
      setLoading(false);
    }
  }

  const key = JSON.stringify(f) + limit;
  useEffect(() => {
    const t = setTimeout(load, 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);
  useEffect(() => {
    if (!auto) return;
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, key]);

  const domainList = Array.from(new Set((hosts.data?.sites ?? []).flatMap((s) => s.domains).filter((d) => !d.startsWith("*") && !d.startsWith(":"))));
  const tags = meta.data?.tags ?? [];
  const active = Object.entries(f).filter(([k, v]) => v && k !== "since").length;

  return (
    <div className="stack" style={{ gap: 12 }}>
      <div className="card stack" style={{ gap: 10 }}>
        <div className="log-filters">
          <label className="field">
            Zeitraum
            <select value={f.since} onChange={(e) => set("since", e.target.value)}>
              <option value="15m">15 Minuten</option>
              <option value="1h">1 Stunde</option>
              <option value="24h">24 Stunden</option>
              <option value="168h">7 Tage</option>
              <option value="720h">30 Tage</option>
              <option value="">alles</option>
            </select>
          </label>
          <label className="field">
            Site
            <select value={f.host} onChange={(e) => set("host", e.target.value)}>
              <option value="">alle</option>
              {domainList.map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            Status
            <select value={f.status} onChange={(e) => set("status", e.target.value)}>
              <option value="">alle</option>
              <option value="2xx">2xx – OK</option>
              <option value="3xx">3xx – Weiterleitung</option>
              <option value="4xx">4xx – Client-Fehler</option>
              <option value="5xx">5xx – Server-Fehler</option>
              <option value="403,429">403/429 – geblockt</option>
              <option value="404">404 – nicht gefunden</option>
              <option value="502,503,504">502–504 – Ziel down</option>
            </select>
          </label>
          <label className="field">
            Methode
            <select value={f.method} onChange={(e) => set("method", e.target.value)}>
              <option value="">alle</option>
              {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map((m) => (
                <option key={m}>{m}</option>
              ))}
            </select>
          </label>
          <label className="field">
            IP (Anfang)
            <input className="mono" value={f.ip} placeholder="203.0.113." onChange={(e) => set("ip", e.target.value)} />
          </label>
          <label className="field">
            Pfad enthält
            <input className="mono" value={f.path} placeholder="/api" onChange={(e) => set("path", e.target.value)} />
          </label>
          <label className="field">
            User-Agent enthält
            <input value={f.agent} placeholder="curl" onChange={(e) => set("agent", e.target.value)} />
          </label>
          <label className="field">
            Langsamer als (ms)
            <input inputMode="numeric" value={f.minMs} placeholder="500" onChange={(e) => set("minMs", e.target.value.replace(/[^0-9]/g, ""))} />
          </label>
          <label className="field log-filters-wide">
            Suche überall
            <input value={f.q} placeholder="Text in Host, Pfad, IP, User-Agent, Referer" onChange={(e) => set("q", e.target.value)} />
          </label>
        </div>
        <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
          <span className="small muted">
            <IconFilter size={14} style={{ verticalAlign: "-2px" }} /> Markierung:
          </span>
          <button className={`preset ${!f.tag ? "preset-on" : ""}`} onClick={() => set("tag", "")}>
            alle
          </button>
          {tags.map((t) => (
            <button key={t.Tag} className={`preset ${f.tag === t.Tag ? "preset-on" : ""}`} title={t.Desc} onClick={() => set("tag", f.tag === t.Tag ? "" : t.Tag)}>
              {t.Label}
              {data?.tags?.[t.Tag] ? <span className="muted"> · {data.tags[t.Tag]}</span> : null}
            </button>
          ))}
          <span className="spacer" />
          {active > 0 && (
            <button className="btn ghost sm" onClick={() => setF({ ...EMPTY, since: f.since })}>
              <IconX size={14} /> Filter zurücksetzen
            </button>
          )}
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))} style={{ width: "auto" }}>
            {[100, 200, 500, 1000, 2000].map((n) => (
              <option key={n} value={n}>
                {n} Einträge
              </option>
            ))}
          </select>
          <label className="check small">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> Live (5 s)
          </label>
          <button className="btn sm" onClick={load} disabled={loading}>
            {loading ? <Spinner /> : <IconRefresh size={14} />}
          </button>
        </div>
      </div>

      <ErrorBox error={err} />
      {data && (
        <div className="small muted">
          {data.matched.toLocaleString("de-DE")} Treffer in {data.scanned.toLocaleString("de-DE")} Zugriffen ({data.files} Datei{data.files === 1 ? "" : "en"})
          {data.matched > data.entries.length && ` · neueste ${data.entries.length} angezeigt`}
          {data.partial && " · ältere Dateien nicht mehr gelesen"}
        </div>
      )}
      <div className="card" style={{ padding: 0 }}>
        <div className="table-wrap">
          <table className="log-table">
            <thead>
              <tr>
                <th>Zeit</th>
                <th>Site</th>
                <th>Anfrage</th>
                <th>Status</th>
                <th>Größe</th>
                <th>Dauer</th>
                <th>IP</th>
                <th>Markierung</th>
              </tr>
            </thead>
            <tbody>
              {data?.entries.length === 0 && (
                <tr>
                  <td colSpan={8} className="empty">
                    Keine Zugriffe für diese Filter.
                  </td>
                </tr>
              )}
              {data?.entries.map((e, i) => (
                <Fragment key={i}>
                  <tr className="log-row" onClick={() => setOpen(open === i ? null : i)}>
                    <td className="small nowrap">{fmtTime(e.ts)}</td>
                    <td className="small">{e.host}</td>
                    <td className="mono small log-uri">
                      <b>{e.method}</b> <Redacted text={e.uri} />
                    </td>
                    <td>
                      <Badge kind={statusKind(e.status)}>{e.status}</Badge>
                    </td>
                    <td className="small nowrap">{fmtBytes(e.size)}</td>
                    <td className="small nowrap">{e.durationMs < 1 ? "<1" : Math.round(e.durationMs)} ms</td>
                    <td className="mono small">
                      <IPCell ip={e.ip} geo={data.ipGeo?.[e.ip]} onFilter={() => set("ip", e.ip)} />
                    </td>
                    <td>
                      <div className="chips">
                        {(e.tags ?? []).map((t) => (
                          <Badge key={t} kind={TAG_KIND[t]}>
                            {tags.find((x) => x.Tag === t)?.Label ?? t}
                          </Badge>
                        ))}
                      </div>
                    </td>
                  </tr>
                  {open === i && (
                    <tr>
                      <td colSpan={8}>
                        <dl className="cert-dl log-detail">
                          <dt>Zeit</dt>
                          <dd>{new Date(e.ts).toLocaleString("de-DE")}</dd>
                          <dt>URL</dt>
                          <dd className="mono">
                            {e.method} {e.host}
                            <Redacted text={e.uri} /> {e.proto && <span className="muted">({e.proto})</span>}
                          </dd>
                          <dt>Übertragen</dt>
                          <dd>
                            {fmtBytes(e.size)} gesendet · {fmtBytes(e.bytesRead)} empfangen
                          </dd>
                          <dt>User-Agent</dt>
                          <dd className="mono">{e.agent || "–"}</dd>
                          <dt>Referer</dt>
                          <dd className="mono">{e.referer ? <Redacted text={e.referer} /> : "–"}</dd>
                        </dl>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ---------- process logs (journal) ----------

interface LogsResp {
  unit: string;
  lines: string[] | null;
  count: number;
  source: string;
  path?: string;
}

function ProcessLog() {
  const [unit, setUnit] = useState<"caddy" | "caddyevolved">("caddy");
  const [lines, setLines] = useState(200);
  const [grep, setGrep] = useState("");
  const [auto, setAuto] = useState(true);
  const [data, setData] = useState<LogsResp | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const preRef = useRef<HTMLPreElement>(null);
  const stick = useRef(true);

  async function load() {
    setLoading(true);
    try {
      const q = new URLSearchParams({ unit, lines: String(lines) });
      if (grep.trim()) q.set("grep", grep.trim());
      setData(await api.get<LogsResp>(`/api/logs?${q}`));
      setError(null);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const t = setTimeout(load, grep ? 300 : 0);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [unit, lines, grep]);
  useEffect(() => {
    if (!auto) return;
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auto, unit, lines, grep]);
  useEffect(() => {
    if (stick.current && preRef.current) preRef.current.scrollTop = preRef.current.scrollHeight;
  }, [data]);

  return (
    <div className="stack" style={{ gap: 12 }}>
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <select value={unit} onChange={(e) => setUnit(e.target.value as "caddy" | "caddyevolved")} style={{ width: "auto" }}>
          <option value="caddy">Caddy</option>
          <option value="caddyevolved">caddyEvolved</option>
        </select>
        <select value={lines} onChange={(e) => setLines(Number(e.target.value))} style={{ width: "auto" }}>
          {[100, 200, 500, 1000, 2000].map((n) => (
            <option key={n} value={n}>
              {n} Zeilen
            </option>
          ))}
        </select>
        <input placeholder="Filter…" value={grep} onChange={(e) => setGrep(e.target.value)} style={{ width: 180 }} />
        <label className="check small">
          <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> Auto (5 s)
        </label>
        <button className="btn" onClick={load} disabled={loading}>
          {loading ? <Spinner /> : <IconRefresh size={16} />}
        </button>
        {data && <span className="small muted">Quelle: {data.source}</span>}
      </div>
      <ErrorBox error={error} />
      <pre
        ref={preRef}
        className="code wrap"
        style={{ height: "calc(100vh - 240px)", minHeight: 300 }}
        onScroll={(e) => {
          const el = e.currentTarget;
          stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
        }}
      >
        {data ? (data.lines?.length ? data.lines.join("\n") : "Keine Einträge.") : "Lade…"}
      </pre>
    </div>
  );
}

// ---------- rotation settings ----------

interface LogSettingsT {
  rotate: boolean;
  sizeMb: number;
  keep: number;
  keepDays: number;
  compress: boolean;
  localTime: boolean;
  redactParams?: string[] | null;
  lookupUrl?: string;
}
interface LoggingResp {
  settings: LogSettingsT;
  path: string;
  files: { name: string; size: number; modTime: string; compressed: boolean; current: boolean }[];
  totalBytes: number;
}

function LogSettings() {
  const data = useLoad(() => api.get<LoggingResp>("/api/logging"));
  const [draft, setDraft] = useState<LogSettingsT | null>(null);
  const [redactText, setRedactText] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const toast = useToast();
  const v = draft ?? data.data?.settings;

  async function save() {
    if (!v) return;
    setSaving(true);
    setErr(null);
    try {
      await api.put("/api/logging", v);
      if (v.lookupUrl) setLookupUrl(v.lookupUrl);
      toast("ok", "Gespeichert – alle Sites neu geschrieben und Caddy neu geladen");
      setDraft(null);
      setRedactText(null);
      data.reload();
    } catch (e) {
      setErr(e);
    } finally {
      setSaving(false);
    }
  }

  const upd = (p: Partial<LogSettingsT>) => v && setDraft({ ...v, ...p });
  const worst = v ? (v.rotate ? v.sizeMb * (v.keep + 1) : null) : null;

  return (
    <div className="grid grid-2" style={{ alignItems: "start" }}>
      <div className="card stack">
        <h2 style={{ margin: 0 }}>Rotation des Zugriffs-Logs</h2>
        <ErrorBox error={data.error} />
        {v && (
          <>
            <ToggleRow checked={v.rotate} onChange={(rotate) => upd({ rotate })} label="Rotation" hint="Wird die Datei zu groß, beginnt Caddy eine neue; alte werden umbenannt und nach Regel gelöscht." />
            <div className="form-grid">
              <label className="field">
                Neue Datei ab (MB)
                <input type="number" min={1} max={10240} disabled={!v.rotate} value={v.sizeMb} onChange={(e) => upd({ sizeMb: Number(e.target.value) })} />
              </label>
              <label className="field">
                Alte Dateien behalten
                <input type="number" min={1} max={1000} disabled={!v.rotate} value={v.keep} onChange={(e) => upd({ keep: Number(e.target.value) })} />
              </label>
              <label className="field">
                Höchstens (Tage)
                <input type="number" min={0} max={3650} disabled={!v.rotate} value={v.keepDays} onChange={(e) => upd({ keepDays: Number(e.target.value) })} />
                <span className="hint">0 = unbegrenzt, nur Anzahl zählt</span>
              </label>
            </div>
            <ToggleRow checked={v.compress} disabled={!v.rotate} onChange={(compress) => upd({ compress })} label="Alte Dateien komprimieren (gzip)" hint="Spart meist 85–95 % Platz. Die Log-Ansicht liest komprimierte Dateien mit." />
            <ToggleRow checked={v.localTime} disabled={!v.rotate} onChange={(localTime) => upd({ localTime })} label="Lokale Zeit in Dateinamen" hint="Sonst UTC." />
            {worst !== null && (
              <p className="small muted" style={{ margin: 0 }}>
                Höchstens etwa {fmtBytes(worst * 1024 * 1024)} {v.compress ? "(unkomprimiert gerechnet, tatsächlich deutlich weniger)" : ""}.
              </p>
            )}
            {!v.rotate && <div className="alert warn">Ohne Rotation wächst die Datei unbegrenzt.</div>}
            <h3 style={{ margin: "8px 0 0", fontSize: 14 }}>IP-Lookup</h3>
            <label className="field">
              Seite für „IP prüfen“
              <input className="mono" value={v.lookupUrl ?? ""} placeholder="https://ipinfo.io/{ip}" onChange={(e) => upd({ lookupUrl: e.target.value })} />
              <span className="hint">
                {"{ip}"} wird durch die Adresse ersetzt. Vorlagen:{" "}
                {LOOKUP_PRESETS.map((p, i) => (
                  <span key={p.url}>
                    {i > 0 && " · "}
                    <button type="button" className="link-btn" onClick={() => upd({ lookupUrl: p.url })}>
                      {p.label}
                    </button>
                  </span>
                ))}
              </span>
            </label>
            <h3 style={{ margin: "8px 0 0", fontSize: 14 }}>Tokens im Log</h3>
            <label className="field">
              Weitere Parameter kürzen (einer pro Zeile)
              <textarea
                className="mono"
                rows={2}
                value={redactText ?? (v.redactParams ?? []).join("\n")}
                placeholder="z. B. hash oder ticket"
                onChange={(e) => {
                  setRedactText(e.target.value);
                  upd({ redactParams: e.target.value.split(/\s+/).filter(Boolean) });
                }}
              />
              <span className="hint">
                Immer gekürzt: token, access_token, api_key, apikey, key, secret, password, pass, auth, sig, signature, code, session sowie die Header X-Api-Key, X-Auth-Token
                und Proxy-Authorization. Im Log stehen nur die ersten vier Zeichen.
              </span>
            </label>
            <ErrorBox error={err} />
            <button className="btn primary" style={{ alignSelf: "flex-start" }} disabled={!draft || saving} onClick={save}>
              {saving && <Spinner />} Speichern & anwenden
            </button>
          </>
        )}
      </div>
      <div className="card">
        <h2>Dateien</h2>
        <p className="small muted" style={{ marginTop: 0 }}>
          <span className="mono">{data.data?.path}</span> · zusammen {fmtBytes(data.data?.totalBytes ?? 0)}
        </p>
        <ul className="list-plain">
          {(data.data?.files ?? []).map((f) => (
            <li key={f.name} className="row">
              {f.compressed && <IconFileZip size={16} className="muted" />}
              <span className="mono small">{f.name}</span>
              {f.current && <Badge kind="ok">aktuell</Badge>}
              <span className="spacer" />
              <span className="small muted">
                {fmtBytes(f.size)} · {fmtTime(f.modTime)}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
