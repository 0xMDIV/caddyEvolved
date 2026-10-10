import { useRef, useState } from "react";
import { api, errMsg, Site } from "../api";
import { navigate } from "../router";
import { Badge, CopyBlock, ErrorBox, PageHead, Spinner } from "../components/ui";

// ---------- Types (docs/API.md "Import") ----------

type Format = "caddyfile" | "zoraxy" | "traefik" | "npm";

interface ImportFile {
  name: string;
  content: string; // base64
  size: number;
}

/** An access list as the importer proposes it; users may carry bcrypt hashes. */
interface ImportACL {
  id: string;
  name: string;
  allow?: string[] | null;
  deny?: string[] | null;
  allowCountries?: string[] | null;
  denyCountries?: string[] | null;
  geoDb?: string;
  users?: { username: string; hash: string }[] | null;
}

interface SiteCandidate {
  site: Site;
  source: string;
  warnings: string[] | null;
  problems: string[] | null;
}

interface ACLCandidate {
  accessList: ImportACL;
  source: string;
  warnings: string[] | null;
}

interface PreviewResponse {
  format: string;
  sites: SiteCandidate[] | null;
  accessLists: ACLCandidate[] | null;
  warnings: string[] | null;
}

interface ApplyResult {
  kind: "site" | "accessList";
  id: string;
  ok: boolean;
  error?: string;
  details?: string[] | null;
}

interface ApplyResponse {
  imported: number;
  results: ApplyResult[] | null;
}

// ---------- Format descriptions ----------

const FORMATS: { id: Format; title: string; line: string; text: boolean }[] = [
  { id: "caddyfile", title: "Caddyfile", line: "Bestehende Caddy-Konfiguration – einfache Proxys werden strukturiert, der Rest als Raw-Site.", text: true },
  { id: "zoraxy", title: "Zoraxy", line: "Proxy-Regeln, Access Rules und Weiterleitungen aus Zoraxy.", text: false },
  { id: "traefik", title: "Traefik", line: "Dynamische Datei-Konfiguration oder Docker-Labels (Traefik v2/v3).", text: true },
  { id: "npm", title: "Nginx Proxy Manager", line: "Proxy- und Redirect-Hosts samt Access Lists als JSON-Export.", text: true },
];

const NPM_CURL = `# Token holen (E-Mail/Passwort des NPM-Admins)
TOKEN=$(curl -s http://NPM-HOST:81/api/tokens -H 'Content-Type: application/json' \\
  -d '{"identity":"admin@example.com","secret":"PASSWORT"}' | sed -E 's/.*"token":"([^"]+)".*/\\1/')
curl -s -H "Authorization: Bearer $TOKEN" \\
  "http://NPM-HOST:81/api/nginx/proxy-hosts?expand=access_list" > proxy-hosts.json
curl -s -H "Authorization: Bearer $TOKEN" \\
  "http://NPM-HOST:81/api/nginx/redirection-hosts" > redirection-hosts.json`;

const NPM_SQLITE = `sqlite3 -json /data/database.sqlite \\
  "select * from proxy_host where is_deleted=0" > proxy-hosts.json`;

function Instructions({ format }: { format: Format }) {
  switch (format) {
    case "caddyfile":
      return (
        <ul className="list-plain small">
          <li>Ein oder mehrere Caddyfiles hochladen oder den Inhalt unten einfügen.</li>
          <li>Globale Optionen und Snippets werden nicht übernommen, sondern als Hinweis gemeldet.</li>
        </ul>
      );
    case "zoraxy":
      return (
        <ul className="list-plain small">
          <li>
            Am einfachsten: das <b>Backup-ZIP</b> aus Zoraxy (Einstellungen → Backup &amp; Restore → Export).
          </li>
          <li>
            Alternativ einzelne Dateien aus <code>conf/proxy/*.config</code>, <code>conf/access/*.json</code> und <code>conf/redirect/*.json</code>.
          </li>
          <li>Basic-Auth-Passwörter lassen sich nicht übertragen – Benutzer danach neu setzen.</li>
        </ul>
      );
    case "traefik":
      return (
        <ul className="list-plain small">
          <li>
            Dynamische Konfiguration als <code>.yml</code>/<code>.yaml</code>/<code>.toml</code> (Bereich <code>http.routers</code>, <code>services</code>, <code>middlewares</code>).
          </li>
          <li>
            Oder eine <code>docker-compose.yml</code> mit <code>traefik.*</code>-Labels – Container-Namen danach durch IP:Port ersetzen.
          </li>
          <li>basicAuth-Benutzer mit bcrypt-Hash werden übernommen, apr1/sha1 nicht.</li>
        </ul>
      );
    case "npm":
      return (
        <div className="stack small">
          <div>Variante A – über die NPM-API (Proxy- und Redirect-Hosts inkl. Access Lists):</div>
          <CopyBlock text={NPM_CURL} />
          <div>Variante B – direkt aus der Datenbank im NPM-Container:</div>
          <CopyBlock text={NPM_SQLITE} />
          <div className="muted">Die entstandenen .json-Dateien hier hochladen. Passwörter aus Access Lists gibt NPM nicht heraus.</div>
        </div>
      );
  }
}

// ---------- Helpers ----------

function readAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => {
      const s = String(r.result);
      resolve(s.slice(s.indexOf(",") + 1)); // strip "data:...;base64,"
    };
    r.onerror = () => reject(r.error);
    r.readAsDataURL(file);
  });
}

function textToBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

function list<T>(v?: T[] | null): T[] {
  return v ?? [];
}
const splitList = (s: string) =>
  s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);

function siteTarget(s: Site): string {
  switch (s.mode) {
    case "proxy":
      return list(s.upstreams).join(", ") || "–";
    case "redirect":
      return "→ " + (s.redirectTo || "–");
    case "static":
      return s.root || "–";
    default:
      return "Raw";
  }
}

const TLS_LABEL: Record<string, string> = { auto: "automatisch", internal: "intern", dns: "DNS", off: "aus (HTTP)" };

// ---------- Page ----------

type Step = 1 | 2 | 3;

interface Row {
  cand: SiteCandidate;
  site: Site;
  selected: boolean;
  open: boolean;
  preview?: string;
  previewErr?: string;
}

interface ACLRow {
  cand: ACLCandidate;
  selected: boolean;
}

export default function Import() {
  const [step, setStep] = useState<Step>(1);
  const [format, setFormat] = useState<Format>("caddyfile");
  const [files, setFiles] = useState<ImportFile[]>([]);
  const [pasted, setPasted] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [globalWarnings, setGlobalWarnings] = useState<string[]>([]);
  const [rows, setRows] = useState<Row[]>([]);
  const [acls, setAcls] = useState<ACLRow[]>([]);
  const [results, setResults] = useState<ApplyResponse | null>(null);

  const fmt = FORMATS.find((f) => f.id === format)!;
  const hasInput = files.length > 0 || (fmt.text && pasted.trim() !== "");

  const runPreview = async () => {
    setBusy(true);
    setError(null);
    try {
      const payload = [...files.map((f) => ({ name: f.name, content: f.content }))];
      if (fmt.text && pasted.trim()) {
        const name = format === "caddyfile" ? "Caddyfile" : format === "npm" ? "eingefuegt.json" : "eingefuegt.yml";
        payload.push({ name, content: textToBase64(pasted) });
      }
      const res = await api.post<PreviewResponse>("/api/import/preview", { format, files: payload });
      setGlobalWarnings(list(res.warnings));
      setRows(
        list(res.sites).map((c: SiteCandidate) => ({
          cand: c,
          site: { ...c.site, domains: list(c.site.domains), upstreams: list(c.site.upstreams) },
          selected: list(c.problems).length === 0,
          open: false,
        })),
      );
      setAcls(list(res.accessLists).map((c: ACLCandidate) => ({ cand: c, selected: true })));
      setResults(null);
      setStep(2);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const runApply = async () => {
    setBusy(true);
    setError(null);
    try {
      const usedAcl = new Set(rows.filter((r) => r.selected && r.site.accessList).map((r) => r.site.accessList as string));
      const res = await api.post<ApplyResponse>("/api/import/apply", {
        accessLists: acls.filter((a) => a.selected || usedAcl.has(a.cand.accessList.id)).map((a) => a.cand.accessList),
        sites: rows.filter((r) => r.selected).map((r) => r.site),
      });
      setResults(res);
      setStep(3);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  const reset = () => {
    setStep(1);
    setFiles([]);
    setPasted("");
    setRows([]);
    setAcls([]);
    setResults(null);
    setError(null);
    setGlobalWarnings([]);
  };

  return (
    <>
      <PageHead title="Import" sub="Konfiguration aus Caddy, Zoraxy, Traefik oder Nginx Proxy Manager übernehmen. Die Vorschau schreibt nichts.">
        {step > 1 && (
          <button className="btn" onClick={reset} disabled={busy}>
            Neuer Import
          </button>
        )}
      </PageHead>

      <div className="import-steps">
        {(["Quelle", "Vorschau", "Übernehmen"] as const).map((label, i) => (
          <div key={label} className={`import-step ${step === i + 1 ? "active" : ""} ${step > i + 1 ? "done" : ""}`}>
            <span className="import-step-num">{step > i + 1 ? "✓" : i + 1}</span>
            {label}
          </div>
        ))}
      </div>

      <ErrorBox error={error} />

      {step === 1 && (
        <SourceStep
          format={format}
          setFormat={(f) => {
            setFormat(f);
            setError(null);
          }}
          files={files}
          setFiles={setFiles}
          pasted={pasted}
          setPasted={setPasted}
          textAllowed={fmt.text}
          busy={busy}
          canContinue={hasInput}
          onPreview={runPreview}
        />
      )}

      {step === 2 && (
        <PreviewStep
          warnings={globalWarnings}
          rows={rows}
          setRows={setRows}
          acls={acls}
          setAcls={setAcls}
          busy={busy}
          onBack={() => setStep(1)}
          onApply={runApply}
        />
      )}

      {step === 3 && results && <ResultStep results={results} onAgain={() => setStep(2)} />}
    </>
  );
}

// ---------- Step 1 ----------

function SourceStep(props: {
  format: Format;
  setFormat: (f: Format) => void;
  files: ImportFile[];
  setFiles: (f: ImportFile[]) => void;
  pasted: string;
  setPasted: (s: string) => void;
  textAllowed: boolean;
  busy: boolean;
  canContinue: boolean;
  onPreview: () => void;
}) {
  const { format, setFormat, files, setFiles, pasted, setPasted, textAllowed, busy, canContinue, onPreview } = props;
  const [drag, setDrag] = useState(false);
  const [readErr, setReadErr] = useState("");
  const input = useRef<HTMLInputElement>(null);

  const addFiles = async (list: FileList | null) => {
    if (!list || list.length === 0) return;
    setReadErr("");
    try {
      const added: ImportFile[] = [];
      for (const f of Array.from(list)) {
        added.push({ name: f.name, size: f.size, content: await readAsBase64(f) });
      }
      const names = new Set(added.map((a) => a.name));
      setFiles([...files.filter((f) => !names.has(f.name)), ...added]);
    } catch (e) {
      setReadErr("Datei nicht lesbar: " + errMsg(e));
    }
  };

  return (
    <div className="stack">
      <div className="grid grid-2 import-formats">
        {FORMATS.map((f) => (
          <button key={f.id} className={`card import-format ${format === f.id ? "active" : ""}`} onClick={() => setFormat(f.id)}>
            <div className="import-format-title">{f.title}</div>
            <div className="small muted">{f.line}</div>
          </button>
        ))}
      </div>

      <div className="card stack">
        <h3 style={{ margin: 0 }}>Was hochladen?</h3>
        <Instructions format={format} />

        <div
          className={`import-drop ${drag ? "drag" : ""}`}
          onDragOver={(e) => {
            e.preventDefault();
            setDrag(true);
          }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDrag(false);
            addFiles(e.dataTransfer.files);
          }}
          onClick={() => input.current?.click()}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
        >
          <div>Dateien hierher ziehen oder klicken</div>
          <div className="small muted">mehrere Dateien möglich{format === "zoraxy" ? " – auch ein ZIP" : ""}</div>
          <input
            ref={input}
            type="file"
            multiple
            hidden
            onChange={(e) => {
              addFiles(e.target.files);
              e.target.value = "";
            }}
          />
        </div>
        {readErr && <div className="alert err">{readErr}</div>}

        {files.length > 0 && (
          <div className="chips">
            {files.map((f) => (
              <span key={f.name} className="badge info">
                {f.name} <span className="muted">({Math.max(1, Math.round(f.size / 1024))} KB)</span>{" "}
                <button className="import-chip-x" aria-label={`${f.name} entfernen`} onClick={() => setFiles(files.filter((x) => x.name !== f.name))}>
                  ×
                </button>
              </span>
            ))}
          </div>
        )}

        {textAllowed && (
          <label className="field">
            <span>oder Inhalt einfügen</span>
            <textarea
              className="code"
              rows={10}
              spellCheck={false}
              value={pasted}
              onChange={(e) => setPasted(e.target.value)}
              placeholder={format === "caddyfile" ? "app.example.com {\n\treverse_proxy 10.0.0.5:8080\n}" : format === "npm" ? "[ {...} ]" : "http:\n  routers:\n    ..."}
            />
          </label>
        )}

        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button className="btn primary" disabled={!canContinue || busy} onClick={onPreview}>
            {busy && <Spinner />} Vorschau erstellen
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------- Step 2 ----------

function PreviewStep(props: {
  warnings: string[];
  rows: Row[];
  setRows: (r: Row[]) => void;
  acls: ACLRow[];
  setAcls: (a: ACLRow[]) => void;
  busy: boolean;
  onBack: () => void;
  onApply: () => void;
}) {
  const { warnings, rows, setRows, acls, setAcls, busy, onBack, onApply } = props;
  const update = (i: number, patch: Partial<Row>) => setRows(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const updateSite = (i: number, patch: Partial<Site>) => update(i, { site: { ...rows[i].site, ...patch }, preview: undefined, previewErr: undefined });

  const loadPreview = async (i: number) => {
    try {
      const res = await api.post<{ caddyfile: string; problems?: string[] | null }>("/api/sites/preview", rows[i].site);
      update(i, { open: true, preview: res.caddyfile, previewErr: list(res.problems).join("\n") || undefined });
    } catch (e) {
      update(i, { open: true, previewErr: errMsg(e) });
    }
  };

  const nSites = rows.filter((r) => r.selected).length;
  const nAcls = acls.filter((a) => a.selected).length;

  if (rows.length === 0 && acls.length === 0) {
    return (
      <div className="card stack">
        {warnings.length > 0 && <WarningList items={warnings} />}
        <div className="empty">Nichts gefunden, was übernommen werden könnte.</div>
        <div className="row">
          <button className="btn" onClick={onBack}>
            Zurück
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="stack">
      {warnings.length > 0 && (
        <div className="card stack">
          <h3 style={{ margin: 0 }}>Hinweise zum Import</h3>
          <WarningList items={warnings} />
        </div>
      )}

      {acls.length > 0 && (
        <div className="card stack">
          <h3 style={{ margin: 0 }}>Access Lists ({acls.length})</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th style={{ width: 32 }} />
                  <th>Name</th>
                  <th>Regeln</th>
                  <th>Herkunft</th>
                </tr>
              </thead>
              <tbody>
                {acls.map((a, i) => {
                  const acl = a.cand.accessList;
                  const rules = [
                    list(acl.allow).length && `erlaubt: ${list(acl.allow).join(", ")}`,
                    list(acl.deny).length && `gesperrt: ${list(acl.deny).join(", ")}`,
                    list(acl.allowCountries).length && `Länder erlaubt: ${list(acl.allowCountries).join(" ")}`,
                    list(acl.denyCountries).length && `Länder gesperrt: ${list(acl.denyCountries).join(" ")}`,
                    list(acl.users).length && `${list(acl.users).length} Benutzer`,
                  ].filter(Boolean) as string[];
                  return (
                    <tr key={i}>
                      <td>
                        <input
                          type="checkbox"
                          checked={a.selected}
                          aria-label={`Access List ${acl.name} übernehmen`}
                          onChange={(e) => setAcls(acls.map((x, j) => (j === i ? { ...x, selected: e.target.checked } : x)))}
                        />
                      </td>
                      <td>
                        <b>{acl.name}</b>
                        <div className="small muted mono">{acl.id}</div>
                      </td>
                      <td className="small">
                        {rules.map((r, k) => (
                          <div key={k}>{r}</div>
                        ))}
                        {list(a.cand.warnings).length > 0 && <WarningList items={list(a.cand.warnings)} />}
                      </td>
                      <td className="small muted">{a.cand.source}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="small muted">Access Lists, die eine ausgewählte Site benutzt, werden immer mit übernommen.</div>
        </div>
      )}

      <div className="card stack">
        <div className="row">
          <h3 style={{ margin: 0 }}>Sites ({rows.length})</h3>
          <span className="spacer" />
          <button className="btn sm" onClick={() => setRows(rows.map((r) => ({ ...r, selected: true })))}>
            Alle
          </button>
          <button className="btn sm" onClick={() => setRows(rows.map((r) => ({ ...r, selected: false })))}>
            Keine
          </button>
        </div>
        <div className="stack">
          {rows.map((r, i) => {
            const problems = list(r.cand.problems);
            const warns = list(r.cand.warnings);
            return (
              <div key={i} className={`import-row ${r.selected ? "" : "off"} ${problems.length ? "has-problems" : ""}`}>
                <div className="import-row-head">
                  <input type="checkbox" checked={r.selected} aria-label={`Site ${r.site.id} übernehmen`} onChange={(e) => update(i, { selected: e.target.checked })} />
                  <div className="import-row-main">
                    <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                      <b>{list(r.site.domains).join(", ") || <span className="muted">keine Domain</span>}</b>
                      <Badge kind="info">{r.site.mode}</Badge>
                      <Badge>TLS {TLS_LABEL[r.site.tls] ?? r.site.tls}</Badge>
                      {r.site.accessList && <Badge>ACL {r.site.accessList}</Badge>}
                      {!r.site.enabled && <Badge kind="warn">deaktiviert</Badge>}
                      {problems.length > 0 && <Badge kind="err">{problems.length} Problem(e)</Badge>}
                      {warns.length > 0 && <Badge kind="warn">{warns.length} Hinweis(e)</Badge>}
                    </div>
                    <div className="small muted">
                      {siteTarget(r.site)} · {r.cand.source}
                    </div>
                  </div>
                  <button className="btn sm" onClick={() => (r.open ? update(i, { open: false }) : loadPreview(i))}>
                    {r.open ? "Zuklappen" : "Details"}
                  </button>
                </div>

                {problems.length > 0 && (
                  <ul className="import-msgs err">
                    {problems.map((p, k) => (
                      <li key={k}>{p}</li>
                    ))}
                  </ul>
                )}
                {warns.length > 0 && <WarningList items={warns} />}

                {r.open && (
                  <div className="stack" style={{ marginTop: 8 }}>
                    <div className="form-grid">
                      <label className="field">
                        <span>ID</span>
                        <input value={r.site.id} onChange={(e) => updateSite(i, { id: e.target.value.toLowerCase() })} />
                      </label>
                      <label className="field">
                        <span>Domains (Komma-getrennt)</span>
                        <input value={list(r.site.domains).join(", ")} onChange={(e) => updateSite(i, { domains: splitList(e.target.value) })} />
                      </label>
                      {r.site.mode === "proxy" && (
                        <label className="field full">
                          <span>Ziele (Komma-getrennt)</span>
                          <input value={list(r.site.upstreams).join(", ")} onChange={(e) => updateSite(i, { upstreams: splitList(e.target.value) })} />
                        </label>
                      )}
                    </div>
                    <div className="row">
                      <span className="small muted">Gerenderter Caddyfile-Block</span>
                      <span className="spacer" />
                      <button className="btn sm" onClick={() => loadPreview(i)}>
                        Aktualisieren
                      </button>
                    </div>
                    {r.previewErr && <pre className="import-msgs err code">{r.previewErr}</pre>}
                    {r.preview && <pre className="code">{r.preview}</pre>}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <div className="row">
        <button className="btn" onClick={onBack} disabled={busy}>
          Zurück
        </button>
        <span className="spacer" />
        <span className="small muted">
          {nSites} Site(s), {nAcls} Access List(s) ausgewählt
        </span>
        <button className="btn primary" disabled={busy || (nSites === 0 && nAcls === 0)} onClick={onApply}>
          {busy && <Spinner />} Übernehmen
        </button>
      </div>
    </div>
  );
}

function WarningList({ items }: { items: string[] }) {
  return (
    <ul className="import-msgs warn">
      {items.map((w, k) => (
        <li key={k}>{w}</li>
      ))}
    </ul>
  );
}

// ---------- Step 3 ----------

function ResultStep({ results, onAgain }: { results: ApplyResponse; onAgain: () => void }) {
  const items = list(results.results);
  const failed = items.filter((r) => !r.ok).length;
  const sites = items.filter((r) => r.kind === "site").length;
  return (
    <div className="stack">
      <div className={`alert ${failed ? "warn" : "ok"}`}>
        {results.imported} von {sites} Site(s) übernommen{failed ? ` – ${failed} Eintrag/Einträge fehlgeschlagen` : ""}.
      </div>
      <div className="card">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Art</th>
                <th>ID</th>
                <th>Ergebnis</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r, i) => (
                <tr key={i}>
                  <td>{r.kind === "site" ? "Site" : "Access List"}</td>
                  <td className="mono">{r.id}</td>
                  <td>
                    {r.ok ? <Badge kind="ok">ok</Badge> : <Badge kind="err">Fehler</Badge>} {r.error && <span className="small">{r.error}</span>}
                    {list(r.details).length > 0 && <pre className="code small">{list(r.details).join("\n")}</pre>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div className="row">
        {failed > 0 && (
          <button className="btn" onClick={onAgain}>
            Zurück zur Vorschau
          </button>
        )}
        <span className="spacer" />
        <button className="btn primary" onClick={() => navigate("/sites")}>
          Zu den Sites
        </button>
      </div>
    </div>
  );
}

