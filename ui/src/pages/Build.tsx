import { useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  ApiError,
  Build as BuildT,
  BuildsResponse,
  errMsg,
  fmtBytes,
  fmtDuration,
  fmtTime,
  ModuleCheck,
  PluginsResponse,
  PluginState,
  Toolchain,
  Versions,
} from "../api";
import { Badge, ConfirmButton, ErrorBox, PageHead, Spinner, useAction, useLoad, useToast } from "../components/ui";
import { IconArrowBackUp, IconX } from "@tabler/icons-react";
import PluginSettings from "./PluginSettings";
import { PluginLink } from "../components/plugins";

const CATEGORY_LABEL: Record<string, string> = {
  dns: "DNS-Anbieter (DNS-01-Zertifikate)",
  security: "Sicherheit – WAF, Bots, CrowdSec, Geo, Rate Limit",
  auth: "Login & SSO",
  storage: "Zertifikatsspeicher",
  infra: "Netzwerk, Kompression, Cache & mehr",
  cert: "Zertifikate",
  observability: "Monitoring",
  unclassified: "Sonstiges",
};

const RUNNING: BuildT["status"][] = ["queued", "preparing", "building", "verifying"];

export default function Build() {
  type Tab = "plugins" | "build" | "history";
  const [tab, setTabState] = useState<Tab>(() => {
    const h = window.location.hash.slice(1);
    return h === "build" || h === "history" ? h : "plugins";
  });
  const setTab = (t: Tab) => {
    setTabState(t);
    history.replaceState(null, "", t === "plugins" ? window.location.pathname : "#" + t);
  };
  const plugins = useLoad(() => api.get<PluginsResponse>("/api/plugins"));
  const builds = useLoad(() => api.get<BuildsResponse>("/api/builds"));
  const toolchain = useLoad(() => api.get<Toolchain>("/api/build/toolchain"));
  const [watchId, setWatchId] = useState<string | null>(null);

  // Attach to a build that is already running when the page opens.
  useEffect(() => {
    if (builds.data?.runningId && !watchId) setWatchId(builds.data.runningId);
  }, [builds.data?.runningId, watchId]);

  const refreshAll = () => {
    builds.reload();
    toolchain.reload();
    plugins.reload();
  };

  return (
    <>
      <PageHead
        title="Plugins & Build"
        sub="Caddy-Plugins werden in die Binary kompiliert. Der Build läuft direkt auf diesem Server (Go + xcaddy)."
      >
        <ToolchainBadge tc={toolchain.data} />
      </PageHead>
      <div className="tabs" role="tablist">
        <button className={`tab ${tab === "plugins" ? "active" : ""}`} onClick={() => setTab("plugins")}>
          Plugins & Einstellungen
        </button>
        <button className={`tab ${tab === "build" ? "active" : ""}`} onClick={() => setTab("build")}>
          Neuer Build
        </button>
        <button className={`tab ${tab === "history" ? "active" : ""}`} onClick={() => setTab("history")}>
          Verlauf {builds.data?.builds?.length ? `(${builds.data.builds.length})` : ""}
        </button>
      </div>
      <ErrorBox error={plugins.error || builds.error} />

      {watchId && (
        <BuildMonitor
          id={watchId}
          onClose={() => setWatchId(null)}
          onFinished={() => {
            refreshAll();
          }}
        />
      )}

      {tab === "plugins" && plugins.data && (
        <PluginSettings plugins={plugins.data} builds={builds.data} onChange={refreshAll} onNewBuild={() => setTab("build")} />
      )}
      {tab === "build" && plugins.data && (
        <NewBuild
          plugins={plugins.data}
          busy={!!builds.data?.runningId}
          onStarted={(b) => {
            setWatchId(b.id);
            builds.reload();
          }}
        />
      )}
      {tab === "history" && <History data={builds.data} onChange={refreshAll} onWatch={(id) => setWatchId(id)} />}
    </>
  );
}

function ToolchainBadge({ tc }: { tc: Toolchain | null }) {
  if (!tc) return null;
  return (
    <span className="row small">
      <Badge kind={tc.go.installed ? "ok" : undefined}>Go {tc.go.installed ? tc.go.version : "wird beim 1. Build geladen"}</Badge>
      <Badge kind={tc.xcaddy.installed ? "ok" : undefined}>xcaddy {tc.xcaddy.installed ? (tc.xcaddy.version || "").split(" ")[0] : "fehlt noch"}</Badge>
      {tc.cacheBytes ? <Badge>Cache {fmtBytes(tc.cacheBytes)}</Badge> : null}
    </span>
  );
}

// ---------- New build ----------

function NewBuild({ plugins, busy, onStarted }: { plugins: PluginsResponse; busy: boolean; onStarted: (b: BuildT) => void }) {
  const versions = useLoad(() => api.get<Versions>("/api/build/versions"));
  const toast = useToast();
  const [selected, setSelected] = useState<Set<string>>(
    () => new Set(plugins.plugins.filter((p) => p.detected || p.active).map((p) => p.id)),
  );
  const [custom, setCustom] = useState<string[]>([]);
  const [customInput, setCustomInput] = useState("");
  const [checking, setChecking] = useState(false);
  const [checkMsg, setCheckMsg] = useState<{ kind: "ok" | "err" | "warn"; text: string } | null>(null);
  const [version, setVersion] = useState("latest");
  const [starting, setStarting] = useState(false);
  const [startErr, setStartErr] = useState<unknown>(null);
  const [filter, setFilter] = useState("");
  const [activate, setActivate] = useState(true);

  const byId = useMemo(() => new Map(plugins.plugins.map((p) => [p.id, p])), [plugins.plugins]);

  const groups = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const m = new Map<string, PluginState[]>();
    for (const p of plugins.plugins) {
      if (f && !`${p.name} ${p.module} ${p.id}`.toLowerCase().includes(f)) continue;
      const k = p.category || "unclassified";
      if (!m.has(k)) m.set(k, []);
      m.get(k)!.push(p);
    }
    const order = plugins.categories?.length ? plugins.categories : Array.from(m.keys());
    const keys = [...order.filter((k) => m.has(k)), ...Array.from(m.keys()).filter((k) => !order.includes(k))];
    return keys.map((k) => [k, m.get(k)!.sort((a, b) => a.name.localeCompare(b.name))] as const);
  }, [plugins, filter]);

  function conflictWith(p: PluginState): string | null {
    for (const c of p.conflicts ?? []) if (selected.has(c)) return byId.get(c)?.name ?? c;
    return null;
  }

  function toggle(p: PluginState) {
    setSelected((s) => {
      const n = new Set(s);
      if (n.has(p.id)) n.delete(p.id);
      else {
        n.add(p.id);
        for (const r of p.requires ?? []) n.add(r);
      }
      return n;
    });
  }

  async function addCustom() {
    const raw = customInput.trim();
    if (!raw) return;
    setChecking(true);
    setCheckMsg(null);
    try {
      const r = await api.post<ModuleCheck>("/api/plugins/check", { module: raw });
      if (!r.exists) {
        setCheckMsg({ kind: "err", text: r.hint || "Modul nicht im Go-Proxy gefunden." });
        return;
      }
      const known = plugins.plugins.find((p) => p.module === r.cleanPath);
      if (known) {
        setSelected((s) => new Set(s).add(known.id));
        setCheckMsg({ kind: "ok", text: `${known.name} ist im Katalog – dort ausgewählt.` });
      } else {
        const entry = r.cleanPath + (r.version ? "@" + r.version : "");
        setCustom((c) => (c.includes(entry) ? c : [...c, entry]));
        setCheckMsg({ kind: r.warning ? "warn" : "ok", text: r.warning || `${entry} hinzugefügt.` });
      }
      setCustomInput("");
    } catch (e) {
      const hint = e instanceof ApiError && e.details.length ? ` – ${e.details.join(" ")}` : "";
      setCheckMsg({ kind: "err", text: errMsg(e) + hint });
    } finally {
      setChecking(false);
    }
  }

  async function start() {
    setStarting(true);
    setStartErr(null);
    try {
      const r = await api.post<{ build: BuildT }>("/api/builds", {
        caddyVersion: version,
        plugins: [...Array.from(selected), ...custom],
        activate,
      });
      toast("info", "Build gestartet");
      onStarted(r.build);
    } catch (e) {
      setStartErr(e);
    } finally {
      setStarting(false);
    }
  }

  const count = selected.size + custom.length;
  const v = versions.data;

  return (
    <div className="grid" style={{ gridTemplateColumns: "minmax(0, 1fr) minmax(260px, 320px)", alignItems: "start" }}>
      <div className="stack">
        <div className="card">
          <div className="row" style={{ marginBottom: 12 }}>
            <h2 style={{ margin: 0 }}>Plugin-Katalog</h2>
            <span className="spacer" />
            <input placeholder="Suchen…" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ maxWidth: 220 }} />
          </div>
          {groups.map(([cat, items]) => (
            <div key={cat}>
              <h3>{CATEGORY_LABEL[cat] ?? cat}</h3>
              <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(250px, 1fr))", gap: 8 }}>
                {items.map((p) => {
                  const conflict = !selected.has(p.id) ? conflictWith(p) : null;
                  const on = selected.has(p.id);
                  return (
                    <label key={p.id} className={`plugin ${on ? "selected" : ""} ${conflict ? "disabled" : ""}`} title={p.note || p.module}>
                      <input type="checkbox" checked={on} disabled={!!conflict} onChange={() => toggle(p)} />
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div className="row" style={{ gap: 6 }}>
                          <span className="name">{p.name}</span>
                          {p.detected && <Badge kind="ok">eingebaut</Badge>}
                          {p.recommended && <Badge kind="ok">empfohlen</Badge>}
                          {p.deprecated && <Badge kind="warn">veraltet</Badge>}
                        </div>
                        <div className="mod">{p.module}</div>
                        {conflict && <div className="small" style={{ color: "var(--warn)" }}>Konflikt mit {conflict}</div>}
                        {p.licenseRisk && on && <div className="small" style={{ color: "var(--warn)" }}>{p.licenseRisk}</div>}
                      </div>
                      <PluginLink plugin={p} size={15} />
                    </label>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        <div className="card">
          <h2>Eigenes Modul</h2>
          <p className="small muted" style={{ marginTop: 0 }}>
            Beliebiger Go-Modulpfad, optional mit Version, z. B. <code>github.com/mholt/caddy-ratelimit</code> oder{" "}
            <code>github.com/foo/bar@v1.2.3</code>. Wird gegen proxy.golang.org geprüft.
          </p>
          <div className="row">
            <input
              value={customInput}
              placeholder="github.com/…"
              onChange={(e) => setCustomInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addCustom()}
              style={{ flex: 1, minWidth: 200 }}
            />
            <button className="btn" onClick={addCustom} disabled={checking || !customInput.trim()}>
              {checking && <Spinner />} Prüfen & hinzufügen
            </button>
          </div>
          {checkMsg && (
            <div className={`alert ${checkMsg.kind}`} style={{ marginTop: 10 }}>
              {checkMsg.text}
            </div>
          )}
          {custom.length > 0 && (
            <div className="chips" style={{ marginTop: 12 }}>
              {custom.map((c) => (
                <span key={c} className="badge info">
                  <span className="mono">{c}</span>
                  <button className="btn ghost sm" style={{ padding: "0 2px" }} onClick={() => setCustom((x) => x.filter((y) => y !== c))} aria-label="entfernen">
                    <IconX size={14} />
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="card stack" style={{ position: "sticky", top: 16 }}>
        <h2 style={{ margin: 0 }}>Build starten</h2>
        <label className="field">
          Caddy-Version
          <select value={version} onChange={(e) => setVersion(e.target.value)}>
            <option value="latest">Neueste{v?.latest ? ` (${v.latest})` : ""}</option>
            {(v?.recent ?? [])
              .filter((r) => r !== v?.latest)
              .map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
          </select>
          {v?.installed && <span className="hint">Installiert: v{v.installed.replace(/^v/, "")}</span>}
        </label>
        <div>
          <div className="small muted" style={{ marginBottom: 6 }}>
            {count} Plugin{count === 1 ? "" : "s"} ausgewählt
          </div>
          <div className="chips">
            {Array.from(selected).map((id) => (
              <Badge key={id} kind="ok">
                {byId.get(id)?.name ?? id}
              </Badge>
            ))}
            {custom.map((c) => (
              <Badge key={c} kind="info">
                {c.split("/").slice(-1)[0]}
              </Badge>
            ))}
            {count === 0 && <span className="small muted">Keine – ergibt Standard-Caddy.</span>}
          </div>
        </div>
        <ErrorBox error={startErr} />
        <button className="btn primary" onClick={start} disabled={starting || busy}>
          {starting && <Spinner />} {busy ? "Build läuft bereits" : "Build starten"}
        </button>
        <label className="check small">
          <input type="checkbox" checked={activate} onChange={(e) => setActivate(e.target.checked)} /> Nach erfolgreichem Build sofort aktivieren
        </label>
        <p className="small muted" style={{ margin: 0 }}>
          Der erste Build lädt Go und xcaddy und dauert einige Minuten.{" "}
          {activate
            ? "Danach tauscht caddyEvolved die Binary und startet Caddy neu – schlägt das fehl, bleibt die alte."
            : "Die neue Binary wird erst nach „Aktivieren“ verwendet."}
        </p>
      </div>
    </div>
  );
}

// ---------- Live monitor ----------

function statusBadge(b: BuildT) {
  switch (b.status) {
    case "succeeded":
      return <Badge kind="ok">erfolgreich</Badge>;
    case "failed":
      return <Badge kind="err">fehlgeschlagen</Badge>;
    case "cancelled":
      return <Badge kind="warn">abgebrochen</Badge>;
    default:
      return (
        <Badge kind="info">
          <Spinner /> {b.stage || b.status}
        </Badge>
      );
  }
}

function BuildMonitor({ id, onClose, onFinished }: { id: string; onClose: () => void; onFinished: () => void }) {
  const [build, setBuild] = useState<BuildT | null>(null);
  const [log, setLog] = useState<string[]>([]);
  const [err, setErr] = useState<unknown>(null);
  const [follow, setFollow] = useState(true);
  const logRef = useRef<HTMLPreElement>(null);
  const { busy, run } = useAction();
  const finishedRef = useRef(onFinished);
  finishedRef.current = onFinished;

  useEffect(() => {
    let es: EventSource | null = null;
    let closed = false;
    (async () => {
      try {
        const r = await api.get<{ build: BuildT; log: string[] | null }>(`/api/builds/${encodeURIComponent(id)}`);
        if (closed) return;
        setBuild(r.build);
        setLog(r.log ?? []);
        if (!RUNNING.includes(r.build.status)) return;
      } catch (e) {
        setErr(e);
        return;
      }
      // The snapshot already holds the log so far; the stream may replay it,
      // so replace the buffer on the first streamed line.
      let fresh = true;
      es = new EventSource(`/api/builds/${encodeURIComponent(id)}/stream`);
      es.addEventListener("line", (ev) => {
        const line = (ev as MessageEvent).data as string;
        setLog((l) => {
          if (fresh) {
            fresh = false;
            return [line];
          }
          const next = l.length > 5000 ? l.slice(-4000) : l.slice();
          next.push(line);
          return next;
        });
      });
      es.addEventListener("status", (ev) => {
        try {
          setBuild(JSON.parse((ev as MessageEvent).data));
        } catch {
          /* ignore */
        }
      });
      es.addEventListener("done", (ev) => {
        try {
          setBuild(JSON.parse((ev as MessageEvent).data));
        } catch {
          /* ignore */
        }
        es?.close();
        finishedRef.current();
      });
      es.onerror = () => {
        // The browser retries automatically; once the build is over the
        // server closes the stream, so stop retrying after a final refresh.
        api
          .get<{ build: BuildT; log: string[] | null }>(`/api/builds/${encodeURIComponent(id)}`)
          .then((r) => {
            setBuild(r.build);
            if (!RUNNING.includes(r.build.status)) {
              setLog(r.log ?? []);
              es?.close();
              finishedRef.current();
            }
          })
          .catch(() => {});
      };
    })();
    return () => {
      closed = true;
      es?.close();
    };
  }, [id]);

  useEffect(() => {
    if (follow && logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log, follow]);

  const running = build ? RUNNING.includes(build.status) : true;

  async function activate() {
    const r = await run("activate", () => api.post<{ build: BuildT; caddyVersion: string }>(`/api/builds/${encodeURIComponent(id)}/activate`), "Neue Caddy-Binary ist aktiv");
    if (r) {
      setBuild(r.build);
      onFinished();
    }
  }

  return (
    <div className="card stack" style={{ marginBottom: 16 }}>
      <div className="row">
        <h2 style={{ margin: 0 }}>Build {id}</h2>
        {build && statusBadge(build)}
        {build?.caddyVersion && <Badge>{build.caddyVersion}</Badge>}
        <span className="spacer" />
        <label className="check small">
          <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} /> mitscrollen
        </label>
        {running && (
          <button className="btn danger sm" disabled={busy === "cancel"} onClick={() => run("cancel", () => api.post(`/api/builds/${encodeURIComponent(id)}/cancel`), "Abbruch angefordert")}>
            Abbrechen
          </button>
        )}
        {build?.status === "succeeded" && !build.active && (
          <button className="btn primary sm" disabled={busy === "activate"} onClick={activate}>
            {busy === "activate" && <Spinner />} Aktivieren
          </button>
        )}
        {build?.active && <Badge kind="ok">aktiv</Badge>}
        {!running && (
          <button className="btn sm" onClick={onClose}>
            Schließen
          </button>
        )}
      </div>
      <ErrorBox error={err} />
      {build?.error && <div className="alert err">{build.error}</div>}
      {build?.status === "succeeded" && (
        <div className="small muted">
          {fmtBytes(build.size)} · {fmtDuration(build.durationSec)} · <span className="mono">sha256 {build.sha256?.slice(0, 16)}…</span>
          {build.detectedModules && build.detectedModules.length > 0 && <> · Module: {build.detectedModules.join(", ")}</>}
        </div>
      )}
      <pre ref={logRef} className="code log">
        {log.length ? log.join("\n") : running ? "Warte auf Ausgabe…" : "Kein Log."}
      </pre>
      {busy === "activate" && <div className="alert info">Binary wird getauscht, Caddy neu gestartet und geprüft…</div>}
    </div>
  );
}

// ---------- History ----------

function History({ data, onChange, onWatch }: { data: BuildsResponse | null; onChange: () => void; onWatch: (id: string) => void }) {
  const { busy, run } = useAction();
  const list = data?.builds ?? [];

  return (
    <div className="card">
      <div className="row" style={{ marginBottom: 12 }}>
        <h2 style={{ margin: 0 }}>Build-Verlauf</h2>
        <span className="spacer" />
        {data?.previousAvailable && (
          <ConfirmButton
            className="btn sm"
            confirmText="Vorherige Binary wiederherstellen?"
            disabled={busy === "rollback"}
            onConfirm={async () => {
              await run("rollback", () => api.post("/api/builds/rollback"), "Vorherige Binary wiederhergestellt");
              onChange();
            }}
          >
            <IconArrowBackUp size={16} /> Rollback
          </ConfirmButton>
        )}
      </div>
      {list.length === 0 ? (
        <div className="empty">Noch keine Builds.</div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Build</th>
                <th>Status</th>
                <th>Plugins</th>
                <th>Größe / Dauer</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {list.map((b) => (
                <tr key={b.id}>
                  <td>
                    <div className="mono small">{b.id}</div>
                    <div className="small muted">
                      {b.caddyVersion} · {fmtTime(b.createdAt)}
                    </div>
                  </td>
                  <td>
                    <div className="row" style={{ gap: 4 }}>
                      {statusBadge(b)}
                      {b.active && <Badge kind="ok">aktiv</Badge>}
                    </div>
                    {b.error && (
                      <div className="small" style={{ color: "var(--danger)", maxWidth: 280 }}>
                        {b.error}
                      </div>
                    )}
                  </td>
                  <td>
                    <div className="chips">
                      {(b.plugins ?? []).map((p) => (
                        <Badge key={p}>{p.split("/").slice(-1)[0]}</Badge>
                      ))}
                      {(b.plugins ?? []).length === 0 && <span className="small muted">keine</span>}
                    </div>
                  </td>
                  <td className="small">
                    {fmtBytes(b.size)}
                    <div className="muted">{fmtDuration(b.durationSec)}</div>
                  </td>
                  <td style={{ whiteSpace: "nowrap", textAlign: "right" }}>
                    <span className="row" style={{ justifyContent: "flex-end" }}>
                      <button className="btn sm" onClick={() => onWatch(b.id)}>
                        Log
                      </button>
                      {b.status === "succeeded" && !b.active && (
                        <button
                          className="btn primary sm"
                          disabled={!!busy}
                          onClick={async () => {
                            await run("act-" + b.id, () => api.post(`/api/builds/${encodeURIComponent(b.id)}/activate`), "Neue Caddy-Binary ist aktiv");
                            onChange();
                          }}
                        >
                          {busy === "act-" + b.id && <Spinner />} Aktivieren
                        </button>
                      )}
                      {!b.active && !RUNNING.includes(b.status) && (
                        <ConfirmButton
                          disabled={!!busy}
                          confirmText="Löschen?"
                          onConfirm={async () => {
                            await run("del-" + b.id, () => api.del(`/api/builds/${encodeURIComponent(b.id)}`), "Build gelöscht");
                            onChange();
                          }}
                        >
                          Löschen
                        </ConfirmButton>
                      )}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
