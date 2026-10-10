import { useEffect, useMemo, useState } from "react";
import {
  AnalyticsRange,
  AnalyticsResponse,
  api,
  fmtBytes,
  fmtMs,
  fmtNum,
  RecentRequest,
  SitesResponse,
} from "../api";
import { Chart, Series, TopList } from "../components/charts";
import { ErrorBox, PageHead, Spinner, useLoad } from "../components/ui";
import { IconRefresh } from "@tabler/icons-react";

const RANGES: AnalyticsRange[] = ["15m", "1h", "6h", "24h", "7d", "30d"];

const STATUS_SERIES: Series[] = [
  { key: "s2xx", label: "2xx", color: "var(--c-2xx)" },
  { key: "s3xx", label: "3xx", color: "var(--c-3xx)" },
  { key: "s4xx", label: "4xx", color: "var(--c-4xx)" },
  { key: "s5xx", label: "5xx", color: "var(--c-5xx)" },
];
const LAT_SERIES: Series[] = [
  { key: "avgMs", label: "Ø ms", color: "var(--c-avg)" },
  { key: "p95Ms", label: "p95 ms", color: "var(--c-p95)" },
];
const BLOCK_SERIES: Series[] = [{ key: "blocked", label: "Geblockt", color: "var(--c-blocked)" }];

export function statusKind(s: number): "ok" | "info" | "warn" | "err" {
  if (s >= 500) return "err";
  if (s >= 400) return "warn";
  if (s >= 300) return "info";
  return "ok";
}

export default function Analytics() {
  const [range, setRange] = useState<AnalyticsRange>("24h");
  const [site, setSite] = useState("");
  const sites = useLoad(() => api.get<SitesResponse>("/api/sites"));
  const q = `range=${range}${site ? `&site=${encodeURIComponent(site)}` : ""}`;
  const data = useLoad(() => api.get<AnalyticsResponse>(`/api/analytics?${q}`), [q]);
  const recent = useLoad(
    () => api.get<{ requests: RecentRequest[] | null }>(`/api/analytics/recent?limit=50${site ? `&site=${encodeURIComponent(site)}` : ""}`),
    [site],
  );

  useEffect(() => {
    const every = range === "15m" || range === "1h" ? 10000 : 30000;
    const t = setInterval(() => {
      data.reload();
      recent.reload();
    }, every);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q]);

  const rep = data.data?.report;
  const rows = useMemo(
    () =>
      (rep?.series ?? []).map((p) => ({
        t: new Date(p.t).getTime(),
        s2xx: p.s2xx,
        s3xx: p.s3xx,
        s4xx: p.s4xx,
        s5xx: p.s5xx,
        blocked: p.blocked,
        avgMs: p.avgMs,
        p95Ms: p.p95Ms,
        requests: p.requests,
      })),
    [rep],
  );
  const hourly = rep?.step === "1h";
  const fmtTime = (t: number) => {
    const d = new Date(t);
    if (hourly && (range === "7d" || range === "30d"))
      return d.toLocaleDateString("de-DE", { day: "2-digit", month: "2-digit" }) + (range === "7d" ? ` ${d.getHours()}h` : "");
    return d.toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });
  };

  const tot = rep?.totals;
  const errRate = tot && tot.requests > 0 ? ((tot.s4xx + tot.s5xx) / tot.requests) * 100 : 0;
  const top = rep?.top ?? {};
  const empty = !!rep && (tot?.requests ?? 0) === 0;

  return (
    <>
      <PageHead title="Analytics" sub="Traffic aller Sites aus Caddys Access-Log">
        <select value={site} onChange={(e) => setSite(e.target.value)} style={{ width: "auto" }}>
          <option value="">Alle Sites</option>
          {(sites.data?.sites ?? []).map((s) => (
            <option key={s.id} value={s.id}>
              {s.id} ({s.domains.join(", ")})
            </option>
          ))}
        </select>
        <div className="seg">
          {RANGES.map((r) => (
            <button key={r} className={`seg-btn ${r === range ? "active" : ""}`} onClick={() => setRange(r)}>
              {r}
            </button>
          ))}
        </div>
        <button className="btn" onClick={() => (data.reload(), recent.reload())} disabled={data.loading}>
          {data.loading ? <Spinner /> : <IconRefresh size={16} />}
        </button>
      </PageHead>
      <ErrorBox error={data.error} />
      {!rep && data.loading && (
        <div className="empty">
          <Spinner />
        </div>
      )}
      {rep && (
        <div className="stack">
          <div className="grid kpi-grid">
            <Kpi label="Anfragen" value={fmtNum(tot?.requests)} />
            <Kpi label="Fehlerquote" value={tot && tot.requests > 0 ? `${errRate.toFixed(1)} %` : "–"} tone={errRate > 5 ? "err" : undefined} />
            <Kpi label="Geblockt" value={fmtNum(tot?.blocked)} tone={(tot?.blocked ?? 0) > 0 ? "warn" : undefined} />
            <Kpi label="Datenmenge" value={fmtBytes(tot?.bytes)} />
            <Kpi label="Ø Antwortzeit" value={fmtMs(tot?.avgMs)} />
            <Kpi label="p95" value={fmtMs(tot?.p95Ms)} />
          </div>

          {empty ? (
            <div className="card empty">
              <p style={{ marginTop: 0 }}>
                <b>Noch kein Traffic im gewählten Zeitraum.</b>
              </p>
              <p className="small muted" style={{ marginBottom: 0 }}>
                Jede Site schreibt automatisch ein JSON-Access-Log nach <code>{data.data?.accessLog}</code>. caddyforge liest es mit –
                sobald Anfragen eingehen, erscheinen sie hier.
              </p>
            </div>
          ) : (
            <>
              <div className="card">
                <h2>Anfragen nach Status ({rep.step === "1m" ? "pro Minute" : "pro Stunde"})</h2>
                <Chart rows={rows} series={STATUS_SERIES} stacked fmtTime={fmtTime} height={220} />
              </div>
              <div className="grid grid-2">
                <div className="card">
                  <h2>Antwortzeit</h2>
                  <Chart rows={rows} series={LAT_SERIES} kind="line" fmtTime={fmtTime} fmt={(v) => `${Math.round(v)}`} height={170} />
                </div>
                <div className="card">
                  <h2>Geblockt (403/429)</h2>
                  <Chart rows={rows} series={BLOCK_SERIES} fmtTime={fmtTime} height={170} />
                </div>
              </div>
              <div className="grid grid-3">
                <TopList title="Pfade" entries={top.paths ?? []} mono />
                <TopList title="IPs" entries={top.ips ?? []} mono />
                <TopList title="Status-Codes" entries={top.status ?? []} />
                <TopList title="User-Agents" entries={top.agents ?? []} />
                <TopList title="Referer" entries={top.referers ?? []} />
                <TopList title="Hosts" entries={rep.hosts ?? []} />
              </div>
            </>
          )}

          <div className="card">
            <div className="row">
              <h2 style={{ margin: 0 }}>Live – letzte Anfragen</h2>
              <span className="spacer" />
              {recent.loading && <Spinner />}
            </div>
            <ErrorBox error={recent.error} />
            {(recent.data?.requests ?? []).length === 0 ? (
              <div className="small muted" style={{ marginTop: 8 }}>
                Noch keine Anfragen.
              </div>
            ) : (
              <div className="table-wrap" style={{ marginTop: 8 }}>
                <table className="compact">
                  <thead>
                    <tr>
                      <th>Zeit</th>
                      <th>Status</th>
                      <th>Host</th>
                      <th>Anfrage</th>
                      <th>IP</th>
                      <th>Dauer</th>
                      <th>Größe</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(recent.data?.requests ?? []).map((r, i) => (
                      <tr key={r.ts + i}>
                        <td className="small muted" style={{ whiteSpace: "nowrap" }}>
                          {new Date(r.ts).toLocaleTimeString("de-DE")}
                        </td>
                        <td>
                          <span className={`badge ${statusKind(r.status)}`}>{r.status}</span>
                        </td>
                        <td className="small">{r.host}</td>
                        <td className="mono small" style={{ wordBreak: "break-all" }} title={r.agent}>
                          <b>{r.method}</b> {r.uri}
                        </td>
                        <td className="mono small">{r.ip}</td>
                        <td className="small" style={{ whiteSpace: "nowrap" }}>
                          {fmtMs(r.durationMs)}
                        </td>
                        <td className="small" style={{ whiteSpace: "nowrap" }}>
                          {fmtBytes(r.size)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}

function Kpi({ label, value, tone }: { label: string; value: string; tone?: "warn" | "err" }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value" style={tone ? { color: `var(--${tone === "err" ? "danger" : "warn"})` } : undefined}>
        {value}
      </div>
    </div>
  );
}
