import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { Chart, Series } from "../components/charts";
import { ErrorBox, PageHead, Spinner } from "../components/ui";
import { fmtBytes } from "./Logs";

interface Proc {
  pid: number;
  cpu: number;
  cpuHost: number;
  rss: number;
  threads: number;
  fds: number;
  readBps: number;
  writeBps: number;
  uptime: number;
}
interface Sample {
  t: string;
  cpu: number;
  cpus: number;
  load1: number;
  load5: number;
  load15: number;
  memTotal: number;
  memUsed: number;
  rxBps: number;
  txBps: number;
  uptime: number;
  caddy?: Proc;
  caddyevolved?: Proc;
  goHeap: number;
  goroutines: number;
}
interface SystemResp {
  current: Sample;
  history: Sample[] | null;
  disks: { path: string; total: number; free: number }[] | null;
  logBytes: number;
}

const CPU_SERIES: Series[] = [
  { key: "other", label: "Rest des Systems", color: "var(--c-grid)" },
  { key: "caddy", label: "Caddy", color: "var(--c-3xx)" },
  { key: "cev", label: "caddyEvolved", color: "var(--c-2xx)" },
];
const MEM_SERIES: Series[] = [
  { key: "other", label: "Rest des Systems", color: "var(--c-grid)" },
  { key: "caddy", label: "Caddy", color: "var(--c-3xx)" },
  { key: "cev", label: "caddyEvolved", color: "var(--c-2xx)" },
];
const NET_SERIES: Series[] = [
  { key: "rx", label: "Empfangen", color: "var(--c-2xx)" },
  { key: "tx", label: "Gesendet", color: "var(--c-3xx)" },
];

function fmtDur(s: number) {
  if (!s) return "–";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  return d > 0 ? `${d} T ${h} Std` : h > 0 ? `${h} Std ${m} Min` : `${m} Min`;
}
const pct = (v: number) => `${v.toFixed(1)} %`;
const rate = (v: number) => `${fmtBytes(Math.round(v))}/s`;

export default function System() {
  const [data, setData] = useState<SystemResp | null>(null);
  const [err, setErr] = useState<unknown>(null);
  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .get<SystemResp>("/api/system")
        .then((d) => alive && (setData(d), setErr(null)))
        .catch((e) => alive && setErr(e));
    load();
    const t = setInterval(load, 5000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  const rows = useMemo(
    () =>
      (data?.history ?? []).map((s) => {
        const caddy = s.caddy?.cpuHost ?? 0;
        const cev = s.caddyevolved?.cpuHost ?? 0;
        const caddyMem = s.caddy?.rss ?? 0;
        const cevMem = s.caddyevolved?.rss ?? 0;
        return {
          t: new Date(s.t).getTime(),
          caddy,
          cev,
          other: Math.max(0, s.cpu - caddy - cev),
          memCaddy: caddyMem,
          memCev: cevMem,
          memOther: Math.max(0, s.memUsed - caddyMem - cevMem),
          rx: s.rxBps,
          tx: s.txBps,
        };
      }),
    [data],
  );
  const memRows = useMemo(() => rows.map((r) => ({ t: r.t, caddy: r.memCaddy, cev: r.memCev, other: r.memOther })), [rows]);
  const fmtTime = (t: number) => new Date(t).toLocaleTimeString("de-DE", { hour: "2-digit", minute: "2-digit" });

  const c = data?.current;
  const ourCPU = (c?.caddy?.cpuHost ?? 0) + (c?.caddyevolved?.cpuHost ?? 0);
  const ourMem = (c?.caddy?.rss ?? 0) + (c?.caddyevolved?.rss ?? 0);
  const avg = (key: "caddy" | "cev") => (rows.length ? rows.reduce((a, r) => a + r[key], 0) / rows.length : 0);

  return (
    <>
      <PageHead title="System" sub="Wie stark Caddy und caddyEvolved den Server belasten – alle 5 Sekunden gemessen, die letzte Stunde." />
      <ErrorBox error={err} />
      {!c && !err && (
        <div className="empty">
          <Spinner />
        </div>
      )}
      {c && (
        <div className="stack">
          <div className="card impact">
            <div>
              <div className="small muted">Anteil von Caddy + caddyEvolved jetzt</div>
              <div className="impact-big">
                {pct(ourCPU)} CPU · {fmtBytes(ourMem)} RAM
              </div>
              <div className="small muted">
                = {c.memTotal ? ((ourMem / c.memTotal) * 100).toFixed(1) : "–"} % des Arbeitsspeichers · Ø der letzten Stunde: Caddy {pct(avg("caddy"))}, caddyEvolved {pct(avg("cev"))} CPU
              </div>
            </div>
            <div className="impact-bars">
              <Bar label="CPU gesamt" value={c.cpu} max={100} fmt={pct} ours={ourCPU} />
              <Bar label="RAM" value={c.memUsed} max={c.memTotal} fmt={(v) => fmtBytes(v)} ours={ourMem} />
            </div>
          </div>

          <div className="grid kpi-grid">
            <Kpi label="Last (1/5/15 min)" value={`${c.load1.toFixed(2)} / ${c.load5.toFixed(2)} / ${c.load15.toFixed(2)}`} sub={`${c.cpus} Kerne`} />
            <Kpi label="Netzwerk" value={`↓ ${rate(c.rxBps)}`} sub={`↑ ${rate(c.txBps)}`} />
            <Kpi label="Arbeitsspeicher" value={fmtBytes(c.memUsed)} sub={`von ${fmtBytes(c.memTotal)}`} />
            <Kpi label="Laufzeit Server" value={fmtDur(c.uptime)} />
            <Kpi label="Zugriffs-Logs" value={fmtBytes(data?.logBytes ?? 0)} />
          </div>

          <div className="grid grid-2">
            <div className="card">
              <h2>CPU (% der ganzen Maschine)</h2>
              <Chart rows={rows} series={CPU_SERIES} stacked fmtTime={fmtTime} fmt={(v) => `${Math.round(v)} %`} height={180} />
            </div>
            <div className="card">
              <h2>Arbeitsspeicher</h2>
              <Chart rows={memRows} series={MEM_SERIES} stacked fmtTime={fmtTime} fmt={(v) => fmtBytes(v)} height={180} />
            </div>
          </div>
          <div className="card">
            <h2>Netzwerk des Servers (alle Schnittstellen)</h2>
            <Chart rows={rows} series={NET_SERIES} kind="line" fmtTime={fmtTime} fmt={(v) => rate(v)} height={160} />
            <p className="small muted" style={{ marginBottom: 0 }}>
              Der Anteil, der über Caddy läuft, steht unter Analytics → Traffic.
            </p>
          </div>

          <div className="grid grid-2">
            <ProcCard name="Caddy" p={c.caddy} />
            <ProcCard name="caddyEvolved" p={c.caddyevolved} extra={`Go-Heap ${fmtBytes(c.goHeap)} · ${c.goroutines} Goroutinen`} />
          </div>

          <div className="card">
            <h2>Speicherplatz</h2>
            {(data?.disks ?? []).map((d) => (
              <Bar key={d.path} label={d.path} value={d.total - d.free} max={d.total} fmt={(v) => fmtBytes(v)} />
            ))}
          </div>
        </div>
      )}
    </>
  );
}

function Kpi({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="card stat">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {sub && <div className="small muted">{sub}</div>}
    </div>
  );
}

function Bar({ label, value, max, fmt, ours }: { label: string; value: number; max: number; fmt: (v: number) => string; ours?: number }) {
  const p = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  const o = max > 0 && ours ? Math.min(p, (ours / max) * 100) : 0;
  const tone = p > 90 ? "var(--danger)" : p > 75 ? "var(--warn)" : "var(--c-grid)";
  return (
    <div className="sysbar">
      <div className="row small" style={{ gap: 8 }}>
        <span className="mono">{label}</span>
        <span className="spacer" />
        <span className="muted">
          {fmt(value)} / {fmt(max)} ({p.toFixed(0)} %)
        </span>
      </div>
      <div className="sysbar-track">
        <span style={{ width: `${p - o}%`, background: tone }} />
        {o > 0 && <span style={{ width: `${o}%`, background: "var(--accent)" }} title="davon Caddy + caddyEvolved" />}
      </div>
    </div>
  );
}

function ProcCard({ name, p, extra }: { name: string; p?: Proc; extra?: string }) {
  return (
    <div className="card">
      <h2>{name}</h2>
      {!p ? (
        <div className="small muted">läuft nicht oder nicht gefunden</div>
      ) : (
        <dl className="cert-dl">
          <dt>PID</dt>
          <dd className="mono">{p.pid}</dd>
          <dt>CPU</dt>
          <dd>
            {pct(p.cpu)} eines Kerns · {pct(p.cpuHost)} der Maschine
          </dd>
          <dt>RAM</dt>
          <dd>{fmtBytes(p.rss)}</dd>
          <dt>Threads / Dateien</dt>
          <dd>
            {p.threads} / {p.fds} offen
          </dd>
          <dt>Platte</dt>
          <dd>
            lesen {rate(p.readBps)} · schreiben {rate(p.writeBps)}
          </dd>
          <dt>Läuft seit</dt>
          <dd>{fmtDur(p.uptime)}</dd>
          {extra && (
            <>
              <dt>Intern</dt>
              <dd>{extra}</dd>
            </>
          )}
        </dl>
      )}
    </div>
  );
}
