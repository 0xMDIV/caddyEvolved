import { useMemo, useRef, useState } from "react";

// Small dependency-free SVG charts. Colors come from CSS variables so light
// and dark themes follow automatically.

export interface Series {
  key: string;
  label: string;
  color: string; // CSS color, usually var(--…)
}

type Row = Record<string, number> & { t: number };

interface ChartProps {
  rows: Row[];
  series: Series[];
  height?: number;
  stacked?: boolean;
  kind?: "bars" | "line";
  fmt?: (v: number) => string;
  fmtTime: (t: number) => string;
}

const PAD = { l: 44, r: 8, t: 8, b: 22 };
const W = 800; // viewBox width; the SVG scales to its container

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / p;
  const step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
  return step * p;
}

function shortNum(v: number): string {
  if (v >= 1e6) return `${(v / 1e6).toFixed(v >= 1e7 ? 0 : 1)}M`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(v >= 1e4 ? 0 : 1)}k`;
  return String(Math.round(v * 100) / 100);
}

export function Chart({ rows, series, height = 200, stacked = false, kind = "bars", fmt = shortNum, fmtTime }: ChartProps) {
  const [hover, setHover] = useState<number | null>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const H = height;
  const innerW = W - PAD.l - PAD.r;
  const innerH = H - PAD.t - PAD.b;

  const max = useMemo(() => {
    let m = 0;
    for (const r of rows) {
      if (stacked) m = Math.max(m, series.reduce((s, x) => s + (r[x.key] || 0), 0));
      else for (const x of series) m = Math.max(m, r[x.key] || 0);
    }
    return niceMax(m);
  }, [rows, series, stacked]);

  const n = rows.length;
  const slot = n > 0 ? innerW / n : innerW;
  const x = (i: number) => PAD.l + i * slot;
  const y = (v: number) => PAD.t + innerH - (v / max) * innerH;

  function onMove(e: React.MouseEvent<SVGSVGElement>) {
    const svg = svgRef.current;
    if (!svg || n === 0) return;
    const rect = svg.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * W;
    const i = Math.floor((px - PAD.l) / slot);
    setHover(i >= 0 && i < n ? i : null);
  }

  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * max);
  const labelEvery = Math.max(1, Math.ceil(n / 6));
  const h = hover !== null ? rows[hover] : null;

  return (
    <div className="chart" style={{ position: "relative" }}>
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        width="100%"
        height={H}
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
        role="img"
      >
        {ticks.map((t) => (
          <g key={t}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y(t)} y2={y(t)} className="chart-grid" />
            <text x={PAD.l - 6} y={y(t) + 4} textAnchor="end" className="chart-axis">
              {fmt(t)}
            </text>
          </g>
        ))}
        {rows.map((r, i) =>
          i % labelEvery === 0 ? (
            <text key={"l" + i} x={x(i) + slot / 2} y={H - 6} textAnchor="middle" className="chart-axis">
              {fmtTime(r.t)}
            </text>
          ) : null,
        )}
        {kind === "bars" &&
          rows.map((r, i) => {
            let acc = 0;
            const bw = Math.max(1, slot * 0.78);
            return (
              <g key={i} opacity={hover === null || hover === i ? 1 : 0.55}>
                {series.map((s, si) => {
                  const v = r[s.key] || 0;
                  if (v <= 0) return null;
                  if (stacked) {
                    const y0 = y(acc);
                    acc += v;
                    const y1 = y(acc);
                    return <rect key={s.key} x={x(i) + (slot - bw) / 2} y={y1} width={bw} height={Math.max(0.5, y0 - y1)} fill={s.color} />;
                  }
                  const w2 = bw / series.length;
                  return <rect key={s.key} x={x(i) + (slot - bw) / 2 + si * w2} y={y(v)} width={w2} height={Math.max(0.5, y(0) - y(v))} fill={s.color} />;
                })}
              </g>
            );
          })}
        {kind === "line" &&
          series.map((s) => (
            <polyline
              key={s.key}
              fill="none"
              stroke={s.color}
              strokeWidth={2}
              vectorEffect="non-scaling-stroke"
              points={rows.map((r, i) => `${x(i) + slot / 2},${y(r[s.key] || 0)}`).join(" ")}
            />
          ))}
        {hover !== null && (
          <line x1={x(hover) + slot / 2} x2={x(hover) + slot / 2} y1={PAD.t} y2={PAD.t + innerH} className="chart-cursor" />
        )}
      </svg>
      {h && hover !== null && (
        <div className="chart-tip" style={{ left: `${Math.min(80, Math.max(2, ((x(hover) + slot / 2) / W) * 100))}%` }}>
          <div className="small muted">{fmtTime(h.t)}</div>
          {series.map((s) => (
            <div key={s.key} className="chart-tip-row">
              <span className="chart-swatch" style={{ background: s.color }} />
              {s.label}
              <b>{fmt(h[s.key] || 0)}</b>
            </div>
          ))}
        </div>
      )}
      <div className="chart-legend">
        {series.map((s) => (
          <span key={s.key}>
            <span className="chart-swatch" style={{ background: s.color }} />
            {s.label}
          </span>
        ))}
      </div>
    </div>
  );
}

/** Tiny inline sparkline, no axes. */
export function Sparkline({ values, color, height = 36, fill = true }: { values: number[]; color: string; height?: number; fill?: boolean }) {
  const w = 200;
  const max = Math.max(1, ...values);
  const n = values.length;
  if (n === 0) return <svg width="100%" height={height} />;
  const pts = values.map((v, i) => `${(i / Math.max(1, n - 1)) * w},${height - 2 - (v / max) * (height - 4)}`);
  return (
    <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" width="100%" height={height} aria-hidden="true">
      {fill && <polygon points={`0,${height} ${pts.join(" ")} ${w},${height}`} fill={color} opacity={0.15} />}
      <polyline points={pts.join(" ")} fill="none" stroke={color} strokeWidth={1.6} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

/** Bar-in-row top list. */
export function TopList({ title, entries, mono }: { title: string; entries: { key: string; count: number }[]; mono?: boolean }) {
  const max = Math.max(1, ...entries.map((e) => e.count));
  return (
    <div className="card">
      <h2>{title}</h2>
      {entries.length === 0 ? (
        <div className="small muted">keine Daten</div>
      ) : (
        <div className="toplist">
          {entries.map((e) => (
            <div key={e.key} className="toplist-row" title={e.key}>
              <div className="toplist-bar" style={{ width: `${(e.count / max) * 100}%` }} />
              <span className={`toplist-key ${mono ? "mono" : ""}`}>{e.key || "–"}</span>
              <span className="toplist-count">{e.count.toLocaleString("de-DE")}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
