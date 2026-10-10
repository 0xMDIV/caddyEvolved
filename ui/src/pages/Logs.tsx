import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { ErrorBox, PageHead, Spinner } from "../components/ui";
import { IconRefresh } from "@tabler/icons-react";

interface LogsResp {
  unit: string;
  lines: string[] | null;
  count: number;
  source: string;
  path?: string;
}

export default function Logs() {
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
    <>
      <PageHead title="Logs" sub={data ? `Quelle: ${data.source}${data.source === "datei" && data.path ? ` (${data.path})` : ""}` : undefined}>
        <select value={unit} onChange={(e) => setUnit(e.target.value as "caddy" | "caddyevolved")} style={{ width: "auto" }}>
          <option value="caddy">caddy</option>
          <option value="caddyevolved">caddyevolved</option>
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
      </PageHead>
      <ErrorBox error={error} />
      <pre
        ref={preRef}
        className="code wrap"
        style={{ height: "calc(100vh - 190px)", minHeight: 300 }}
        onScroll={(e) => {
          const el = e.currentTarget;
          stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
        }}
      >
        {data ? (data.lines?.length ? data.lines.join("\n") : "Keine Einträge.") : "Lade…"}
      </pre>
    </>
  );
}
