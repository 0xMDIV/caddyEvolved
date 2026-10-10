import { useMemo, useState } from "react";
import { api, AuditEntry, fmtTime } from "../api";
import { Badge, ErrorBox, PageHead, Spinner, useLoad } from "../components/ui";
import { IconRefresh } from "@tabler/icons-react";
import { statusKind } from "./Analytics";

export default function Audit() {
  const log = useLoad(() => api.get<{ entries: AuditEntry[] | null }>("/api/audit?limit=500"));
  const [text, setText] = useState("");
  const [kind, setKind] = useState<"" | "audit" | "auth">("");

  const rows = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return (log.data?.entries ?? []).filter((e) => {
      if (kind && e.kind !== kind) return false;
      if (!needle) return true;
      const hay = [e.summary, e.step, e.error, e.meta?.actor, e.meta?.remote, e.meta?.path].filter(Boolean).join(" ").toLowerCase();
      return hay.includes(needle);
    });
  }, [log.data, text, kind]);

  return (
    <>
      <PageHead title="Audit Log" sub="Jede Änderung über die API und jeder Login">
        <input placeholder="Filter…" value={text} onChange={(e) => setText(e.target.value)} style={{ width: 200 }} />
        <select value={kind} onChange={(e) => setKind(e.target.value as typeof kind)} style={{ width: "auto" }}>
          <option value="">Alle</option>
          <option value="audit">Änderungen</option>
          <option value="auth">Logins</option>
        </select>
        <button className="btn" onClick={log.reload} disabled={log.loading}>
          {log.loading ? <Spinner /> : <IconRefresh size={16} />} Aktualisieren
        </button>
      </PageHead>
      <ErrorBox error={log.error} />
      <div className="card">
        {rows.length === 0 ? (
          <div className="empty">{log.loading ? <Spinner /> : "Keine Einträge."}</div>
        ) : (
          <div className="table-wrap">
            <table className="compact">
              <thead>
                <tr>
                  <th>Zeit</th>
                  <th>Wer</th>
                  <th>Von</th>
                  <th>Aktion</th>
                  <th>Status</th>
                  <th></th>
                  <th>Dauer</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => {
                  const m = e.meta ?? {};
                  const status = typeof m.status === "number" ? m.status : undefined;
                  return (
                    <tr key={e.id}>
                      <td className="small muted" style={{ whiteSpace: "nowrap" }}>
                        {fmtTime(e.ts)}
                      </td>
                      <td className="small">{m.actor ?? (e.kind === "auth" ? "Login" : "–")}</td>
                      <td className="mono small">{m.remote ?? "–"}</td>
                      <td>
                        {m.method ? (
                          <span className="mono small">
                            <b>{m.method}</b> {m.path}
                          </span>
                        ) : (
                          e.summary || e.step
                        )}
                        {e.error && (
                          <div className="small" style={{ color: "var(--danger)" }}>
                            {e.error}
                          </div>
                        )}
                      </td>
                      <td>{status !== undefined ? <span className={`badge ${statusKind(status)}`}>{status}</span> : <Badge>{e.kind}</Badge>}</td>
                      <td>{e.ok ? <Badge kind="ok">ok</Badge> : <Badge kind="err">Fehler</Badge>}</td>
                      <td className="small muted">{typeof m.ms === "number" ? `${m.ms} ms` : ""}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
