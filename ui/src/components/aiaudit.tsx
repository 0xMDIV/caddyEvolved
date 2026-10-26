import { Fragment, useState } from "react";
import { IconDownload, IconShieldCheck, IconShieldX } from "@tabler/icons-react";
import { AIAuditEntry, AIAuditResponse, api, fmtTime } from "../api";
import { Redacted } from "./ip";
import { Badge, ErrorBox, Spinner, useLoad } from "./ui";

const KIND: Record<string, [string, "ok" | "err" | "warn" | "info" | undefined]> = {
  request: ["Anfrage", undefined],
  proposal: ["Vorschlag", "warn"],
  approved: ["freigegeben", "ok"],
  rejected: ["abgelehnt", "err"],
  expired: ["verfallen", "info"],
  executed: ["ausgeführt", "ok"],
  note: ["Notiz der KI", "info"],
};

function fmtSize(n: number) {
  return n < 1024 * 1024 ? `${Math.max(1, Math.round(n / 1024))} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** AIAuditView shows the AI protocol. It has no edit or delete on purpose. */
export function AIAuditView({ chat }: { chat?: string }) {
  const [limit, setLimit] = useState(100);
  const [open, setOpen] = useState<number | null>(null);
  const data = useLoad(() => api.get<AIAuditResponse>(`/api/ai/audit?limit=${limit}${chat ? `&chat=${chat}` : ""}`), [limit, chat]);
  const d = data.data;

  return (
    <div className="card stack" style={{ gap: 12 }}>
      <div className="row">
        <h2 style={{ margin: 0 }}>KI-Protokoll</h2>
        {d &&
          (d.ok ? (
            <Badge kind="ok">
              <IconShieldCheck size={13} /> Kette intakt
            </Badge>
          ) : (
            <Badge kind="err">
              <IconShieldX size={13} /> Kette gebrochen ab Eintrag {d.brokenAt}
            </Badge>
          ))}
        <span className="spacer" />
        {d && (
          <span className="small muted">
            {d.total.toLocaleString("de-DE")} Einträge · {fmtSize(d.sizeBytes)}
          </span>
        )}
        <a className="btn sm" href="/api/ai/audit/export" download>
          <IconDownload size={14} /> Exportieren
        </a>
      </div>
      <div className="small muted">
        Jede Anfrage an die KI, jeder Vorschlag, jede Entscheidung und jede ausgeführte Aktion – nur anhängend, nicht änderbar und nicht löschbar. Jeder
        Eintrag enthält die Prüfsumme des vorigen; wird eine Zeile in der Datei geändert oder entfernt, zeigt das die Kette.
      </div>
      <ErrorBox error={data.error} />
      {!d && data.loading && <Spinner />}
      {d && d.entries.length === 0 && <div className="empty">Noch keine Einträge.</div>}
      {d && d.entries.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Zeit</th>
                <th>Art</th>
                <th>Wer</th>
                <th>Was</th>
              </tr>
            </thead>
            <tbody>
              {d.entries.map((e) => (
                <Fragment key={e.n}>
                  <tr className="log-row" onClick={() => setOpen(open === e.n ? null : e.n)}>
                    <td className="small muted">{e.n}</td>
                    <td className="small nowrap">{fmtTime(e.ts)}</td>
                    <td>
                      {e.kind === "executed" && (e.status ?? 0) >= 400 ? (
                        <Badge kind="err">fehlgeschlagen</Badge>
                      ) : (
                        <Badge kind={KIND[e.kind]?.[1]}>{KIND[e.kind]?.[0] ?? e.kind}</Badge>
                      )}
                    </td>
                    <td className="small">{e.actor}</td>
                    <td className="small" style={{ wordBreak: "break-word" }}>
                      {summary(e)}
                    </td>
                  </tr>
                  {open === e.n && (
                    <tr>
                      <td colSpan={5}>
                        <dl className="cert-dl log-detail">
                          {e.chat && (
                            <>
                              <dt>Chat</dt>
                              <dd className="mono">{e.chat}</dd>
                            </>
                          )}
                          {e.model && (
                            <>
                              <dt>Modell</dt>
                              <dd className="mono">{e.model}</dd>
                            </>
                          )}
                          {e.text && (
                            <>
                              <dt>Text</dt>
                              <dd style={{ whiteSpace: "pre-wrap" }}>{e.text}</dd>
                            </>
                          )}
                          {e.args !== undefined && (
                            <>
                              <dt>Argumente</dt>
                              <dd>
                                <pre className="ai-pre">
                                  <Redacted text={JSON.stringify(e.args, null, 2)} />
                                </pre>
                              </dd>
                            </>
                          )}
                          {e.result && (
                            <>
                              <dt>Ergebnis</dt>
                              <dd>
                                <pre className="ai-pre">
                                  <Redacted text={e.result} />
                                </pre>
                              </dd>
                            </>
                          )}
                        </dl>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {d && d.total > d.entries.length && (
        <button className="btn" style={{ alignSelf: "center" }} onClick={() => setLimit(limit + 200)}>
          Ältere laden
        </button>
      )}
    </div>
  );
}

function summary(e: AIAuditEntry): string {
  const call = e.tool ? `${e.tool}${e.method ? ` · ${e.method} ${e.path}` : ""}${e.status ? ` → ${e.status}` : ""}` : "";
  const text = e.text ? e.text.slice(0, 160) + (e.text.length > 160 ? "…" : "") : "";
  return [call, text].filter(Boolean).join(" – ") || (e.path ?? "");
}
