import { useEffect } from "react";
import { AnalyticsResponse, api, CertificatesResponse, CfEvent, expiryKind, fmtExpiry, fmtNum, fmtTime, StatusResponse } from "../api";
import { Sparkline } from "../components/charts";
import { navigate } from "../router";
import { Badge, ErrorBox, PageHead, Spinner, useAction, useLoad } from "../components/ui";
import { IconPlayerPlayFilled, IconPlayerStopFilled, IconRefresh } from "@tabler/icons-react";

export default function Dashboard() {
  const status = useLoad(() => api.get<StatusResponse>("/api/status"));
  const events = useLoad(() => api.get<{ events: CfEvent[] | null }>("/api/events?limit=200"));
  const { busy, run } = useAction();

  useEffect(() => {
    const t = setInterval(() => {
      status.reload();
      events.reload();
    }, 15000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function service(action: string) {
    await run(action, () => api.post(`/api/service/${action}?unit=caddy.service`), `caddy: ${action} ausgeführt`);
    status.reload();
    events.reload();
  }

  const s = status.data;
  const recent = (events.data?.events ?? []).slice(-12).reverse();
  const modules = (s?.enabledPlugins ?? []).filter((p) => p.detected);

  return (
    <>
      <PageHead title="Dashboard" sub={s?.host.hostname ? `Host ${s.host.hostname}` : undefined}>
        <button className="btn" onClick={() => (status.reload(), events.reload())} disabled={status.loading}>
          {status.loading ? <Spinner /> : <IconRefresh size={16} />} Aktualisieren
        </button>
      </PageHead>
      <ErrorBox error={status.error} />
      {s && (
        <div className="stack">
          {s.warnings && s.warnings.length > 0 && (
            <div className="alert warn">
              {s.warnings.map((w) => (
                <div key={w}>{w}</div>
              ))}
            </div>
          )}
          <div className="grid grid-3">
            <div className="card stat">
              <div className="label">Caddy-Dienst</div>
              <div className="value">
                {s.serviceActive ? <Badge kind="ok"><IconPlayerPlayFilled size={11} /> läuft</Badge> : <Badge kind="err"><IconPlayerStopFilled size={11} /> gestoppt</Badge>}
              </div>
              <div className="small muted" style={{ marginTop: 6 }}>
                {s.serviceState || "–"}
              </div>
            </div>
            <div className="card stat">
              <div className="label">Caddy-Version</div>
              <div className="value">{s.caddyVersion ? `v${s.caddyVersion.replace(/^v/, "")}` : "nicht installiert"}</div>
              <div className="small muted" style={{ marginTop: 6 }}>
                {s.variant ? `Variante ${s.variant}` : ""}
              </div>
            </div>
            <div className="card stat">
              <div className="label">Admin-API</div>
              <div className="value">
                {s.adminReachable ? <Badge kind="ok">erreichbar</Badge> : <Badge kind="warn">nicht erreichbar</Badge>}
              </div>
              <div className="small muted mono" style={{ marginTop: 6 }}>
                {s.adminUrl}
              </div>
            </div>
            <div className="card stat">
              <div className="label">Host</div>
              <div className="value" style={{ fontSize: 16 }}>
                {[s.host.distro, s.host.distroVersion].filter(Boolean).join(" ") || "–"}
              </div>
              <div className="small muted" style={{ marginTop: 6 }}>
                {s.host.init}
                {s.host.virt ? ` · ${s.host.virt}` : ""}
                {s.host.unprivilegedLxc ? " · unprivilegiert" : ""}
              </div>
            </div>
          </div>

          <div className="grid grid-2">
            <div className="card">
              <h2>Steuerung</h2>
              <div className="row">
                {(["start", "stop", "restart", "reload"] as const).map((a) => (
                  <button key={a} className={`btn ${a === "stop" ? "danger" : ""}`} disabled={!!busy} onClick={() => service(a)}>
                    {busy === a && <Spinner />}
                    {{ start: "Starten", stop: "Stoppen", restart: "Neu starten", reload: "Neu laden" }[a]}
                  </button>
                ))}
              </div>
              <p className="small muted" style={{ marginBottom: 0 }}>
                „Neu laden“ prüft das Caddyfile vorher und übernimmt es ohne Unterbrechung.
              </p>
              <h3>Ports</h3>
              <div className="chips">
                {(s.ports ?? []).map((p) => (
                  <Badge key={p.Port} kind={p.Own ? "ok" : p.Free ? undefined : "warn"}>
                    :{p.Port} {p.Own ? "caddy" : p.Free ? "frei" : p.UsedBy || "belegt"}
                  </Badge>
                ))}
                {(s.ports ?? []).length === 0 && <span className="muted small">keine Angaben</span>}
              </div>
            </div>

            <div className="card">
              <div className="row">
                <h2 style={{ margin: 0 }}>Eingebaute Plugins</h2>
                <span className="spacer" />
                <button className="btn sm" onClick={() => navigate("/build")}>
                  Plugins verwalten
                </button>
              </div>
              <div className="chips" style={{ marginTop: 12 }}>
                {modules.map((p) => (
                  <Badge key={p.id} kind={p.active && !p.complete ? "warn" : "info"}>
                    {p.name}
                    {p.active && !p.complete ? " · Zugangsdaten fehlen" : ""}
                  </Badge>
                ))}
                {modules.length === 0 && <span className="muted small">Keine Zusatz-Plugins im Binary (Standard-Caddy).</span>}
              </div>
            </div>

            <CertCard />
            <TrafficCard />
          </div>

          <div className="card">
            <h2>Letzte Ereignisse</h2>
            <ErrorBox error={events.error} />
            {recent.length === 0 ? (
              <div className="empty">Noch keine Ereignisse.</div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Zeit</th>
                      <th>Art</th>
                      <th>Ereignis</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {recent.map((e) => (
                      <tr key={e.id}>
                        <td className="small muted" style={{ whiteSpace: "nowrap" }}>
                          {fmtTime(e.ts)}
                        </td>
                        <td>
                          <Badge>{e.kind}</Badge>
                        </td>
                        <td>
                          {e.summary || e.step}
                          {e.error && <div className="small" style={{ color: "var(--danger)" }}>{e.error}</div>}
                        </td>
                        <td>{e.ok ? <Badge kind="ok">ok</Badge> : <Badge kind="err">Fehler</Badge>}</td>
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

function TrafficCard() {
  const data = useLoad(() => api.get<AnalyticsResponse>("/api/analytics?range=24h"));
  const rep = data.data?.report;
  const series = rep?.series ?? [];
  const tot = rep?.totals;
  return (
    <div className="card">
      <div className="row">
        <h2 style={{ margin: 0 }}>Traffic (24 h)</h2>
        <span className="spacer" />
        <button className="btn sm" onClick={() => navigate("/analytics")}>
          Analytics
        </button>
      </div>
      <ErrorBox error={data.error} />
      {rep && (
        <>
          <div className="row" style={{ marginTop: 10, gap: 18 }}>
            <div>
              <div className="small muted">Anfragen</div>
              <b>{fmtNum(tot?.requests)}</b>
            </div>
            <div>
              <div className="small muted">Geblockt</div>
              <b style={{ color: (tot?.blocked ?? 0) > 0 ? "var(--warn)" : undefined }}>{fmtNum(tot?.blocked)}</b>
            </div>
            <div>
              <div className="small muted">Fehler</div>
              <b>{fmtNum((tot?.s4xx ?? 0) + (tot?.s5xx ?? 0))}</b>
            </div>
          </div>
          <div style={{ marginTop: 8 }}>
            <Sparkline values={series.map((p) => p.requests)} color="var(--c-2xx)" />
            <Sparkline values={series.map((p) => p.blocked)} color="var(--c-blocked)" height={22} />
          </div>
        </>
      )}
    </div>
  );
}

function CertCard() {
  const certs = useLoad(() => api.get<CertificatesResponse>("/api/certificates"));
  const list = certs.data?.certificates ?? [];
  // Internal certs renew every few hours; the interesting expiry is the
  // next public one, falling back to whatever expires first.
  const sorted = [...list].sort((a, b) => new Date(a.notAfter).getTime() - new Date(b.notAfter).getTime());
  const next = sorted.find((c) => c.source !== "internal") ?? sorted[0];
  const publicCount = list.filter((c) => c.source !== "internal").length;
  return (
    <div className="card">
      <div className="row">
        <h2 style={{ margin: 0 }}>Zertifikate</h2>
        <span className="spacer" />
        <button className="btn sm" onClick={() => navigate("/certificates")}>
          Alle anzeigen
        </button>
      </div>
      <ErrorBox error={certs.error} />
      {certs.loading && !certs.data ? (
        <div className="empty">
          <Spinner />
        </div>
      ) : list.length === 0 ? (
        <p className="small muted">Noch keine Zertifikate ausgestellt.</p>
      ) : (
        <div className="stack" style={{ marginTop: 12, gap: 8 }}>
          <div className="small">
            {list.length} Zertifikat{list.length === 1 ? "" : "e"} · {publicCount} öffentlich · {list.length - publicCount} intern
          </div>
          {next && (
            <div className="row">
              <span className="small muted">Nächster Ablauf:</span>
              <span className="mono small">{(next.domains ?? [next.name]).join(", ")}</span>
              <span className="spacer" />
              <Badge kind={expiryKind(next)}>{fmtExpiry(next)}</Badge>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
