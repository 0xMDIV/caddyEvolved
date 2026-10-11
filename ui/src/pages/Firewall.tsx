import { useState } from "react";
import { api, FirewallLogResponse, FirewallResponse, Site, SitesResponse, WafEvent } from "../api";
import { FirewallRules } from "../components/firewall";
import { AutoBanPanel } from "../components/autoban";
import { Badge, ErrorBox, PageHead, Spinner, useAction, useLoad } from "../components/ui";

/** Labels for the reasons the access log carries (cev_block). */
export const BLOCK_REASON: Record<string, string> = {
  "firewall-ip": "Firewall: IP gesperrt",
  "firewall-land": "Firewall: Land",
  "firewall-asn": "Firewall: Netzbetreiber",
  "acl-ip": "Access List: IP",
  "acl-land": "Access List: Land",
  geschuetzt: "Geschützte Datei",
  ratelimit: "Rate Limit",
  falle: "Auto-Bann: Falle",
  autoban: "Auto-Bann: gesperrt",
  "403": "403 (WAF, CrowdSec, Bot-Abwehr oder App)",
};

const fmtTime = (s: string) => new Date(s).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "medium" });

// Rules that only sum up the score; switching them off would disable the WAF.
const isEvaluation = (id: number) => id === 949110 || id === 959100 || (id >= 980000 && id < 981000);

/** siteForHost finds the site a request was for: by domain, or by port for ":8081" sites. */
function siteForHost(sites: Site[], host: string): Site | undefined {
  const h = host.toLowerCase();
  const name = h.replace(/:\d+$/, "");
  const port = h.match(/:(\d+)$/)?.[1];
  return (
    sites.find((s) => s.domains.some((d) => d.toLowerCase() === name || (d.startsWith("*.") && name.endsWith(d.slice(1).toLowerCase())))) ??
    (port ? sites.find((s) => s.domains.some((d) => d === `:${port}`)) : undefined)
  );
}

export default function FirewallPage() {
  const [tab, setTab] = useState<"rules" | "autoban" | "blocked" | "waf">("rules");
  const fw = useLoad(() => api.get<FirewallResponse>("/api/firewall"));
  const log = useLoad(() => api.get<FirewallLogResponse>("/api/firewall/log"));
  const sites = useLoad(() => api.get<SitesResponse>("/api/sites"));
  const { busy, run } = useAction();

  const quick = (ip: string, action: "block" | "allow") =>
    run(`${action}-${ip}`, () => api.post("/api/firewall/quick", { ip, action }), action === "block" ? `${ip} gesperrt` : `${ip} freigegeben`).then(
      (r) => r && (fw.reload(), log.reload()),
    );

  const excludeRule = async (ev: WafEvent, id: number) => {
    const site = siteForHost(sites.data?.sites ?? [], ev.host);
    if (!site?.waf) return;
    const waf = { ...site.waf, exclude: [...new Set([...(site.waf.exclude ?? []), id])].sort((a, b) => a - b) };
    await run(`ex-${ev.id}-${id}`, () => api.put(`/api/sites/${site.id}`, { ...site, waf }), `Regel ${id} auf ${site.id} ausgeschaltet`);
    sites.reload();
  };

  const blocked = log.data?.blocked ?? [];
  const waf = log.data?.waf ?? [];
  const allowed = new Set(fw.data?.firewall.allow ?? []);
  const denied = new Set(fw.data?.firewall.block ?? []);

  return (
    <>
      <PageHead title="Firewall" sub="IPs, Sperrlisten, Länder und Netzbetreiber für alle Sites – und was davon blockiert wurde.">
        <button className="btn" onClick={() => (fw.reload(), log.reload())}>
          Aktualisieren
        </button>
      </PageHead>
      <div className="tabs" role="tablist">
        <button className={`tab ${tab === "rules" ? "active" : ""}`} onClick={() => setTab("rules")}>
          Regeln
        </button>
        <button className={`tab ${tab === "autoban" ? "active" : ""}`} onClick={() => setTab("autoban")}>
          Auto-Bann {fw.data?.bans?.length ? `(${fw.data.bans.length})` : ""}
        </button>
        <button className={`tab ${tab === "blocked" ? "active" : ""}`} onClick={() => setTab("blocked")}>
          Blockiert {blocked.length ? `(${blocked.length})` : ""}
        </button>
        <button className={`tab ${tab === "waf" ? "active" : ""}`} onClick={() => setTab("waf")}>
          WAF-Treffer {waf.length ? `(${waf.length})` : ""}
        </button>
      </div>
      <ErrorBox error={fw.error || log.error} />

      {tab === "rules" && (fw.data ? <FirewallRules data={fw.data} onSaved={() => fw.reload()} /> : <Spinner />)}
      {tab === "autoban" && (fw.data ? <AutoBanPanel data={fw.data} onSaved={() => fw.reload()} /> : <Spinner />)}

      {tab === "blocked" && (
        <div className="stack" style={{ gap: 16 }}>
          {(log.data?.reasons?.length ?? 0) > 0 && (
            <div className="card stack" style={{ gap: 8 }}>
              <h2 style={{ margin: 0, fontSize: 15 }}>Letzte 24 Stunden</h2>
              <div className="chips">
                {log.data!.reasons!.map((r) => (
                  <span key={r.key} className="chip">
                    {BLOCK_REASON[r.key] ?? r.key} <b>{r.count}</b>
                  </span>
                ))}
              </div>
            </div>
          )}
          <div className="card">
            <h2 style={{ marginTop: 0, fontSize: 15 }}>Abgewiesene Anfragen</h2>
            {blocked.length === 0 ? (
              <span className="muted">Noch nichts blockiert.</span>
            ) : (
              <div className="table-wrap">
                <table className="log-table">
                  <thead>
                    <tr>
                      <th>Zeit</th>
                      <th>Grund</th>
                      <th>IP</th>
                      <th>Anfrage</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {blocked.map((b, i) => (
                      <tr key={i}>
                        <td className="nowrap">{fmtTime(b.ts)}</td>
                        <td>{BLOCK_REASON[b.block] ?? b.block}</td>
                        <td className="mono">{b.ip}</td>
                        <td className="mono" title={b.agent}>
                          {b.method} {b.host}
                          {b.uri}
                        </td>
                        <td className="nowrap">
                          {!denied.has(b.ip) && (
                            <button className="btn sm danger" disabled={!!busy} onClick={() => quick(b.ip, "block")}>
                              Sperren
                            </button>
                          )}{" "}
                          {!allowed.has(b.ip) && (
                            <button className="btn sm" disabled={!!busy} onClick={() => quick(b.ip, "allow")}>
                              Freigeben
                            </button>
                          )}
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

      {tab === "waf" && (
        <div className="stack" style={{ gap: 12 }}>
          {!fw.data?.caps.waf && <div className="card muted">Coraza ist nicht in der Binary – WAF-Treffer gibt es erst mit dem Plugin.</div>}
          {waf.length === 0 && fw.data?.caps.waf && <div className="card muted">Noch keine WAF-Treffer.</div>}
          {waf.map((ev) => {
            const site = siteForHost(sites.data?.sites ?? [], ev.host);
            return (
              <div key={ev.id} className="card stack" style={{ gap: 6 }}>
                <div className="row">
                  {ev.blocked ? <Badge kind="err">blockiert</Badge> : <Badge kind="warn">nur erkannt</Badge>}
                  <span className="small">{fmtTime(ev.ts)}</span>
                  <span className="mono small">{ev.ip}</span>
                  <span className="mono small" style={{ wordBreak: "break-all" }}>
                    {ev.host}
                    {ev.uri}
                  </span>
                  <span className="spacer" />
                  {site && <span className="small muted">Site {site.id}</span>}
                </div>
                {ev.rules.map((r) => {
                  const off = site?.waf?.exclude?.includes(r.id);
                  return (
                    <div key={r.id} className="row" style={{ alignItems: "flex-start" }}>
                      <span className="mono small" style={{ minWidth: 60 }}>
                        {r.id}
                      </span>
                      <span className="small" style={{ flex: 1 }}>
                        {r.msg}
                        {r.data && <div className="muted mono" style={{ wordBreak: "break-all" }}>{r.data}</div>}
                      </span>
                      {isEvaluation(r.id) ? (
                        <span className="muted small">Bewertung</span>
                      ) : off ? (
                        <Badge>ausgeschaltet</Badge>
                      ) : (
                        site?.waf && (
                          <button className="btn sm" disabled={!!busy} onClick={() => excludeRule(ev, r.id)} title="Fehlalarm? Regel nur für diese Site ausschalten">
                            Auf Site ausschalten
                          </button>
                        )
                      )}
                    </div>
                  );
                })}
                {!denied.has(ev.ip) && (
                  <div>
                    <button className="btn sm danger" disabled={!!busy} onClick={() => quick(ev.ip, "block")}>
                      IP {ev.ip} sperren
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}
