import { useState } from "react";
import { api, AutoBan, Ban, FirewallResponse } from "../api";
import { ListArea } from "./features";
import { IPCell } from "./ip";
import { Badge, Switch, useAction } from "./ui";

// Paths only scanners ask for. Each preset is safe unless such an app runs
// behind the proxy – then leave it out or exclude that site from the firewall.
const TRAP_PRESETS: { name: string; hint: string; paths: string[] }[] = [
  {
    name: "Scanner allgemein",
    hint: "phpMyAdmin, CGI, Router-Lücken, PHPUnit",
    paths: ["/phpmyadmin*", "/pma/*", "/myadmin/*", "/cgi-bin/*", "/boaform/*", "/vendor/phpunit/*", "/HNAP1*", "/GponForm/*", "/setup.cgi"],
  },
  {
    name: "WordPress",
    hint: "nur wenn kein WordPress läuft",
    paths: ["/wp-login.php", "/xmlrpc.php", "/wp-admin/*", "/wp-includes/*", "/wp-content/*", "/wordpress/*", "/wp/*"],
  },
  {
    name: "PHP-Dateien",
    hint: "nur wenn keine PHP-App läuft (Nextcloud, WordPress …)",
    paths: ["*.php"],
  },
  {
    name: "Java / Tomcat",
    hint: "nur ohne Tomcat- oder Spring-App",
    paths: ["/manager/html*", "/actuator/*", "/solr/*", "/jmx-console/*"],
  },
];

export const DEFAULT_AUTOBAN: AutoBan = {
  enabled: false,
  traps: TRAP_PRESETS[0].paths,
  guarded: true,
  strikes: 10,
  strikeMinutes: 10,
  notFound: 40,
  notFoundMinutes: 5,
  hours: 24,
  escalate: true,
  v6Net: true,
};

const REASON: Record<string, string> = {
  falle: "Falle",
  geschuetzt: "Geschützte Datei",
  verstoesse: "Zu viele Abweisungen",
  "404": "404-Scan",
};

const fmtTime = (s: string) => new Date(s).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" });

/** AutoBanPanel edits the auto-ban rules and lists the current bans. */
export function AutoBanPanel({ data, onSaved }: { data: FirewallResponse; onSaved: () => void }) {
  const saved = data.firewall.autoBan;
  const [a, setA] = useState<AutoBan>(saved?.strikeMinutes ? saved : DEFAULT_AUTOBAN); // never saved: defaults
  const [key, setKey] = useState(0);
  const [filter, setFilter] = useState("");
  const { busy, run } = useAction();
  const set = <K extends keyof AutoBan>(k: K, v: AutoBan[K]) => setA((x) => ({ ...x, [k]: v }));
  const num = (v: string) => Math.max(0, parseInt(v, 10) || 0);

  const save = () =>
    run(
      "save",
      () => api.put("/api/firewall", { ...data.firewall, enabled: data.firewall.enabled || a.enabled, autoBan: a }),
      a.enabled ? "Auto-Bann aktiv" : "Auto-Bann gespeichert",
    ).then((r) => r && onSaved());
  const act = (ip: string, action: "unban" | "block" | "allow", msg: string) =>
    run(`${action}-${ip}`, () => api.post("/api/firewall/quick", { ip, action }), msg).then((r) => r && onSaved());
  const clear = () => {
    if (!confirm("Alle automatischen Sperren aufheben?")) return;
    run("clear", () => api.post("/api/firewall/bans/clear"), "Alle Sperren aufgehoben").then((r) => r && onSaved());
  };
  const addPreset = (paths: string[]) => {
    set("traps", [...new Set([...(a.traps ?? []), ...paths])]);
    setKey((k) => k + 1);
  };

  const bans = data.bans ?? [];
  const shown = filter ? bans.filter((b) => b.ip.includes(filter) || (b.detail ?? "").toLowerCase().includes(filter.toLowerCase())) : bans;
  const today = bans.filter((b) => Date.now() - new Date(b.since).getTime() < 864e5).length;

  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="card stack" style={{ gap: 10 }}>
        <div className="row">
          <Switch checked={a.enabled} onChange={(v) => set("enabled", v)} label="Auto-Bann aktiv" />
          <h2 style={{ margin: 0 }}>Auto-Bann {a.enabled ? <Badge kind="ok">aktiv</Badge> : <Badge>aus</Badge>}</h2>
        </div>
        <span className="hint">
          caddyEvolved liest das Access-Log mit und sperrt Adressen, die nach Lücken suchen, für alle Sites. Die Liste wächst mit jedem Scanner. Nie gesperrt
          werden private Netze, die Freigaben, vertrauenswürdige Proxys und Cloudflare.
          {!data.firewall.enabled && a.enabled && " Die Firewall wird beim Speichern eingeschaltet."}
        </span>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16 }}>
        <div className="card stack" style={{ gap: 8 }}>
          <h2 style={{ margin: 0, fontSize: 15 }}>Fallen – sofort sperren</h2>
          <span className="hint">
            Pfade, die kein echter Besucher aufruft. Sie antworten allen mit 404 und sperren den Absender. <code>*</code> steht für beliebige Zeichen.
          </span>
          <ListArea key={key} value={a.traps} onChange={(v) => set("traps", v)} rows={6} placeholder={"/wp-login.php\n/phpmyadmin*"} />
          <div className="inline-fields">
            <span className="small muted">Hinzufügen:</span>
            {TRAP_PRESETS.map((p) => (
              <button key={p.name} className="btn sm" title={p.hint} onClick={() => addPreset(p.paths)}>
                + {p.name}
              </button>
            ))}
          </div>
          <label className="check">
            <input type="checkbox" checked={a.guarded} onChange={(e) => set("guarded", e.target.checked)} />
            <span>
              Zugriffe auf geschützte Dateien sperren <span className="muted small">(.env, .git, Schlüssel, Backups – Dateischutz)</span>
            </span>
          </label>
        </div>

        <div className="card stack" style={{ gap: 10 }}>
          <h2 style={{ margin: 0, fontSize: 15 }}>Schwellen</h2>
          <div className="inline-fields">
            <span className="small">Ab</span>
            <input type="number" min={0} style={{ width: 80 }} value={a.strikes} onChange={(e) => set("strikes", num(e.target.value))} />
            <span className="small">abgewiesenen Anfragen (WAF, Rate Limit, 403) in</span>
            <input type="number" min={1} style={{ width: 80 }} value={a.strikeMinutes} onChange={(e) => set("strikeMinutes", num(e.target.value))} />
            <span className="small">Minuten</span>
          </div>
          <div className="inline-fields">
            <span className="small">Ab</span>
            <input type="number" min={0} style={{ width: 80 }} value={a.notFound} onChange={(e) => set("notFound", num(e.target.value))} />
            <span className="small">× „nicht gefunden“ (404) in</span>
            <input type="number" min={1} style={{ width: 80 }} value={a.notFoundMinutes} onChange={(e) => set("notFoundMinutes", num(e.target.value))} />
            <span className="small">Minuten</span>
          </div>
          <span className="hint">0 schaltet eine Schwelle ab. Scanner erzeugen Dutzende 404 in Sekunden; ein Besucher mit kaputtem Link kaum.</span>

          <h2 style={{ margin: "6px 0 0", fontSize: 15 }}>Sperrdauer</h2>
          <div className="inline-fields">
            <select value={a.hours} onChange={(e) => set("hours", num(e.target.value))} style={{ width: "auto" }}>
              {[
                [1, "1 Stunde"],
                [24, "1 Tag"],
                [168, "1 Woche"],
                [720, "30 Tage"],
                [0, "dauerhaft"],
              ].map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
              {![1, 24, 168, 720, 0].includes(a.hours) && <option value={a.hours}>{a.hours} Stunden</option>}
            </select>
          </div>
          <label className="check">
            <input type="checkbox" checked={a.escalate} disabled={a.hours === 0} onChange={(e) => set("escalate", e.target.checked)} />
            <span>Wiederholungstäter: Dauer verdoppeln, beim dritten Mal dauerhaft</span>
          </label>
          <label className="check">
            <input type="checkbox" checked={a.v6Net} onChange={(e) => set("v6Net", e.target.checked)} />
            <span>
              IPv6: ganzes /64-Netz sperren <span className="muted small">(ein Anschluss hat Milliarden Adressen)</span>
            </span>
          </label>
        </div>
      </div>

      <div className="row">
        <button className="btn primary" onClick={save} disabled={busy === "save"}>
          {busy === "save" ? "Speichert…" : "Speichern & übernehmen"}
        </button>
        <span className="hint">Neue Sperren werden alle 10 Sekunden gesammelt übernommen.</span>
      </div>

      <div className="card stack" style={{ gap: 8 }}>
        <div className="row">
          <h2 style={{ margin: 0, fontSize: 15 }}>
            Gesperrt: {bans.length.toLocaleString("de-DE")} {today > 0 && <span className="muted small">(+{today} in 24 h)</span>}
          </h2>
          <span className="spacer" />
          {bans.length > 0 && (
            <>
              <input placeholder="IP oder Pfad suchen" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ width: 180 }} />
              <button className="btn sm danger" onClick={clear} disabled={!!busy}>
                Alle aufheben
              </button>
            </>
          )}
        </div>
        {bans.length === 0 ? (
          <span className="muted">Noch niemand gesperrt.</span>
        ) : (
          <div className="table-wrap">
            <table className="log-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Grund</th>
                  <th>Auslöser</th>
                  <th>Seit</th>
                  <th>Bis</th>
                  <th>Abgewiesen</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {shown.slice(0, 500).map((b: Ban) => (
                  <tr key={b.ip}>
                    <td>
                      <IPCell ip={b.ip} geo={data.ipGeo?.[b.ip]} />
                    </td>
                    <td className="nowrap">
                      {REASON[b.reason] ?? b.reason}
                      {b.times > 1 && <span className="muted small"> · {b.times}. Mal</span>}
                    </td>
                    <td className="mono small" style={{ wordBreak: "break-all" }}>
                      {b.detail}
                    </td>
                    <td className="nowrap small">{fmtTime(b.since)}</td>
                    <td className="nowrap small">{b.until ? fmtTime(b.until) : <b>dauerhaft</b>}</td>
                    <td className="small">{b.hits || ""}</td>
                    <td className="nowrap">
                      <button className="btn sm" disabled={!!busy} onClick={() => act(b.ip, "unban", `${b.ip} entsperrt`)}>
                        Entsperren
                      </button>{" "}
                      <button className="btn sm" disabled={!!busy} title="In die Freigaben – wird nie wieder gesperrt" onClick={() => act(b.ip, "allow", `${b.ip} freigegeben`)}>
                        Freigeben
                      </button>{" "}
                      {b.until && (
                        <button className="btn sm danger" disabled={!!busy} title="In die feste Sperrliste übernehmen" onClick={() => act(b.ip, "block", `${b.ip} dauerhaft gesperrt`)}>
                          Dauerhaft
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {shown.length > 500 && <div className="small muted">… und {shown.length - 500} weitere (Suche nutzen)</div>}
          </div>
        )}
      </div>
    </div>
  );
}
