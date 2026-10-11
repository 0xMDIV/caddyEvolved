import { FormEvent, ReactNode, useEffect, useState } from "react";
import { api, errMsg } from "../api";
import { Badge, ErrorBox, PageHead, Spinner, useLoad } from "../components/ui";
import { IconPlayerPlay } from "@tabler/icons-react";

// ---------- Types (internal/toolbox) ----------

interface CIDRInfo {
  input: string;
  network: string;
  version: number;
  address: string;
  broadcast?: string;
  first: string;
  last: string;
  netmask?: string;
  wildcard?: string;
  bits: number;
  total: string;
  usable: string;
  private: boolean;
  contains?: string;
}
interface PingResult {
  host: string;
  addr: string;
  sent: number;
  received: number;
  loss: number;
  minMs: number;
  avgMs: number;
  maxMs: number;
  replies: { seq: number; rttMs: number; ttl?: number }[] | null;
}
interface Hop {
  ttl: number;
  addr?: string;
  name?: string;
  rttMs: number[] | null;
  reached: boolean;
}
interface PortResult {
  port: number;
  service?: string;
  rttMs: number;
  banner?: string;
}
interface HostResult {
  ip: string;
  rttMs: number;
  via: string;
  name?: string;
  mac?: string;
  self?: boolean;
  openOn?: number[];
}
interface MDNSService {
  instance: string;
  type: string;
  host?: string;
  port?: number;
  addrs?: string[];
  txt?: string[];
  from: string;
}
/** Answer of the POST tools: a result, maybe partial with an error text. */
interface ToolResp<T> {
  result: T;
  error: string;
  seconds: number;
}

type Tab = "cidr" | "ping" | "trace" | "ports" | "hosts" | "mdns" | "dns";
const TABS: { id: Tab; label: string }[] = [
  { id: "cidr", label: "Netzrechner" },
  { id: "ping", label: "Ping" },
  { id: "trace", label: "Traceroute" },
  { id: "ports", label: "Port-Scan" },
  { id: "hosts", label: "IP-Scan" },
  { id: "mdns", label: "mDNS" },
  { id: "dns", label: "DNS" },
];

const ms = (v: number) => (v < 0 ? "–" : v < 10 ? `${v.toFixed(2)} ms` : `${v.toFixed(1)} ms`);

export default function Toolbox() {
  const [tab, setTab] = useState<Tab>(() => {
    const h = window.location.hash.slice(1) as Tab;
    return TABS.some((t) => t.id === h) ? h : "cidr";
  });
  // Host handed from one tool to another ("Ports prüfen" in the IP-Scan).
  const [handoff, setHandoff] = useState("");
  const info = useLoad(() => api.get<{ networks: string[] | null; commonPorts: number[] }>("/api/tools"));

  const go = (t: Tab, host = "") => {
    setHandoff(host);
    setTab(t);
    history.replaceState(null, "", "#" + t);
  };

  return (
    <>
      <PageHead title="Toolbox" sub="Netzwerk-Werkzeuge – sie laufen auf dem Server, also aus Sicht von Caddy." />
      <div className="tabs" role="tablist">
        {TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={tab === t.id} className={`tab ${tab === t.id ? "active" : ""}`} onClick={() => go(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      <ErrorBox error={info.error} />
      {tab === "cidr" && <CIDRTool networks={info.data?.networks ?? []} />}
      {tab === "ping" && <PingTool initial={handoff} />}
      {tab === "trace" && <TraceTool initial={handoff} />}
      {tab === "ports" && <PortsTool initial={handoff} common={info.data?.commonPorts ?? []} />}
      {tab === "hosts" && <HostsTool networks={info.data?.networks ?? []} go={go} />}
      {tab === "mdns" && <MDNSTool go={go} />}
      {tab === "dns" && <DNSTool initial={handoff} />}
    </>
  );
}

// ---------- Shared pieces ----------

/** Runs one POST tool; the server allows only one at a time. */
function useTool<T>(path: string) {
  const [resp, setResp] = useState<ToolResp<T> | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const run = async (body: unknown) => {
    setBusy(true);
    setErr(null);
    setResp(null);
    try {
      setResp(await api.post<ToolResp<T>>(path, body));
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };
  return { resp, err, busy, run };
}

function ToolForm({ onRun, busy, label, children, hint }: { onRun: () => void; busy: boolean; label: string; children: ReactNode; hint?: ReactNode }) {
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!busy) onRun();
  };
  return (
    <form className="card stack" onSubmit={submit}>
      <div className="tool-form">
        {children}
        <button className="btn primary" type="submit" disabled={busy}>
          {busy ? <Spinner /> : <IconPlayerPlay size={16} />} {label}
        </button>
      </div>
      {hint && <div className="small muted">{hint}</div>}
    </form>
  );
}

function Status({ busy, err, resp, wait }: { busy: boolean; err: unknown; resp: ToolResp<unknown> | null; wait: string }) {
  if (busy)
    return (
      <div className="card row muted">
        <Spinner /> {wait}
      </div>
    );
  return (
    <>
      <ErrorBox error={err} />
      {resp?.error && <div className="alert warn">{resp.error}</div>}
    </>
  );
}

function Took({ s }: { s: number }) {
  return <span className="small muted">Dauer {s < 1 ? `${Math.round(s * 1000)} ms` : `${s.toFixed(1)} s`}</span>;
}

// ---------- Netzrechner ----------

function CIDRTool({ networks }: { networks: string[] }) {
  const [q, setQ] = useState(networks[0] ?? "");
  const [info, setInfo] = useState<CIDRInfo | null>(null);
  const [err, setErr] = useState("");
  // The server's networks arrive after the first render.
  useEffect(() => {
    if (networks[0]) setQ((v) => v || networks[0]);
  }, [networks]);
  useEffect(() => {
    if (!q.trim()) {
      setInfo(null);
      setErr("");
      return;
    }
    let alive = true;
    const t = setTimeout(() => {
      api
        .get<CIDRInfo>("/api/tools/cidr?q=" + encodeURIComponent(q.trim()))
        .then((d) => alive && (setInfo(d), setErr("")))
        .catch((e) => alive && (setInfo(null), setErr(errMsg(e))));
    }, 200);
    return () => {
      alive = false;
      clearTimeout(t);
    };
  }, [q]);

  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [cidrs, setCidrs] = useState<string[] | null>(null);
  const [rangeErr, setRangeErr] = useState("");
  const convert = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const r = await api.get<{ cidrs: string[] }>(`/api/tools/cidr?from=${encodeURIComponent(from.trim())}&to=${encodeURIComponent(to.trim())}`);
      setCidrs(r.cidrs);
      setRangeErr("");
    } catch (e) {
      setCidrs(null);
      setRangeErr(errMsg(e));
    }
  };

  return (
    <div className="grid grid-2" style={{ alignItems: "start" }}>
      <div className="card stack">
        <h2 style={{ margin: 0 }}>CIDR-Rechner</h2>
        <label className="field">
          Netz oder Adresse mit Präfix
          <input className="mono" value={q} onChange={(e) => setQ(e.target.value)} placeholder="10.0.0.0/8, 192.168.1.17/24, 2001:db8::/48" spellCheck={false} />
          <span className="hint">Rechnet beim Tippen. Eine Host-Adresse wie 192.168.1.17/24 zeigt das Netz, in dem sie liegt.</span>
        </label>
        {networks.length > 0 && (
          <div className="chips">
            {networks.map((n) => (
              <button key={n} type="button" className="btn sm" onClick={() => setQ(n)}>
                {n}
              </button>
            ))}
          </div>
        )}
        {err && <div className="small" style={{ color: "var(--danger)" }}>{err}</div>}
        {info && (
          <dl className="cert-dl mono-dd">
            <dt>Netz</dt>
            <dd>
              {info.network} <Badge kind={info.private ? "info" : "warn"}>{info.private ? "privat" : "öffentlich"}</Badge>
            </dd>
            {info.contains && (
              <>
                <dt>Eingegebene Adresse</dt>
                <dd>{info.contains}</dd>
              </>
            )}
            {info.netmask && (
              <>
                <dt>Netzmaske</dt>
                <dd>{info.netmask}</dd>
              </>
            )}
            {info.wildcard && (
              <>
                <dt>Wildcard</dt>
                <dd>{info.wildcard}</dd>
              </>
            )}
            <dt>Netzadresse</dt>
            <dd>{info.address}</dd>
            {info.broadcast && (
              <>
                <dt>Broadcast</dt>
                <dd>{info.broadcast}</dd>
              </>
            )}
            <dt>Erster Host</dt>
            <dd>{info.first}</dd>
            <dt>Letzter Host</dt>
            <dd>{info.last}</dd>
            <dt>Adressen</dt>
            <dd>
              {info.total} gesamt · {info.usable} nutzbar
            </dd>
          </dl>
        )}
      </div>

      <form className="card stack" onSubmit={convert}>
        <h2 style={{ margin: 0 }}>IP-Bereich → CIDR</h2>
        <div className="form-grid">
          <label className="field">
            Von
            <input className="mono" value={from} onChange={(e) => setFrom(e.target.value)} placeholder="192.168.1.10" spellCheck={false} />
          </label>
          <label className="field">
            Bis
            <input className="mono" value={to} onChange={(e) => setTo(e.target.value)} placeholder="192.168.1.70" spellCheck={false} />
          </label>
        </div>
        <button className="btn" type="submit" style={{ alignSelf: "flex-start" }} disabled={!from.trim() || !to.trim()}>
          Umrechnen
        </button>
        {rangeErr && <div className="small" style={{ color: "var(--danger)" }}>{rangeErr}</div>}
        {cidrs && (
          <>
            <div className="small muted">
              {cidrs.length} {cidrs.length === 1 ? "Block" : "Blöcke"} – z. B. für eine Access List:
            </div>
            <pre className="code">{cidrs.join("\n")}</pre>
          </>
        )}
      </form>
    </div>
  );
}

// ---------- Ping ----------

function PingTool({ initial }: { initial: string }) {
  const [host, setHost] = useState(initial || "1.1.1.1");
  const [count, setCount] = useState(4);
  const t = useTool<PingResult>("/api/tools/ping");
  const r = t.resp?.result;
  const maxRtt = Math.max(1, ...(r?.replies ?? []).map((x) => x.rttMs));
  return (
    <div className="stack">
      <ToolForm busy={t.busy} label="Ping" onRun={() => t.run({ host: host.trim(), count })}>
        <label className="field grow">
          Host oder IP
          <input className="mono" value={host} onChange={(e) => setHost(e.target.value)} spellCheck={false} />
        </label>
        <label className="field" style={{ width: 110 }}>
          Anzahl
          <input type="number" min={1} max={20} value={count} onChange={(e) => setCount(Number(e.target.value))} />
        </label>
      </ToolForm>
      <Status busy={t.busy} err={t.err} resp={t.resp} wait={`Sende ${count} Pakete an ${host} …`} />
      {r && (
        <div className="card stack">
          <div className="row">
            <h2 style={{ margin: 0 }}>
              {r.host} <span className="muted mono small">{r.addr !== r.host ? r.addr : ""}</span>
            </h2>
            <span className="spacer" />
            <Took s={t.resp!.seconds} />
          </div>
          <div className="row">
            <Badge kind={r.received === 0 ? "err" : r.loss > 0 ? "warn" : "ok"}>
              {r.received}/{r.sent} Antworten · {r.loss.toFixed(0)} % Verlust
            </Badge>
            {r.received > 0 && (
              <span className="small">
                min {ms(r.minMs)} · Ø {ms(r.avgMs)} · max {ms(r.maxMs)}
              </span>
            )}
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Zeit</th>
                  <th>TTL</th>
                  <th style={{ width: "50%" }}></th>
                </tr>
              </thead>
              <tbody>
                {(r.replies ?? []).map((p) => (
                  <tr key={p.seq}>
                    <td>{p.seq}</td>
                    <td className="mono">{p.rttMs < 0 ? <span style={{ color: "var(--danger)" }}>verloren</span> : ms(p.rttMs)}</td>
                    <td>{p.ttl || "–"}</td>
                    <td>{p.rttMs >= 0 && <div className="rtt-bar" style={{ width: `${Math.max(2, (p.rttMs / maxRtt) * 100)}%` }} />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------- Traceroute ----------

function TraceTool({ initial }: { initial: string }) {
  const [host, setHost] = useState(initial || "1.1.1.1");
  const [hops, setHops] = useState(30);
  const t = useTool<{ addr: string; hops: Hop[] | null }>("/api/tools/traceroute");
  const r = t.resp?.result;
  return (
    <div className="stack">
      <ToolForm busy={t.busy} label="Traceroute" onRun={() => t.run({ host: host.trim(), maxHops: hops })} hint="Je Station drei Pakete, eine Sekunde Wartezeit. Stationen ohne Antwort (*) filtern ICMP – das ist normal.">
        <label className="field grow">
          Host oder IP
          <input className="mono" value={host} onChange={(e) => setHost(e.target.value)} spellCheck={false} />
        </label>
        <label className="field" style={{ width: 110 }}>
          Max. Stationen
          <input type="number" min={1} max={64} value={hops} onChange={(e) => setHops(Number(e.target.value))} />
        </label>
      </ToolForm>
      <Status busy={t.busy} err={t.err} resp={t.resp} wait={`Verfolge den Weg zu ${host} – das kann bis zu einer Minute dauern …`} />
      {r && (
        <div className="card">
          <div className="row" style={{ marginBottom: 8 }}>
            <h2 style={{ margin: 0 }}>
              Weg zu {host} <span className="muted mono small">{r.addr}</span>
            </h2>
            <span className="spacer" />
            <Took s={t.resp!.seconds} />
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Station</th>
                  <th>Zeiten</th>
                </tr>
              </thead>
              <tbody>
                {(r.hops ?? []).map((h) => (
                  <tr key={h.ttl}>
                    <td>{h.ttl}</td>
                    <td>
                      {h.addr ? (
                        <>
                          <div className="mono">{h.addr}</div>
                          {h.name && <div className="small muted wrap-any">{h.name}</div>}
                        </>
                      ) : (
                        <span className="muted">*</span>
                      )}
                      {h.reached && <Badge kind="ok">Ziel</Badge>}
                    </td>
                    <td className="mono small">{(h.rttMs ?? []).map((v) => (v < 0 ? "*" : ms(v))).join("  ")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------- Port-Scan ----------

function PortsTool({ initial, common }: { initial: string; common: number[] }) {
  const [host, setHost] = useState(initial);
  const [ports, setPorts] = useState("");
  const t = useTool<{ addr: string; scanned: number; open: PortResult[] }>("/api/tools/ports");
  const r = t.resp?.result;
  return (
    <div className="stack">
      <ToolForm
        busy={t.busy}
        label="Scannen"
        onRun={() => t.run({ host: host.trim(), ports: ports.trim() })}
        hint={
          <>
            Leer = {common.length} häufige Ports. Bereiche gehen auch: <span className="mono">22,80,443,8000-8100</span> (höchstens 4096). Nur Netze scannen, die dir gehören.
          </>
        }
      >
        <label className="field grow">
          Host oder IP
          <input className="mono" value={host} onChange={(e) => setHost(e.target.value)} placeholder="192.168.1.10" spellCheck={false} />
        </label>
        <label className="field grow">
          Ports
          <input className="mono" value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="häufige Ports" spellCheck={false} />
        </label>
      </ToolForm>
      <Status busy={t.busy} err={t.err} resp={t.resp} wait={`Prüfe Ports auf ${host} …`} />
      {r && (
        <div className="card">
          <div className="row" style={{ marginBottom: 8 }}>
            <h2 style={{ margin: 0 }}>
              {r.open.length} von {r.scanned} Ports offen <span className="muted mono small">{r.addr}</span>
            </h2>
            <span className="spacer" />
            <Took s={t.resp!.seconds} />
          </div>
          {r.open.length === 0 ? (
            <div className="empty">Kein geprüfter Port antwortet – geschlossen oder von einer Firewall verworfen.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>Dienst</th>
                    <th>Antwortzeit</th>
                    <th>Banner</th>
                  </tr>
                </thead>
                <tbody>
                  {r.open.map((p) => (
                    <tr key={p.port}>
                      <td className="mono">{p.port}</td>
                      <td>{p.service || "–"}</td>
                      <td className="mono">{ms(p.rttMs)}</td>
                      <td className="mono small wrap-any">{p.banner || ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------- IP-Scan ----------

function HostsTool({ networks, go }: { networks: string[]; go: (t: Tab, host: string) => void }) {
  const [cidr, setCidr] = useState(networks[0] ?? "");
  useEffect(() => {
    if (!cidr && networks[0]) setCidr(networks[0]);
  }, [networks, cidr]);
  const t = useTool<{ hosts: HostResult[] }>("/api/tools/hosts");
  const r = t.resp?.result;
  return (
    <div className="stack">
      <ToolForm busy={t.busy} label="Netz scannen" onRun={() => t.run({ cidr: cidr.trim() })} hint="Ping an jede Adresse, wer nicht antwortet, wird noch auf ein paar TCP-Ports geprüft. Namen per Reverse-DNS, MAC aus der ARP-Tabelle des Servers.">
        <label className="field grow">
          Netz (CIDR)
          <input className="mono" list="tool-networks" value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="192.168.1.0/24" spellCheck={false} />
          <datalist id="tool-networks">
            {networks.map((n) => (
              <option key={n} value={n} />
            ))}
          </datalist>
        </label>
      </ToolForm>
      <Status busy={t.busy} err={t.err} resp={t.resp} wait={`Suche Geräte in ${cidr} – bei einem /24 etwa 10–20 Sekunden …`} />
      {r && (
        <div className="card">
          <div className="row" style={{ marginBottom: 8 }}>
            <h2 style={{ margin: 0 }}>{r.hosts.length} Geräte erreichbar</h2>
            <span className="spacer" />
            <Took s={t.resp!.seconds} />
          </div>
          {r.hosts.length === 0 ? (
            <div className="empty">Keine Antwort aus diesem Netz.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>IP</th>
                    <th>Name</th>
                    <th>MAC</th>
                    <th>Antwort</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {r.hosts.map((h) => (
                    <tr key={h.ip}>
                      <td className="mono">
                        {h.ip} {h.self && <Badge kind="info">dieser Server</Badge>}
                      </td>
                      <td className="wrap-any">{h.name || <span className="muted">–</span>}</td>
                      <td className="mono small">{h.mac || "–"}</td>
                      <td className="small">
                        {ms(h.rttMs)} <span className="muted">{h.via === "tcp" ? `TCP ${(h.openOn ?? []).join(", ")}` : "Ping"}</span>
                      </td>
                      <td>
                        <div className="row" style={{ justifyContent: "flex-end", flexWrap: "nowrap" }}>
                          <button className="btn sm" onClick={() => go("ports", h.ip)}>
                            Ports
                          </button>
                          <button className="btn sm" onClick={() => go("ping", h.ip)}>
                            Ping
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------- mDNS ----------

function MDNSTool({ go }: { go: (t: Tab, host: string) => void }) {
  const [secs, setSecs] = useState(4);
  const t = useTool<{ services: MDNSService[] }>("/api/tools/mdns");
  const svcs = t.resp?.result.services ?? [];
  const groups = new Map<string, MDNSService[]>();
  for (const s of svcs) groups.set(s.type, [...(groups.get(s.type) ?? []), s]);
  return (
    <div className="stack">
      <ToolForm busy={t.busy} label="Lauschen" onRun={() => t.run({ seconds: secs })} hint="Fragt per Multicast nach angekündigten Diensten (Drucker, Chromecast, Home Assistant …). Funktioniert nur im selben Netzsegment wie der Server.">
        <label className="field" style={{ width: 160 }}>
          Wartezeit
          <select value={secs} onChange={(e) => setSecs(Number(e.target.value))}>
            {[2, 4, 8, 15].map((s) => (
              <option key={s} value={s}>
                {s} Sekunden
              </option>
            ))}
          </select>
        </label>
      </ToolForm>
      <Status busy={t.busy} err={t.err} resp={t.resp} wait={`Lausche ${secs} Sekunden auf Antworten …`} />
      {t.resp && (
        <div className="card">
          <div className="row" style={{ marginBottom: 8 }}>
            <h2 style={{ margin: 0 }}>{svcs.length} Dienste gefunden</h2>
            <span className="spacer" />
            <Took s={t.resp.seconds} />
          </div>
          {svcs.length === 0 ? (
            <div className="empty">Nichts gehört. Im LXC/Container kommt Multicast oft nicht durch.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Dienst</th>
                    <th>Host</th>
                    <th>Adresse</th>
                    <th>Details</th>
                  </tr>
                </thead>
                {[...groups.entries()].map(([type, list]) => (
                  <tbody key={type}>
                    <tr>
                      <td colSpan={4} className="small muted mono" style={{ background: "var(--surface-2)" }}>
                        {type}
                      </td>
                    </tr>
                    {list.map((s) => {
                      // Devices announce many IPv6 addresses; IPv4 first, the rest folded.
                      const all = s.addrs?.length ? s.addrs : [s.from];
                      const sorted = [...all.filter((a) => !a.includes(":")), ...all.filter((a) => a.includes(":"))];
                      const addr = sorted[0];
                      return (
                        <tr key={s.instance + s.type}>
                          <td className="wrap-any">{s.instance}</td>
                          <td className="mono small wrap-any">{s.host || "–"}</td>
                          <td className="mono small">
                            <span title={sorted.join("\n")}>
                              {addr}
                              {s.port ? `:${s.port}` : ""}
                              {sorted.length > 1 && <span className="muted"> +{sorted.length - 1}</span>}
                            </span>{" "}
                            {addr && (
                              <button className="btn sm ghost" onClick={() => go("ports", addr)}>
                                Ports
                              </button>
                            )}
                          </td>
                          <td className="small muted wrap-any">{(s.txt ?? []).join(" · ")}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                ))}
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------- DNS ----------

function DNSTool({ initial }: { initial: string }) {
  const [name, setName] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [recs, setRecs] = useState<{ type: string; value: string }[] | null>(null);
  const run = async () => {
    setBusy(true);
    setErr(null);
    setRecs(null);
    try {
      const r = await api.get<{ records: { type: string; value: string }[] | null }>("/api/tools/dns?name=" + encodeURIComponent(name.trim()));
      setRecs(r.records ?? []);
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack">
      <ToolForm busy={busy} label="Abfragen" onRun={run} hint="Fragt den DNS-Resolver des Servers – also genau das, was auch Caddy sieht. Eine IP ergibt den Reverse-Eintrag (PTR).">
        <label className="field grow">
          Name oder IP
          <input className="mono" value={name} onChange={(e) => setName(e.target.value)} placeholder="example.com" spellCheck={false} />
        </label>
      </ToolForm>
      <ErrorBox error={err} />
      {recs && (
        <div className="card">
          {recs.length === 0 ? (
            <div className="empty">Keine Einträge.</div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Typ</th>
                    <th>Wert</th>
                  </tr>
                </thead>
                <tbody>
                  {recs.map((r, i) => (
                    <tr key={i}>
                      <td>
                        <Badge>{r.type}</Badge>
                      </td>
                      <td className="mono wrap-any">{r.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
