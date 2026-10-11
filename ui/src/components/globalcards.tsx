import { ReactNode, useEffect, useState } from "react";
import { api, GlobalOptions, GlobalResponse } from "../api";
import { Badge, ErrorBox, Spinner, Switch } from "./ui";

// Host-wide options (real client IPs, DynDNS, CrowdSec, Tailscale, cache).
// Every card edits its part and saves the whole object; the server validates,
// writes the global snippet and reloads caddy – or keeps the old state.


export function useGlobal() {
  const [data, setData] = useState<GlobalResponse | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const load = () =>
    api
      .get<GlobalResponse>("/api/global")
      .then((d) => (setData(d), setErr(null)))
      .catch(setErr);
  useEffect(() => {
    load();
  }, []);
  return { data, err, reload: load };
}

/** Local draft of one part of the options with a save button. */
function useDraft<T>(value: T) {
  const [draft, setDraft] = useState<T>(value);
  const key = JSON.stringify(value);
  useEffect(() => setDraft(value), [key]); // eslint-disable-line react-hooks/exhaustive-deps
  return [draft, setDraft, JSON.stringify(draft) !== key] as const;
}

function SaveRow({ dirty, onSave, err, label = "Speichern & übernehmen" }: { dirty: boolean; onSave: () => Promise<void>; err: unknown; label?: string }) {
  const [busy, setBusy] = useState(false);
  return (
    <>
      <ErrorBox error={err} />
      <div className="row">
        <button
          className="btn primary"
          disabled={!dirty || busy}
          onClick={async () => {
            setBusy(true);
            try {
              await onSave();
            } finally {
              setBusy(false);
            }
          }}
        >
          {busy && <Spinner />} {label}
        </button>
        {dirty && <span className="small muted">Caddy prüft die Änderung, bevor sie live geht.</span>}
      </div>
    </>
  );
}

/** Saves the whole options object and reports caddy's verdict. */
export function useSaver(g: GlobalOptions, onSaved: () => void) {
  const [err, setErr] = useState<unknown>(null);
  const save = async (next: GlobalOptions) => {
    setErr(null);
    try {
      await api.put("/api/global", next);
      onSaved();
    } catch (e) {
      setErr(e);
    }
  };
  return { err, save: (patch: Partial<GlobalOptions>) => save({ ...g, ...patch }) };
}

// ---------- Echte Besucher-IPs ----------

export function RealIPCard({ data, onSaved }: { data: GlobalResponse; onSaved: () => void }) {
  const g = data.global;
  const [d, setD, dirty] = useDraft({ cloudflare: g.realIp.cloudflare, proxies: (g.realIp.proxies ?? []).join("\n") });
  const { err, save } = useSaver(g, onSaved);
  return (
    <div className="card stack" style={{ gap: 12 }}>
      <div className="row">
        <h2 style={{ margin: 0, fontSize: 15 }}>Echte Besucher-IPs</h2>
        {g.realIp.cloudflare || (g.realIp.proxies ?? []).length ? <Badge kind="ok">aktiv</Badge> : <Badge>aus</Badge>}
      </div>
      <div className="small muted">
        Steht ein Proxy vor Caddy (z. B. die orange Wolke von Cloudflare), sieht Caddy sonst nur dessen Adresse – Access Lists, Rate Limit, CrowdSec und
        Logs arbeiten dann mit der falschen IP. Kein Plugin nötig.
      </div>
      <label className="toggle-row">
        <Switch checked={d.cloudflare} onChange={(v) => setD({ ...d, cloudflare: v })} label="Cloudflare" />
        <span>
          <span className="toggle-label">Domains laufen über den Cloudflare-Proxy</span>
          <span className="hint">
            {data.caps.cloudflareIp
              ? "Die Liste der Cloudflare-Adressen holt das Plugin alle 12 Stunden frisch."
              : "Nutzt die eingebaute Liste der Cloudflare-Adressen. Mit dem Plugin „Cloudflare-IP-Liste“ bleibt sie automatisch aktuell."}
          </span>
        </span>
      </label>
      <label className="field">
        Weitere Proxys davor (IP oder Bereich, einer pro Zeile)
        <textarea className="mono" rows={2} value={d.proxies} placeholder="z. B. 192.168.10.1 oder 10.0.0.0/8" onChange={(e) => setD({ ...d, proxies: e.target.value })} />
      </label>
      <SaveRow
        dirty={dirty}
        err={err}
        onSave={() => save({ realIp: { cloudflare: d.cloudflare, proxies: d.proxies.split(/\s+/).filter(Boolean) } })}
      />
    </div>
  );
}

// ---------- Plugin-spezifische Teile ----------

/** Extra settings below a plugin card, keyed by catalog id. */
export function GlobalPluginSettings({ id, data, onSaved }: { id: string; data: GlobalResponse; onSaved: () => void }): ReactNode {
  switch (id) {
    case "dynamic-dns":
      return <DynDNSSettings data={data} onSaved={onSaved} />;
    case "crowdsec":
      return <CrowdSecSettings data={data} onSaved={onSaved} />;
    case "tailscale":
      return <TailscaleSettings data={data} onSaved={onSaved} />;
    case "souin-cache":
      return <CacheSettings data={data} onSaved={onSaved} />;
    case "brotli":
      return <div className="small muted">Kein Schalter nötig: Sites mit „Komprimierung“ liefern br aus, wenn der Browser es bevorzugt.</div>;
    case "webdav":
      return <div className="small muted">Unter Sites → Neue Site die Art „WebDAV“ wählen. Mit einer Access List mit Benutzern absichern.</div>;
    case "cloudflare-ip":
      return <div className="small muted">Wird von „Echte Besucher-IPs“ oben genutzt.</div>;
    case "crowdsec-appsec":
      return <div className="small muted">Die AppSec-Adresse steht in der CrowdSec-Karte.</div>;
    case "otter-cache":
      return <div className="small muted">Speicher für den Souin-Cache – Einstellungen dort.</div>;
  }
  return null;
}

function DynDNSSettings({ data, onSaved }: { data: GlobalResponse; onSaved: () => void }) {
  const g = data.global;
  const rows = (g.dynDns.domains ?? []).map((z) => `${z.zone} ${z.names.join(" ")}`).join("\n");
  const [d, setD, dirty] = useDraft({
    enabled: g.dynDns.enabled,
    provider: g.dynDns.provider || data.dnsProviders[0]?.id || "",
    rows,
    interval: g.dynDns.interval || "5m",
    ipv6: g.dynDns.ipv6,
  });
  const { err, save } = useSaver(g, onSaved);
  const provider = data.dnsProviders.find((p) => p.id === d.provider);
  if (data.dnsProviders.length === 0) {
    return <div className="alert warn small">DynDNS braucht zusätzlich ein DNS-Anbieter-Plugin (z. B. Cloudflare) – unter „Neuer Build“ einbauen.</div>;
  }
  return (
    <div className="stack" style={{ gap: 10 }}>
      <label className="toggle-row">
        <Switch checked={d.enabled} onChange={(v) => setD({ ...d, enabled: v })} label="DynDNS aktiv" />
        <span>
          <span className="toggle-label">DNS-Einträge auf die aktuelle öffentliche IP halten</span>
          <span className="hint">Prüft regelmäßig die IP und ändert die Einträge nur, wenn sie sich geändert hat.</span>
        </span>
      </label>
      <div className="form-grid">
        <label className="field">
          DNS-Anbieter
          <select value={d.provider} onChange={(e) => setD({ ...d, provider: e.target.value })}>
            {data.dnsProviders.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.ready ? "" : " (Zugangsdaten fehlen)"}
              </option>
            ))}
          </select>
          {provider && !provider.ready && <span className="hint">Zuerst die Zugangsdaten in der Karte von {provider.name} speichern.</span>}
        </label>
        <label className="field">
          Prüfen alle
          <select value={d.interval} onChange={(e) => setD({ ...d, interval: e.target.value })}>
            {["1m", "5m", "15m", "1h"].map((x) => (
              <option key={x} value={x}>
                {x.replace("m", " Minuten").replace("1h", "1 Stunde").replace("1 Minuten", "1 Minute")}
              </option>
            ))}
          </select>
        </label>
        <label className="field full">
          Domains (eine Zone pro Zeile, danach die Einträge)
          <textarea className="mono" rows={3} value={d.rows} placeholder={"example.com @ www\nexample.net home"} onChange={(e) => setD({ ...d, rows: e.target.value })} />
          <span className="hint">@ ist die Domain selbst. „example.com @ vault“ hält example.com und vault.example.com aktuell.</span>
        </label>
      </div>
      <label className="check small">
        <input type="checkbox" checked={d.ipv6} onChange={(e) => setD({ ...d, ipv6: e.target.checked })} /> auch IPv6 (AAAA-Einträge)
      </label>
      <SaveRow
        dirty={dirty}
        err={err}
        onSave={() =>
          save({
            dynDns: {
              enabled: d.enabled,
              provider: d.provider,
              interval: d.interval,
              ipv6: d.ipv6,
              domains: d.rows
                .split("\n")
                .map((l) => l.trim().split(/\s+/).filter(Boolean))
                .filter((p) => p.length > 0)
                .map(([zone, ...names]) => ({ zone, names })),
            },
          })
        }
      />
    </div>
  );
}

function CrowdSecSettings({ data, onSaved }: { data: GlobalResponse; onSaved: () => void }) {
  const g = data.global;
  const [d, setD, dirty] = useDraft({ enabled: g.crowdsec.enabled, apiUrl: g.crowdsec.apiUrl || "http://127.0.0.1:8080", appsecUrl: g.crowdsec.appsecUrl || "" });
  const { err, save } = useSaver(g, onSaved);
  return (
    <div className="stack" style={{ gap: 10 }}>
      <label className="toggle-row">
        <Switch checked={d.enabled} onChange={(v) => setD({ ...d, enabled: v })} label="CrowdSec aktiv" />
        <span>
          <span className="toggle-label">Bekannte Angreifer auf allen Sites sperren</span>
          <span className="hint">Ausnahmen pro Site unter Sites → Bearbeiten → Zugriff und Schutz. Ist CrowdSec nicht erreichbar, lässt Caddy weiter alles durch.</span>
        </span>
      </label>
      <div className="form-grid">
        <label className="field">
          Adresse der Local API
          <input className="mono" value={d.apiUrl} onChange={(e) => setD({ ...d, apiUrl: e.target.value })} />
        </label>
        {data.caps.appsec && (
          <label className="field">
            AppSec-Adresse (optional)
            <input className="mono" value={d.appsecUrl} placeholder="http://127.0.0.1:7422" onChange={(e) => setD({ ...d, appsecUrl: e.target.value })} />
          </label>
        )}
      </div>
      <SaveRow dirty={dirty} err={err} onSave={() => save({ crowdsec: d })} />
    </div>
  );
}

function TailscaleSettings({ data, onSaved }: { data: GlobalResponse; onSaved: () => void }) {
  const g = data.global;
  const [d, setD, dirty] = useDraft(g.tailscale);
  const { err, save } = useSaver(g, onSaved);
  return (
    <div className="stack" style={{ gap: 10 }}>
      <label className="toggle-row">
        <Switch checked={d.enabled} onChange={(v) => setD({ ...d, enabled: v })} label="Tailscale aktiv" />
        <span>
          <span className="toggle-label">Sites dürfen sich ins Tailnet einklinken</span>
          <span className="hint">Pro Site unter Sites → Bearbeiten einen Tailnet-Namen setzen; die Domain ist dann name.dein-tailnet.ts.net.</span>
        </span>
      </label>
      <label className="check small">
        <input type="checkbox" checked={d.ephemeral} onChange={(e) => setD({ ...d, ephemeral: e.target.checked })} /> flüchtige Knoten (verschwinden nach dem Trennen)
      </label>
      <SaveRow dirty={dirty} err={err} onSave={() => save({ tailscale: d })} />
    </div>
  );
}

function CacheSettings({ data, onSaved }: { data: GlobalResponse; onSaved: () => void }) {
  const g = data.global;
  const [d, setD, dirty] = useDraft({ enabled: g.cache.enabled, ttl: g.cache.ttl || "120s" });
  const { err, save } = useSaver(g, onSaved);
  return (
    <div className="stack" style={{ gap: 10 }}>
      <label className="toggle-row">
        <Switch checked={d.enabled} onChange={(v) => setD({ ...d, enabled: v })} label="Cache aktiv" />
        <span>
          <span className="toggle-label">Antworten zwischenspeichern</span>
          <span className="hint">Pro Site einschalten unter Sites → Bearbeiten. Was der Dienst als privat oder no-store markiert, wird nie gespeichert.</span>
        </span>
      </label>
      <label className="field" style={{ maxWidth: 220 }}>
        Standard-Haltezeit
        <select value={d.ttl} onChange={(e) => setD({ ...d, ttl: e.target.value })}>
          {["60s", "120s", "300s", "600s", "3600s"].map((x) => (
            <option key={x} value={x}>
              {parseInt(x) >= 120 ? `${parseInt(x) / 60} Minuten` : "1 Minute"}
            </option>
          ))}
        </select>
      </label>
      <SaveRow dirty={dirty} err={err} onSave={() => save({ cache: d })} />
    </div>
  );
}
