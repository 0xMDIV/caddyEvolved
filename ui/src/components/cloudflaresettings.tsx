import { useEffect, useState } from "react";
import { api, CloudflareSettings, errMsg } from "../api";
import { ToggleRow } from "./siteform";
import { Badge, ErrorBox, Spinner, useToast } from "./ui";

interface Draft {
  apiToken: string;
  email: string;
  target: string;
  proxied: boolean;
}

/** CloudflareCard stores the token sites use to create their DNS records. */
export function CloudflareCard() {
  const [s, setS] = useState<CloudflareSettings | null>(null);
  const [d, setD] = useState<Draft | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState("");
  const [test, setTest] = useState("");
  const toast = useToast();

  const apply = (r: CloudflareSettings) => {
    setS(r);
    setD({ apiToken: "", email: r.email, target: r.target, proxied: r.proxied });
  };
  useEffect(() => {
    api.get<CloudflareSettings>("/api/cloudflare").then(apply).catch(setErr);
  }, []);

  if (!s || !d) return <div className="card">{err ? <ErrorBox error={err} /> : <Spinner />}</div>;

  async function act(name: string, fn: () => Promise<CloudflareSettings>, msg: string) {
    setBusy(name);
    setErr(null);
    try {
      apply(await fn());
      toast("ok", msg);
    } catch (e) {
      setErr(e);
    } finally {
      setBusy("");
    }
  }

  async function runTest() {
    setBusy("test");
    setTest("");
    try {
      const r = await api.post<{ zones: string[]; target: string; type: string; targetError: string }>("/api/cloudflare/test");
      const zones = r.zones.length ? r.zones.join(", ") : "keine – der Token braucht Zone: Lesen";
      const target = r.target ? `neue Einträge: ${r.type} → ${r.target}` : `Ziel unbekannt (${r.targetError})`;
      setTest(`Zonen: ${zones} · ${target}`);
    } catch (e) {
      setTest("Fehler: " + errMsg(e));
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="card stack" id="cloudflare" style={{ gap: 12, marginTop: 16 }}>
      <div className="row">
        <h2 style={{ margin: 0 }}>Cloudflare-DNS</h2>
        {s.source === "own" && <Badge kind="ok">eigener Token</Badge>}
        {s.source === "plugin" && <Badge kind="info">Token des DNS-Plugins</Badge>}
        {!s.source && <Badge>aus</Badge>}
      </div>
      <div className="small muted">
        Sites mit dem Schalter „DNS-Eintrag bei Cloudflare anlegen“ bekommen beim Speichern ihren Eintrag: fehlt er, legt caddyEvolved ihn an; gibt es ihn schon,
        bleibt das Ziel unverändert und nur Proxy an/aus wird angepasst. Gelöscht wird nie etwas. Token anlegen unter Cloudflare → Mein Profil → API-Token,
        Vorlage „Zone-DNS bearbeiten“, Zonen: alle oder deine Domains.
      </div>
      <div className="form-grid">
        <label className="field">
          API-Token
          <input
            type="password"
            autoComplete="off"
            value={d.apiToken}
            placeholder={s.keyHint ? `gespeichert: ${s.keyHint} – leer lassen zum Behalten` : s.source === "plugin" ? "leer = Token des Cloudflare-DNS-Plugins" : ""}
            onChange={(e) => setD({ ...d, apiToken: e.target.value })}
          />
        </label>
        <label className="field">
          E-Mail (nur für Global API Key)
          <input value={d.email} placeholder="leer bei API-Token" onChange={(e) => setD({ ...d, email: e.target.value })} />
        </label>
        <label className="field">
          Ziel neuer Einträge
          <input className="mono" value={d.target} placeholder="leer = öffentliche IPv4 dieses Servers" onChange={(e) => setD({ ...d, target: e.target.value })} />
          <span className="hint">IPv4 → A-Eintrag, IPv6 → AAAA, Hostname (z. B. DynDNS-Name) → CNAME.</span>
        </label>
      </div>
      <ToggleRow
        checked={d.proxied}
        onChange={(v) => setD({ ...d, proxied: v })}
        label="Neue Sites über Cloudflare leiten (Proxy, orange Wolke)"
        hint="Vorgabe für neue Sites, pro Site änderbar. Mit Proxy sieht Caddy Cloudflares Adressen – dann in den globalen Einstellungen Cloudflare als CDN anhaken."
      />
      <ErrorBox error={err} />
      <div className="row">
        <button className="btn primary" disabled={!!busy} onClick={() => act("save", () => api.put<CloudflareSettings>("/api/cloudflare", d), "Cloudflare gespeichert")}>
          {busy === "save" && <Spinner />} Speichern
        </button>
        <button className="btn" disabled={!s.configured || !!busy} onClick={runTest}>
          {busy === "test" && <Spinner />} Verbindung testen
        </button>
        {s.source === "own" && (
          <button className="btn ghost" disabled={!!busy} onClick={() => act("forget", () => api.del<CloudflareSettings>("/api/cloudflare/token"), "Token entfernt")}>
            Token entfernen
          </button>
        )}
        {test && <span className="small">{test}</span>}
      </div>
    </div>
  );
}
