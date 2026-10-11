import { useEffect, useState } from "react";
import { api, Firewall, FirewallResponse } from "../api";
import { navigate } from "../router";
import { CountryPicker, COUNTRY_PRESETS } from "./countries";
import { ListArea } from "./features";
import { Blocklists } from "./blocklists";
import { Badge, Switch, useAction } from "./ui";

// Data-center networks: real visitors rarely come from there, scanners do.
const ASN_PRESETS: { asn: number; name: string }[] = [
  { asn: 14061, name: "DigitalOcean" },
  { asn: 16276, name: "OVH" },
  { asn: 24940, name: "Hetzner" },
  { asn: 51167, name: "Contabo" },
  { asn: 16509, name: "Amazon AWS" },
  { asn: 396982, name: "Google Cloud" },
  { asn: 8075, name: "Microsoft Azure" },
  { asn: 31898, name: "Oracle Cloud" },
  { asn: 45102, name: "Alibaba Cloud" },
  { asn: 132203, name: "Tencent Cloud" },
  { asn: 63949, name: "Linode / Akamai" },
  { asn: 20473, name: "Vultr" },
  { asn: 12876, name: "Scaleway" },
  { asn: 9009, name: "M247" },
];

const fmtDate = (s?: string) => (s ? new Date(s).toLocaleString("de-DE", { dateStyle: "short", timeStyle: "short" }) : "–");

type GeoMode = "off" | "block" | "allow";

/** FirewallRules is the editor for the host-wide firewall. */
export function FirewallRules({ data, onSaved }: { data: FirewallResponse; onSaved: () => void }) {
  const [f, setF] = useState<Firewall>(data.firewall);
  const [mode, setMode] = useState<GeoMode>(data.firewall.allowCountries?.length ? "allow" : data.firewall.blockCountries?.length ? "block" : "off");
  const [countries, setCountries] = useState<string[]>(data.firewall.allowCountries?.length ? data.firewall.allowCountries : (data.firewall.blockCountries ?? []));
  const [asnText, setAsnText] = useState(() => (data.firewall.blockAsn ?? []).filter((a) => !ASN_PRESETS.some((p) => p.asn === a)).join(" "));
  const [key, setKey] = useState(0); // remounts the list fields after "add my IP"
  const { busy, run } = useAction();
  useEffect(() => setF(data.firewall), [data.firewall]);

  const set = <K extends keyof Firewall>(k: K, v: Firewall[K]) => setF((x) => ({ ...x, [k]: v }));
  const asn = new Set(f.blockAsn ?? []);
  const toggleAsn = (a: number, on: boolean) => set("blockAsn", on ? [...asn, a] : [...asn].filter((x) => x !== a));

  const save = () => {
    const extra = asnText.split(/[\s,;]+/).map((x) => parseInt(x.replace(/^AS/i, ""), 10)).filter((n) => n > 0);
    const body: Firewall = {
      ...f,
      blockAsn: [...new Set([...[...asn].filter((a) => ASN_PRESETS.some((p) => p.asn === a)), ...extra])],
      allowCountries: mode === "allow" ? countries : [],
      blockCountries: mode === "block" ? countries : [],
    };
    run("save", () => api.put("/api/firewall", body), "Firewall gespeichert und übernommen").then((r) => r && onSaved());
  };
  const refresh = () => run("refresh", () => api.post("/api/firewall/refresh"), "Listen aktualisiert").then((r) => r && onSaved());
  const addMine = () => {
    if (!data.yourIp || (f.allow ?? []).includes(data.yourIp)) return;
    set("allow", [...(f.allow ?? []), data.yourIp]);
    setKey((k) => k + 1);
  };
  const needsGeo = mode !== "off" || asn.size > 0 || asnText.trim() !== "";

  return (
    <div className="stack" style={{ gap: 16 }}>
      <div className="card stack" style={{ gap: 10 }}>
        <div className="row">
          <Switch checked={f.enabled} onChange={(v) => set("enabled", v)} label="Firewall aktiv" />
          <h2 style={{ margin: 0 }}>Firewall {f.enabled ? <Badge kind="ok">aktiv</Badge> : <Badge>aus</Badge>}</h2>
        </div>
        <span className="hint">
          Gilt für alle Sites, vor WAF, Bot-Abwehr und Rate Limit. Einzelne Sites lassen sich im Site-Formular ausnehmen. Dein eigenes Netz (private IPs) wird von
          Länder- und Netzregeln nie gesperrt.
        </span>
        <div className="inline-fields">
          <span className="small">Gesperrte Anfragen:</span>
          <label className="check">
            <input type="radio" checked={!f.drop} onChange={() => set("drop", false)} /> mit 403 abweisen
          </label>
          <label className="check">
            <input type="radio" checked={f.drop} onChange={() => set("drop", true)} /> Verbindung kommentarlos trennen
          </label>
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16 }}>
        <div className="card stack" style={{ gap: 8 }}>
          <h2 style={{ margin: 0, fontSize: 15 }}>Freigaben (Whitelist)</h2>
          <span className="hint">Diese IPs und Bereiche umgehen Firewall, WAF, Bot-Abwehr, Rate Limit und CrowdSec. Access Lists und der Dateischutz gelten weiter.</span>
          <ListArea key={`a${key}`} value={f.allow} onChange={(v) => set("allow", v)} rows={4} placeholder={"203.0.113.7\n198.51.100.0/24"} />
          {data.yourIp && (
            <button className="btn sm" style={{ alignSelf: "flex-start" }} onClick={addMine} disabled={(f.allow ?? []).includes(data.yourIp)}>
              + Meine IP ({data.yourIp})
            </button>
          )}
        </div>
        <div className="card stack" style={{ gap: 8 }}>
          <h2 style={{ margin: 0, fontSize: 15 }}>Gesperrt (Blacklist)</h2>
          <span className="hint">Einzelne IPs oder Bereiche (CIDR). Schneller geht es unter „Blockiert“ per Klick.</span>
          <ListArea key={`b${key}`} value={f.block} onChange={(v) => set("block", v)} rows={4} placeholder={"192.0.2.10\n198.51.100.0/24"} />
        </div>
      </div>

      <div className="card stack" style={{ gap: 10 }}>
        <div className="row">
          <h2 style={{ margin: 0, fontSize: 15 }}>Sperrlisten</h2>
          <span className="spacer" />
          <button className="btn sm" onClick={refresh} disabled={busy === "refresh"}>
            {busy === "refresh" ? "Lädt…" : "Jetzt aktualisieren"}
          </button>
        </div>
        <span className="hint">Werden täglich automatisch geladen. Private und reservierte Netze darin werden immer übersprungen; dein LAN bleibt also erreichbar.</span>
        <Blocklists lists={data.lists} f={f} onChange={setF} />
      </div>

      {needsGeo && !data.caps.geo && (
        <div className="card" style={{ borderColor: "var(--warn)" }}>
          Länder- und Netzregeln brauchen das Plugin <b>Geo-Blocking (MaxMind)</b>.{" "}
          <button className="link-btn" onClick={() => navigate("/build")}>
            Unter Plugins & Build einbauen
          </button>
          . Die Geodaten selbst lädt caddyEvolved kostenlos von DB-IP – ohne Account.
        </div>
      )}

      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16 }}>
        <div className="card stack" style={{ gap: 8 }}>
          <h2 style={{ margin: 0, fontSize: 15 }}>Länder</h2>
          <select value={mode} onChange={(e) => setMode(e.target.value as GeoMode)}>
            <option value="off">keine Länderregeln</option>
            <option value="block">diese Länder sperren</option>
            <option value="allow">nur diese Länder erlauben</option>
          </select>
          {mode !== "off" && (
            <>
              <CountryPicker value={countries} onChange={setCountries} />
              <div className="inline-fields">
                <span className="small muted">Schnell hinzufügen:</span>
                {Object.entries(COUNTRY_PRESETS).map(([n, cs]) => (
                  <button key={n} className="btn sm" onClick={() => setCountries([...new Set([...countries, ...cs])].sort())}>
                    {n}
                  </button>
                ))}
              </div>
            </>
          )}
          <span className="hint">
            Datenbank: {data.geo.country.path ? `DB-IP Lite, Stand ${fmtDate(data.geo.country.updated)}` : "wird beim Speichern geladen"}. IP-Geodaten von{" "}
            <a href="https://db-ip.com" target="_blank" rel="noreferrer">
              DB-IP.com
            </a>{" "}
            (CC BY 4.0), monatlich aktualisiert.
          </span>
        </div>
        <div className="card stack" style={{ gap: 8 }}>
          <h2 style={{ margin: 0, fontSize: 15 }}>Netzbetreiber (ASN)</h2>
          <span className="hint">Rechenzentren sperren: echte Besucher kommen selten von dort, Scanner und Bots oft. Nicht sperren, wenn eigene Server dort laufen.</span>
          <div className="check-grid">
            {ASN_PRESETS.map((p) => (
              <label key={p.asn} className="check small">
                <input type="checkbox" checked={asn.has(p.asn)} onChange={(e) => toggleAsn(p.asn, e.target.checked)} /> {p.name}{" "}
                <span className="muted mono">AS{p.asn}</span>
              </label>
            ))}
          </div>
          <label className="field">
            Weitere ASNs
            <input className="mono" value={asnText} placeholder="z. B. AS4134 3320" onChange={(e) => setAsnText(e.target.value)} />
          </label>
        </div>
      </div>

      <div className="row">
        <button className="btn primary" onClick={save} disabled={busy === "save"}>
          {busy === "save" ? "Speichert…" : "Speichern & übernehmen"}
        </button>
        <span className="hint">Caddy prüft die Regeln vor dem Übernehmen; bei einem Fehler bleibt der alte Stand aktiv.</span>
      </div>
    </div>
  );
}
