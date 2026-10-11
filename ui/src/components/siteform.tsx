import { ReactNode } from "react";
import { IconHelpCircle, IconLock, IconLockOpen, IconPlus, IconX } from "@tabler/icons-react";
import { SiteTLS } from "../api";
import { Switch } from "./ui";

// ---------- targets ----------

export interface Target {
  host: string;
  port: string;
}

/** Splits "https://192.168.10.5:8006/x" into scheme, host and port. */
export function parseTarget(raw: string): { target: Target; https?: boolean; droppedPath: boolean } {
  let s = raw.trim();
  let https: boolean | undefined;
  const m = /^(https?):\/\//i.exec(s);
  if (m) {
    https = m[1].toLowerCase() === "https";
    s = s.slice(m[0].length);
  }
  let droppedPath = false;
  const slash = s.indexOf("/");
  if (slash >= 0) {
    droppedPath = s.slice(slash).replace(/\/+$/, "") !== "";
    s = s.slice(0, slash);
  }
  // [v6]:port, v6 without port, host:port, host
  const v6 = /^\[([^\]]+)\](?::(\d*))?$/.exec(s);
  if (v6) return { target: { host: v6[1], port: v6[2] ?? "" }, https, droppedPath };
  if ((s.match(/:/g) ?? []).length > 1) return { target: { host: s, port: "" }, https, droppedPath };
  const [host, port = ""] = s.split(":");
  return { target: { host, port }, https, droppedPath };
}

export function formatTarget(t: Target): string {
  const host = t.host.trim();
  if (!host) return "";
  const h = host.includes(":") ? `[${host}]` : host;
  return t.port.trim() ? `${h}:${t.port.trim()}` : h;
}

interface Preset {
  name: string;
  port: string;
  https: boolean;
  insecure?: boolean;
}

const PRESETS: Preset[] = [
  { name: "Proxmox VE", port: "8006", https: true, insecure: true },
  { name: "Proxmox Backup", port: "8007", https: true, insecure: true },
  { name: "Home Assistant", port: "8123", https: false },
  { name: "Jellyfin", port: "8096", https: false },
  { name: "Portainer", port: "9443", https: true, insecure: true },
  { name: "UniFi", port: "8443", https: true, insecure: true },
  { name: "TrueNAS", port: "443", https: true, insecure: true },
  { name: "Nextcloud", port: "80", https: false },
];

export function TargetEditor({
  targets,
  https,
  insecure,
  onChange,
}: {
  targets: Target[];
  https: boolean;
  insecure: boolean;
  onChange: (v: { targets: Target[]; https: boolean; insecure: boolean; note?: string }) => void;
}) {
  const rows = targets.length ? targets : [{ host: "", port: "" }];
  const update = (i: number, t: Target) => onChange({ targets: rows.map((r, j) => (j === i ? t : r)), https, insecure });

  // A pasted URL ("http://…" or with a path) is split right away; a typed
  // "host:port" only when the field is left, so typing is never interrupted.
  function typedHost(i: number, value: string) {
    if (/^https?:\/\//i.test(value) || value.includes("/")) {
      splitHost(i, value);
      return;
    }
    update(i, { ...rows[i], host: value });
  }

  function splitHost(i: number, value: string) {
    const p = parseTarget(value);
    const next = rows.map((r, j) => (j === i ? { host: p.target.host, port: p.target.port || r.port } : r));
    onChange({
      targets: next,
      https: p.https ?? https,
      insecure: p.https === false ? false : insecure,
      note: p.droppedPath ? "Der Pfad wurde entfernt – Caddy leitet immer den aufgerufenen Pfad weiter." : undefined,
    });
  }

  function applyPreset(p: Preset) {
    const first = rows[0] ?? { host: "", port: "" };
    onChange({ targets: [{ ...first, port: p.port }, ...rows.slice(1)], https: p.https, insecure: !!p.insecure });
  }

  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="target-scheme">
        <span className="small muted">Ziel spricht</span>
        <div className="seg" role="radiogroup" aria-label="Protokoll zum Ziel">
          <button type="button" className={`seg-btn ${!https ? "active" : ""}`} onClick={() => onChange({ targets: rows, https: false, insecure: false })}>
            <IconLockOpen size={14} style={{ verticalAlign: "-2px" }} /> HTTP
          </button>
          <button type="button" className={`seg-btn ${https ? "active" : ""}`} onClick={() => onChange({ targets: rows, https: true, insecure })}>
            <IconLock size={14} style={{ verticalAlign: "-2px" }} /> HTTPS
          </button>
        </div>
      </div>

      {rows.map((t, i) => (
        <div key={i} className="target-row">
          <span className="target-prefix mono">{https ? "https://" : "http://"}</span>
          <input
            className="mono"
            value={t.host}
            placeholder="192.168.10.132 oder pve.lan"
            aria-label="Host des Ziels"
            onChange={(e) => typedHost(i, e.target.value)}
            onBlur={(e) => {
              const v = e.target.value;
              if ((v.match(/:/g) ?? []).length === 1 || /^\[.*\]:\d+$/.test(v)) splitHost(i, v);
            }}
          />
          <span className="mono muted">:</span>
          <input
            className="mono target-port"
            value={t.port}
            inputMode="numeric"
            placeholder={https ? "443" : "80"}
            aria-label="Port des Ziels"
            onChange={(e) => update(i, { ...t, port: e.target.value.replace(/[^0-9]/g, "") })}
          />
          {rows.length > 1 && (
            <button type="button" className="btn ghost sm" aria-label="Ziel entfernen" onClick={() => onChange({ targets: rows.filter((_, j) => j !== i), https, insecure })}>
              <IconX size={14} />
            </button>
          )}
        </div>
      ))}
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <button type="button" className="btn ghost sm" onClick={() => onChange({ targets: [...rows, { host: "", port: rows[0]?.port ?? "" }], https, insecure })}>
          <IconPlus size={14} /> weiteres Ziel (Lastverteilung)
        </button>
      </div>

      {https && (
        <ToggleRow
          checked={insecure}
          onChange={(v) => onChange({ targets: rows, https, insecure: v })}
          label="Zertifikat des Ziels nicht prüfen"
          hint="Für selbstsignierte Zertifikate, wie sie Proxmox, UniFi, TrueNAS oder Portainer mitbringen."
        />
      )}

      <div className="presets">
        <span className="small muted">Schnellwahl:</span>
        {PRESETS.map((p) => (
          <button key={p.name} type="button" className="preset" onClick={() => applyPreset(p)} title={`${p.https ? "HTTPS" : "HTTP"} · Port ${p.port}${p.insecure ? " · Zertifikat nicht prüfen" : ""}`}>
            {p.name}
          </button>
        ))}
      </div>
    </div>
  );
}

// ---------- TLS for visitors ----------

const TLS_OPTIONS: { value: SiteTLS; label: string; desc: string }[] = [
  { value: "auto", label: "Automatisch", desc: "Let's Encrypt / ZeroSSL. Die Domain muss aus dem Internet erreichbar sein (Port 80 und 443 weitergeleitet)." },
  { value: "dns", label: "DNS-Challenge", desc: "Zertifikat über die API deines DNS-Anbieters – auch für Wildcards und ohne offene Ports. Braucht ein DNS-Plugin." },
  { value: "internal", label: "Intern", desc: "Eigene CA für LAN-Namen wie nas.lan. Die Root-CA einmal auf den Geräten importieren (Seite Zertifikate)." },
  { value: "off", label: "Aus (nur HTTP)", desc: "Keine Verschlüsselung. Nur für Tests oder wenn davor schon ein anderer Proxy HTTPS macht." },
];

export function TlsPicker({ value, onChange }: { value: SiteTLS; onChange: (v: SiteTLS) => void }) {
  const current = TLS_OPTIONS.find((o) => o.value === value) ?? TLS_OPTIONS[0];
  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="seg seg-wrap" role="radiogroup" aria-label="HTTPS für Besucher">
        {TLS_OPTIONS.map((o) => (
          <button key={o.value} type="button" className={`seg-btn ${o.value === value ? "active" : ""}`} onClick={() => onChange(o.value)}>
            {o.label}
          </button>
        ))}
      </div>
      <span className="hint">{current.desc}</span>
    </div>
  );
}

// ---------- layout helpers ----------

export function ToggleRow({ checked, onChange, label, hint, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string; disabled?: boolean }) {
  return (
    <label className="toggle-row">
      <Switch checked={checked} onChange={onChange} disabled={disabled} label={label} />
      <span>
        <span className="toggle-label">{label}</span>
        {hint && <span className="hint">{hint}</span>}
      </span>
    </label>
  );
}

export function FormSection({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section className="form-section">
      <div className="form-section-head">
        <h3>{title}</h3>
        {aside}
      </div>
      {children}
    </section>
  );
}

export function SiteHelp() {
  return (
    <details className="help-box">
      <summary>
        <IconHelpCircle size={16} style={{ verticalAlign: "-3px" }} /> Hilfe: Was trage ich wo ein?
      </summary>
      <div className="help-body">
        <p>
          <b>Beispiel:</b> <span className="mono">pve.deinedomain.de</span> soll auf Proxmox unter{" "}
          <span className="mono">https://192.168.10.132:8006</span> zeigen.
        </p>
        <table className="help-table">
          <tbody>
            <tr>
              <th>Domains</th>
              <td>
                <span className="mono">pve.deinedomain.de</span> – der Name, den Besucher im Browser eintippen. Der DNS-Eintrag muss auf deine öffentliche IP
                zeigen.
              </td>
            </tr>
            <tr>
              <th>Ziel spricht</th>
              <td>
                <b>HTTPS</b> – so wie du den Dienst im LAN aufrufst. Proxmox, UniFi, TrueNAS und Portainer sprechen HTTPS, die meisten anderen Dienste HTTP.
              </td>
            </tr>
            <tr>
              <th>Host : Port</th>
              <td>
                <span className="mono">192.168.10.132</span> : <span className="mono">8006</span> – nur Adresse und Port, ohne <span className="mono">http://</span>{" "}
                und ohne Pfad. Eine komplette URL einfügen geht auch, sie wird zerlegt.
              </td>
            </tr>
            <tr>
              <th>Zertifikat nicht prüfen</th>
              <td>An, wenn das Ziel ein selbstsigniertes Zertifikat hat (Browser zeigt dort eine Warnung). Der Weg ist trotzdem verschlüsselt.</td>
            </tr>
            <tr>
              <th>HTTPS für Besucher</th>
              <td>
                Das Zertifikat, das Besucher sehen – unabhängig vom Ziel. <b>Automatisch</b> für öffentliche Domains, <b>Intern</b> fürs LAN.
              </td>
            </tr>
            <tr>
              <th>Mehrere Ziele</th>
              <td>Gleicher Dienst auf mehreren Servern: Caddy verteilt die Anfragen und lässt ausgefallene aus (Health-Check unter „Erweitert“).</td>
            </tr>
          </tbody>
        </table>
        <p className="small muted" style={{ margin: 0 }}>
          Funktioniert es nicht? Auf dem Server <span className="mono">sudo caddyevolved doctor</span> ausführen – prüft Ports, DNS und Zertifikate.
        </p>
      </div>
    </details>
  );
}
