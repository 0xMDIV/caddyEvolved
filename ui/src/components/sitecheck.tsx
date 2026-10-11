import { useEffect, useState } from "react";
import {
  IconAlertTriangle,
  IconCertificate,
  IconCircleCheck,
  IconCircleX,
  IconInfoCircle,
  IconShieldCheck,
  IconShieldX,
  IconStethoscope,
  IconWorld,
  IconX,
} from "@tabler/icons-react";
import { api, fmtTime, Site } from "../api";
import { Badge, ErrorBox, Spinner } from "./ui";

type Level = "ok" | "warn" | "fail" | "info";

interface Finding {
  group: string;
  level: Level;
  title: string;
  detail?: string;
  hint?: string;
}

interface TestResponse {
  findings: Finding[];
  failures: number;
  warnings: number;
  publicIp: string;
  lanIp: string;
  extern: boolean;
  testedAt: string;
}

interface CertInfo {
  subject: string;
  issuer: string;
  dnsNames?: string[];
  notBefore: string;
  notAfter: string;
  daysLeft: number;
  serial: string;
  sha256: string;
  keyType: string;
  isCa: boolean;
  selfSigned: boolean;
  signatureAlgorithm: string;
}

interface DomainCert {
  domain: string;
  stored?: { issuer: string; notAfter: string; daysLeft: number; source: string; staging: boolean };
  chain?: CertInfo[];
  trusted: boolean;
  verifyError?: string;
  error?: string;
}

const LEVEL_ICON: Record<Level, JSX.Element> = {
  ok: <IconCircleCheck size={18} className="lvl-ok" />,
  warn: <IconAlertTriangle size={18} className="lvl-warn" />,
  fail: <IconCircleX size={18} className="lvl-fail" />,
  info: <IconInfoCircle size={18} className="lvl-info" />,
};

export type PanelTab = "test" | "cert";

export function SitePanel({ site, tab, onTab, onClose }: { site: Site; tab: PanelTab; onTab: (t: PanelTab) => void; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <aside className="panel" role="dialog" aria-label={`Site ${site.id}`} onClick={(e) => e.stopPropagation()}>
        <div className="panel-head">
          <div style={{ minWidth: 0 }}>
            <div style={{ fontWeight: 700, overflowWrap: "anywhere" }}>{site.domains.join(", ") || site.id}</div>
            <div className="small muted mono">{site.id}</div>
          </div>
          <button className="btn ghost sm" aria-label="Schließen" onClick={onClose}>
            <IconX size={16} />
          </button>
        </div>
        <div className="seg" style={{ alignSelf: "flex-start" }}>
          <button className={`seg-btn ${tab === "test" ? "active" : ""}`} onClick={() => onTab("test")}>
            <IconStethoscope size={14} style={{ verticalAlign: "-2px" }} /> Test
          </button>
          <button className={`seg-btn ${tab === "cert" ? "active" : ""}`} onClick={() => onTab("cert")}>
            <IconCertificate size={14} style={{ verticalAlign: "-2px" }} /> Zertifikat
          </button>
        </div>
        {tab === "test" ? <TestView site={site} /> : <CertView site={site} />}
      </aside>
    </div>
  );
}

function TestView({ site }: { site: Site }) {
  const [res, setRes] = useState<TestResponse | null>(null);
  const [busy, setBusy] = useState<"" | "local" | "extern">("");
  const [err, setErr] = useState<unknown>(null);

  async function run(extern: boolean) {
    setBusy(extern ? "extern" : "local");
    setErr(null);
    try {
      setRes(await api.post<TestResponse>(`/api/sites/${encodeURIComponent(site.id)}/test`, { extern }));
    } catch (e) {
      setErr(e);
    } finally {
      setBusy("");
    }
  }

  useEffect(() => {
    run(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [site.id]);

  return (
    <div className="stack" style={{ gap: 12 }}>
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <button className="btn" disabled={!!busy} onClick={() => run(false)}>
          {busy === "local" ? <Spinner /> : <IconStethoscope size={16} />} Erneut testen
        </button>
        <button className="btn" disabled={!!busy} onClick={() => run(true)} title="Ruft die Site über check-host.net von mehreren Orten im Internet auf">
          {busy === "extern" ? <Spinner /> : <IconWorld size={16} />} Von außen testen
        </button>
      </div>
      <p className="small muted" style={{ margin: 0 }}>
        Prüft DNS, Zertifikat, den Weg über Caddy auf dem Server und den öffentlichen Weg. „Von außen“ nutzt check-host.net (übermittelt die Adresse der
        Site) und dauert etwa 20 Sekunden.
      </p>
      <ErrorBox error={err} />
      {busy && !res && (
        <div className="empty">
          <Spinner />
        </div>
      )}
      {res && (
        <>
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            {res.failures > 0 ? (
              <Badge kind="err">{res.failures} Problem(e)</Badge>
            ) : res.warnings > 0 ? (
              <Badge kind="warn">{res.warnings} Hinweis(e)</Badge>
            ) : (
              <Badge kind="ok">alles in Ordnung</Badge>
            )}
            {res.extern && <Badge kind="info">inkl. Test von außen</Badge>}
            <span className="small muted">
              öffentliche IP {res.publicIp || "?"} · Server {res.lanIp || "?"} · {fmtTime(res.testedAt)}
            </span>
          </div>
          <ul className="findings">
            {res.findings.map((f, i) => (
              <li key={i} className={`finding lvl-${f.level}-row`}>
                {LEVEL_ICON[f.level]}
                <div style={{ minWidth: 0 }}>
                  <div className="finding-title">{f.title}</div>
                  {f.detail && <div className="small muted finding-detail">{f.detail}</div>}
                  {f.hint && f.level !== "ok" && <div className="small finding-hint">→ {f.hint}</div>}
                </div>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

function CertView({ site }: { site: Site }) {
  const [data, setData] = useState<{ tls: string; domains: DomainCert[] } | null>(null);
  const [err, setErr] = useState<unknown>(null);
  useEffect(() => {
    api
      .get<{ tls: string; domains: DomainCert[] }>(`/api/sites/${encodeURIComponent(site.id)}/certificate`)
      .then(setData)
      .catch(setErr);
  }, [site.id]);

  if (err) return <ErrorBox error={err} />;
  if (!data)
    return (
      <div className="empty">
        <Spinner />
      </div>
    );
  if (data.tls === "off") return <div className="empty">Diese Site läuft ohne TLS (nur HTTP) – es gibt kein Zertifikat.</div>;
  if (data.domains.length === 0) return <div className="empty">Keine einzelnen Namen (Wildcard oder Port) – im Browser prüfen.</div>;

  return (
    <div className="stack" style={{ gap: 14 }}>
      {data.domains.map((d) => (
        <div key={d.domain} className="cert-domain">
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            {d.chain?.length ? d.trusted ? <IconShieldCheck size={18} className="lvl-ok" /> : <IconShieldX size={18} className="lvl-warn" /> : <IconShieldX size={18} className="lvl-fail" />}
            <span className="mono" style={{ fontWeight: 600 }}>
              {d.domain}
            </span>
            {d.chain?.length ? (
              d.trusted ? (
                <Badge kind="ok">vertrauenswürdig</Badge>
              ) : (
                <Badge kind="warn">{site.tls === "internal" ? "interne CA" : "nicht vertrauenswürdig"}</Badge>
              )
            ) : (
              <Badge kind="err">kein Zertifikat</Badge>
            )}
          </div>
          {d.error && (
            <div className="small" style={{ marginTop: 6 }}>
              Caddy liefert für diesen Namen kein Zertifikat aus: <span className="mono">{d.error}</span>. Den Grund zeigt der Tab „Test“.
            </div>
          )}
          {d.verifyError && site.tls !== "internal" && <div className="small muted" style={{ marginTop: 6 }}>{d.verifyError}</div>}
          {site.tls === "internal" && d.chain?.length ? (
            <div className="small muted" style={{ marginTop: 6 }}>
              Ausgestellt von Caddys interner CA. Geräte vertrauen ihr, sobald die Root-CA (Seite Zertifikate) importiert ist.
            </div>
          ) : null}
          {d.stored && (
            <div className="small" style={{ marginTop: 6 }}>
              Gespeichert: {d.stored.issuer} · gültig bis {fmtTime(d.stored.notAfter)}{d.stored.staging ? " · Staging" : ""}
            </div>
          )}
          {d.chain?.map((c, i) => (
            <div key={i} className="cert-card">
              <div className="small muted">{i === 0 ? "Zertifikat" : c.selfSigned ? "Root" : "Zwischenzertifikat"}</div>
              <dl className="cert-dl">
                <dt>Antragsteller</dt>
                <dd className="mono">{c.subject || <span className="muted">leer – üblich, der Name steht unter „Namen“</span>}</dd>
                <dt>Aussteller</dt>
                <dd className="mono">{c.issuer}</dd>
                {i === 0 && c.dnsNames && c.dnsNames.length > 0 && (
                  <>
                    <dt>Namen</dt>
                    <dd className="mono">{c.dnsNames.join(", ")}</dd>
                  </>
                )}
                <dt>Gültig</dt>
                <dd>
                  {fmtTime(c.notBefore)} – {fmtTime(c.notAfter)}{" "}
                  <Validity notAfter={c.notAfter} shortLived={site.tls === "internal"} />
                </dd>
                <dt>Schlüssel</dt>
                <dd>
                  {c.keyType} · {c.signatureAlgorithm}
                </dd>
                <dt>Seriennr.</dt>
                <dd className="mono wrap-any">{c.serial}</dd>
                <dt>SHA-256</dt>
                <dd className="mono wrap-any small">{c.sha256.match(/.{1,2}/g)?.join(":")}</dd>
              </dl>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

/** Remaining validity; hours below two days. Caddy's internal CA issues
 * 12-hour certificates on purpose, so short is not a warning there. */
function Validity({ notAfter, shortLived }: { notAfter: string; shortLived: boolean }) {
  const hours = (new Date(notAfter).getTime() - Date.now()) / 3_600_000;
  if (hours < 0) return <Badge kind="err">abgelaufen</Badge>;
  const text = hours < 48 ? `noch ${Math.max(1, Math.round(hours))} Std.` : `noch ${Math.floor(hours / 24)} Tage`;
  const kind = shortLived || hours >= 14 * 24 ? "ok" : "warn";
  return <Badge kind={kind}>{text}</Badge>;
}
