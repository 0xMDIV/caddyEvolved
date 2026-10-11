import { useState } from "react";
import { api, CertificatesResponse, CertInfo, downloadFile, errMsg, expiryKind, fmtExpiry, fmtTime, PendingCert, SitesResponse } from "../api";
import { Badge, ErrorBox, PageHead, Spinner, useAction, useLoad, useToast } from "../components/ui";
import { navigate } from "../router";

function SourceBadge({ c }: { c: CertInfo }) {
  if (c.staging) return <Badge kind="warn">Staging</Badge>;
  switch (c.source) {
    case "letsencrypt":
      return <Badge kind="ok">Let's Encrypt</Badge>;
    case "zerossl":
      return <Badge kind="ok">ZeroSSL</Badge>;
    case "internal":
      return <Badge kind="info">Intern</Badge>;
    default:
      return <Badge>{c.issuerKey}</Badge>;
  }
}

export default function Certificates() {
  const list = useLoad(() => api.get<CertificatesResponse>("/api/certificates"));
  const [downloading, setDownloading] = useState(false);
  const toast = useToast();

  async function downloadRoot() {
    setDownloading(true);
    try {
      await downloadFile("/api/certificates/root.crt", "caddy-local-root.crt");
    } catch (e) {
      toast("err", errMsg(e));
    } finally {
      setDownloading(false);
    }
  }

  const certs = [...(list.data?.certificates ?? [])].sort((a, b) => new Date(a.notAfter).getTime() - new Date(b.notAfter).getTime());
  return (
    <>
      <PageHead
        title="Zertifikate"
        sub="Von Caddy verwaltete Zertifikate. Caddy holt und erneuert sie selbst – ACME-Zertifikate rund 30 Tage vor Ablauf, interne alle paar Stunden."
      >
        <button className="btn" onClick={list.reload} disabled={list.loading}>
          {list.loading && <Spinner />} Aktualisieren
        </button>
      </PageHead>
      <ErrorBox error={list.error} />

      {(list.data?.pending ?? []).length > 0 && <PendingCard pending={list.data!.pending!} onChange={list.reload} />}

      <div className="card">
        {list.loading && !list.data ? (
          <div className="empty">
            <Spinner />
          </div>
        ) : certs.length === 0 ? (
          <div className="empty">
            {(list.data?.pending ?? []).length > 0
              ? "Noch kein Zertifikat ausgestellt – den Grund zeigt die Karte oben."
              : "Noch keine Zertifikate. Caddy holt sie, sobald eine Site mit HTTPS „Automatisch“ oder „DNS-Challenge“ angelegt ist."}
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Domains</th>
                  <th>Quelle</th>
                  <th>Aussteller</th>
                  <th>Gültig bis</th>
                  <th>Sites</th>
                </tr>
              </thead>
              <tbody>
                {certs.map((c) => (
                  <tr key={c.issuerKey + "/" + c.name}>
                    <td>
                      <div className="mono small" style={{ fontWeight: 600 }}>
                        {(c.domains ?? [c.name]).join(", ")}
                      </div>
                      <div className="small muted">{c.keyType}</div>
                    </td>
                    <td>
                      <SourceBadge c={c} />
                    </td>
                    <td className="small">{c.issuer || "–"}</td>
                    <td>
                      <div className="small">{fmtTime(c.notAfter)}</div>
                      <Badge kind={expiryKind(c)}>{fmtExpiry(c)}</Badge>
                    </td>
                    <td>
                      <div className="chips">
                        {(c.sites ?? []).map((s) => (
                          <Badge key={s}>{s}</Badge>
                        ))}
                        {(c.sites ?? []).length === 0 && <span className="muted small">–</span>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {list.data && <p className="small muted" style={{ marginBottom: 0 }}>Speicherort: <code>{list.data.storage}</code></p>}
      </div>

      <div className="card" style={{ marginTop: 16 }}>
        <h2>Interne CA (TLS „intern“)</h2>
        <p className="small">
          Sites mit TLS „intern“ bekommen Zertifikate von Caddys eigener CA. Damit Browser im LAN ihnen vertrauen, das Root-Zertifikat
          einmal importieren: Windows – Doppelklick → „Zertifikat installieren“ → „Vertrauenswürdige Stammzertifizierungsstellen“; macOS –
          Schlüsselbundverwaltung → System → „Immer vertrauen“; Firefox – Einstellungen → Zertifikate → Importieren.
        </p>
        {list.data?.internalCA ? (
          <button className="btn primary" onClick={downloadRoot} disabled={downloading}>
            {downloading && <Spinner />} Root-Zertifikat herunterladen
          </button>
        ) : (
          <div className="small muted">Die interne CA entsteht mit der ersten Site, die TLS „intern“ nutzt.</div>
        )}
      </div>
    </>
  );
}

const TLS_LABEL: Record<string, string> = { auto: "Automatisch (HTTP-Challenge)", dns: "DNS-Challenge" };

/** Domains of enabled sites that still have no certificate, with the reason. */
function PendingCard({ pending, onChange }: { pending: PendingCert[]; onChange: () => void }) {
  const sites = useLoad(() => api.get<SitesResponse>("/api/sites"));
  const { busy, run } = useAction();
  const cf = (sites.data?.dnsProviders ?? []).find((p) => p.id === "cloudflare");

  const retry = async () => {
    const r = await run("retry", () => api.post("/api/service/restart?unit=caddy.service"), "Caddy neu gestartet – versucht es jetzt erneut");
    if (r) setTimeout(onChange, 8000);
  };
  const toDNS = async (p: PendingCert) => {
    const site = sites.data?.sites?.find((s) => s.id === p.site);
    if (!site) return;
    const r = await run("dns-" + p.site, () => api.put(`/api/sites/${encodeURIComponent(site.id)}`, { ...site, tls: "dns", dnsProvider: "cloudflare" }), `${p.domain}: DNS-Challenge über Cloudflare aktiv`);
    if (r) {
      sites.reload();
      setTimeout(onChange, 8000);
    }
  };

  return (
    <div className="card stack" style={{ marginBottom: 16, gap: 12 }}>
      <div className="row">
        <h2 style={{ margin: 0 }}>Warten auf ein Zertifikat</h2>
        <Badge kind="warn">{pending.length}</Badge>
        <span className="spacer" />
        <button className="btn sm" onClick={retry} disabled={busy === "retry"} title="Caddy neu starten – danach versucht es sofort erneut">
          {busy === "retry" && <Spinner />} Erneut versuchen
        </button>
      </div>
      {pending.map((p) => (
        <div key={p.site + p.domain} className="pending-cert">
          <div className="row">
            <span className="mono" style={{ fontWeight: 600 }}>
              {p.domain}
            </span>
            <Badge>{p.tls === "dns" && p.dnsProvider ? `DNS · ${p.dnsProvider}` : TLS_LABEL[p.tls] ?? p.tls}</Badge>
            {p.cloudflare && <Badge kind="info">Cloudflare-Proxy</Badge>}
          </div>
          <div className="small">{p.hint}</div>
          {p.error && (
            <details className="small">
              <summary className="muted">Meldung von Caddy</summary>
              <pre className="code wrap" style={{ marginTop: 6 }}>{p.error}</pre>
            </details>
          )}
          {p.cloudflare && p.tls === "auto" && (
            <div className="row">
              {cf?.ready ? (
                <button className="btn primary sm" disabled={busy === "dns-" + p.site} onClick={() => toDNS(p)}>
                  {busy === "dns-" + p.site && <Spinner />} Auf DNS-Challenge (Cloudflare) umstellen
                </button>
              ) : (
                <button className="btn primary sm" onClick={() => navigate("/build")}>
                  {cf ? "Cloudflare-Token eintragen" : "Cloudflare-Plugin einrichten"}
                </button>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
