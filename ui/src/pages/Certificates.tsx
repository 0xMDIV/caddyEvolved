import { useState } from "react";
import { api, CertificatesResponse, CertInfo, downloadFile, errMsg, expiryKind, fmtExpiry, fmtTime } from "../api";
import { Badge, ErrorBox, PageHead, Spinner, useLoad, useToast } from "../components/ui";

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

      <div className="card">
        {list.loading && !list.data ? (
          <div className="empty">
            <Spinner />
          </div>
        ) : certs.length === 0 ? (
          <div className="empty">
            Noch keine Zertifikate. Caddy holt sie beim ersten Aufruf einer Site mit automatischem TLS – dafür müssen Port 80/443 von außen
            erreichbar sein und die Domain auf diesen Server zeigen.
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
