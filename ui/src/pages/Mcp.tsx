import { useState } from "react";
import { api, defaultMcpEndpoint, downloadFile, errMsg, McpInfo, TokenCreated } from "../api";
import { navigate } from "../router";
import { CreateTokenForm, NewTokenBox, ScopeBadge } from "../components/tokens";
import { Badge, CopyBlock, ErrorBox, PageHead, Spinner, useLoad, useToast } from "../components/ui";

const TOKEN_PLACEHOLDER = "<TOKEN>";

function link(path: string, label: string) {
  return (
    <a
      href={path}
      onClick={(e) => {
        e.preventDefault();
        navigate(path);
      }}
    >
      {label}
    </a>
  );
}

export default function Mcp() {
  const info = useLoad(() => api.get<McpInfo>("/api/mcp/info"));
  const [created, setCreated] = useState<TokenCreated | null>(null);
  const [certBusy, setCertBusy] = useState(false);
  const toast = useToast();

  const endpoint = info.data?.endpoint || defaultMcpEndpoint();
  const token = created?.token ?? TOKEN_PLACEHOLDER;
  const tools = info.data?.tools ?? [];

  const cli = `claude mcp add --transport http caddyevolved ${endpoint} --header "Authorization: Bearer ${token}"`;
  const json = JSON.stringify(
    { mcpServers: { caddyevolved: { type: "http", url: endpoint, headers: { Authorization: `Bearer ${token}` } } } },
    null,
    2,
  );
  const curl = `curl -k -X POST ${endpoint} \\
  -H "Authorization: Bearer ${token}" \\
  -H "Content-Type: application/json" \\
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'`;

  async function downloadCert() {
    setCertBusy(true);
    try {
      await downloadFile("/api/ui.crt", "caddyevolved-ui.crt");
    } catch (e) {
      toast("err", errMsg(e));
    } finally {
      setCertBusy(false);
    }
  }

  return (
    <>
      <PageHead
        title="KI / MCP"
        sub="Model Context Protocol: KI-Assistenten wie Claude können caddyEvolved direkt bedienen – Sites anlegen, Logs lesen, Analytics auswerten."
      />

      <div className="grid grid-2" style={{ alignItems: "start" }}>
        <div className="card stack">
          <h2 style={{ margin: 0 }}>Endpoint</h2>
          <CopyBlock text={endpoint} />
          <p className="small muted" style={{ margin: 0 }}>
            Streamable HTTP, nur POST. Authentifizierung ausschließlich per API-Token im Header <span className="mono">Authorization: Bearer cev_…</span>.
            Unterstützt aktuelle (2026-07-28) und ältere MCP-Clients.
          </p>
          {info.error ? <div className="alert warn small">Server-Infos nicht abrufbar ({errMsg(info.error)}) – der Endpoint ist aus der aktuellen Adresse abgeleitet.</div> : null}
        </div>

        <div className="card stack">
          <h2 style={{ margin: 0 }}>Sicherheit</h2>
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
            <li>
              <ScopeBadge scope="read" /> Lese-Tokens bevorzugen: Die KI sieht dann nur lesende Werkzeuge.
            </li>
            <li>
              <ScopeBadge scope="write" /> Ein Schreib-Token erlaubt der KI, Sites, Access Lists und die Caddy-Binary zu ändern.
            </li>
            <li>Jeder Aufruf erscheint im {link("/audit", "Audit Log")} als „token &lt;name&gt; (mcp)“.</li>
            <li>Tokens lassen sich jederzeit in den {link("/settings", "Einstellungen")} widerrufen.</li>
          </ul>
        </div>
      </div>

      <div className="card stack" style={{ marginTop: 16 }}>
        <h2 style={{ margin: 0 }}>Einrichtung</h2>

        <h3 style={{ margin: 0 }}>1. Token erstellen</h3>
        {created ? (
          <NewTokenBox created={created} />
        ) : (
          <>
            <CreateTokenForm defaultName="KI-Client" compact onCreated={setCreated} />
            <p className="small muted" style={{ margin: 0 }}>
              Oder vorhandene Tokens in den {link("/settings", "Einstellungen")} verwalten. Die Konfiguration unten enthält dann den Platzhalter{" "}
              <span className="mono">{TOKEN_PLACEHOLDER}</span>.
            </p>
          </>
        )}

        <h3 style={{ margin: 0 }}>2. Client verbinden</h3>
        <div className="stack" style={{ gap: 8 }}>
          <div className="small">
            <strong>Claude Code (CLI)</strong>
          </div>
          <CopyBlock text={cli} wrap />
          <div className="small">
            <strong>JSON-Konfiguration</strong> <span className="muted">(Claude Desktop, Cursor & andere MCP-Clients mit HTTP-Transport)</span>
          </div>
          <CopyBlock text={json} />
          <div className="small">
            <strong>Test mit curl</strong>
          </div>
          <CopyBlock text={curl} />
        </div>

        <h3 style={{ margin: 0 }}>3. Zertifikat</h3>
        <p className="small" style={{ margin: 0 }}>
          Die WebUI nutzt ein selbstsigniertes Zertifikat. Clients müssen ihm vertrauen – sonst schlägt die Verbindung fehl:
        </p>
        <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
          <button className="btn" type="button" onClick={downloadCert} disabled={certBusy}>
            {certBusy && <Spinner />} UI-Zertifikat herunterladen
          </button>
          {info.data && !info.data.uiCertAvailable && <Badge kind="warn">kein Zertifikat vorhanden</Badge>}
        </div>
        <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
          <li>
            Node-basierte Clients (Claude Code, viele MCP-Clients): <span className="mono">NODE_EXTRA_CA_CERTS=/pfad/caddyevolved-ui.crt</span> setzen.
          </li>
          <li>
            Alternativ caddyEvolved als eigene Site hinter Caddy veröffentlichen (Ziel <span className="mono">https://127.0.0.1:8484</span>, „Upstream-Zertifikat
            nicht prüfen“, mit Access List) – dann gilt ein echtes Zertifikat. → {link("/sites", "Sites")}
          </li>
        </ul>
      </div>

      <div className="card stack" style={{ marginTop: 16 }}>
        <h2 style={{ margin: 0 }}>Was die KI kann</h2>
        <ErrorBox error={info.error} />
        {info.loading && !info.data && <Spinner />}
        {tools.length > 0 && (
          <div className="table-wrap">
            <table className="compact">
              <thead>
                <tr>
                  <th>Werkzeug</th>
                  <th>Beschreibung</th>
                  <th>Art</th>
                </tr>
              </thead>
              <tbody>
                {tools.map((t) => (
                  <tr key={t.name}>
                    <td className="mono small">{t.name}</td>
                    <td className="small">{t.description}</td>
                    <td>{t.readOnly ? <Badge kind="info">nur lesen</Badge> : <Badge kind="warn">ändert</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  );
}
