import { ReactNode, useState } from "react";
import {
  AccessListsResponse,
  api,
  defaultDefender,
  defaultRateLimit,
  defaultWaf,
  errMsg,
  NavItem,
  PluginsResponse,
  Site,
  SitesResponse,
} from "../api";
import { navigate } from "../router";
import { DefenderFields, RateLimitFields, WafFields } from "../components/features";
import { Badge, ErrorBox, PageHead, Spinner, useLoad, useToast } from "../components/ui";
import { CredentialCard } from "./Build";

function Link({ to, children }: { to: string; children: ReactNode }) {
  return (
    <a
      href={to}
      onClick={(e) => {
        e.preventDefault();
        navigate(to);
      }}
    >
      {children}
    </a>
  );
}

export default function PluginPage({ page, nav }: { page: string; nav: NavItem[] }) {
  const item = nav.find((n) => n.page === page);
  switch (page) {
    case "waf":
      return <WafPage item={item} />;
    case "defender":
      return <DefenderPage item={item} />;
    case "ratelimit":
      return <RateLimitPage item={item} />;
    case "geo":
      return <GeoPage item={item} />;
    default:
      return <GenericPluginPage page={page} item={item} />;
  }
}

function NotCompiled({ item }: { item?: NavItem }) {
  if (item) return null;
  return (
    <div className="alert warn" style={{ marginBottom: 16 }}>
      Dieses Plugin steckt nicht in der laufenden Caddy-Binary. Einstellungen hier wirken erst nach einem Build mit dem Plugin –{" "}
      <Link to="/build">Plugins & Build</Link>.
    </div>
  );
}

/**
 * Lists every site with one editable feature block. Each change PUTs the whole
 * site back; caddy validates, and a rejection leaves the old config live.
 */
function SiteFeatureTable({ render }: { render: (site: Site, save: (patch: Partial<Site>) => Promise<void>, saving: boolean) => ReactNode }) {
  const list = useLoad(() => api.get<SitesResponse>("/api/sites"));
  const [saving, setSaving] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const toast = useToast();

  async function save(site: Site, patch: Partial<Site>) {
    setSaving(site.id);
    setErr(null);
    try {
      const r = await api.put<{ reloaded: boolean }>(`/api/sites/${encodeURIComponent(site.id)}`, { ...site, ...patch });
      toast("ok", r.reloaded ? `${site.id} gespeichert, Caddy neu geladen` : `${site.id} gespeichert`);
      list.reload();
    } catch (e) {
      setErr(e);
      toast("err", errMsg(e));
    } finally {
      setSaving(null);
    }
  }

  const sites = list.data?.sites ?? [];
  return (
    <div className="card">
      <ErrorBox error={list.error} />
      <ErrorBox error={err} />
      {list.loading && !list.data ? (
        <div className="empty">
          <Spinner />
        </div>
      ) : sites.length === 0 ? (
        <div className="empty">
          Noch keine Sites. <Link to="/sites">Site anlegen</Link>
        </div>
      ) : (
        <div className="stack">
          {sites.map((s) => (
            <div key={s.id} className="stack" style={{ gap: 8 }}>
              <div className="row">
                <strong>{s.domains.join(", ") || s.id}</strong>
                <span className="small muted mono">{s.id}</span>
                {!s.enabled && <Badge kind="warn">deaktiviert</Badge>}
                {saving === s.id && <Spinner />}
              </div>
              {render(s, (patch) => save(s, patch), saving === s.id)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function WafPage({ item }: { item?: NavItem }) {
  return (
    <>
      <PageHead
        title="WAF"
        sub="Web Application Firewall: prüft jede Anfrage gegen Angriffsmuster (SQL-Injection, XSS, Path Traversal, Scanner …)."
      />
      <NotCompiled item={item} />
      <div className="card" style={{ marginBottom: 16 }}>
        <p className="small" style={{ margin: 0 }}>
          {item?.plugin ?? "Coraza"} nutzt das <strong>OWASP Core Rule Set</strong> (CRS), den Standard-Regelsatz für WAFs.
          <strong> Blockieren</strong> beantwortet Treffer mit 403, <strong>Nur erkennen</strong> protokolliert nur. Empfehlung: neue Sites erst
          einige Tage im Erkennungsmodus laufen lassen und die Logs auf Fehlalarme prüfen, dann auf Blockieren stellen.
        </p>
      </div>
      <SiteFeatureTable render={(s, save) => <WafFields value={s.waf} onChange={(v) => save({ waf: v ?? { ...defaultWaf(), enabled: false } })} />} />
    </>
  );
}

function DefenderPage({ item }: { item?: NavItem }) {
  return (
    <>
      <PageHead title="Bot-Abwehr" sub="Sperrt bekannte KI-Crawler, Cloud-Rechenzentren und VPN-Netze anhand ihrer IP-Bereiche." />
      <NotCompiled item={item} />
      <div className="card" style={{ marginBottom: 16 }}>
        <p className="small" style={{ margin: 0 }}>
          Die IP-Listen (OpenAI, AWS, Google Cloud, Azure, DeepSeek, GitHub Copilot …) stecken im Plugin und werden mit jedem Build aktualisiert.
          Bereiche, die eigene Dienste nutzen (z. B. „cloudflare“ hinter Cloudflare-Proxy), nicht sperren.
        </p>
      </div>
      <SiteFeatureTable
        render={(s, save) => (
          <DefenderFields value={s.defender} onChange={(v) => save({ defender: v ?? { ...defaultDefender(), enabled: false } })} />
        )}
      />
    </>
  );
}

function RateLimitPage({ item }: { item?: NavItem }) {
  return (
    <>
      <PageHead title="Rate Limit" sub="Begrenzt Anfragen pro Client-IP – gegen Brute-Force auf Logins und überlastende Scraper." />
      <NotCompiled item={item} />
      <SiteFeatureTable
        render={(s, save) => (
          <RateLimitFields value={s.rateLimit} onChange={(v) => save({ rateLimit: v ?? { ...defaultRateLimit(), enabled: false } })} />
        )}
      />
    </>
  );
}

function GeoPage({ item }: { item?: NavItem }) {
  const acls = useLoad(() => api.get<AccessListsResponse>("/api/access-lists"));
  const withGeo = (acls.data?.accessLists ?? []).filter((a) => a.needsGeo);
  return (
    <>
      <PageHead title="Geo-Blocking" sub="Länder erlauben oder sperren – über Access Lists." />
      <NotCompiled item={item} />
      <div className="card" style={{ marginBottom: 16 }}>
        <h2>Einrichtung</h2>
        <ol className="small" style={{ paddingLeft: 18, margin: 0, lineHeight: 1.7 }}>
          <li>
            Kostenlosen Account bei MaxMind anlegen (<span className="mono">maxmind.com → GeoLite2</span>) und{" "}
            <span className="mono">GeoLite2-Country.mmdb</span> herunterladen.
          </li>
          <li>
            Datei auf den Server legen, z. B. <code>/var/lib/caddyforge/GeoLite2-Country.mmdb</code>, lesbar für den Benutzer{" "}
            <code>caddy</code> (<code>chmod 644</code>).
          </li>
          <li>
            In einer <Link to="/access-lists">Access List</Link> Länder (ISO-Codes wie DE, AT, CH) erlauben oder sperren und den Pfad zur Datei
            angeben.
          </li>
          <li>Die Access List einer Site zuweisen.</li>
        </ol>
        <p className="small muted" style={{ marginBottom: 0 }}>
          MaxMind aktualisiert die Datenbank wöchentlich; eine veraltete Datei funktioniert weiter, wird aber ungenauer.
        </p>
      </div>
      <div className="card">
        <h2>Access Lists mit Länderregeln</h2>
        <ErrorBox error={acls.error} />
        {withGeo.length === 0 ? (
          <div className="empty">
            Noch keine. <Link to="/access-lists">Access List anlegen</Link>
          </div>
        ) : (
          <ul className="list-plain">
            {withGeo.map((a) => (
              <li key={a.id} className="row">
                <strong>{a.name}</strong>
                {(a.allowCountries ?? []).length > 0 && <Badge kind="ok">erlaubt: {(a.allowCountries ?? []).join(" ")}</Badge>}
                {(a.denyCountries ?? []).length > 0 && <Badge kind="err">gesperrt: {(a.denyCountries ?? []).join(" ")}</Badge>}
                <span className="spacer" />
                <span className="small muted">{(a.usedBy ?? []).join(", ") || "keiner Site zugewiesen"}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
}

function GenericPluginPage({ page, item }: { page: string; item?: NavItem }) {
  const plugins = useLoad(() => api.get<PluginsResponse>("/api/plugins"));
  const entry = (plugins.data?.plugins ?? []).find((p) => (item ? p.id === item.pluginId : p.ui?.page === page));
  return (
    <>
      <PageHead title={item?.label ?? entry?.ui?.label ?? page} sub={entry?.name} />
      <NotCompiled item={item} />
      <ErrorBox error={plugins.error} />
      {plugins.loading && !plugins.data ? (
        <div className="empty">
          <Spinner />
        </div>
      ) : !entry ? (
        <div className="empty">Unbekanntes Plugin.</div>
      ) : (
        <div className="grid grid-2" style={{ alignItems: "start" }}>
          <div className="card">
            <h2>{entry.name}</h2>
            <dl className="small" style={{ margin: 0, display: "grid", gridTemplateColumns: "auto 1fr", gap: "6px 14px" }}>
              <dt className="muted">Modul</dt>
              <dd className="mono" style={{ margin: 0 }}>
                {entry.module}
              </dd>
              {entry.registers && (
                <>
                  <dt className="muted">Registriert</dt>
                  <dd className="mono" style={{ margin: 0 }}>
                    {entry.registers}
                  </dd>
                </>
              )}
              {entry.license && (
                <>
                  <dt className="muted">Lizenz</dt>
                  <dd style={{ margin: 0 }}>{entry.license}</dd>
                </>
              )}
              {entry.docs && (
                <>
                  <dt className="muted">Doku</dt>
                  <dd style={{ margin: 0 }}>
                    <a href={entry.docs} target="_blank" rel="noreferrer">
                      {entry.docs}
                    </a>
                  </dd>
                </>
              )}
            </dl>
            {entry.note && <p className="small">{entry.note}</p>}
            {entry.licenseRisk && <div className="alert warn small">{entry.licenseRisk}</div>}
            <p className="small muted" style={{ marginBottom: 0 }}>
              Für dieses Plugin gibt es noch keine eigene Oberfläche. Konfiguration über den <Link to="/caddyfile">Caddyfile-Expertenmodus</Link>{" "}
              (globale Optionen) oder das Feld „Zusätzliche Direktiven“ einer Site.
            </p>
          </div>
          {(entry.env ?? []).length > 0 && (
            <div className="card">
              <h2>Zugangsdaten</h2>
              <CredentialCard plugin={entry} onSaved={plugins.reload} />
            </div>
          )}
        </div>
      )}
    </>
  );
}
