import { useEffect, useState } from "react";
import { AccessListsResponse, api, emptySite, PluginsResponse, Site, SiteMode, SitesResponse } from "../api";
import { CredentialFields } from "../components/plugins";
import { useGlobal } from "../components/globalcards";
import { DefenderFields, FEATURE_PLUGINS, RateLimitFields, useCompiledPlugins, WafFields } from "../components/features";
import { Badge, ConfirmButton, ErrorBox, PageHead, Spinner, Switch, useAction, useLoad, useToast } from "../components/ui";
import { formatTarget, FormSection, parseTarget, SiteHelp, Target, TargetEditor, TlsPicker, ToggleRow } from "../components/siteform";
import { PanelTab, SitePanel } from "../components/sitecheck";
import { IconCertificate, IconExternalLink, IconStethoscope } from "@tabler/icons-react";

export default function Sites() {
  const list = useLoad(() => api.get<SitesResponse>("/api/sites"));
  const [editing, setEditing] = useState<{ site: Site; isNew: boolean } | null>(null);
  const [panel, setPanel] = useState<{ site: Site; tab: PanelTab } | null>(null);
  const { busy, run } = useAction();

  async function toggle(site: Site, enabled: boolean) {
    await run(
      "toggle-" + site.id,
      () => api.post(`/api/sites/${encodeURIComponent(site.id)}/enabled`, { enabled }),
      enabled ? `${site.id} aktiviert` : `${site.id} deaktiviert`,
    );
    list.reload();
  }

  async function remove(site: Site) {
    await run("del-" + site.id, () => api.del(`/api/sites/${encodeURIComponent(site.id)}`), `${site.id} gelöscht`);
    list.reload();
  }

  if (editing) {
    return (
      <SiteEditor
        initial={editing.site}
        isNew={editing.isNew}
        dnsProviders={list.data?.dnsProviders ?? []}
        onProvidersChanged={list.reload}
        onDone={(saved) => {
          setEditing(null);
          if (saved) {
            list.reload();
            // Show right away whether the new configuration works.
            setPanel({ site: saved, tab: "test" });
          }
        }}
      />
    );
  }

  const sites = list.data?.sites ?? [];
  return (
    <>
      <PageHead title="Sites" sub="Reverse-Proxy-Einträge. Jede Site ist eine eigene Datei, die Caddy per import lädt.">
        <button className="btn primary" onClick={() => setEditing({ site: emptySite(), isNew: true })}>
          + Neue Site
        </button>
      </PageHead>
      <ErrorBox error={list.error} />
      {list.data && !list.data.importOk && (
        <div className="alert warn" style={{ marginBottom: 16 }}>
          Das Caddyfile enthält noch keine <code>import {list.data.sitesDir}/*.caddy</code>-Zeile. Sie wird beim Speichern der ersten Site
          ergänzt.
        </div>
      )}
      <div className="card">
        {list.loading && !list.data ? (
          <div className="empty">
            <Spinner />
          </div>
        ) : sites.length === 0 ? (
          <div className="empty">
            Noch keine Sites angelegt.
            <div style={{ marginTop: 12 }}>
              <button className="btn primary" onClick={() => setEditing({ site: emptySite(), isNew: true })}>
                Erste Site anlegen
              </button>
            </div>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Aktiv</th>
                  <th>Domains</th>
                  <th>Ziel</th>
                  <th>TLS & Schutz</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {sites.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <Switch checked={s.enabled} disabled={busy === "toggle-" + s.id} onChange={(v) => toggle(s, v)} label="Site aktiv" />
                    </td>
                    <td>
                      <div className="site-names">
                        {(s.domains.length ? s.domains : [s.id]).map((d) => (
                          <span key={d} className="site-name">
                            <button className="link-btn" title="Bearbeiten" onClick={() => setEditing({ site: { ...emptySite(), ...s }, isNew: false })}>
                              {d}
                            </button>
                            {siteURL(s, d) && (
                              <a href={siteURL(s, d)!} target="_blank" rel="noreferrer" className="site-open" title={`${siteURL(s, d)} öffnen`} aria-label={`${d} im Browser öffnen`}>
                                <IconExternalLink size={15} />
                              </a>
                            )}
                          </span>
                        ))}
                      </div>
                      <div className="small muted mono">{s.id}</div>
                    </td>
                    <td className="small">
                      <TargetText site={s} />
                    </td>
                    <td>
                      <div className="chips">
                        <TlsBadge site={s} />
                        {s.accessList && <Badge kind="info">ACL · {s.accessList}</Badge>}
                        {s.waf?.enabled && <Badge kind={s.waf.mode === "detect" ? "warn" : "ok"}>WAF{s.waf.mode === "detect" ? " · erkennen" : ""}</Badge>}
                        {s.defender?.enabled && <Badge kind="ok">Bot-Abwehr</Badge>}
                        {s.rateLimit?.enabled && <Badge kind="ok">{`${s.rateLimit.events}/${s.rateLimit.window}`}</Badge>}
                        {s.cache && <Badge kind="info">Cache</Badge>}
                        {s.tailnet && <Badge kind="info">Tailnet · {s.tailnet}</Badge>}
                      </div>
                    </td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      <span className="row" style={{ justifyContent: "flex-end" }}>
                        <button className="btn ghost sm" title="Testen" aria-label="Site testen" onClick={() => setPanel({ site: s, tab: "test" })}>
                          <IconStethoscope size={16} /> Testen
                        </button>
                        {s.tls !== "off" && (
                          <button className="btn ghost sm" title="Zertifikat ansehen" aria-label="Zertifikat ansehen" onClick={() => setPanel({ site: s, tab: "cert" })}>
                            <IconCertificate size={16} />
                          </button>
                        )}
                        <button className="btn sm" onClick={() => setEditing({ site: { ...emptySite(), ...s }, isNew: false })}>
                          Bearbeiten
                        </button>
                        <ConfirmButton onConfirm={() => remove(s)} disabled={busy === "del-" + s.id} confirmText="Löschen?">
                          Löschen
                        </ConfirmButton>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {panel && <SitePanel site={panel.site} tab={panel.tab} onTab={(tab) => setPanel({ ...panel, tab })} onClose={() => setPanel(null)} />}
    </>
  );
}

/** The address a visitor would open, or null for wildcards and bare ports. */
function siteURL(site: Site, domain: string): string | null {
  const d = domain.trim();
  if (/^https?:\/\//.test(d)) return d;
  if (!d || d.startsWith(":") || d.includes("*") || d.includes("/")) return null;
  return (site.tls === "off" ? "http://" : "https://") + d;
}

function TargetText({ site }: { site: Site }) {
  switch (site.mode) {
    case "proxy":
      return <span className="mono">{(site.upstreams ?? []).map((u) => (site.upstreamTls ? "https://" : "http://") + u).join(", ") || "–"}</span>;
    case "redirect":
      return <span>→ {site.redirectTo}</span>;
    case "static":
      return <span className="mono">Dateien: {site.root}</span>;
    case "webdav":
      return <span className="mono">WebDAV: {site.root}</span>;
    default:
      return <span className="muted">eigene Konfiguration</span>;
  }
}

function TlsBadge({ site }: { site: Site }) {
  switch (site.tls) {
    case "auto":
      return <Badge kind="ok">Let's Encrypt</Badge>;
    case "internal":
      return <Badge kind="info">intern</Badge>;
    case "dns":
      return <Badge kind="ok">DNS · {site.dnsProvider}</Badge>;
    case "off":
      return <Badge kind="warn">nur HTTP</Badge>;
    default:
      return <Badge>{site.tls}</Badge>;
  }
}

const lines = (s: string) =>
  s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);

function SiteEditor({
  initial,
  isNew,
  dnsProviders,
  onProvidersChanged,
  onDone,
}: {
  initial: Site;
  isNew: boolean;
  dnsProviders: { id: string; name: string; ready: boolean }[];
  onProvidersChanged: () => void;
  onDone: (saved: Site | null) => void;
}) {
  // Old entries may still carry "https://" in the address; that becomes the
  // HTTPS switch, the same rule the server applies.
  const parsed = (initial.upstreams ?? []).map(parseTarget);
  const [site, setSite] = useState<Site>({
    ...initial,
    upstreamTls: initial.upstreamTls || initial.upstreamInsecure || parsed.some((p) => p.https),
  });
  const [domainsText, setDomainsText] = useState((initial.domains ?? []).join("\n"));
  const [targets, setTargets] = useState<Target[]>(parsed.map((p) => p.target));
  const [targetNote, setTargetNote] = useState<string>("");
  const [preview, setPreview] = useState<string>("");
  const [previewErr, setPreviewErr] = useState<unknown>(null);
  const [saveErr, setSaveErr] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const toast = useToast();
  const compiled = useCompiledPlugins();
  const global = useGlobal().data;
  const caps = global?.caps;
  const g = global?.global;
  const acls = useLoad(() => api.get<AccessListsResponse>("/api/access-lists"));

  // Disabled feature blocks are not sent: the server treats a missing block
  // as "off", and a binary without the plugin then has nothing to reject.
  const full: Site = {
    ...site,
    domains: lines(domainsText),
    upstreams: targets.map(formatTarget).filter(Boolean),
    waf: site.waf?.enabled ? site.waf : undefined,
    defender: site.defender?.enabled ? site.defender : undefined,
    rateLimit: site.rateLimit?.enabled ? site.rateLimit : undefined,
  };
  const set = <K extends keyof Site>(k: K, v: Site[K]) => setSite((s) => ({ ...s, [k]: v }));

  // Live preview, debounced.
  const key = JSON.stringify(full);
  useEffect(() => {
    const t = setTimeout(async () => {
      try {
        const r = await api.post<{ caddyfile: string }>("/api/sites/preview", full);
        setPreview(r.caddyfile);
        setPreviewErr(null);
      } catch (e) {
        setPreviewErr(e);
      }
    }, 350);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  async function save() {
    setSaving(true);
    setSaveErr(null);
    try {
      const r = isNew
        ? await api.post<{ site: Site; reloaded: boolean }>("/api/sites", full)
        : await api.put<{ site: Site; reloaded: boolean }>(`/api/sites/${encodeURIComponent(initial.id)}`, full);
      toast("ok", r.reloaded ? "Gespeichert und Caddy neu geladen" : "Gespeichert");
      onDone(r.site);
    } catch (e) {
      setSaveErr(e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageHead title={isNew ? "Neue Site" : `Site ${initial.id} bearbeiten`}>
        <button className="btn" onClick={() => onDone(null)}>
          Abbrechen
        </button>
        <button className="btn primary" onClick={save} disabled={saving || (full.mode !== "raw" && full.domains.length === 0)}>
          {saving && <Spinner />} Speichern & anwenden
        </button>
      </PageHead>
      <div className="grid grid-2" style={{ alignItems: "start" }}>
        <div className="card stack">
          <SiteHelp />

          <FormSection title="Allgemein" aside={<ToggleRow checked={site.enabled} onChange={(v) => set("enabled", v)} label="Aktiv" />}>
            <div className="form-grid">
              <label className="field">
                Art
                <select value={site.mode} onChange={(e) => set("mode", e.target.value as SiteMode)}>
                  <option value="proxy">Reverse Proxy</option>
                  <option value="redirect">Weiterleitung (Redirect)</option>
                  <option value="static">Statische Dateien</option>
                  {(caps?.webdav || site.mode === "webdav") && <option value="webdav">WebDAV (Netzlaufwerk)</option>}
                  <option value="raw">Eigene Konfiguration</option>
                </select>
              </label>
              <label className="field">
                ID
                <input
                  value={site.id}
                  disabled={!isNew}
                  placeholder="leer = aus der Domain, z. B. pve"
                  onChange={(e) => set("id", e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, "-"))}
                />
                <span className="hint">Interner Name, später nicht änderbar.</span>
              </label>
            </div>
          </FormSection>

          <FormSection title="Aufgerufen unter">
            <label className="field">
              Domains
              <textarea rows={2} value={domainsText} placeholder={"pve.deinedomain.de\nproxmox.deinedomain.de"} onChange={(e) => setDomainsText(e.target.value)} />
              <span className="hint">
                Eine pro Zeile, ohne <span className="mono">https://</span>. Fürs LAN z. B. <span className="mono">pve.lan</span>, für einen Port{" "}
                <span className="mono">:8080</span>.
              </span>
            </label>
          </FormSection>

          {site.mode === "proxy" && (
            <FormSection title="Weiterleiten an">
              <TargetEditor
                targets={targets}
                https={site.upstreamTls}
                insecure={site.upstreamInsecure}
                onChange={(v) => {
                  setTargets(v.targets);
                  setSite((s) => ({ ...s, upstreamTls: v.https, upstreamInsecure: v.https && v.insecure }));
                  setTargetNote(v.note ?? "");
                }}
              />
              {targetNote && <span className="hint">{targetNote}</span>}
              <details className="advanced">
                <summary>Erweitert: Lastverteilung und Health-Check</summary>
                <div className="form-grid" style={{ marginTop: 10 }}>
                  <label className="field">
                    Lastverteilung
                    <select value={site.lbPolicy} onChange={(e) => set("lbPolicy", e.target.value)}>
                      <option value="">Zufällig (Standard)</option>
                      <option value="round_robin">Reihum (round_robin)</option>
                      <option value="least_conn">Wenigste Verbindungen (least_conn)</option>
                      <option value="first">Erstes erreichbares – Failover (first)</option>
                      <option value="ip_hash">Gleicher Besucher → gleiches Ziel (ip_hash)</option>
                    </select>
                    <span className="hint">Nur relevant bei mehreren Zielen.</span>
                  </label>
                  <label className="field">
                    Health-Check-Pfad
                    <input value={site.healthUri} placeholder="/health (optional)" onChange={(e) => set("healthUri", e.target.value)} />
                    <span className="hint">Caddy fragt den Pfad regelmäßig ab und lässt Ziele aus, die nicht antworten.</span>
                  </label>
                </div>
              </details>
            </FormSection>
          )}

          {site.mode === "redirect" && (
            <FormSection title="Umleiten auf">
              <label className="field">
                Ziel-URL
                <input value={site.redirectTo} placeholder="https://neue-domain.de" onChange={(e) => set("redirectTo", e.target.value)} />
                <span className="hint">Der aufgerufene Pfad wird angehängt (dauerhafte Umleitung, 308).</span>
              </label>
            </FormSection>
          )}

          {site.mode === "static" && (
            <FormSection title="Dateien aus">
              <label className="field">
                Verzeichnis
                <input value={site.root} placeholder="/var/www/site" onChange={(e) => set("root", e.target.value)} />
              </label>
            </FormSection>
          )}

          {site.mode === "webdav" && (
            <FormSection title="WebDAV-Ordner">
              <label className="field">
                Ordner auf dem Server
                <input value={site.root} placeholder="/srv/dateien" onChange={(e) => set("root", e.target.value)} />
                <span className="hint">
                  Als Netzlaufwerk einbinden: Windows „Netzlaufwerk verbinden“, macOS Finder → „Mit Server verbinden“. Unbedingt eine Access List mit Benutzern
                  zuweisen – sonst kann jeder lesen und schreiben. Der Ordner muss für den Caddy-Benutzer beschreibbar sein.
                </span>
              </label>
            </FormSection>
          )}

          {site.mode === "raw" && (
            <FormSection title="Konfiguration">
              <label className="field">
                Blockinhalt
                <textarea className="editor" style={{ minHeight: 220 }} spellCheck={false} value={site.raw} onChange={(e) => set("raw", e.target.value)} />
                <span className="hint">Alles zwischen den geschweiften Klammern des Site-Blocks.</span>
              </label>
            </FormSection>
          )}

          <FormSection title="HTTPS für Besucher">
            <TlsPicker value={site.tls} onChange={(v) => set("tls", v)} />
            {site.tls === "dns" && (
              <label className="field">
                DNS-Anbieter
                <select value={site.dnsProvider} onChange={(e) => set("dnsProvider", e.target.value)}>
                  <option value="">– wählen –</option>
                  {dnsProviders.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                      {p.ready ? "" : " (Zugangsdaten fehlen)"}
                    </option>
                  ))}
                </select>
                {dnsProviders.length === 0 && <span className="hint">Kein DNS-Plugin im Binary – unter „Plugins & Build“ einbauen.</span>}
              </label>
            )}
            {site.tls === "dns" && dnsProviders.some((p) => p.id === site.dnsProvider && !p.ready) && (
              <ProviderSetup id={site.dnsProvider} onSaved={onProvidersChanged} />
            )}
            {site.mode !== "raw" && (
              <ToggleRow checked={site.compress} onChange={(v) => set("compress", v)} label="Komprimierung (zstd/gzip)" hint="Spart Bandbreite bei Text, HTML und JSON." />
            )}
          </FormSection>

          <FormSection title="Zugriff und Schutz">
            <span className="hint">
              Dateien wie .env, .git, Schlüssel und Datenbank-Dumps sind bei jeder Site immer gesperrt – Liste und eigene Muster unter Access Lists.
            </span>
            <label className="field">
              Access List
              <select value={site.accessList ?? ""} onChange={(e) => set("accessList", e.target.value)}>
                <option value="">keine – öffentlich erreichbar</option>
                {(acls.data?.accessLists ?? []).map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </select>
              <span className="hint">IP-, Länder- und Login-Regeln. Anlegen unter „Access Lists“.</span>
            </label>

            {g?.firewall?.enabled && (
              <ToggleRow
                checked={!site.noFirewall}
                onChange={(v) => set("noFirewall", !v)}
                label="Firewall"
                hint="Gesperrte IPs, Sperrlisten, Länder und Netze (gilt für alle Sites, einstellbar unter „Firewall“). Ausschalten nur für Dienste, die jeder erreichen muss."
              />
            )}
            {compiled[FEATURE_PLUGINS.waf] && <WafFields value={site.waf} onChange={(v) => set("waf", v)} />}
            {compiled[FEATURE_PLUGINS.defender] && <DefenderFields value={site.defender} onChange={(v) => set("defender", v)} />}
            {compiled[FEATURE_PLUGINS.rateLimit] && <RateLimitFields value={site.rateLimit} onChange={(v) => set("rateLimit", v)} />}
            {caps?.crowdsec && g?.crowdsec.enabled && (
              <ToggleRow
                checked={!site.noCrowdsec}
                onChange={(v) => set("noCrowdsec", !v)}
                label="CrowdSec"
                hint="Bekannte Angreifer sperren (gilt für alle Sites). Ausschalten nur für Dienste, die etwa von eigenen Servern in Blocklisten erreicht werden."
              />
            )}
          </FormSection>

          {((caps?.cache && g?.cache.enabled && (site.mode === "proxy" || site.mode === "static")) || (caps?.tailscale && g?.tailscale.enabled)) && (
            <FormSection title="Netzwerk & Cache">
              {caps?.cache && g?.cache.enabled && (site.mode === "proxy" || site.mode === "static") && (
                <ToggleRow
                  checked={!!site.cache}
                  onChange={(v) => set("cache", v)}
                  label="Antworten zwischenspeichern"
                  hint={`Souin-Cache, Haltezeit ${g.cache.ttl ?? "120s"}. Nur für öffentliche Inhalte – was der Dienst als privat markiert, wird nicht gespeichert.`}
                />
              )}
              {caps?.tailscale && g?.tailscale.enabled && (
                <label className="field">
                  Nur im Tailnet anbieten als
                  <input className="mono" value={site.tailnet ?? ""} placeholder="z. B. nas (leer = normal im Internet/LAN)" onChange={(e) => set("tailnet", e.target.value)} />
                  <span className="hint">Die Site lauscht dann nur im Tailnet. Als Domain name.dein-tailnet.ts.net eintragen – das Zertifikat kommt von Tailscale.</span>
                </label>
              )}
            </FormSection>
          )}

          {site.mode !== "raw" && (
            <label className="field">
              Zusätzliche Direktiven <span className="hint">(Experten, optional)</span>
              <textarea
                className="editor"
                style={{ minHeight: 110 }}
                spellCheck={false}
                value={site.extra}
                placeholder={"header X-Robots-Tag noindex\nbasic_auth /admin/* { … }"}
                onChange={(e) => set("extra", e.target.value)}
              />
            </label>
          )}
          <ErrorBox error={saveErr} />
        </div>

        <div className="card" style={{ position: "sticky", top: 16 }}>
          <h2>Vorschau</h2>
          {previewErr ? <ErrorBox error={previewErr} /> : <pre className="code">{preview || " "}</pre>}
          <p className="small muted" style={{ marginBottom: 0 }}>
            Beim Speichern wird die Konfiguration mit <code>caddy validate</code> geprüft. Ist sie ungültig, bleibt der alte Stand aktiv.
          </p>
        </div>
      </div>
    </>
  );
}

/** Inline credentials for a DNS provider that has none yet. */
function ProviderSetup({ id, onSaved }: { id: string; onSaved: () => void }) {
  const plugins = useLoad(() => api.get<PluginsResponse>("/api/plugins"));
  const p = plugins.data?.plugins.find((x) => x.id === id);
  if (!p) return plugins.loading ? <Spinner /> : null;
  return (
    <div className="alert warn stack" style={{ gap: 10 }}>
      <div>
        <b>{p.name}</b> braucht Zugangsdaten, sonst bekommt die Site kein Zertifikat.
      </div>
      <div style={{ color: "var(--text)" }}>
        <CredentialFields plugin={p} compact onSaved={() => (plugins.reload(), onSaved())} />
      </div>
    </div>
  );
}
