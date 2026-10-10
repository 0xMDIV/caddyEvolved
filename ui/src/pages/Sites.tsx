import { useEffect, useState } from "react";
import { api, emptySite, Site, SiteMode, SitesResponse, SiteTLS } from "../api";
import { Badge, ConfirmButton, ErrorBox, PageHead, Spinner, Switch, useAction, useLoad, useToast } from "../components/ui";

export default function Sites() {
  const list = useLoad(() => api.get<SitesResponse>("/api/sites"));
  const [editing, setEditing] = useState<{ site: Site; isNew: boolean } | null>(null);
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
        onDone={(saved) => {
          setEditing(null);
          if (saved) list.reload();
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
                  <th>TLS</th>
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
                      <div style={{ fontWeight: 600 }}>{s.domains.join(", ") || s.id}</div>
                      <div className="small muted mono">{s.id}</div>
                    </td>
                    <td className="small">
                      <TargetText site={s} />
                    </td>
                    <td>
                      <TlsBadge site={s} />
                    </td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      <span className="row" style={{ justifyContent: "flex-end" }}>
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
    </>
  );
}

function TargetText({ site }: { site: Site }) {
  switch (site.mode) {
    case "proxy":
      return <span className="mono">{(site.upstreams ?? []).join(", ") || "–"}</span>;
    case "redirect":
      return <span>→ {site.redirectTo}</span>;
    case "static":
      return <span className="mono">Dateien: {site.root}</span>;
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
  onDone,
}: {
  initial: Site;
  isNew: boolean;
  dnsProviders: { id: string; name: string; ready: boolean }[];
  onDone: (saved: boolean) => void;
}) {
  const [site, setSite] = useState<Site>(initial);
  const [domainsText, setDomainsText] = useState((initial.domains ?? []).join("\n"));
  const [upstreamsText, setUpstreamsText] = useState((initial.upstreams ?? []).join("\n"));
  const [preview, setPreview] = useState<string>("");
  const [previewErr, setPreviewErr] = useState<unknown>(null);
  const [saveErr, setSaveErr] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const toast = useToast();

  const full: Site = { ...site, domains: lines(domainsText), upstreams: lines(upstreamsText) };
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
      onDone(true);
    } catch (e) {
      setSaveErr(e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <PageHead title={isNew ? "Neue Site" : `Site ${initial.id} bearbeiten`}>
        <button className="btn" onClick={() => onDone(false)}>
          Abbrechen
        </button>
        <button className="btn primary" onClick={save} disabled={saving || (full.mode !== "raw" && full.domains.length === 0)}>
          {saving && <Spinner />} Speichern & anwenden
        </button>
      </PageHead>
      <div className="grid grid-2" style={{ alignItems: "start" }}>
        <div className="card stack">
          <div className="form-grid">
            <label className="field">
              ID
              <input
                value={site.id}
                disabled={!isNew}
                placeholder="z. B. nextcloud (leer = aus Domain)"
                onChange={(e) => set("id", e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, "-"))}
              />
              <span className="hint">Dateiname der Site, nachträglich nicht änderbar.</span>
            </label>
            <label className="field">
              Art
              <select value={site.mode} onChange={(e) => set("mode", e.target.value as SiteMode)}>
                <option value="proxy">Reverse Proxy</option>
                <option value="redirect">Weiterleitung</option>
                <option value="static">Statische Dateien</option>
                <option value="raw">Eigene Konfiguration</option>
              </select>
            </label>
            <label className="field full">
              Domains
              <textarea rows={2} value={domainsText} placeholder={"cloud.example.com\nwww.cloud.example.com"} onChange={(e) => setDomainsText(e.target.value)} />
              <span className="hint">Eine pro Zeile. Auch :8080 oder http://intern.lan möglich.</span>
            </label>
          </div>

          {site.mode === "proxy" && (
            <div className="form-grid">
              <label className="field full">
                Upstreams
                <textarea rows={2} value={upstreamsText} placeholder={"192.168.10.40:80"} onChange={(e) => setUpstreamsText(e.target.value)} />
                <span className="hint">Ziel-Server, einer pro Zeile. Mehrere = Lastverteilung.</span>
              </label>
              <label className="field">
                Lastverteilung
                <select value={site.lbPolicy} onChange={(e) => set("lbPolicy", e.target.value)}>
                  <option value="">Standard (random)</option>
                  <option value="round_robin">round_robin</option>
                  <option value="least_conn">least_conn</option>
                  <option value="first">first (Failover)</option>
                  <option value="ip_hash">ip_hash</option>
                </select>
              </label>
              <label className="field">
                Health-Check-Pfad
                <input value={site.healthUri} placeholder="/health (optional)" onChange={(e) => set("healthUri", e.target.value)} />
              </label>
              <label className="check">
                <input type="checkbox" checked={site.upstreamTls} onChange={(e) => set("upstreamTls", e.target.checked)} /> Upstream spricht HTTPS
              </label>
              <label className="check">
                <input
                  type="checkbox"
                  checked={site.upstreamInsecure}
                  disabled={!site.upstreamTls}
                  onChange={(e) => set("upstreamInsecure", e.target.checked)}
                />{" "}
                Zertifikat des Upstreams nicht prüfen
              </label>
            </div>
          )}

          {site.mode === "redirect" && (
            <label className="field">
              Ziel-URL
              <input value={site.redirectTo} placeholder="https://example.com{uri}" onChange={(e) => set("redirectTo", e.target.value)} />
            </label>
          )}

          {site.mode === "static" && (
            <label className="field">
              Verzeichnis
              <input value={site.root} placeholder="/var/www/site" onChange={(e) => set("root", e.target.value)} />
            </label>
          )}

          {site.mode === "raw" && (
            <label className="field">
              Blockinhalt
              <textarea className="editor" style={{ minHeight: 220 }} spellCheck={false} value={site.raw} onChange={(e) => set("raw", e.target.value)} />
              <span className="hint">Alles zwischen den geschweiften Klammern des Site-Blocks.</span>
            </label>
          )}

          <div className="form-grid">
            <label className="field">
              Zertifikat
              <select value={site.tls} onChange={(e) => set("tls", e.target.value as SiteTLS)}>
                <option value="auto">Automatisch (Let's Encrypt / ZeroSSL)</option>
                <option value="dns">DNS-Challenge (Plugin)</option>
                <option value="internal">Intern (eigene CA, LAN)</option>
                <option value="off">Kein TLS (nur HTTP)</option>
              </select>
            </label>
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
            {site.mode !== "raw" && (
              <label className="check">
                <input type="checkbox" checked={site.compress} onChange={(e) => set("compress", e.target.checked)} /> Komprimierung (zstd/gzip)
              </label>
            )}
            <label className="check">
              <input type="checkbox" checked={site.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Aktiv
            </label>
          </div>

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
