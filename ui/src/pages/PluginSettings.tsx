import { ReactNode } from "react";
import { api, Build as BuildT, BuildsResponse, GlobalResponse, PluginsResponse, PluginState, Site, SitesResponse } from "../api";
import { CredentialFields } from "../components/plugins";
import { GlobalPluginSettings, RealIPCard, useGlobal } from "../components/globalcards";
import { Badge, Spinner, useAction, useLoad } from "../components/ui";
import { navigate } from "../router";
import { IconAlertTriangle, IconArrowRight, IconExternalLink, IconPlus } from "@tabler/icons-react";

// The plugins compiled into the running caddy, grouped by what they are for,
// each with its settings in one place.

interface Group {
  title: string;
  desc: string;
  match: (p: PluginState) => boolean;
}

const GROUPS: Group[] = [
  {
    title: "Zertifikate & DNS",
    desc: "Wie Caddy an HTTPS-Zertifikate kommt und wo es sie ablegt. Ein DNS-Anbieter wird pro Site unter „HTTPS für Besucher → DNS-Challenge“ gewählt.",
    match: (p) => ["dns", "cert", "storage"].includes(p.category) || p.subcat === "ddns",
  },
  {
    title: "Schutz & Zugriff",
    desc: "Filter vor deinen Diensten. Ein- und ausgeschaltet wird pro Site, die Regeln stehen auf der jeweiligen Seite.",
    match: (p) => p.category === "security" || p.category === "auth",
  },
  {
    title: "Netzwerk & Dienste",
    desc: "Tailnet, Kompression, Cache, WebDAV und mehr.",
    match: () => true,
  },
];

/**
 * The newest successful build that is not running yet and brings a plugin the
 * running binary lacks – an older build of the same set is no news.
 */
export function pendingBuild(data: BuildsResponse | null, plugins: PluginState[]): BuildT | null {
  const list = data?.builds ?? [];
  const active = list.find((b) => b.active);
  const cand = list
    .filter((b) => b.status === "succeeded" && !b.active)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
  if (!cand || (active && active.createdAt > cand.createdAt)) return null;
  const adds = (cand.plugins ?? []).some((id) => !plugins.find((p) => p.id === id)?.detected);
  return adds ? cand : null;
}

export function PendingBuildBanner({ build, plugins, onActivated }: { build: BuildT; plugins: PluginState[]; onActivated: () => void }) {
  const { busy, run } = useAction();
  const names = (build.plugins ?? []).map((id) => plugins.find((p) => p.id === id)?.name ?? id);
  const activate = async () => {
    const r = await run("act", () => api.post(`/api/builds/${encodeURIComponent(build.id)}/activate`), "Neue Caddy-Binary ist aktiv");
    if (r) onActivated();
  };
  return (
    <div className="alert warn row" style={{ marginBottom: 16 }}>
      <IconAlertTriangle size={18} />
      <span style={{ flex: "1 1 260px" }}>
        Build {build.id} ist fertig, läuft aber noch nicht{names.length ? ` (mit ${names.join(", ")})` : ""}. Erst nach „Aktivieren“ nutzt Caddy die neuen Plugins.
      </span>
      <button className="btn primary sm" onClick={activate} disabled={busy === "act"}>
        {busy === "act" && <Spinner />} Jetzt aktivieren
      </button>
    </div>
  );
}

export default function PluginSettings({
  plugins,
  builds,
  onChange,
  onNewBuild,
}: {
  plugins: PluginsResponse;
  builds: BuildsResponse | null;
  onChange: () => void;
  onNewBuild: () => void;
}) {
  const sites = useLoad(() => api.get<SitesResponse>("/api/sites"));
  const global = useGlobal();
  const pending = pendingBuild(builds, plugins.plugins);
  const waiting = new Set((pending?.plugins ?? []).filter((id) => !plugins.plugins.find((p) => p.id === id)?.detected));
  const shown = plugins.plugins.filter((p) => p.detected || waiting.has(p.id));

  const used = new Set<string>();
  const groups = GROUPS.map((g) => {
    const items = shown.filter((p) => !used.has(p.id) && g.match(p)).sort((a, b) => a.name.localeCompare(b.name));
    items.forEach((p) => used.add(p.id));
    return { ...g, items };
  }).filter((g) => g.items.length > 0);

  const reload = () => {
    onChange();
    sites.reload();
    global.reload();
  };

  return (
    <div className="stack">
      {pending && <PendingBuildBanner build={pending} plugins={plugins.plugins} onActivated={reload} />}
      {shown.length === 0 && (
        <div className="card empty">
          Caddy läuft ohne Zusatz-Plugins.{" "}
          <button className="btn sm" onClick={onNewBuild}>
            <IconPlus size={14} /> Plugins einbauen
          </button>
        </div>
      )}
      {global.data && (
        <section className="stack" style={{ gap: 10 }}>
          <div>
            <h2 style={{ margin: "8px 0 2px" }}>Netzwerk</h2>
            <div className="small muted">Gilt für alle Sites, unabhängig von Plugins.</div>
          </div>
          <RealIPCard data={global.data} onSaved={reload} />
        </section>
      )}
      {groups.map((g) => (
        <section key={g.title} className="stack" style={{ gap: 10 }}>
          <div>
            <h2 style={{ margin: "8px 0 2px" }}>{g.title}</h2>
            <div className="small muted">{g.desc}</div>
          </div>
          {g.items.map((p) => (
            <PluginCard key={p.id} p={p} waiting={waiting.has(p.id)} sites={sites.data?.sites ?? []} global={global.data} onChange={reload} />
          ))}
        </section>
      ))}
      {shown.length > 0 && (
        <button className="btn" style={{ alignSelf: "flex-start" }} onClick={onNewBuild}>
          <IconPlus size={16} /> Weitere Plugins einbauen
        </button>
      )}
    </div>
  );
}

function PluginCard({ p, waiting, sites, global, onChange }: { p: PluginState; waiting: boolean; sites: Site[]; global: GlobalResponse | null; onChange: () => void }) {
  const extra = global ? GlobalPluginSettings({ id: p.id, data: global, onSaved: onChange }) : null;
  const hasEnv = (p.env?.length ?? 0) > 0;
  const missing = hasEnv && Object.values(p.credentialState ?? {}).includes("missing");
  let body: ReactNode;
  if (waiting) {
    body = <div className="small muted">Einstellungen gibt es, sobald der Build aktiviert ist.</div>;
  } else {
    body = (
      <>
        {hasEnv && <CredentialFields plugin={p} onSaved={onChange} />}
        {extra}
        {p.category === "dns" && <DNSUsage p={p} sites={sites} ready={!missing} onChange={onChange} />}
        {p.ui && (
          <div>
            <button className="btn" onClick={() => navigate("/plugin/" + encodeURIComponent(p.ui!.page))}>
              {p.ui.label} einrichten <IconArrowRight size={15} />
            </button>
          </div>
        )}
        {!hasEnv && !p.ui && p.category !== "dns" && !extra && (
          <div className="small muted">
            {p.category === "cert" || p.subcat === "cache" || p.subcat === "proxy"
              ? "Für dieses Plugin gibt es noch keine Oberfläche – Einstellungen bisher über den Caddyfile-Editor."
              : "Braucht keine Einstellungen."}
          </div>
        )}
      </>
    );
  }
  return (
    <div className="card stack" style={{ gap: 12 }}>
      <div className="row">
        <h2 style={{ margin: 0, fontSize: 15 }}>{p.name}</h2>
        {waiting ? <Badge kind="warn">wartet auf Aktivierung</Badge> : <Badge kind="ok">eingebaut</Badge>}
        {missing && !waiting && <Badge kind="warn">Zugangsdaten fehlen</Badge>}
        <span className="spacer" />
        {p.docs && (
          <a href={p.docs} target="_blank" rel="noreferrer" className="small">
            Doku <IconExternalLink size={13} style={{ verticalAlign: "-2px" }} />
          </a>
        )}
      </div>
      {body}
    </div>
  );
}

/** Which sites use a DNS provider, and a one-click switch for the others. */
function DNSUsage({ p, sites, ready, onChange }: { p: PluginState; sites: Site[]; ready: boolean; onChange: () => void }) {
  const { busy, run } = useAction();
  const using = sites.filter((s) => s.tls === "dns" && s.dnsProvider === p.id);
  const auto = sites.filter((s) => s.tls === "auto" && s.mode !== "raw");
  const switchSite = (s: Site) =>
    run(
      "sw-" + s.id,
      () => api.put(`/api/sites/${encodeURIComponent(s.id)}`, { ...s, tls: "dns", dnsProvider: p.id }),
      `${s.domains[0]} holt sein Zertifikat jetzt per DNS-Challenge`,
    ).then((r) => r && onChange());
  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="small">
        {using.length > 0 ? (
          <>
            Verwendet von:{" "}
            {using.map((s) => (
              <Badge key={s.id}>{s.domains[0]}</Badge>
            ))}
          </>
        ) : (
          <span className="muted">Noch keine Site nutzt {p.name} für ihr Zertifikat.</span>
        )}
      </div>
      {auto.length > 0 && (
        <div className="stack" style={{ gap: 6 }}>
          <div className="small muted">
            Sites mit „Automatisch“ (HTTP-Challenge) – umstellen, wenn die Domain bei {p.name} liegt, z. B. hinter dem Cloudflare-Proxy:
          </div>
          {auto.map((s) => (
            <div key={s.id} className="row small">
              <span className="mono">{s.domains.join(", ")}</span>
              <button className="btn sm" disabled={!ready || busy === "sw-" + s.id} title={ready ? "" : "Erst die Zugangsdaten speichern"} onClick={() => switchSite(s)}>
                {busy === "sw-" + s.id && <Spinner />} Auf DNS-Challenge umstellen
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
