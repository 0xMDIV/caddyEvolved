import { useEffect, useState } from "react";
import { IconExternalLink, IconRefresh } from "@tabler/icons-react";
import { api, CaddyUpdateInfo, UpdateResponse, VersionInfo } from "../api";
import { navigate } from "../router";
import { Badge, ConfirmButton, ErrorBox, Spinner, useLoad } from "./ui";

/** Caddy and plugin versions against the newest releases; the sidebar reads it too. */
export function useCaddyUpdateCheck(enabled = true) {
  const [data, setData] = useState<CaddyUpdateInfo | null>(null);
  useEffect(() => {
    if (!enabled) return;
    api
      .get<CaddyUpdateInfo>("/api/update/caddy")
      .then(setData)
      .catch(() => setData(null));
  }, [enabled]);
  return data;
}

/** Shared check result; the sidebar and the settings card both read it. */
export function useUpdateCheck(enabled = true) {
  const [data, setData] = useState<UpdateResponse | null>(null);
  useEffect(() => {
    if (!enabled) return;
    api
      .get<UpdateResponse>("/api/update")
      .then(setData)
      .catch(() => setData(null));
  }, [enabled]);
  return data;
}

async function waitForVersion(want: string, timeoutMs = 90_000) {
  const until = Date.now() + timeoutMs;
  // The daemon restarts: the first polls fail, then the new version answers.
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, 1500));
    try {
      const v = await api.get<VersionInfo>("/api/version");
      if (v.version === want) return true;
    } catch {
      /* restarting */
    }
  }
  return false;
}

export function UpdateCard() {
  const check = useLoad(() => api.get<UpdateResponse>("/api/update"));
  const [phase, setPhase] = useState<"" | "install" | "restart">("");
  const [err, setErr] = useState<unknown>(null);
  const u = check.data?.update;

  async function apply() {
    setErr(null);
    setPhase("install");
    try {
      const r = await api.post<{ version: string; restarting: boolean }>("/api/update", {});
      if (!r.restarting) {
        setPhase("");
        setErr(new Error(`Version ${r.version} installiert – Dienst bitte neu starten: systemctl restart caddyevolved`));
        return;
      }
      setPhase("restart");
      if (await waitForVersion(r.version)) {
        window.location.reload();
      } else {
        setPhase("");
        setErr(new Error("caddyEvolved meldet sich nicht zurück. Auf dem Server: systemctl status caddyevolved"));
      }
    } catch (e) {
      setPhase("");
      setErr(e);
    }
  }

  return (
    <div className="card stack" id="update" style={{ gap: 12 }}>
      <div className="row">
        <h2 style={{ margin: 0 }}>Updates</h2>
        <span className="spacer" />
        <button className="btn ghost sm" disabled={check.loading || !!phase} onClick={() => api.get<UpdateResponse>("/api/update?refresh=1").then(() => check.reload())}>
          {check.loading ? <Spinner /> : <IconRefresh size={14} />} Prüfen
        </button>
      </div>
      <ErrorBox error={check.error} />
      {check.data?.error && <ErrorBox error={new Error("Update-Prüfung: " + check.data.error)} />}
      {u && (
        <>
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <span className="small muted">Installiert</span>
            <Badge>{u.current}</Badge>
            {u.dev && <Badge kind="warn">Entwicklerversion</Badge>}
            {u.latest && (
              <>
                <span className="small muted">Neuestes Release</span>
                <Badge kind={u.available ? "info" : "ok"}>{u.latest}</Badge>
              </>
            )}
          </div>
          {u.available && check.data?.container ? (
            <div className="alert info small">
              Läuft im Docker-Container: Update über ein neues Image – <span className="mono">docker compose pull && docker compose up -d</span>, auf
              Unraid „Update“ am Container. Sites, Einstellungen und selbst gebaute Plugins liegen im Daten-Volume und bleiben.
            </div>
          ) : u.available ? (
            <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
              <ConfirmButton
                className="btn primary"
                confirmText={`Auf ${u.latest} aktualisieren? Die WebUI startet dabei kurz neu.`}
                disabled={!!phase}
                onConfirm={apply}
              >
                {phase && <Spinner />} {phase === "restart" ? "Startet neu …" : phase === "install" ? "Lädt …" : `Auf ${u.latest} aktualisieren`}
              </ConfirmButton>
              <a className="small" href={u.notesUrl} target="_blank" rel="noreferrer">
                Was ist neu <IconExternalLink size={13} style={{ verticalAlign: "-2px" }} />
              </a>
            </div>
          ) : (
            u.latest && <span className="small">✔ caddyEvolved ist aktuell.</span>
          )}
        </>
      )}
      <ErrorBox error={err} />
      <p className="small muted" style={{ margin: 0 }}>
        Aktualisiert caddyEvolved selbst – Sites und Einstellungen bleiben, Caddy und Plugins aktualisiert die Karte darunter. Prüfsumme wird geprüft, die alte Version bleibt als{" "}
        <span className="mono">caddyevolved.prev</span> erhalten. Auf dem Server geht dasselbe mit <span className="mono">sudo caddyevolved update</span>.
      </p>
    </div>
  );
}

export function CaddyUpdateCard() {
  const check = useLoad(() => api.get<CaddyUpdateInfo>("/api/update/caddy"));
  const [refreshing, setRefreshing] = useState(false);
  const [starting, setStarting] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const c = check.data;
  const pending = !!c && (c.available || c.pluginUpdates > 0);
  const what = c?.available && c.pluginUpdates > 0 ? "Caddy & Plugins" : c?.available ? "Caddy" : "Plugins";

  async function refresh() {
    setRefreshing(true);
    try {
      await api.get<CaddyUpdateInfo>("/api/update/caddy?refresh=1");
      check.reload();
    } finally {
      setRefreshing(false);
    }
  }

  async function apply() {
    setErr(null);
    setStarting(true);
    try {
      await api.post("/api/update/caddy", {});
      // The build page attaches to the running build and shows its log.
      navigate("/build");
    } catch (e) {
      setErr(e);
    } finally {
      setStarting(false);
    }
  }

  const toBuild = (e: React.MouseEvent) => {
    e.preventDefault();
    navigate("/build");
  };

  return (
    <div className="card stack" id="caddy-update" style={{ gap: 12 }}>
      <div className="row">
        <h2 style={{ margin: 0 }}>Caddy & Plugins</h2>
        <span className="spacer" />
        <button className="btn ghost sm" disabled={check.loading || refreshing || starting} onClick={refresh}>
          {check.loading || refreshing ? <Spinner /> : <IconRefresh size={14} />} Prüfen
        </button>
      </div>
      <ErrorBox error={check.error} />
      {c?.error && <ErrorBox error={new Error(c.error)} />}
      {c && (
        <>
          <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
            <span className="small muted">Caddy installiert</span>
            <Badge>{c.installed ?? "unbekannt"}</Badge>
            {c.latest && (
              <>
                <span className="small muted">Neuestes Release</span>
                <Badge kind={c.available ? "info" : "ok"}>{c.latest}</Badge>
              </>
            )}
          </div>
          {c.plugins.length > 0 ? (
            <div className="table-wrap">
              <table className="compact">
                <thead>
                  <tr>
                    <th>Plugin</th>
                    <th>Installiert</th>
                    <th>Neueste</th>
                  </tr>
                </thead>
                <tbody>
                  {c.plugins.map((p) => (
                    <tr key={p.id}>
                      <td className="small" title={p.module}>
                        {p.name}
                      </td>
                      <td className="mono small">{p.installed ?? "–"}</td>
                      <td className="mono small">
                        {p.pinned ? (
                          <Badge>fest auf {p.latest}</Badge>
                        ) : p.error ? (
                          <span className="muted" title={p.error}>
                            nicht ermittelbar
                          </span>
                        ) : p.available ? (
                          <Badge kind="info">{p.latest}</Badge>
                        ) : (
                          <span className="muted">{p.latest ? "✔ aktuell" : "–"}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <span className="small muted">Keine zusätzlichen Plugins in der Caddy-Binary.</span>
          )}
          {c.runningBuildId ? (
            <div className="row" style={{ gap: 10 }}>
              <Spinner /> <span className="small">Ein Build läuft gerade.</span>
              <a className="small" href="/build" onClick={toBuild}>
                Zum Build-Protokoll
              </a>
            </div>
          ) : pending && c.canBuild ? (
            <ConfirmButton
              className="btn primary"
              confirmText={`${what} aktualisieren? Caddy wird mit ${c.latest ?? "der neuesten Version"} und den neuesten Plugin-Versionen neu gebaut und danach automatisch aktiviert. Startet der neue Caddy nicht, kommt die alte Binary zurück.`}
              disabled={starting}
              onConfirm={apply}
            >
              {starting && <Spinner />} {what} aktualisieren
            </ConfirmButton>
          ) : pending ? (
            <div className="alert info small">Updates verfügbar, aber der Builder ist auf diesem Host nicht verfügbar.</div>
          ) : (
            c.latest && <span className="small">✔ Caddy und Plugins sind aktuell.</span>
          )}
        </>
      )}
      <ErrorBox error={err} />
      <p className="small muted" style={{ margin: 0 }}>
        Plugins sind in die Caddy-Binary kompiliert, ein Update ist deshalb ein neuer Build auf diesem Server (beim ersten Mal lädt er Go und xcaddy).
        Die neue Binary muss das aktuelle Caddyfile akzeptieren und gesund starten, sonst kommt die alte zurück. Verlauf und Rollback unter{" "}
        <a href="/build" onClick={toBuild}>
          Plugins & Build
        </a>
        .
      </p>
    </div>
  );
}
