import { useEffect, useState } from "react";
import { IconExternalLink, IconRefresh } from "@tabler/icons-react";
import { api, UpdateResponse, VersionInfo } from "../api";
import { Badge, ConfirmButton, ErrorBox, Spinner, useLoad } from "./ui";

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
          {u.available ? (
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
        Aktualisiert nur caddyEvolved selbst – Caddy, Sites und Einstellungen bleiben. Prüfsumme wird geprüft, die alte Version bleibt als{" "}
        <span className="mono">caddyevolved.prev</span> erhalten. Auf dem Server geht dasselbe mit <span className="mono">sudo caddyevolved update</span>.
      </p>
    </div>
  );
}
