import { useState } from "react";
import { api, PluginState } from "../api";
import { Badge, Spinner, useAction } from "./ui";
import { IconExternalLink } from "@tabler/icons-react";

/**
 * Saves plugin credentials and restarts caddy: the values reach caddy as
 * environment variables, which a reload does not pick up.
 */
export function useSaveCredentials(onSaved: () => void) {
  const { busy, run } = useAction();
  const save = async (set: Record<string, string>, unset: string[] = []) => {
    const r = await run("save", async () => {
      const res = await api.post<{ changed: string[] | null }>("/api/plugins/credentials", { set, unset });
      if ((res.changed ?? []).length > 0) await api.post("/api/service/restart?unit=caddy.service");
      return res;
    }, "Gespeichert – Caddy wurde neu gestartet");
    if (r) onSaved();
    return !!r;
  };
  return { busy, save };
}

/** The input fields of one plugin's settings, with save button. */
export function CredentialFields({ plugin, onSaved, compact }: { plugin: PluginState; onSaved: () => void; compact?: boolean }) {
  const [values, setValues] = useState<Record<string, string>>({});
  const { busy, save } = useSaveCredentials(onSaved);
  const dirty = Object.values(values).some((v) => v.trim());

  async function submit() {
    const set: Record<string, string> = {};
    for (const [k, v] of Object.entries(values)) if (v.trim()) set[k] = v.trim();
    if (await save(set)) setValues({});
  }

  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className={compact ? "stack" : "form-grid"} style={compact ? { gap: 10 } : undefined}>
        {(plugin.env ?? []).map((v) => {
          const state = plugin.credentialState?.[v.name];
          return (
            <label key={v.name} className="field">
              <span className="row" style={{ gap: 6 }}>
                {v.label || v.name}
                {state === "set" ? <Badge kind="ok">gesetzt</Badge> : v.required ? <Badge kind="warn">fehlt</Badge> : <Badge>optional</Badge>}
              </span>
              <input
                type={v.secret ? "password" : "text"}
                autoComplete="off"
                placeholder={state === "set" ? "•••••• (neu setzen)" : v.name}
                value={values[v.name] ?? ""}
                onChange={(e) => setValues((x) => ({ ...x, [v.name]: e.target.value }))}
                onKeyDown={(e) => e.key === "Enter" && dirty && submit()}
              />
              <span className="hint row">
                {v.help && <span>{v.help}</span>}
                {state === "set" && (
                  <button className="btn ghost sm" style={{ padding: "0 4px", color: "var(--danger)" }} disabled={!!busy} onClick={(e) => (e.preventDefault(), save({}, [v.name]))}>
                    entfernen
                  </button>
                )}
              </span>
            </label>
          );
        })}
      </div>
      <div className="row">
        <button className="btn primary" onClick={submit} disabled={!!busy || !dirty}>
          {busy && <Spinner />} Speichern & übernehmen
        </button>
        <span className="small muted">Gespeichert in /etc/caddyevolved/env (nur für Caddy lesbar), danach startet Caddy kurz neu.</span>
      </div>
    </div>
  );
}

/** A card with a plugin's credentials – used on plugin pages. */
export function CredentialCard({ plugin, onSaved }: { plugin: PluginState; onSaved: () => void }) {
  return (
    <div className="card">
      <div className="row" style={{ marginBottom: 10 }}>
        <h2 style={{ margin: 0 }}>{plugin.name}</h2>
        {plugin.detected ? <Badge kind="ok">eingebaut</Badge> : <Badge>nicht eingebaut</Badge>}
        {plugin.active && !plugin.complete && <Badge kind="warn">unvollständig</Badge>}
        <span className="spacer" />
        {plugin.docs && (
          <a href={plugin.docs} target="_blank" rel="noreferrer" className="small">
            Doku <IconExternalLink size={13} style={{ verticalAlign: "-2px" }} />
          </a>
        )}
      </div>
      <CredentialFields plugin={plugin} onSaved={onSaved} />
    </div>
  );
}
