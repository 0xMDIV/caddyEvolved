import { FormEvent, useState } from "react";
import { api, ApiError, ApiTokenInfo, fmtTime, TokenCreated, TokenScope } from "../api";
import { Badge, ConfirmButton, CopyBlock, ErrorBox, Spinner, useAction, useLoad } from "./ui";

const TTL_OPTIONS = [
  { days: 0, label: "nie" },
  { days: 30, label: "30 Tage" },
  { days: 90, label: "90 Tage" },
  { days: 365, label: "365 Tage" },
];

export function ScopeBadge({ scope }: { scope: TokenScope }) {
  return scope === "write" ? <Badge kind="warn">Schreiben</Badge> : <Badge kind="info">Lesen</Badge>;
}

/** The plaintext token, shown exactly once after creation. */
export function NewTokenBox({ created, onDismiss }: { created: TokenCreated; onDismiss?: () => void }) {
  return (
    <div className="alert ok stack" style={{ gap: 8 }}>
      <strong>Token „{created.info.name}“ erstellt – jetzt kopieren!</strong>
      <CopyBlock text={created.token} wrap />
      <span className="small">
        Dieser Wert wird nur dieses eine Mal angezeigt. Gespeichert ist nur ein Hash – geht der Token verloren, einfach widerrufen und neu erstellen.
      </span>
      {onDismiss && (
        <button type="button" className="btn sm" style={{ alignSelf: "flex-start" }} onClick={onDismiss}>
          Ausgeblendet lassen
        </button>
      )}
    </div>
  );
}

/** Form creating a token; reports the created token to the parent. */
export function CreateTokenForm({
  defaultName = "",
  defaultScope = "read",
  onCreated,
  compact,
}: {
  defaultName?: string;
  defaultScope?: TokenScope;
  onCreated: (t: TokenCreated) => void;
  compact?: boolean;
}) {
  const [name, setName] = useState(defaultName);
  const [scope, setScope] = useState<TokenScope>(defaultScope);
  const [ttl, setTtl] = useState(0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const t = await api.post<TokenCreated>("/api/tokens", { name: name.trim(), scope, ttlDays: ttl });
      onCreated(t);
      setName(defaultName);
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="stack" onSubmit={submit} style={{ gap: 10 }}>
      <div className={compact ? "row" : "grid grid-3"} style={{ alignItems: "end", gap: 10, flexWrap: "wrap" }}>
        <label className="field" style={{ flex: "1 1 180px" }}>
          Name
          <input value={name} maxLength={64} placeholder="z. B. Backup-Skript" onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="field" style={{ flex: "0 1 160px" }}>
          Berechtigung
          <select value={scope} onChange={(e) => setScope(e.target.value as TokenScope)}>
            <option value="read">Lesen</option>
            <option value="write">Schreiben</option>
          </select>
        </label>
        <label className="field" style={{ flex: "0 1 140px" }}>
          Ablauf
          <select value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
            {TTL_OPTIONS.map((o) => (
              <option key={o.days} value={o.days}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      {scope === "write" && (
        <div className="alert warn small">Ein Schreib-Token darf Sites, Access Lists und die Caddy-Binary ändern. Nur vergeben, wenn nötig.</div>
      )}
      <TokenError error={err} />
      <button className="btn primary" type="submit" disabled={busy || !name.trim()} style={{ alignSelf: "flex-start" }}>
        {busy && <Spinner />} Token erstellen
      </button>
    </form>
  );
}

function TokenError({ error }: { error: unknown }) {
  if (error instanceof ApiError && error.code === "token_forbidden") {
    return <div className="alert warn">API-Tokens lassen sich nur mit einer normalen Anmeldung verwalten, nicht mit einem Token.</div>;
  }
  return <ErrorBox error={error} />;
}

/** Settings card: list, create and revoke API tokens. */
export function TokenCard() {
  const tokens = useLoad(() => api.get<{ tokens: ApiTokenInfo[] | null }>("/api/tokens"));
  const [created, setCreated] = useState<TokenCreated | null>(null);
  const { busy, run } = useAction();

  async function revoke(id: string) {
    const r = await run(`revoke-${id}`, () => api.del(`/api/tokens/${encodeURIComponent(id)}`), "Token widerrufen");
    if (r !== undefined) tokens.reload();
  }

  const list = tokens.data?.tokens ?? [];
  return (
    <div className="card stack" id="tokens">
      <h2 style={{ margin: 0 }}>API-Tokens</h2>
      <p className="small muted" style={{ margin: 0 }}>
        Für Skripte und KI-Clients (MCP): <span className="mono">Authorization: Bearer cfx_…</span>. Jeder Aufruf erscheint im Audit Log unter dem
        Token-Namen.
      </p>
      {created && <NewTokenBox created={created} onDismiss={() => setCreated(null)} />}
      <CreateTokenForm
        onCreated={(t) => {
          setCreated(t);
          tokens.reload();
        }}
      />
      <TokenError error={tokens.error} />
      {tokens.loading && !tokens.data && <Spinner />}
      {list.length === 0 && !tokens.loading && !tokens.error && <p className="small muted">Noch keine Tokens.</p>}
      {list.length > 0 && (
        <div className="table-wrap">
          <table className="compact">
            <thead>
              <tr>
                <th>Name</th>
                <th>Recht</th>
                <th>Token</th>
                <th>Erstellt</th>
                <th>Zuletzt benutzt</th>
                <th>Läuft ab</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.map((t) => {
                const expired = !!t.expires && new Date(t.expires).getTime() < Date.now();
                return (
                  <tr key={t.id}>
                    <td>{t.name}</td>
                    <td>
                      <ScopeBadge scope={t.scope} />
                    </td>
                    <td className="mono small">{t.prefix}…</td>
                    <td className="small">{fmtTime(t.created)}</td>
                    <td className="small">{t.lastUsed ? fmtTime(t.lastUsed) : "nie"}</td>
                    <td className="small">{t.expires ? expired ? <Badge kind="err">abgelaufen</Badge> : fmtTime(t.expires) : "nie"}</td>
                    <td style={{ textAlign: "right" }}>
                      <ConfirmButton onConfirm={() => revoke(t.id)} disabled={busy === `revoke-${t.id}`} confirmText="Widerrufen?">
                        Widerrufen
                      </ConfirmButton>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
