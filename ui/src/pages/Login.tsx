import { FormEvent, useState } from "react";
import { api, VersionInfo } from "../api";
import { ErrorBox, Spinner } from "../components/ui";

export default function Login({ version, onLogin }: { version: VersionInfo | null; onLogin: () => void }) {
  const [password, setPassword] = useState("");
  const [keep, setKeep] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post("/api/login", { password, keepMeLoggedIn: keep });
      onLogin();
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="card login stack" onSubmit={submit}>
        <div className="brand" style={{ padding: 0 }}>
          <span className="brand-mark">cE</span> caddyEvolved
        </div>
        <p className="muted" style={{ margin: 0 }}>
          Anmeldung an der Caddy-Verwaltung.
        </p>
        {version?.setup && (
          <div className="alert warn">
            Noch kein UI-Passwort gesetzt. Auf dem Server <code>caddyevolved passwd</code> ausführen.
          </div>
        )}
        <label className="field">
          Passwort
          <input type="password" autoFocus autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <label className="check">
          <input type="checkbox" checked={keep} onChange={(e) => setKeep(e.target.checked)} /> Angemeldet bleiben (30 Tage)
        </label>
        <ErrorBox error={error} />
        <button className="btn primary" type="submit" disabled={busy || !password}>
          {busy && <Spinner />} Anmelden
        </button>
        {version && <span className="small muted">Version {version.version}</span>}
      </form>
    </div>
  );
}
