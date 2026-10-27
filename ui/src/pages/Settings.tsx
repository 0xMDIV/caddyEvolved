import { FormEvent, useState } from "react";
import { api, fmtTime, Session } from "../api";
import { Badge, ErrorBox, PageHead, Spinner, useAction, useLoad, useToast } from "../components/ui";
import { TokenCard } from "../components/tokens";
import { AISettingsCard } from "../components/aisettings";
import { CloudflareCard } from "../components/cloudflaresettings";
import { CaddyUpdateCard, UpdateCard } from "../components/update";

export default function Settings({ onLogout }: { onLogout: () => void }) {
  const session = useLoad(() => api.get<{ sessionId: string; remote: string; sessions: Session[] | null }>("/api/session"));
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [pwErr, setPwErr] = useState<unknown>(null);
  const [pwBusy, setPwBusy] = useState(false);
  const toast = useToast();
  const { busy, run } = useAction();

  async function changePassword(e: FormEvent) {
    e.preventDefault();
    if (next !== repeat) {
      setPwErr(new Error("Die neuen Passwörter stimmen nicht überein."));
      return;
    }
    setPwBusy(true);
    setPwErr(null);
    try {
      await api.post("/api/password", { current, new: next });
      toast("ok", "Passwort geändert – bitte neu anmelden");
      onLogout();
    } catch (err) {
      setPwErr(err);
    } finally {
      setPwBusy(false);
    }
  }

  async function logout() {
    await run("logout", () => api.post("/api/logout"));
    onLogout();
  }

  return (
    <>
      <PageHead title="Einstellungen">
        <button className="btn" onClick={logout} disabled={busy === "logout"}>
          Abmelden
        </button>
      </PageHead>
      <div className="grid grid-2" style={{ alignItems: "start" }}>
        <form className="card stack" onSubmit={changePassword}>
          <h2 style={{ margin: 0 }}>UI-Passwort ändern</h2>
          <label className="field">
            Aktuelles Passwort
            <input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
          </label>
          <label className="field">
            Neues Passwort
            <input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
          </label>
          <label className="field">
            Wiederholen
            <input type="password" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} />
          </label>
          <ErrorBox error={pwErr} />
          <button className="btn primary" type="submit" disabled={pwBusy || !current || !next} style={{ alignSelf: "flex-start" }}>
            {pwBusy && <Spinner />} Passwort ändern
          </button>
          <p className="small muted" style={{ margin: 0 }}>
            Alle Sitzungen werden dabei abgemeldet.
          </p>
        </form>

        <div className="card">
          <h2>Aktive Sitzungen</h2>
          <ErrorBox error={session.error} />
          <ul className="list-plain">
            {(session.data?.sessions ?? []).map((s) => (
              <li key={s.id}>
                <div className="row">
                  <span className="mono small">{s.remote || "–"}</span>
                  {s.id === session.data?.sessionId && <Badge kind="ok">diese Sitzung</Badge>}
                  <span className="spacer" />
                  <span className="small muted">bis {fmtTime(s.expires)}</span>
                </div>
                <div className="small muted" style={{ wordBreak: "break-word" }}>
                  {s.userAgent || "unbekannter Client"} · seit {fmtTime(s.created)}
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
      <div style={{ marginTop: 16 }}>
        <UpdateCard />
      </div>
      <div style={{ marginTop: 16 }}>
        <CaddyUpdateCard />
      </div>
      <div style={{ marginTop: 16 }}>
        <TokenCard />
        <AISettingsCard />
        <CloudflareCard />
      </div>
    </>
  );
}
