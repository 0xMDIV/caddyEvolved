import { FormEvent, useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Spinner, useAction, useLoad } from "./ui";
import { IconLock } from "@tabler/icons-react";

interface ProtectResponse {
  rules: string[];
  extra: string[] | null;
}

/** Paths every site refuses: built-in rules plus the operator's own list. */
export function ProtectCard() {
  const data = useLoad(() => api.get<ProtectResponse>("/api/protect"));
  const [text, setText] = useState("");
  const { busy, run } = useAction();
  const [probe, setProbe] = useState("");
  const [result, setResult] = useState<{ path: string; blocked: boolean } | null>(null);

  useEffect(() => {
    if (data.data) setText((data.data.extra ?? []).join("\n"));
  }, [data.data]);

  const saved = (data.data?.extra ?? []).join("\n");
  const save = async () => {
    const extra = text
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (await run("save", () => api.put("/api/protect", { extra }), "Gespeichert – alle Sites neu geladen")) data.reload();
  };
  const check = async (e: FormEvent) => {
    e.preventDefault();
    if (!probe.trim()) return;
    setResult(await api.get<{ path: string; blocked: boolean }>("/api/protect/check?path=" + encodeURIComponent(probe.trim())));
  };

  return (
    <div className="card stack" style={{ marginBottom: 16 }}>
      <div className="row">
        <IconLock size={18} />
        <h2 style={{ margin: 0 }}>Sensible Dateien – immer gesperrt</h2>
        <Badge kind="ok">alle Sites</Badge>
      </div>
      <p className="small muted" style={{ margin: 0 }}>
        Diese Pfade beantwortet Caddy bei jeder Site mit 404, bevor die Anfrage den Dienst dahinter erreicht – auch wenn der Dienst die Datei selbst
        ausliefern würde. Das lässt sich nicht abschalten. Groß-/Kleinschreibung, Umwege wie <span className="mono">//.env</span> oder{" "}
        <span className="mono">%2eenv</span> spielen keine Rolle.
      </p>
      <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
        {(data.data?.rules ?? []).map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>

      <div className="grid grid-2" style={{ alignItems: "start" }}>
        <label className="field">
          Zusätzlich sperren
          <textarea
            className="mono"
            rows={5}
            spellCheck={false}
            value={text}
            placeholder={"/backup/*\n*.xlsx\n/admin/export"}
            onChange={(e) => setText(e.target.value)}
          />
          <span className="hint">Ein Muster pro Zeile, mit * als Platzhalter: /ordner/* sperrt alles darunter, *.xlsx jede Excel-Datei.</span>
          <button className="btn primary" style={{ alignSelf: "flex-start" }} disabled={busy === "save" || text.trim() === saved.trim()} onClick={save}>
            {busy === "save" && <Spinner />} Speichern
          </button>
        </label>

        <form className="stack" style={{ gap: 5, fontWeight: 550, fontSize: 13 }} onSubmit={check}>
          Pfad prüfen
          <div className="row" style={{ flexWrap: "nowrap" }}>
            <input className="mono" value={probe} onChange={(e) => (setProbe(e.target.value), setResult(null))} placeholder="/app/.env oder https://…/pfad" spellCheck={false} />
            <button className="btn" type="submit" disabled={!probe.trim()}>
              Prüfen
            </button>
          </div>
          {result && (
            <span className="row small" style={{ gap: 6 }}>
              <span className="mono wrap-any">{result.path}</span>
              {result.blocked ? <Badge kind="ok">gesperrt (404)</Badge> : <Badge kind="warn">erreichbar</Badge>}
            </span>
          )}
          <span className="hint" style={{ fontWeight: 400 }}>Gespeicherte eigene Muster zählen mit.</span>
        </form>
      </div>
    </div>
  );
}
