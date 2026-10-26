import { useEffect, useState } from "react";
import { AISettings, api, errMsg } from "../api";
import { refreshConfigured } from "./aichat";
import { Badge, ErrorBox, Spinner, useToast } from "./ui";

interface Draft {
  kind: string;
  baseUrl: string;
  model: string;
  apiKey: string;
}

/** AISettingsCard connects the AI chat to a provider. */
export function AISettingsCard() {
  const [s, setS] = useState<AISettings | null>(null);
  const [d, setD] = useState<Draft | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState("");
  const [models, setModels] = useState<string[]>([]);
  const [filter, setFilter] = useState("");
  const shown = models.filter((m) => m.toLowerCase().includes(filter.trim().toLowerCase()));
  const [test, setTest] = useState("");
  const toast = useToast();

  const load = () =>
    api
      .get<AISettings>("/api/ai/settings")
      .then((r) => {
        setS(r);
        setD({ kind: r.kind || "anthropic", baseUrl: r.baseUrl || "https://api.anthropic.com", model: r.model || r.defaultModel || "", apiKey: "" });
      })
      .catch(setErr);
  useEffect(() => {
    load();
  }, []);

  if (!s || !d) return <div className="card">{err ? <ErrorBox error={err} /> : <Spinner />}</div>;

  async function save() {
    setBusy("save");
    setErr(null);
    try {
      await api.put("/api/ai/settings", d);
      toast("ok", "KI-Einstellungen gespeichert");
      refreshConfigured();
      await load();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy("");
    }
  }

  async function runTest() {
    setBusy("test");
    setTest("");
    try {
      const r = await api.post<{ reply: string; ms: number }>("/api/ai/test");
      setTest(`Antwort in ${(r.ms / 1000).toFixed(1)} s: ${r.reply}`);
    } catch (e) {
      setTest("Fehler: " + errMsg(e));
    } finally {
      setBusy("");
    }
  }

  async function loadModels() {
    setBusy("models");
    try {
      const r = await api.get<{ models: string[] }>("/api/ai/models");
      setModels(r.models.sort());
      if (r.models.length === 0) toast("err", "Der Anbieter liefert keine Modellliste");
    } catch (e) {
      toast("err", errMsg(e));
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="card stack" id="ki" style={{ gap: 12 }}>
      <div className="row">
        <h2 style={{ margin: 0 }}>KI</h2>
        {s.configured ? <Badge kind="ok">eingerichtet</Badge> : <Badge>aus</Badge>}
      </div>
      <div className="small muted">
        Der KI-Chat (Seitenleiste und Knopf unten rechts) kann alles lesen und Änderungen vorschlagen. Ausgeführt wird nur, was du freigibst; jede Anfrage, jeder
        Vorschlag und jede Entscheidung steht im nicht löschbaren KI-Protokoll. Der Schlüssel bleibt auf dem Server.
      </div>
      <div className="presets">
        {(s.presets ?? []).map((p) => (
          <button
            key={p.id}
            className="preset"
            onClick={() => setD({ ...d, kind: p.kind, baseUrl: p.baseUrl || d.baseUrl, model: p.model ?? (p.kind === d.kind ? d.model : "") })}
          >
            {p.label}
          </button>
        ))}
      </div>
      <div className="form-grid">
        <label className="field">
          Schnittstelle
          <select value={d.kind} onChange={(e) => setD({ ...d, kind: e.target.value })}>
            <option value="anthropic">Anthropic (Claude Messages API)</option>
            <option value="openai">OpenAI-kompatibel (chat/completions)</option>
          </select>
        </label>
        <label className="field">
          Basis-URL
          <input className="mono" value={d.baseUrl} onChange={(e) => setD({ ...d, baseUrl: e.target.value })} />
        </label>
        <label className="field">
          API-Key
          <input
            type="password"
            autoComplete="off"
            value={d.apiKey}
            placeholder={s.keyHint ? `gespeichert: ${s.keyHint} – leer lassen zum Behalten` : "z. B. sk-ant-… (für Ollama leer)"}
            onChange={(e) => setD({ ...d, apiKey: e.target.value })}
          />
        </label>
        <label className="field">
          Modell
          <input className="mono" value={d.model} placeholder={s.defaultModel} onChange={(e) => setD({ ...d, model: e.target.value })} />
          {/* A real list instead of a datalist: browsers filter a datalist by the
              field's text, so with a model already entered it showed nothing. */}
          {models.length > 0 && (
            <>
              <input placeholder={`${models.length} Modelle durchsuchen …`} value={filter} onChange={(e) => setFilter(e.target.value)} />
              <select
                className="mono"
                size={Math.min(8, Math.max(2, shown.length))}
                value={shown.includes(d.model) ? d.model : ""}
                onChange={(e) => setD({ ...d, model: e.target.value })}
              >
                {shown.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
              {shown.length === 0 && <span className="hint">Kein Modell enthält „{filter}“.</span>}
            </>
          )}
          <span className="hint">
            <button type="button" className="link-btn" disabled={!s.configured || !!busy} onClick={loadModels}>
              Modelle vom Anbieter laden
            </button>
            {busy === "models" && <Spinner />}
          </span>
        </label>
      </div>
      <ErrorBox error={err} />
      <div className="row">
        <button className="btn primary" disabled={!!busy} onClick={save}>
          {busy === "save" && <Spinner />} Speichern
        </button>
        <button className="btn" disabled={!s.configured || !!busy} onClick={runTest}>
          {busy === "test" && <Spinner />} Verbindung testen
        </button>
        {test && <span className="small">{test}</span>}
      </div>
    </div>
  );
}
