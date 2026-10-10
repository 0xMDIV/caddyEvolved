import { KeyboardEvent, useEffect, useState } from "react";
import { api } from "../api";
import { Badge, ErrorBox, PageHead, Spinner, useAction, useLoad, useToast } from "../components/ui";

interface CaddyfileResp {
  path: string;
  content: string;
  sitesDir: string;
}

export default function Caddyfile() {
  const file = useLoad(() => api.get<CaddyfileResp>("/api/caddyfile"));
  const [content, setContent] = useState("");
  const [output, setOutput] = useState<{ ok: boolean; text: string } | null>(null);
  const [saveErr, setSaveErr] = useState<unknown>(null);
  const { busy, run } = useAction();
  const [saving, setSaving] = useState(false);
  const toast = useToast();

  useEffect(() => {
    if (file.data) setContent(file.data.content);
  }, [file.data]);

  const dirty = file.data ? content !== file.data.content : false;

  async function validate() {
    setSaveErr(null);
    const r = await run("validate", () => api.post<{ ok: boolean; output: string }>("/api/caddyfile/validate", { content }));
    if (r) setOutput({ ok: r.ok, text: r.output || (r.ok ? "Konfiguration ist gültig." : "") });
  }

  async function format() {
    const r = await run("fmt", () => api.post<{ content: string }>("/api/caddyfile/fmt", { content }));
    if (r) setContent(r.content);
  }

  async function save() {
    setSaveErr(null);
    setOutput(null);
    setSaving(true);
    try {
      const r = await api.put<{ ok: boolean; output: string; reloaded: boolean }>("/api/caddyfile", { content });
      toast("ok", "Caddyfile gespeichert");
      setOutput({ ok: true, text: r.output || (r.reloaded ? "Gespeichert, Caddy neu geladen." : "Gespeichert.") });
      file.setData(file.data ? { ...file.data, content } : file.data);
    } catch (e) {
      setSaveErr(e);
    } finally {
      setSaving(false);
    }
  }

  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Tab" && !e.shiftKey) {
      e.preventDefault();
      const el = e.currentTarget;
      const { selectionStart: s, selectionEnd: en } = el;
      const next = content.slice(0, s) + "\t" + content.slice(en);
      setContent(next);
      requestAnimationFrame(() => {
        el.selectionStart = el.selectionEnd = s + 1;
      });
    }
    if ((e.ctrlKey || e.metaKey) && e.key === "s") {
      e.preventDefault();
      if (dirty) save();
    }
  }

  return (
    <>
      <PageHead title="Caddyfile" sub={file.data ? <span className="mono">{file.data.path}</span> : undefined}>
        {dirty && <Badge kind="warn">ungespeichert</Badge>}
        <button className="btn" onClick={() => file.data && setContent(file.data.content)} disabled={!dirty}>
          Verwerfen
        </button>
        <button className="btn" onClick={format} disabled={!!busy}>
          {busy === "fmt" && <Spinner />} Formatieren
        </button>
        <button className="btn" onClick={validate} disabled={!!busy}>
          {busy === "validate" && <Spinner />} Prüfen
        </button>
        <button className="btn primary" onClick={save} disabled={!!busy || saving || !dirty}>
          {saving && <Spinner />} Speichern & laden
        </button>
      </PageHead>
      <ErrorBox error={file.error} />
      <div className="stack">
        <div className="alert info small">
          Expertenmodus. Sites aus der Sites-Seite liegen separat in <code>{file.data?.sitesDir ?? "/etc/caddy/sites"}</code> und werden über die
          import-Zeile eingebunden – diese Zeile bitte nicht entfernen. Ungültige Konfigurationen werden nicht übernommen.
        </div>
        <textarea
          className="editor"
          spellCheck={false}
          value={content}
          onChange={(e) => setContent(e.target.value)}
          onKeyDown={onKey}
          aria-label="Caddyfile"
        />
        <ErrorBox error={saveErr} />
        {output && !saveErr && (
          <div className={`alert ${output.ok ? "ok" : "err"}`}>
            {output.ok ? "OK" : "Fehler"}
            {output.text && <pre>{output.text}</pre>}
          </div>
        )}
      </div>
    </>
  );
}
