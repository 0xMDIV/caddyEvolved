import { createContext, ReactNode, useCallback, useContext, useEffect, useRef, useState } from "react";
import { ApiError, errMsg } from "../api";

// ---------- Toasts ----------

type ToastKind = "ok" | "err" | "info";
interface ToastItem {
  id: number;
  kind: ToastKind;
  text: string;
}
const ToastCtx = createContext<(kind: ToastKind, text: string) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const seq = useRef(0);
  const push = useCallback((kind: ToastKind, text: string) => {
    const id = ++seq.current;
    setItems((v) => [...v, { id, kind, text }]);
    setTimeout(() => setItems((v) => v.filter((t) => t.id !== id)), kind === "err" ? 7000 : 3500);
  }, []);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toast-host" role="status" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={`toast alert ${t.kind}`}>
            {t.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast() {
  return useContext(ToastCtx);
}

// ---------- Small pieces ----------

export function PageHead({ title, sub, children }: { title: string; sub?: ReactNode; children?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <p>{sub}</p>}
      </div>
      {children && <div className="row">{children}</div>}
    </div>
  );
}

export function Badge({ kind, children }: { kind?: "ok" | "err" | "warn" | "info"; children: ReactNode }) {
  return <span className={`badge ${kind ?? ""}`}>{children}</span>;
}

export function Spinner() {
  return <span className="spinner" aria-hidden="true" />;
}

/** Error box that also lists server-side details (e.g. caddy validate output). */
export function ErrorBox({ error }: { error: unknown }) {
  if (!error) return null;
  const details = error instanceof ApiError ? error.details : [];
  return (
    <div className="alert err">
      {errMsg(error)}
      {details.length > 0 && <pre>{details.join("\n")}</pre>}
    </div>
  );
}

/** Button that asks for confirmation inline (no browser dialogs). */
export function ConfirmButton({
  onConfirm,
  children,
  confirmText = "Wirklich?",
  className = "btn danger sm",
  disabled,
}: {
  onConfirm: () => void;
  children: ReactNode;
  confirmText?: string;
  className?: string;
  disabled?: boolean;
}) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const t = setTimeout(() => setArmed(false), 4000);
    return () => clearTimeout(t);
  }, [armed]);
  if (!armed) {
    return (
      <button className={className} disabled={disabled} onClick={() => setArmed(true)}>
        {children}
      </button>
    );
  }
  return (
    <span className="row" style={{ gap: 4 }}>
      <span className="small muted">{confirmText}</span>
      <button
        className="btn danger solid sm"
        onClick={() => {
          setArmed(false);
          onConfirm();
        }}
      >
        Ja
      </button>
      <button className="btn sm" onClick={() => setArmed(false)}>
        Nein
      </button>
    </span>
  );
}

export function Switch({ checked, onChange, disabled, label }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; label?: string }) {
  return (
    <label className="switch" title={label}>
      <input type="checkbox" checked={checked} disabled={disabled} aria-label={label} onChange={(e) => onChange(e.target.checked)} />
      <span />
    </label>
  );
}

// ---------- Data hook ----------

export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const v = await fnRef.current();
      setData(v);
      setError(null);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { data, error, loading, reload, setData };
}

/** Run an async action with a busy flag and toast on error. */
export function useAction() {
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const run = useCallback(
    async <T,>(key: string, fn: () => Promise<T>, okText?: string): Promise<T | undefined> => {
      setBusy(key);
      try {
        const v = await fn();
        if (okText) toast("ok", okText);
        return v;
      } catch (e) {
        toast("err", errMsg(e));
        return undefined;
      } finally {
        setBusy(null);
      }
    },
    [toast],
  );
  return { busy, run };
}

/** Preformatted text with a copy button. */
export function CopyBlock({ text, wrap }: { text: string; wrap?: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="import-copy">
      <pre className={`code${wrap ? " wrap" : ""}`}>{text}</pre>
      <button
        className="btn sm"
        type="button"
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          } catch {
            /* clipboard blocked – the text is selectable anyway */
          }
        }}
      >
        {copied ? "Kopiert" : "Kopieren"}
      </button>
    </div>
  );
}
