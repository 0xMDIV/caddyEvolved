import { KeyboardEvent, useEffect, useRef, useState } from "react";
import { IconCheck, IconMessageChatbot, IconPlus, IconSend, IconX } from "@tabler/icons-react";
import { AIChat, AIProposal, ApiError, api, errMsg } from "../api";
import { navigate } from "../router";
import { Redacted } from "./ip";
import { Badge, Spinner } from "./ui";

// One active chat shared by the page and the floating panel: both read this
// module's state, so a conversation started in the panel continues on the
// page and the other way round.

const STORAGE_KEY = "cev.ai.chat";

interface State {
  chat: AIChat | null;
  busy: boolean;
  error: string;
  configured: boolean | null;
}

let state: State = { chat: null, busy: false, error: "", configured: null };
let loaded = false;
const listeners = new Set<() => void>();

function set(p: Partial<State>) {
  state = { ...state, ...p };
  listeners.forEach((fn) => fn());
}

function remember(id: string | null) {
  try {
    if (id) localStorage.setItem(STORAGE_KEY, id);
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* storage unavailable */
  }
}

function remembered(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

async function load() {
  loaded = true;
  try {
    const s = await api.get<{ configured: boolean }>("/api/ai/settings");
    set({ configured: s.configured });
  } catch {
    set({ configured: false });
  }
  const id = remembered();
  if (!id) return;
  try {
    set({ chat: await api.get<AIChat>(`/api/ai/chats/${id}`) });
  } catch {
    remember(null);
  }
}

/** openChat makes a chat the active one (page list, after delete …). */
export async function openChat(id: string | null) {
  remember(id);
  if (!id) {
    set({ chat: null, error: "" });
    return;
  }
  try {
    set({ chat: await api.get<AIChat>(`/api/ai/chats/${id}`), error: "" });
  } catch (e) {
    set({ error: errMsg(e) });
  }
}

/** refreshConfigured re-reads whether the AI is set up (after saving settings). */
export function refreshConfigured() {
  api
    .get<{ configured: boolean }>("/api/ai/settings")
    .then((s) => set({ configured: s.configured }))
    .catch(() => {});
}

async function run(fn: () => Promise<AIChat>) {
  set({ busy: true, error: "" });
  try {
    const c = await fn();
    set({ chat: c, error: c.error ?? "" });
    remember(c.id);
  } catch (e) {
    // 409: the proposal was decided elsewhere – show the current state.
    if (e instanceof ApiError && e.status === 409 && state.chat) {
      set({ chat: await api.get<AIChat>(`/api/ai/chats/${state.chat.id}`).catch(() => state.chat), error: e.message });
    } else {
      set({ error: errMsg(e) });
    }
  } finally {
    set({ busy: false });
  }
}

function pageContext(): string {
  return window.location.pathname + window.location.search;
}

export function sendMessage(text: string) {
  return run(async () => {
    let id = state.chat?.id;
    if (!id) id = (await api.post<AIChat>("/api/ai/chats")).id;
    return api.post<AIChat>(`/api/ai/chats/${id}/messages`, { text, context: pageContext() });
  });
}

function decide(p: AIProposal, approve: boolean) {
  const id = state.chat?.id;
  if (!id) return;
  return run(() => api.post<AIChat>(`/api/ai/chats/${id}/proposals/${p.id}`, { approve }));
}

export function useAIChat(): State {
  const [, force] = useState(0);
  useEffect(() => {
    const fn = () => force((n) => n + 1);
    listeners.add(fn);
    if (!loaded) load();
    return () => {
      listeners.delete(fn);
    };
  }, []);
  return state;
}

const STATE_LABEL: Record<AIProposal["state"], [string, "ok" | "err" | "warn" | "info"]> = {
  pending: ["wartet auf Freigabe", "warn"],
  approved: ["ausgeführt", "ok"],
  rejected: ["abgelehnt", "err"],
  expired: ["verfallen", "info"],
};

function ProposalCard({ p, busy }: { p: AIProposal; busy: boolean }) {
  const args = p.args === undefined ? "" : JSON.stringify(p.args, null, 2);
  const [label, kind] = p.failed ? (["fehlgeschlagen", "err"] as const) : STATE_LABEL[p.state];
  return (
    <div className={`ai-proposal ${p.failed ? "rejected" : p.state}`}>
      <div className="row">
        <b>Vorschlag</b>
        <span className="mono small">{p.tool}</span>
        <span className="spacer" />
        <Badge kind={kind}>{label}</Badge>
      </div>
      {p.summary && <div className="ai-text">{p.summary}</div>}
      <div className="mono small muted">
        {p.method} {p.path}
      </div>
      {args && args !== "{}" && (
        <details>
          <summary className="small muted">Genaue Änderung</summary>
          <pre className="ai-pre">
            <Redacted text={args} />
          </pre>
        </details>
      )}
      {p.state === "pending" && (
        <div className="row">
          <button className="btn primary sm" disabled={busy} onClick={() => decide(p, true)}>
            <IconCheck size={14} /> Ausführen
          </button>
          <button className="btn sm" disabled={busy} onClick={() => decide(p, false)}>
            <IconX size={14} /> Ablehnen
          </button>
        </div>
      )}
      {p.result && p.state === "approved" && (
        <details open={p.failed}>
          <summary className="small muted">Ergebnis</summary>
          <pre className="ai-pre">{p.result}</pre>
        </details>
      )}
    </div>
  );
}

/** ChatView is the conversation with its input; compact for the panel. */
export function ChatView({ compact }: { compact?: boolean }) {
  const { chat, busy, error, configured } = useAIChat();
  const [text, setText] = useState("");
  const end = useRef<HTMLDivElement>(null);
  const items = chat?.display ?? [];
  const proposals = new Map((chat?.proposals ?? []).map((p) => [p.id, p]));

  useEffect(() => {
    end.current?.scrollIntoView({ block: "end" });
  }, [items.length, busy]);

  function submit() {
    const t = text.trim();
    if (!t || busy) return;
    setText("");
    sendMessage(t);
  }

  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  }

  if (configured === false) {
    return (
      <div className="empty">
        <IconMessageChatbot size={28} />
        <p>Noch keine KI eingerichtet.</p>
        <button className="btn primary" onClick={() => navigate("/settings#ki")}>
          KI einrichten
        </button>
      </div>
    );
  }

  return (
    <div className={`ai-chat ${compact ? "compact" : ""}`}>
      <div className="ai-messages">
        {items.length === 0 && (
          <div className="empty small">
            Frag nach Sites, Logs oder der Firewall – oder lass etwas ändern, z. B. „Sperr die IP mit den meisten 404 heute“. Jede Änderung zeigt die KI erst als
            Vorschlag; ausgeführt wird nur, was du freigibst.
          </div>
        )}
        {items.map((d, i) => {
          if (d.kind === "proposal") {
            const p = proposals.get(d.proposalId ?? "");
            return p ? <ProposalCard key={i} p={p} busy={busy} /> : null;
          }
          if (d.kind === "tool") {
            const label = d.tool === "write_ai_log" ? "Ins KI-Protokoll geschrieben" : d.isError ? "Fehler bei" : "Gelesen:";
            return (
              <details key={i} className={`ai-tool ${d.isError ? "err" : ""}`}>
                <summary>
                  {label} {d.tool !== "write_ai_log" && <span className="mono">{d.tool}</span>}
                </summary>
                <pre className="ai-pre">
                  <Redacted text={d.text ?? ""} />
                </pre>
              </details>
            );
          }
          // The proposal card repeats what the AI said along with it.
          const next = items[i + 1];
          if (d.kind === "assistant" && next?.kind === "proposal" && proposals.get(next.proposalId ?? "")?.summary === d.text?.trim()) return null;
          return (
            <div key={i} className={`ai-msg ${d.kind}`}>
              <div className="ai-text">{d.text}</div>
            </div>
          );
        })}
        {busy && (
          <div className="ai-msg assistant muted">
            <Spinner /> denkt nach …
          </div>
        )}
        {error && <div className="alert err small">{error}</div>}
        <div ref={end} />
      </div>
      <div className="ai-input">
        <textarea
          rows={compact ? 2 : 3}
          value={text}
          placeholder="Nachricht an die KI (Enter sendet, Umschalt+Enter für neue Zeile)"
          onChange={(e) => setText(e.target.value)}
          onKeyDown={onKey}
          disabled={busy}
        />
        <div className="row">
          <button className="btn ghost sm" title="Neuer Chat" disabled={busy} onClick={() => openChat(null)}>
            <IconPlus size={14} /> Neu
          </button>
          <span className="spacer" />
          <button className="btn primary sm" disabled={busy || !text.trim()} onClick={submit}>
            <IconSend size={14} /> Senden
          </button>
        </div>
      </div>
    </div>
  );
}

/** AIFab is the floating chat button with its panel, on every page but /ai. */
export function AIFab() {
  const [open, setOpen] = useState(false);
  const { chat } = useAIChat();
  const pending = chat?.pending ?? 0;
  return (
    <>
      {open && (
        <div className="ai-panel" role="dialog" aria-label="KI-Chat">
          <div className="ai-panel-head">
            <b>KI-Chat</b>
            <span className="small muted" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {chat?.title}
            </span>
            <span className="spacer" />
            <button className="btn ghost sm" onClick={() => (setOpen(false), navigate("/ai"))}>
              Ganze Seite
            </button>
            <button className="icon-btn" aria-label="Schließen" onClick={() => setOpen(false)}>
              <IconX size={16} />
            </button>
          </div>
          <ChatView compact />
        </div>
      )}
      <button className="ai-fab" title="KI-Chat" aria-label="KI-Chat öffnen" onClick={() => setOpen(!open)}>
        <IconMessageChatbot size={24} />
        {pending > 0 && <span className="ai-fab-badge">{pending}</span>}
      </button>
    </>
  );
}
