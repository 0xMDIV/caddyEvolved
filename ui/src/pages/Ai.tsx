import { useState } from "react";
import { IconTrash } from "@tabler/icons-react";
import { AIChatSummary, api, fmtTime } from "../api";
import { AIAuditView } from "../components/aiaudit";
import { ChatView, openChat, useAIChat } from "../components/aichat";
import { Badge, ConfirmButton, PageHead, useLoad } from "../components/ui";

export default function Ai() {
  const [tab, setTab] = useState<"chat" | "audit">(() => (window.location.hash === "#protokoll" ? "audit" : "chat"));
  const { chat, busy } = useAIChat();
  const list = useLoad(() => api.get<{ chats: AIChatSummary[] }>("/api/ai/chats"), [chat?.id, chat?.updated]);

  async function remove(id: string) {
    await api.del(`/api/ai/chats/${id}`);
    if (chat?.id === id) openChat(null);
    list.reload();
  }

  return (
    <>
      <PageHead title="KI-Chat" sub="Fragen stellen und Änderungen vorschlagen lassen – ausgeführt wird nur, was du freigibst." />
      <div className="tabs">
        <button className={`tab ${tab === "chat" ? "active" : ""}`} onClick={() => setTab("chat")}>
          Chat
        </button>
        <button className={`tab ${tab === "audit" ? "active" : ""}`} onClick={() => setTab("audit")}>
          Protokoll
        </button>
      </div>
      {tab === "chat" && (
        <div className="ai-page">
          <div className="card ai-list">
            <button className="btn sm" style={{ width: "100%", justifyContent: "center" }} disabled={busy} onClick={() => openChat(null)}>
              Neuer Chat
            </button>
            <ul className="list-plain">
              {(list.data?.chats ?? []).map((c) => (
                <li key={c.id} className={`ai-list-item ${chat?.id === c.id ? "active" : ""}`}>
                  <button className="link-btn" disabled={busy} onClick={() => openChat(c.id)}>
                    {c.title || "Neuer Chat"}
                  </button>
                  <span className="small muted">
                    {fmtTime(c.updated)} {c.pending > 0 && <Badge kind="warn">{c.pending} offen</Badge>}
                  </span>
                  <ConfirmButton className="icon-btn" confirmText="Löschen?" onConfirm={() => remove(c.id)}>
                    <IconTrash size={14} />
                  </ConfirmButton>
                </li>
              ))}
            </ul>
            <p className="small muted" style={{ marginBottom: 0 }}>
              Chats lassen sich löschen, das KI-Protokoll nicht.
            </p>
          </div>
          <div className="card" style={{ padding: 0 }}>
            <ChatView />
          </div>
        </div>
      )}
      {tab === "audit" && <AIAuditView />}
    </>
  );
}
