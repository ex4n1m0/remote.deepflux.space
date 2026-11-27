/** Agent chat box: YOUR line to the peer machine's assistant, and its
 * replies — in its own box, separate from the human Conversation. It
 * exists only while a live session with that machine is ongoing (the
 * offline inbox carries no agent bit, so the backend would refuse).
 * Give the assistant instructions; it executes them ON that machine and
 * answers here. Attach the visual ("Show the screen" on the session
 * card) to watch what it does; closing that window returns here. */
import { useEffect, useRef, useState } from "react";
import type { ChatBinding } from "../hooks/useChat";
import { Icon } from "./Icon";

/** Lines that belong to the agent conversation: your instructions
 * ("to-agent") and the peer assistant's replies ("peer-agent"). */
const AGENT_SENDERS = new Set(["to-agent", "peer-agent"]);

export function AgentChat({
  name,
  chat,
}: {
  name: string | null;
  chat: ChatBinding;
}) {
  const [draft, setDraft] = useState("");
  const logRef = useRef<HTMLDivElement | null>(null);

  const lines = chat.lines.filter((line) => AGENT_SENDERS.has(line.sender));

  useEffect(() => {
    logRef.current?.scrollTo?.({ top: logRef.current.scrollHeight });
  }, [chat.lines.length]);

  const submit = async () => {
    const text = draft.trim();
    if (!text || chat.sending) return;
    setDraft("");
    await chat.send(text, true);
  };

  return (
    <div className="conversation agent-box" aria-label="Assistant on the remote machine">
      <header className="agent-box-head">
        <span className="agent-box-title" title={`Runs on ${name ?? "that machine"} — it executes there and answers here`}>
          <Icon name="bot" />
          {name ? `${name}'s assistant` : "Their assistant"}
        </span>
      </header>
      <div className="conversation-log" ref={logRef}>
        {lines.length === 0 ? (
          <p className="muted">
            Tell {name ? `${name}'s assistant` : "the assistant"} what to do.
          </p>
        ) : (
          lines.map((line) => (
            <div
              key={line.id}
              className={`chat-msg ${line.sender.startsWith("peer") ? "incoming" : "outgoing"} agent`}
            >
              <span className="chat-who">
                {line.sender === "to-agent" ? "you → their assistant" : "their assistant"}
              </span>
              {line.body}
            </div>
          ))
        )}
      </div>
      <div className="conversation-compose">
        <input
          value={draft}
          placeholder={name ? `tell ${name}'s assistant what to do…` : "tell the assistant what to do…"}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void submit();
            }
          }}
          aria-label="Instruction for their assistant"
        />
        <button
          type="button"
          className="primary"
          disabled={!draft.trim() || chat.sending}
          onClick={() => void submit()}
        >
          <Icon name="send" />
          Send
        </button>
      </div>
    </div>
  );
}
