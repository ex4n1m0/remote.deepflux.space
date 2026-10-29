/** Conversation pane (RD-022): the center column's chat with one
 * machine's HUMAN — your lines, their lines, and your own assistant's
 * lines on your behalf. Works with or without a live session (the
 * backend routes accordingly: in-session direct, offline sealed inbox).
 * The peer machine's assistant has its own box (AgentChat) that exists
 * only while a session with that machine is live. */
import { useEffect, useRef, useState } from "react";
import type { ChatBinding } from "../hooks/useChat";

/** Lines that belong to the human conversation: you, them, and your own
 * assistant speaking for you. Agent-to-agent lines ("to-agent" /
 * "peer-agent") render in AgentChat instead. */
const HUMAN_SENDERS = new Set(["user", "agent", "peer-user"]);

export function Conversation({
  name,
  chat,
}: {
  name: string | null;
  chat: ChatBinding;
}) {
  const [draft, setDraft] = useState("");
  const logRef = useRef<HTMLDivElement | null>(null);

  const lines = chat.lines.filter((line) => HUMAN_SENDERS.has(line.sender));

  useEffect(() => {
    logRef.current?.scrollTo?.({ top: logRef.current.scrollHeight });
  }, [chat.lines.length]);

  const submit = async () => {
    const text = draft.trim();
    if (!text || chat.sending) return;
    setDraft("");
    await chat.send(text, false);
  };

  return (
    <div className="conversation">
      <div className="conversation-log" ref={logRef}>
        {lines.length === 0 ? (
          <p className="muted">
            {name
              ? `No messages yet with ${name}. Chat works even without a session — messages wait sealed until the machine returns.`
              : "Select a machine to see your conversation."}
          </p>
        ) : (
          lines.map((line) => (
            <div
              key={line.id}
              className={`chat-msg ${line.sender.startsWith("peer") ? "incoming" : "outgoing"}${
                line.sender === "agent" ? " agent" : ""
              }`}
            >
              <span className="chat-who">
                {line.sender === "user"
                  ? "you"
                  : line.sender === "agent"
                    ? "your assistant"
                    : "them"}
              </span>
              {line.body}
            </div>
          ))
        )}
      </div>
      <div className="conversation-compose">
        <input
          value={draft}
          placeholder={!name ? "select a machine first" : `message ${name}…`}
          disabled={!name}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void submit();
            }
          }}
          aria-label="Chat message"
        />
        <button
          type="button"
          className="primary"
          disabled={!draft.trim() || !name || chat.sending}
          onClick={() => void submit()}
        >
          Send
        </button>
      </div>
    </div>
  );
}
