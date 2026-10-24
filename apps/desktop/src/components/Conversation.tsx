/** Conversation pane (RD-022): the center column's chat with one machine
 * — human lines both ways, agent lines styled distinctly. Works with or
 * without a live session (the backend routes accordingly). */
import { useEffect, useRef, useState } from "react";
import type { ChatBinding } from "../hooks/useChat";

export function Conversation({
  name,
  chat,
}: {
  name: string | null;
  chat: ChatBinding;
}) {
  const [draft, setDraft] = useState("");
  const logRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    logRef.current?.scrollTo?.({ top: logRef.current.scrollHeight });
  }, [chat.lines.length]);

  const submit = async () => {
    const text = draft.trim();
    if (!text || chat.sending) return;
    setDraft("");
    await chat.send(text);
  };

  return (
    <div className="conversation">
      <div className="conversation-log" ref={logRef}>
        {chat.lines.length === 0 ? (
          <p className="muted">
            {name
              ? `No messages yet with ${name}. Chat works even without a session — messages wait sealed until the machine returns.`
              : "Select a machine to see your conversation."}
          </p>
        ) : (
          chat.lines.map((line) => (
            <div
              key={line.id}
              className={`chat-msg ${line.sender.startsWith("peer") ? "incoming" : "outgoing"}${
                line.sender.endsWith("agent") ? " agent" : ""
              }`}
            >
              <span className="chat-who">
                {line.sender === "user"
                  ? "you"
                  : line.sender === "agent"
                    ? "your assistant"
                    : line.sender === "peer-user"
                      ? "them"
                      : "their assistant"}
              </span>
              {line.body}
            </div>
          ))
        )}
      </div>
      <div className="conversation-compose">
        <input
          value={draft}
          placeholder={name ? `message ${name}…` : "select a machine first"}
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
