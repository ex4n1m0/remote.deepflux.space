/** Conversation pane (RD-022): the center column's chat with one machine
 * — human lines both ways, agent lines styled distinctly. Works with or
 * without a live session (the backend routes accordingly).
 *
 * Destination toggle (2026-10-28): the composer addresses either the
 * machine's human ("them") or its assistant ("{name}'s assistant") —
 * this is THE chat box for giving the remote agent instructions. The
 * assistant destination needs a live session with that machine (the
 * inbox carries no agent bit), so it is gated on `agentReachable` and
 * explains itself when disabled. The peer's assistant replies land here
 * as "their assistant" lines. */
import { useEffect, useRef, useState } from "react";
import type { ChatBinding } from "../hooks/useChat";

export function Conversation({
  name,
  chat,
  agentReachable,
}: {
  name: string | null;
  chat: ChatBinding;
  /** A live session with THIS machine exists — its assistant is
   * addressable (controller session to it, or it connected to us). */
  agentReachable: boolean;
}) {
  const [draft, setDraft] = useState("");
  const [agentMode, setAgentMode] = useState(false);
  const logRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    logRef.current?.scrollTo?.({ top: logRef.current.scrollHeight });
  }, [chat.lines.length]);

  // A dropped session silently downgrades the destination to "them" —
  // the backend would refuse the agent send anyway.
  const dest = agentMode && agentReachable ? "agent" : "them";

  const submit = async () => {
    const text = draft.trim();
    if (!text || chat.sending) return;
    setDraft("");
    await chat.send(text, dest === "agent");
  };

  return (
    <div className="conversation">
      <div className="conversation-log" ref={logRef}>
        {chat.lines.length === 0 ? (
          <p className="muted">
            {name
              ? `No messages yet with ${name}. Chat works even without a session — messages wait sealed until the machine returns. Or switch below to ${name}'s assistant and give it instructions while connected.`
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
                    : line.sender === "to-agent"
                      ? "you → their assistant"
                      : line.sender === "peer-user"
                        ? "them"
                        : "their assistant"}
              </span>
              {line.body}
            </div>
          ))
        )}
      </div>
      <div
        className="conversation-dest"
        role="group"
        aria-label="Who receives your messages"
      >
        <button
          type="button"
          className={`dest-option${dest === "them" ? " active" : ""}`}
          aria-pressed={dest === "them"}
          onClick={() => setAgentMode(false)}
        >
          Them
        </button>
        <button
          type="button"
          className={`dest-option${dest === "agent" ? " active" : ""}`}
          aria-pressed={dest === "agent"}
          disabled={!agentReachable}
          title={
            agentReachable
              ? `Give instructions to the assistant on this machine — it executes them there and replies here`
              : "Their assistant answers during a session — connect to this machine first (Control)"
          }
          onClick={() => setAgentMode(true)}
        >
          {name ? `${name}'s assistant` : "Their assistant"}
        </button>
        {dest === "agent" ? (
          <span className="hint dest-hint">
            runs on {name} — its reply appears here
          </span>
        ) : null}
      </div>
      <div className="conversation-compose">
        <input
          value={draft}
          placeholder={
            !name
              ? "select a machine first"
              : dest === "agent"
                ? `tell ${name}'s assistant what to do…`
                : `message ${name}…`
          }
          disabled={!name}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void submit();
            }
          }}
          aria-label={dest === "agent" ? "Instruction for their assistant" : "Chat message"}
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
