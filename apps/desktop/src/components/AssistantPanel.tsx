/** Assistant panel (ADR-005): the always-visible right rail. Shows the
 * chat log (user / assistant / tool cards), the provider setup card when
 * no key is configured, and the composer. */
import { useEffect, useRef, useState } from "react";
import type { AssistantBinding } from "../hooks/useAssistant";

const STARTERS = [
  "Save a machine for me",
  "Share this screen",
  "What can you do here?",
];

export function AssistantPanel({ assistant }: { assistant: AssistantBinding }) {
  const [draft, setDraft] = useState("");
  const [keyDraft, setKeyDraft] = useState("");
  const [showKey, setShowKey] = useState(false);
  const logRef = useRef<HTMLDivElement | null>(null);

  // Keep the newest message visible (jsdom: scrollTo is optional).
  useEffect(() => {
    logRef.current?.scrollTo?.({ top: logRef.current.scrollHeight });
  }, [assistant.messages.length]);

  const submit = async () => {
    const text = draft.trim();
    if (!text || assistant.busy) return;
    setDraft("");
    await assistant.send(text);
  };

  const configured = assistant.status?.configured ?? false;

  return (
    <aside className="assistant" aria-label="Assistant">
      <header className="assistant-head">
        <span className="assistant-title">Assistant</span>
        {assistant.status ? (
          <span className={`chip ${configured ? "chip-good" : "chip-warn"}`}>
            <span className="chip-dot" aria-hidden="true" />
            {configured ? assistant.status.model : "no key"}
          </span>
        ) : null}
        <button
          type="button"
          className="ghost small"
          onClick={() => setShowKey((v) => !v)}
          aria-expanded={showKey}
        >
          {showKey ? "Hide setup" : "Setup"}
        </button>
      </header>

      {showKey || !configured ? (
        <div className="assistant-setup">
          <p className="muted">
            Paste an OpenAI-compatible API key (DeepSeek by default). It is stored
            in Windows Credential Manager — never in files or logs.
          </p>
          <div className="row">
            <input
              type="password"
              value={keyDraft}
              placeholder="sk-…"
              onChange={(e) => setKeyDraft(e.target.value)}
              aria-label="API key"
            />
            <button
              type="button"
              className="primary"
              disabled={keyDraft.trim().length < 8}
              onClick={async () => {
                await assistant.configure({ apiKey: keyDraft.trim() });
                setKeyDraft("");
                setShowKey(false);
              }}
            >
              Save key
            </button>
          </div>
        </div>
      ) : null}

      <div className="assistant-log" ref={logRef}>
        {assistant.messages.length === 0 ? (
          <div className="assistant-empty">
            <p className="muted">
              I can set up this app for you — save machines, change settings,
              start sharing — and once you connect, see and drive the remote
              screen to fix things.
            </p>
            <div className="starter-col">
              {STARTERS.map((s) => (
                <button
                  key={s}
                  type="button"
                  className="starter"
                  onClick={() => void assistant.send(s)}
                  disabled={!configured}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          assistant.messages.map((m) => {
            if (m.kind === "user") {
              return (
                <div key={m.id} className="msg user">
                  {m.content}
                </div>
              );
            }
            if (m.kind === "assistant") {
              return (
                <div key={m.id} className="msg assistant-msg">
                  {m.content}
                </div>
              );
            }
            if (m.kind === "tool") {
              return (
                <div key={m.id} className="msg tool-msg" title={m.summary}>
                  <span className="tool-glyph" aria-hidden="true">⚙</span>
                  <span className="tool-name">{m.name}</span>
                  <span className="muted tool-summary">{m.summary}</span>
                </div>
              );
            }
            return (
              <div key={m.id} className="msg error-msg" role="alert">
                {m.message}
              </div>
            );
          })
        )}
        {assistant.busy ? (
          <div className="msg assistant-msg pending" aria-live="polite">
            working…
          </div>
        ) : null}
      </div>

      <footer className="assistant-compose">
        <textarea
          value={draft}
          placeholder={configured ? "ask anything, or give a task…" : "add your API key above first"}
          disabled={!configured}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void submit();
            }
          }}
          aria-label="Message the assistant"
        />
        <div className="row compose-actions">
          <button
            type="button"
            className="ghost small"
            onClick={() => void assistant.reset()}
            title="Clear the conversation"
          >
            Clear
          </button>
          <button
            type="button"
            className="primary"
            disabled={!draft.trim() || assistant.busy || !configured}
            onClick={() => void submit()}
          >
            Send
          </button>
        </div>
      </footer>
    </aside>
  );
}
