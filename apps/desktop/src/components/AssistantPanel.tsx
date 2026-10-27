/** Assistant panel (ADR-005): the always-visible right rail. Shows the
 * chat log (user / assistant / tool cards) and the composer. Provider
 * setup (API key, base URL, model) lives in Config → Assistant since the
 * 0.8.0 menu-bar restructure. */
import { useEffect, useRef, useState } from "react";
import type { AssistantBinding } from "../hooks/useAssistant";

const STARTERS = [
  "Save a machine for me",
  "Share this screen",
  "What can you do here?",
];

export function AssistantPanel({
  assistant,
  onOpenConfig,
}: {
  assistant: AssistantBinding;
  onOpenConfig: () => void;
}) {
  const [draft, setDraft] = useState("");
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
          onClick={onOpenConfig}
          title="Config → Assistant"
        >
          Setup
        </button>
      </header>

      {assistant.confirm ? (
        <div className="assistant-confirm" role="alertdialog" aria-label={assistant.confirm.question}>
          <b>{assistant.confirm.question}</b>
          {assistant.confirm.detail ? <p className="muted">{assistant.confirm.detail}</p> : null}
          <div className="row">
            <button
              type="button"
              className="primary small"
              onClick={() => void assistant.answerConfirm(true, true)}
            >
              Always allow this site
            </button>
            <button
              type="button"
              className="ghost small"
              onClick={() => void assistant.answerConfirm(true, false)}
            >
              Allow once
            </button>
            <button
              type="button"
              className="danger small"
              onClick={() => void assistant.answerConfirm(false, false)}
            >
              Deny
            </button>
          </div>
          <p className="muted small">No answer in 5 minutes = not allowed.</p>
        </div>
      ) : null}

      {!configured ? (
        <div className="assistant-setup">
          <p className="muted">
            No API key yet — add one (and pick the model) in{" "}
            <button type="button" className="link" onClick={onOpenConfig}>
              Config → Assistant
            </button>
            .
          </p>
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
                <span className="err-glyph" aria-hidden="true">⚠</span>
                <span className="err-body">
                  <b>Something went wrong</b>
                  {m.message}
                </span>
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
          placeholder={configured ? "ask anything, or give a task…" : "add an API key in Config → Assistant first"}
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
