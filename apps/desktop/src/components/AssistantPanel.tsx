/** Assistant panel (ADR-005): the always-visible right rail. Shows the
 * chat log (user / assistant / tool cards) and the composer. Provider
 * setup (API key, base URL, model) lives in Config → Assistant since the
 * 0.8.0 menu-bar restructure. */
import { useEffect, useRef, useState } from "react";
import type { AssistantBinding } from "../hooks/useAssistant";
import { Icon } from "./Icon";
import type { IconName } from "./Icon";

/** One-tap tasks: each says exactly what will happen. */
const STARTERS: ReadonlyArray<{ icon: IconName; text: string }> = [
  { icon: "monitor", text: "Connect me to another machine" },
  { icon: "share", text: "Share this screen" },
  { icon: "bot", text: "Tell another machine's assistant what to do" },
  { icon: "sparkle", text: "What can you do here?" },
];

const THIS_SCREEN = "this screen";
const OTHER_SCREEN = "the other screen";

/** What a tool call reads as in the log: a line icon and a plain-English
 * verb. The raw tool name and its result stay on the row's tooltip. An
 * unknown tool shows its own name, so nothing is ever hidden. */
export function toolLine(name: string): { icon: IconName; label: string } {
  switch (name) {
    case "local_screenshot":
      return { icon: "eye", label: `Looks at ${THIS_SCREEN}` };
    case "local_click":
      return { icon: "pointer", label: `Clicks on ${THIS_SCREEN}` };
    case "local_drag":
      return { icon: "move", label: `Drags on ${THIS_SCREEN}` };
    case "local_scroll":
      return { icon: "wheel", label: `Scrolls ${THIS_SCREEN}` };
    case "local_type_text":
      return { icon: "keyboard", label: "Types on this machine" };
    case "local_press_key":
      return { icon: "keyboard", label: "Presses a key on this machine" };
    case "local_wait":
      return { icon: "clock", label: "Waits" };
    case "screenshot":
      return { icon: "eye", label: `Looks at ${OTHER_SCREEN}` };
    case "click":
      return { icon: "pointer", label: `Clicks on ${OTHER_SCREEN}` };
    case "scroll":
      return { icon: "wheel", label: `Scrolls ${OTHER_SCREEN}` };
    case "type_text":
      return { icon: "keyboard", label: "Types on the other machine" };
    case "press_key":
      return { icon: "keyboard", label: "Presses a key on the other machine" };
    case "connect":
      return { icon: "monitor", label: "Connects to a machine" };
    case "wait_connected":
      return { icon: "clock", label: "Waits for the connection" };
    case "disconnect":
      return { icon: "x", label: "Disconnects" };
    case "host_start":
      return { icon: "share", label: "Starts sharing this screen" };
    case "host_stop":
      return { icon: "stop", label: "Stops sharing this screen" };
    case "chat_send":
      return { icon: "send", label: "Sends a message" };
    case "chat_wait":
      return { icon: "clock", label: "Waits for the other assistant's answer" };
    case "chat_read":
      return { icon: "message", label: "Reads the chat" };
    case "fleet_run":
      return { icon: "users", label: "Sends a task to several machines" };
    case "run_shell":
      return { icon: "terminal", label: "Runs a command" };
    case "fs_list":
      return { icon: "file", label: "Lists a folder" };
    case "fs_read":
      return { icon: "file", label: "Reads a file" };
    case "fs_write":
      return { icon: "file", label: "Writes a file" };
    case "fs_delete":
      return { icon: "trash", label: "Deletes a file" };
    case "search":
      return { icon: "search", label: "Searches files" };
    case "ps":
      return { icon: "list", label: "Lists processes" };
    case "kill":
      return { icon: "x", label: "Ends a process" };
    case "windows_list":
      return { icon: "list", label: "Lists open windows" };
    case "window_focus":
      return { icon: "monitor", label: "Brings a window to the front" };
    case "window_minimize":
      return { icon: "monitor", label: "Minimizes a window" };
    case "window_close":
      return { icon: "x", label: "Closes a window" };
    case "app_install":
      return { icon: "download", label: "Installs an app" };
    case "app_uninstall":
      return { icon: "trash", label: "Uninstalls an app" };
    case "app_upgrade":
      return { icon: "refresh", label: "Updates apps" };
    case "app_search":
      return { icon: "search", label: "Searches for an app" };
    case "apps_list":
      return { icon: "list", label: "Lists installed apps" };
    case "download_file":
      return { icon: "download", label: "Downloads a file" };
    case "download_status":
      return { icon: "clock", label: "Checks a download" };
    case "power":
      return { icon: "power", label: "Restarts or shuts down" };
    case "power_cancel":
      return { icon: "power", label: "Cancels the restart" };
    case "schedule":
      return { icon: "clock", label: "Schedules a task" };
    case "ask_the_human":
      return { icon: "users", label: "Asks you" };
    default:
      return { icon: "tool", label: name.replaceAll("_", " ") };
  }
}

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
          className="ghost small icon-btn"
          onClick={onOpenConfig}
          title="Assistant settings"
          aria-label="Setup"
        >
          <Icon name="sliders" />
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
            No API key yet —{" "}
            <button type="button" className="link" onClick={onOpenConfig}>
              add one in Config → Assistant
            </button>
          </p>
        </div>
      ) : null}

      <div className="assistant-log" ref={logRef}>
        {assistant.messages.length === 0 ? (
          <div className="assistant-empty">
            <div className="starter-col">
              {STARTERS.map((s) => (
                <button
                  key={s.text}
                  type="button"
                  className="starter"
                  onClick={() => void assistant.send(s.text)}
                  disabled={!configured}
                >
                  <Icon name={s.icon} />
                  {s.text}
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
              const line = toolLine(m.name);
              return (
                <div
                  key={m.id}
                  className="msg tool-msg"
                  title={`${m.name}: ${m.summary}`}
                  data-tool={m.name}
                >
                  <Icon name={line.icon} />
                  <span className="tool-name">{line.label}</span>
                </div>
              );
            }
            return (
              <div key={m.id} className="msg error-msg" role="alert">
                <span className="err-glyph" aria-hidden="true">
                  <Icon name="alert" />
                </span>
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
            <Icon name="x" />
            Clear
          </button>
          <button
            type="button"
            className="primary"
            disabled={!draft.trim() || assistant.busy || !configured}
            onClick={() => void submit()}
          >
            <Icon name="send" />
            Send
          </button>
        </div>
      </footer>
    </aside>
  );
}
