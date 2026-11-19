/** Config modal (0.8.0 GUI restructure): everything configurable, one
 * place, opened from the Config menu. Reuses the existing sections
 * (SettingsPanel, TrustedMachinesSection) and adds the Assistant section
 * that finally exposes the provider base URL and model (they lived in
 * settings with no UI before). ADR-013 adds the Swarm section (account
 * membership). Esc and the backdrop close it. */
import { useEffect, useRef, useState } from "react";
import type { AssistantBinding } from "../hooks/useAssistant";
import { SettingsPanel } from "./IdentityCard";
import { TrustedMachinesSection } from "./TrustedMachines";
import {
  SWARM_DASHBOARD_URL,
  sessionExpiryText,
  swarmJoinable,
  swarmStatusLine,
} from "../state/swarm";
import type { Settings, SwarmState } from "../types";

export type ConfigSection = "settings" | "trusted" | "assistant" | "swarm";

export interface ConfigDialogProps {
  open: boolean;
  section: ConfigSection;
  settings: Settings | null;
  onSaveSettings: (patch: Settings) => Promise<Settings | null>;
  version: string | null;
  assistant: AssistantBinding;
  onRevokedTrusted: () => void;
  /** ADR-013: swarm membership state + the join/leave verbs. */
  swarm: SwarmState | null;
  onJoinSwarm: () => void;
  onLeaveSwarm: () => void;
  onClose: () => void;
}

const SECTION_IDS: Array<{ id: ConfigSection; label: string }> = [
  { id: "settings", label: "Settings" },
  { id: "trusted", label: "Trusted machines" },
  { id: "assistant", label: "Assistant" },
  { id: "swarm", label: "Swarm" },
];

export function ConfigDialog({
  open,
  section,
  settings,
  onSaveSettings,
  version,
  assistant,
  onRevokedTrusted,
  swarm,
  onJoinSwarm,
  onLeaveSwarm,
  onClose,
}: ConfigDialogProps) {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const closeRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  useEffect(() => {
    if (open) {
      // Land on the section the menu item named (headings carry ids), and
      // put focus inside the dialog (keyboard users start at Close).
      closeRef.current?.focus();
      dialogRef.current
        ?.querySelector(`#${sectionAnchor(section)}`)
        ?.scrollIntoView({ block: "start" });
    }
  }, [open, section]);

  if (!open) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal config-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Configuration"
        ref={dialogRef}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="modal-head">
          <h2>Configuration</h2>
          <button
            type="button"
            className="ghost small"
            onClick={onClose}
            aria-label="Close"
            ref={closeRef}
          >
            Close
          </button>
        </header>
        <nav className="config-nav" aria-label="Sections">
          {SECTION_IDS.map((entry) => (
            <button
              key={entry.id}
              type="button"
              className={entry.id === section ? "config-nav-active" : "ghost small"}
              onClick={() =>
                dialogRef.current
                  ?.querySelector(`#${sectionAnchor(entry.id)}`)
                  ?.scrollIntoView({ block: "start", behavior: "smooth" })
              }
            >
              {entry.label}
            </button>
          ))}
        </nav>
        <div className="config-body">
          <section id={sectionAnchor("settings")}>
            {/* Opened from the menu = explicit intent; no double
             * disclosure inside the modal. */}
            <SettingsPanel
              settings={settings}
              onSave={onSaveSettings}
              version={version}
              initiallyOpen
            />
          </section>
          <section id={sectionAnchor("trusted")}>
            <TrustedMachinesSection onRevoked={onRevokedTrusted} />
          </section>
          <section id={sectionAnchor("assistant")}>
            <AssistantSection assistant={assistant} />
          </section>
          <section id={sectionAnchor("swarm")}>
            <SwarmSection state={swarm} onJoin={onJoinSwarm} onLeave={onLeaveSwarm} />
          </section>
        </div>
      </div>
    </div>
  );
}

function sectionAnchor(section: ConfigSection): string {
  return `config-section-${section}`;
}

/** Assistant provider settings: API key (Credential Manager — never in
 * files or logs), OpenAI-compatible base URL, and model name. Previously
 * only the key was settable, from the assistant panel. */
export function AssistantSection({ assistant }: { assistant: AssistantBinding }) {
  const [keyDraft, setKeyDraft] = useState("");
  const [urlDraft, setUrlDraft] = useState(assistant.status?.base_url ?? "");
  const [modelDraft, setModelDraft] = useState(assistant.status?.model ?? "");
  const [saved, setSaved] = useState<"ok" | "failed" | null>(null);

  // Adopt the loaded status once (the 2 s poll would otherwise fight typing).
  const status = assistant.status;
  const adopted = useRef(false);
  useEffect(() => {
    if (!adopted.current && status) {
      adopted.current = true;
      setUrlDraft((current) => (current === "" ? status.base_url : current));
      setModelDraft((current) => (current === "" ? status.model : current));
    }
  }, [status]);

  const save = async () => {
    const ok = await assistant.configure({
      ...(keyDraft.trim() ? { apiKey: keyDraft.trim() } : {}),
      ...(urlDraft.trim() ? { baseUrl: urlDraft.trim() } : {}),
      ...(modelDraft.trim() ? { model: modelDraft.trim() } : {}),
    });
    if (ok) {
      setKeyDraft("");
    }
    setSaved(ok ? "ok" : "failed");
  };

  const configured = status?.configured ?? false;

  return (
    <div className="settings-section">
      <h3>Assistant</h3>
      <p className="muted">
        The built-in assistant uses an OpenAI-compatible API (DeepSeek by default). The key is
        stored in Windows Credential Manager — never in files or logs.
      </p>
      <label>
        API key {configured ? <span className="chip chip-good">set</span> : null}
        <input
          type="password"
          value={keyDraft}
          placeholder={configured ? "unchanged — paste to replace" : "sk-…"}
          onChange={(event) => setKeyDraft(event.target.value)}
          aria-label="API key"
        />
      </label>
      <label>
        Base URL
        <input
          value={urlDraft}
          placeholder="https://api.deepseek.com/v1"
          onChange={(event) => setUrlDraft(event.target.value)}
          aria-label="Base URL"
          spellCheck={false}
        />
      </label>
      <label>
        Model
        <input
          value={modelDraft}
          placeholder="deepseek-chat"
          onChange={(event) => setModelDraft(event.target.value)}
          aria-label="Model"
          spellCheck={false}
        />
      </label>
      <div className="row">
        <button
          type="button"
          className="primary"
          disabled={
            assistant.busy ||
            (!keyDraft.trim() && !urlDraft.trim() && !modelDraft.trim())
          }
          onClick={() => void save()}
        >
          Save assistant settings
        </button>
        <button
          type="button"
          className="ghost"
          onClick={() => {
            setUrlDraft("https://api.deepseek.com/v1");
            setModelDraft("deepseek-chat");
            setSaved(null);
          }}
          title="Restore the DeepSeek defaults"
        >
          Reset to default
        </button>
        {saved === "ok" ? <span className="muted small">Saved.</span> : null}
        {saved === "failed" ? (
          <span className="muted small" role="alert">
            Couldn't save — check the key, URL, and model.
          </span>
        ) : null}
      </div>
    </div>
  );
}

/** Swarm membership (ADR-013): one status line, the join/leave verbs,
 * and the dashboard link. Join opens the modal that carries the 8-char
 * pairing code (the Config dialog itself closes — App's onJoinSwarm).
 * Leave is LOCAL only: the website dashboard's revoke stays
 * authoritative for the account binding. */
export function SwarmSection({
  state,
  onJoin,
  onLeave,
}: {
  state: SwarmState | null;
  onJoin: () => void;
  onLeave: () => void;
}) {
  const joined = state?.status === "joined" ? state : null;
  const needsRejoin = state?.status === "needs_rejoin";
  return (
    <div className="settings-section">
      <h3>Swarm</h3>
      <p className="muted">{swarmStatusLine(state)}</p>
      {joined ? (
        <p className="muted small">Session valid until {sessionExpiryText(joined.session_expires_at_ms)}.</p>
      ) : null}
      {needsRejoin ? (
        <div className="banner banner-info" role="status">
          <p>This machine needs to rejoin the swarm — start the join again below.</p>
        </div>
      ) : null}
      <div className="row">
        {swarmJoinable(state) ? (
          <button type="button" className="primary" onClick={onJoin}>
            Join a swarm
          </button>
        ) : null}
        {joined ? (
          <button type="button" className="danger" onClick={onLeave}>
            Leave this swarm
          </button>
        ) : null}
        <button
          type="button"
          className="ghost"
          onClick={() => void openDashboard()}
          title="Open the ModelSwarm website's account page in your browser"
        >
          Open the dashboard
        </button>
      </div>
      <p className="hint">
        Joining binds this machine to your ModelSwarm account — you approve
        it with a short code on the website. Leaving here only removes the
        local membership; removing the machine for good happens on the
        dashboard.
      </p>
    </div>
  );
}

async function openDashboard(): Promise<void> {
  // MenuBar precedent: no opener plugin — the site opens in the default
  // browser via target=_blank.
  window.open(SWARM_DASHBOARD_URL, "_blank", "noopener");
}
