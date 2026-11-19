/**
 * IPC wrappers: typed Tauri `invoke` calls. The ONLY bridge between the
 * React tree and the Rust engine. Commands and payloads are metadata
 * (strings/numbers) — frames never cross here (invariant 1).
 */
import { invoke } from "@tauri-apps/api/core";
import type {
  AccountMachine,
  DirectoryMachine,
  EngineStatus,
  Identity,
  MonitorInfo,
  PairingInfo,
  Settings,
  SwarmState,
} from "./types";

export const EVENT = {
  state: "engine://state",
  consent: "engine://consent",
  sessionEstablished: "engine://session-established",
  sessionEnded: "engine://session-ended",
  peer: "engine://peer",
  caps: "engine://caps",
  diagnostics: "engine://diagnostics",
  error: "engine://error",
  info: "engine://info",
} as const;

/** Assistant worker events (ADR-005): text + metadata only. */
export const ASSISTANT_EVENT = {
  message: "assistant://message",
  tool: "assistant://tool",
  busy: "assistant://busy",
  done: "assistant://done",
  error: "assistant://error",
  confirm: "assistant://confirm",
  confirmDone: "assistant://confirm-done",
} as const;

/** Machine chat (RD-022): the engine://chat event payload + APIs. */
export const CHAT_EVENT = "engine://chat";

/** Automatic updates (ADR-008): updater → UI event. */
export const UPDATE_EVENT = "update://state";

/** Swarm enrollment (ADR-013): membership state push. */
export const SWARM_EVENT = "swarm://state";
/** ADR-013 P2 account directory snapshot push (payload: AccountMachine[]). */
export const ACCOUNT_DIRECTORY_EVENT = "app://account-directory";

export interface UpdateState {
  status:
    | "idle"
    | "checking"
    | "available"
    | "none"
    | "downloading"
    | "ready"
    | "installing"
    | "error"
    /** 0.15.0: one-shot post-update states (see updater.rs). */
    | "updated"
    | "pending-restart";
  /** Which step an error belongs to: check | download | install (empty
   * outside errors) — words the failure for the banner. */
  stage: "check" | "download" | "install" | "";
  current_version: string;
  latest_version: string;
  notes: string;
  size_text: string;
  progress_percent: number;
  error: string;
}

export interface ChatLine {
  id: number;
  ts_ms: number;
  /** user | agent | peer-user | peer-agent | to-agent (this machine's
   * perspective; "to-agent" = your line addressed to their assistant). */
  sender: string;
  body: string;
}

export interface AssistantStatus {
  configured: boolean;
  busy: boolean;
  base_url: string;
  model: string;
}

export const api = {
  getIdentity: (): Promise<Identity> => invoke("get_identity"),
  getSettings: (): Promise<Settings> => invoke("get_settings"),
  setSettings: (patch: Settings): Promise<Settings> => invoke("set_settings", { patch }),

  engineStart: (): Promise<EngineStatus> => invoke("engine_start"),
  engineStatus: (): Promise<EngineStatus> => invoke("engine_status"),

  hostStart: (): Promise<void> => invoke("host_start"),
  hostStop: (): Promise<void> => invoke("host_stop"),
  controllerStart: (): Promise<void> => invoke("controller_start"),
  controllerStop: (): Promise<void> => invoke("controller_stop"),

  connect: (code: string, agent = false): Promise<void> =>
    invoke("connect", { args: { code, agent } }),
  cancelConnect: (): Promise<void> => invoke("cancel_connect"),
  disconnect: (): Promise<void> => invoke("disconnect"),
  // Attach the viewer to a live agent session (monitor what the agent
  // does) — the same session, just the visual on top; the host streams
  // again. viewer_hide detaches: chat-only, host streaming back off.
  viewerShow: (): Promise<void> => invoke("viewer_show"),
  viewerHide: (): Promise<void> => invoke("viewer_hide"),

  consentAccept: (remember: boolean): Promise<void> => invoke("consent_accept", { remember }),
  consentReject: (): Promise<void> => invoke("consent_reject"),

  // Trusted machines (ADR-005 §5 revocation, wired by ADR-006; names +
  // rename per ADR-009 — this list IS the machine list).
  pairingsList: (): Promise<PairingInfo[]> => invoke("pairings_list"),
  pairingRemove: (code: string): Promise<void> => invoke("pairing_remove", { code }),
  pairingRename: (code: string, name: string): Promise<void> =>
    invoke("pairing_rename", { code, name }),

  // ADR-010 discovery list: the sealed circle directory, decrypted.
  directoryMachines: (): Promise<DirectoryMachine[]> => invoke("directory_machines"),
  directoryRefresh: (): Promise<void> => invoke("directory_refresh"),

  // ADR-013 P2 account directory: the website account's machines (the
  // connectable discovery source — replaces the circle directory rows in
  // the rail).
  accountDirectoryMachines: (): Promise<AccountMachine[]> => invoke("account_directory_machines"),

  setQuality: (preset: string): Promise<void> =>
    invoke("set_quality", { args: { preset } }),
  selectMonitor: (monitorId: string): Promise<void> =>
    invoke("select_monitor", { args: { monitor_id: monitorId } }),
  listMonitors: (): Promise<{ host: MonitorInfo[]; peer: MonitorInfo[] }> =>
    invoke("list_monitors"),

  viewerSetScale: (scale: string): Promise<void> => invoke("viewer_set_scale", { scale }),
  viewerToggleFullscreen: (): Promise<void> => invoke("viewer_toggle_fullscreen"),

  // In-app assistant (ADR-005). The API key argument goes straight to the
  // Credential Manager on the Rust side — it is never stored in TS state.
  agentStatus: (): Promise<AssistantStatus> => invoke("agent_status"),
  agentConfigure: (args: { apiKey?: string; baseUrl?: string; model?: string }): Promise<AssistantStatus> =>
    invoke("agent_configure", { args }),
  agentSend: (text: string): Promise<void> => invoke("agent_send", { args: { text } }),
  agentReset: (): Promise<void> => invoke("agent_reset"),
  agentConfirm: (id: number, allow: boolean, remember: boolean): Promise<void> =>
    invoke("agent_confirm", { id, allow, remember }),

  // File → Quit: same shutdown path as the tray's Quit.
  quitApp: (): Promise<void> => invoke("quit_app"),

  // Automatic updates (ADR-008). Check is the Help-menu verb; download
  // and install are the banner's explicit presses.
  updateState: (): Promise<UpdateState> => invoke("update_state"),
  updateCheck: (): Promise<void> => invoke("update_check"),
  updateDownload: (): Promise<void> => invoke("update_download"),
  updateInstall: (): Promise<void> => invoke("update_install"),
  updateDismiss: (): Promise<void> => invoke("update_dismiss"),

  // Machine chat + pairing (RD-022/RD-023).
  chatSend: (code: string, text: string, agent: boolean): Promise<void> =>
    invoke("chat_send", { args: { code, text, agent } }),
  chatHistory: (code: string): Promise<ChatLine[]> => invoke("chat_history", { code }),

  // Swarm enrollment (ADR-013): join shows the userCode via the state
  // event; cancel abandons the poll; claimAnswer resolves the gate (a)
  // account-claim prompt (Allow binds, Deny frees the code); leave drops
  // the LOCAL membership (the website dashboard's revoke stays
  // authoritative); rekey mints a fresh device identity (gate (d)
  // recovery — new installation id, fresh enrollment).
  swarmStatus: (): Promise<SwarmState> => invoke("swarm_status"),
  swarmJoin: (): Promise<void> => invoke("swarm_join"),
  swarmCancelJoin: (): Promise<void> => invoke("swarm_cancel_join"),
  swarmClaimAnswer: (accept: boolean): Promise<void> => invoke("swarm_claim_answer", { accept }),
  swarmRekey: (): Promise<string> => invoke("swarm_rekey"),
  swarmLeave: (): Promise<void> => invoke("swarm_leave"),
};

/** Normalize a pasted connection code (trim, lowercase). */
export function normalizeCode(raw: string): string {
  return raw.trim().toLowerCase();
}
