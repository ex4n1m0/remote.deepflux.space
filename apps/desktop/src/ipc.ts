/**
 * IPC wrappers: typed Tauri `invoke` calls. The ONLY bridge between the
 * React tree and the Rust engine. Commands and payloads are metadata
 * (strings/numbers) — frames never cross here (invariant 1).
 */
import { invoke } from "@tauri-apps/api/core";
import type {
  AccountState,
  CircleStatus,
  ComputersList,
  DirectoryMachine,
  EngineStatus,
  Favorite,
  Identity,
  MonitorInfo,
  PairingInfo,
  PresenceResult,
  Settings,
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

export interface UpdateState {
  status: "idle" | "checking" | "available" | "none" | "downloading" | "ready" | "installing" | "error";
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
  listFavorites: (): Promise<Favorite[]> => invoke("list_favorites"),
  addFavorite: (name: string, code: string): Promise<Favorite> =>
    invoke("add_favorite", { args: { name, code } }),
  removeFavorite: (id: string): Promise<Favorite[]> =>
    invoke("remove_favorite", { args: { id } }),
  renameFavorite: (id: string, name: string): Promise<Favorite> =>
    invoke("rename_favorite", { args: { id, name } }),

  // Accounts & roster (post-MVP). Passwords are arguments ONLY — results
  // never carry them (invariant 6 discipline).
  accountState: (): Promise<AccountState> => invoke("account_state"),
  accountRegister: (username: string, displayName: string, password: string): Promise<AccountState> =>
    invoke("account_register", { args: { username, display_name: displayName, password } }),
  accountLogin: (username: string, password: string): Promise<AccountState> =>
    invoke("account_login", { args: { username, password } }),
  accountUnlock: (password: string): Promise<AccountState> =>
    invoke("account_unlock", { args: { password } }),
  // ADR-007: set/update the signed-in account's display name.
  accountSetName: (displayName: string): Promise<AccountState> =>
    invoke("account_set_name", { args: { display_name: displayName } }),
  accountLogout: (): Promise<AccountState> => invoke("account_logout"),
  computersList: (): Promise<ComputersList> => invoke("computers_list"),
  computerAdd: (name: string, code: string): Promise<ComputersList> =>
    invoke("computer_add", { args: { name, code } }),
  computerAddThis: (): Promise<ComputersList> => invoke("computer_add_this"),
  computerRemove: (id: string): Promise<ComputersList> =>
    invoke("computer_remove", { args: { id } }),
  computerRename: (id: string, name: string): Promise<ComputersList> =>
    invoke("computer_rename", { args: { id, name } }),
  computersPresence: (): Promise<PresenceResult> => invoke("computers_presence"),

  engineStart: (): Promise<EngineStatus> => invoke("engine_start"),
  engineStatus: (): Promise<EngineStatus> => invoke("engine_status"),

  hostStart: (): Promise<void> => invoke("host_start"),
  hostStop: (): Promise<void> => invoke("host_stop"),
  controllerStart: (): Promise<void> => invoke("controller_start"),
  controllerStop: (): Promise<void> => invoke("controller_stop"),

  connect: (code: string): Promise<void> => invoke("connect", { args: { code } }),
  cancelConnect: (): Promise<void> => invoke("cancel_connect"),
  disconnect: (): Promise<void> => invoke("disconnect"),

  consentAccept: (remember: boolean): Promise<void> => invoke("consent_accept", { remember }),
  consentReject: (): Promise<void> => invoke("consent_reject"),

  // Family circle / machine directory (ADR-006).
  circleStatus: (): Promise<CircleStatus> => invoke("circle_status"),
  circleJoin: (invite: string): Promise<CircleStatus> =>
    invoke("circle_join", { args: { invite } }),
  circleCreate: (): Promise<CircleStatus> => invoke("circle_create"),
  circleInvite: (): Promise<string> => invoke("circle_invite"),
  circleLeave: (): Promise<CircleStatus> => invoke("circle_leave"),
  circleSetShared: (share: boolean): Promise<CircleStatus> =>
    invoke("circle_set_shared", { args: { share } }),
  directoryRefresh: (): Promise<DirectoryMachine[]> => invoke("directory_refresh"),

  // Trusted machines (ADR-005 §5 revocation, wired by ADR-006).
  pairingsList: (): Promise<PairingInfo[]> => invoke("pairings_list"),
  pairingRemove: (code: string): Promise<void> => invoke("pairing_remove", { code }),

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
};

/** Normalize a pasted connection code (trim, lowercase). */
export function normalizeCode(raw: string): string {
  return raw.trim().toLowerCase();
}
