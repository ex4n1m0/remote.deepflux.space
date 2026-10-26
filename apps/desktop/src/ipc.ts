/**
 * IPC wrappers: typed Tauri `invoke` calls. The ONLY bridge between the
 * React tree and the Rust engine. Commands and payloads are metadata
 * (strings/numbers) — frames never cross here (invariant 1).
 */
import { invoke } from "@tauri-apps/api/core";
import type {
  AccountState,
  ComputersList,
  EngineStatus,
  Favorite,
  Identity,
  MonitorInfo,
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
} as const;

/** Machine chat (RD-022): the engine://chat event payload + APIs. */
export const CHAT_EVENT = "engine://chat";

export interface ChatLine {
  id: number;
  ts_ms: number;
  /** user | agent | peer-user | peer-agent (this machine's perspective). */
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
  accountRegister: (username: string, password: string): Promise<AccountState> =>
    invoke("account_register", { args: { username, password } }),
  accountLogin: (username: string, password: string): Promise<AccountState> =>
    invoke("account_login", { args: { username, password } }),
  accountUnlock: (password: string): Promise<AccountState> =>
    invoke("account_unlock", { args: { password } }),
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
  agentConfigure: (args: { apiKey?: string; model?: string }): Promise<AssistantStatus> =>
    invoke("agent_configure", { args }),
  agentSend: (text: string): Promise<void> => invoke("agent_send", { args: { text } }),
  agentReset: (): Promise<void> => invoke("agent_reset"),

  // Machine chat + pairing (RD-022/RD-023).
  chatSend: (code: string, text: string, agent: boolean): Promise<void> =>
    invoke("chat_send", { args: { code, text, agent } }),
  chatHistory: (code: string): Promise<ChatLine[]> => invoke("chat_history", { code }),
  pairingsList: (): Promise<Array<{ code: string; created_ms: number; pending_ack: boolean }>> =>
    invoke("pairings_list"),
  pairingRemove: (code: string): Promise<void> => invoke("pairing_remove", { code }),
};

/** Normalize a pasted connection code (trim, lowercase). */
export function normalizeCode(raw: string): string {
  return raw.trim().toLowerCase();
}
