/**
 * Shared TS types mirroring the Rust IPC DTOs (`src-tauri/src/ipc.rs` and
 * `src-tauri/src/engine`). Field names are snake_case on purpose — they
 * match the Rust serde output exactly (the same convention as the
 * signaling schema). These are METADATA types: none of them can carry
 * frame bytes or input payloads (AGENTS.md invariant 1).
 */

export type MachineName = "host" | "controller";

/** Host state-machine names — must match `session::HostState::name()`. */
export type HostStateName =
  | "Idle"
  | "Registering"
  | "Online"
  | "ConsentPrompted"
  | "Exchanging"
  | "Connecting"
  | "Connected"
  | "Disconnected";

/** Controller state-machine names — must match `ControllerState::name()`. */
export type ControllerStateName =
  | "Idle"
  | "Registering"
  | "Online"
  | "Requesting"
  | "Offering"
  | "Connecting"
  | "Connected"
  | "Disconnected";

export const HOST_STATES: readonly HostStateName[] = [
  "Idle",
  "Registering",
  "Online",
  "ConsentPrompted",
  "Exchanging",
  "Connecting",
  "Connected",
  "Disconnected",
] as const;

export const CONTROLLER_STATES: readonly ControllerStateName[] = [
  "Idle",
  "Registering",
  "Online",
  "Requesting",
  "Offering",
  "Connecting",
  "Connected",
  "Disconnected",
] as const;

export type QualityPresetName = "auto" | "low" | "balanced" | "high";
export const QUALITY_PRESETS: readonly QualityPresetName[] = ["auto", "low", "balanced", "high"] as const;

export type ScaleModeName = "fit" | "one_to_one";
export const SCALE_MODES: readonly ScaleModeName[] = ["fit", "one_to_one"] as const;

export interface Identity {
  device_id: string;
  device_name: string;
  connection_code: string;
}

export interface Settings {
  device_id: string;
  device_name: string;
  signaling_base_url: string;
  default_quality: string;
  default_viewer_scale: string;
  /** First-run onboarding skip flag (persisted in settings.json). */
  skipped_onboarding: boolean;
}

export interface Favorite {
  id: string;
  name: string;
  code: string;
}

// ---- accounts / roster (post-MVP accounts phase) ----

/** Account gate states — mirrors `AccountStateDto.status` in ipc.rs. */
export type AccountStatus = "logged_out" | "saved_account" | "logged_in";

export interface AccountState {
  status: AccountStatus;
  username: string | null;
  /** null = unknown (register carries no expiry). */
  expires_ms: number | null;
}

/** One computer in the encrypted, server-synced roster. */
export interface Computer {
  id: string;
  name: string;
  code: string;
  added_at_ms: number;
  updated_at_ms: number;
  /** True when this entry is the machine the app runs on. */
  is_self: boolean;
}

export interface ComputersList {
  computers: Computer[];
  server_version: number;
}

export interface PresenceResult {
  online: string[];
}

export interface MonitorInfo {
  monitor_id: string;
  label: string;
  width_px: number;
  height_px: number;
  is_primary: boolean;
  desktop_left: number;
  desktop_top: number;
}

export interface ViewerInfo {
  created: boolean;
  fullscreen: boolean;
  focused: boolean;
  scale: string;
}

export interface EngineCounters {
  input_sent_fast: number;
  input_sent_reliable: number;
  input_all_keys_up_sent: number;
  frames_captured: number;
  frames_encoded: number;
  frames_presented: number;
  keyframes: number;
  monitor_switches: number;
  encoder_rebuilds: number;
}

export interface EngineStatus {
  device_id: string;
  host_state: HostStateName;
  controller_state: ControllerStateName;
  session_id: string | null;
  viewer: ViewerInfo;
  viewer_client_w: number;
  viewer_client_h: number;
  viewer_swapchain_w: number;
  viewer_swapchain_h: number;
  host_monitors: MonitorInfo[];
  peer_monitors: MonitorInfo[];
  active_monitor: string | null;
  quality: string;
  encoder: string | null;
  counters: EngineCounters;
}

export interface StageStat {
  p50_ms: number;
  p95_ms: number;
  count: number;
}

export interface LinkStat {
  send_bitrate_kbps: number | null;
  recv_bitrate_kbps: number | null;
  rtt_ms: number | null;
  loss_percent: number | null;
}

export interface QueueStat {
  depth: number;
  capacity: number;
  high_water: number;
  dropped: number;
  replaced: number;
}

export interface InputStat {
  applied: number;
  suppressed: number;
  gaps: number;
  all_keys_up: number;
  held: number;
  inject_errors: number;
}

/** Diagnostics overlay payload — numbers and id strings only. */
export interface DiagSnapshot {
  session_id: string | null;
  origin: string;
  stages_ms: Record<string, StageStat>;
  fps: Record<string, number>;
  link: LinkStat | null;
  queues: Record<string, QueueStat>;
  input: InputStat;
  encoder: string | null;
  encoder_kind: string | null;
  encoder_rebuilds: number;
  viewer_input_dropped: number;
}

// ---- engine events (payloads of the `engine://*` channels) ----

export interface StateEvent {
  machine: MachineName;
  state: HostStateName | ControllerStateName;
  session_id: string | null;
}

export interface ConsentEvent {
  controller_device_id: string;
  session_id: string;
}

export interface SessionEstablishedEvent {
  session_id: string;
  peer: string | null;
}

export interface SessionEndedEvent {
  cause: string;
  code: string;
  message: string;
  hint: string | null;
}

export interface PeerEvent {
  device_id: string;
  online: boolean;
}

export interface CapsEvent {
  origin: "host" | "peer";
  monitors: MonitorInfo[];
}

export interface ErrorEvent {
  code: string;
  message: string;
  hint: string | null;
}

export interface InfoEvent {
  message: string;
}
