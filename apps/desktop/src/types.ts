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
  /** ADR-006 always-ready: launch at Windows login (tray keeps it alive). */
  launch_at_login: boolean;
  /** Domains the local user allowed the assistant to download from
   * without asking again ("always allow" on the confirm card). */
  agent_download_domains: string[];
  /** ADR-008: automatic update checks (download/install stay explicit
   * presses). Settings toggle, default on. */
  auto_update: boolean;
}

export interface Favorite {
  id: string;
  name: string;
  code: string;
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
  /** Agent session: the viewer is suppressed (chat-only) right now. */
  viewer_suppressed: boolean;
  /** This controller session was initiated with the Agent verb. */
  session_agent: boolean;
  /** Host side: the connected controller asked us not to stream video. */
  streaming_suppressed: boolean;
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
  /** ADR-004: controller advertised `FeatureFlags::AI_SESSION`. */
  ai_session: boolean;
  /** ADR-006: a pairing with this controller exists locally. */
  paired: boolean;
  /** ADR-006: the claimed pairing proof verified (silent accept requires
   * it; `paired && !pairing_proof_ok` renders the warning copy). */
  pairing_proof_ok: boolean;
  /** ADR-006: the requester's self-chosen circle nickname, when known —
   * advisory only; the device code beside it is the identity. */
  requester_name: string | null;
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

// ---- family circle / machine directory (ADR-006) ----

export interface DirectoryMachine {
  device: string;
  name: string;
  online: boolean;
  refreshed_ms: number;
  is_self: boolean;
}

export interface CircleStatus {
  joined: boolean;
  circle_id: string | null;
  share_in_circle: boolean;
  family_build: boolean;
  machines: DirectoryMachine[];
  loaded: boolean;
}

export interface PairingInfo {
  code: string;
  secret_hex: string;
  created_ms: number;
  pending_ack: boolean;
  /** host | controller | legacy (ADR-006). */
  role: string;
  /** ADR-009: cached display name of the peer machine (from the wire;
   * null on pre-0.10 rows and until the first session supplies it). */
  name: string | null;
}
