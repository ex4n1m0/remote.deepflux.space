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
  /** ADR-009: answer connection requests (host presence at launch). Was
   * the circle visibility toggle; default on. */
  host_sharing: boolean;
  /** ADR-011: run elevated — the agent has admin rights. */
  agent_admin: boolean;
  /** Domains the local user allowed the assistant to download from
   * without asking again ("always allow" on the confirm card). */
  agent_download_domains: string[];
  /** ADR-008: automatic update checks (download/install stay explicit
   * presses). Settings toggle, default on. */
  auto_update: boolean;
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
  /** Signaling service reachable right now (WS up or a send acked
   * recently) — the recovery signal: a "couldn't reach the connection
   * service" banner clears itself when this is true. */
  signaling_online: boolean;
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
  /** ADR-006: the requester's machine display name from the wire, when known —
   * advisory only; the device code beside it is the identity. */
  requester_name: string | null;
  /** ADR-013 P2: present when a VERIFIED account-scope proof rode the
   * request — the controller cryptographically proved it is this
   * installation of the machine's own website account. The prompt renders
   * the account variant; "Always allow" keys to the installation id.
   * Null/absent on every other path (and on pre-P2 payloads). */
  account?: { installation_id: string; label: string | null } | null;
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

// ---- trusted machines (ADR-009: the machine list) ----

// ---- swarm enrollment (ADR-013: the tracker's device binding) ----

/** Swarm membership state — mirrors the Rust `SwarmState` DTO (internally
 * tagged, snake_case). Metadata only: the pairing `deviceCode` and the
 * session bearer never cross IPC (Rust state + Credential Manager). */
export type SwarmState =
  | { status: "not_joined" }
  | { status: "joining"; user_code: string; expires_at_ms: number }
  | { status: "confirm_claim"; claimed_by: string; expires_at_ms: number }
  | { status: "joined"; installation_id: string; session_expires_at_ms: number }
  | { status: "needs_rejoin"; reason: string }
  | { status: "failed"; reason: string };

export type SwarmStatusName = SwarmState["status"];

// ---- human chat (ADR-013 D4/P3: humans-only E2E word rooms) ----

/** One room member (peer id + shared display name) — mirrors the Rust
 * `human_chat::HumanMember`. */
export interface HumanMember {
  peer: string;
  name: string;
}

/** Human-chat room state — mirrors the Rust `human_chat::HumanRoomState`
 * (snake_case). Metadata only: the room WORD never crosses IPC (it lives in
 * Rust state + settings); `room` is the derived room id hex. */
export interface HumanRoomState {
  joined: boolean;
  room: string | null;
  epoch: number;
  we_are_host: boolean;
  /** idle | connecting | searching | joining | founding | hosting |
   * connected | sealed | failed. */
  status: string;
  peers: HumanMember[];
  my_peer: string | null;
  presence_linked: boolean;
  online: number;
  error: string | null;
}

/** One decrypted room message — the `human-chat://message` payload. */
export interface HumanRoomMessage {
  room: string;
  sender: string;
  body: string;
  epoch: number;
  mine: boolean;
  via_site: boolean;
}

/** A non-fatal node log line — the `human-chat://log` payload. */
export interface HumanRoomLog {
  message: string;
}

/** ADR-010: one discovered machine from the sealed circle directory
 * (decrypted app-side; `is_self` keeps self out of the rail's list). */
export interface DirectoryMachine {
  device: string;
  name: string;
  online: boolean;
  refreshed_ms: number;
  is_self: boolean;
}

export interface PairingInfo {
  code: string;
  created_ms: number;
  pending_ack: boolean;
  /** host | controller | legacy (ADR-006). */
  role: string;
  /** ADR-009: cached display name of the peer machine (from the wire;
   * null on pre-0.10 rows and until the first session supplies it). */
  name: string | null;
}

/** ADR-013 P2: one machine of the website account, as the heartbeat
 * thread's tracker poll reports it. `signaling_device_id` is the connect
 * key (null = online-but-not-controllable); `is_self` keeps this machine's
 * own row out of the rail's list. */
export interface AccountMachine {
  installation_id: string;
  label: string | null;
  last_seen_at_ms: number | null;
  signaling_device_id: string | null;
  is_self: boolean;
}

/** Online window for the account directory's last-seen (mirrors the
 * website dashboard's Seen column: the heartbeat cadence is 60 s, so
 * anything older than two ticks is offline). */
export const ACCOUNT_ONLINE_WINDOW_MS = 120_000;
