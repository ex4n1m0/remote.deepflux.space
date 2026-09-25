/**
 * State-mapping: the ONE place UI state is derived from the session state
 * machines. The UI never invents states (RD-011): every view is a pure
 * function of the machine-state names surfaced by the engine (which takes
 * them verbatim from `session::HostState/ControllerState::name()`).
 *
 * The mapping is exhaustive over the legal state names — the component
 * tests assert every state and transition trigger.
 */

import type {
  ControllerStateName,
  HostStateName,
  QualityPresetName,
  ScaleModeName,
} from "../types";

export type Tone = "neutral" | "progress" | "good" | "warn" | "bad";

export interface HostView {
  /** Which host panel to render. */
  view: "idle" | "registering" | "online" | "incoming" | "sharing" | "ended";
  tone: Tone;
  /** Short status label. */
  status: string;
  /** Longer explanation shown under the status. */
  detail: string;
  can: { start: boolean; stop: boolean; accept: boolean; reject: boolean };
}

export interface ControllerView {
  view:
    | "idle"
    | "registering"
    | "online"
    | "connecting"
    | "session"
    | "ended";
  tone: Tone;
  status: string;
  detail: string;
  can: {
    start: boolean;
    stop: boolean;
    connect: boolean;
    cancel: boolean;
    disconnect: boolean;
    /** Session controls (monitor/quality/scale/fullscreen). */
    controls: boolean;
  };
}

const HOST_VIEWS: Record<HostStateName, HostView> = {
  Idle: {
    view: "idle",
    tone: "neutral",
    status: "Sharing off",
    detail: "This machine is not accepting remote control.",
    can: { start: true, stop: false, accept: false, reject: false },
  },
  Registering: {
    view: "registering",
    tone: "progress",
    status: "Going online…",
    detail: "Registering with the signaling service.",
    can: { start: false, stop: false, accept: false, reject: false },
  },
  Online: {
    view: "online",
    tone: "good",
    status: "Waiting for a controller",
    detail: "This machine is online and can be controlled with your code.",
    can: { start: false, stop: true, accept: false, reject: false },
  },
  ConsentPrompted: {
    view: "incoming",
    tone: "warn",
    status: "Connection request",
    detail: "A controller asks to control this machine. Accept once to share.",
    can: { start: false, stop: true, accept: true, reject: true },
  },
  Exchanging: {
    view: "sharing",
    tone: "progress",
    status: "Exchanging connection details…",
    detail: "Accepted. Setting up the direct connection (offer/answer).",
    can: { start: false, stop: true, accept: false, reject: false },
  },
  Connecting: {
    view: "sharing",
    tone: "progress",
    status: "Connecting…",
    detail: "Opening the direct peer connection.",
    can: { start: false, stop: true, accept: false, reject: false },
  },
  Connected: {
    view: "sharing",
    tone: "good",
    status: "Sharing this machine",
    detail: "A controller is viewing this desktop. Stop to end the session.",
    can: { start: false, stop: true, accept: false, reject: false },
  },
  Disconnected: {
    view: "ended",
    tone: "bad",
    status: "Session ended",
    detail: "The sharing session ended. Press Share again to re-enable.",
    can: { start: true, stop: false, accept: false, reject: false },
  },
};

const CONTROLLER_VIEWS: Record<ControllerStateName, ControllerView> = {
  Idle: {
    view: "idle",
    tone: "neutral",
    status: "Controller off",
    detail: "Enter a connection code or pick a favorite to control a machine.",
    can: { start: true, stop: false, connect: false, cancel: false, disconnect: false, controls: false },
  },
  Registering: {
    view: "registering",
    tone: "progress",
    status: "Going online…",
    detail: "Registering with the signaling service.",
    can: { start: false, stop: false, connect: false, cancel: false, disconnect: false, controls: false },
  },
  Online: {
    view: "online",
    tone: "good",
    status: "Ready to connect",
    detail: "Enter the host machine's connection code.",
    can: { start: false, stop: true, connect: true, cancel: false, disconnect: false, controls: false },
  },
  Requesting: {
    view: "connecting",
    tone: "progress",
    status: "Requesting…",
    detail: "Waiting for the host user to accept.",
    can: { start: false, stop: false, connect: false, cancel: true, disconnect: false, controls: false },
  },
  Offering: {
    view: "connecting",
    tone: "progress",
    status: "Exchanging connection details…",
    detail: "Accepted. Setting up the direct connection.",
    can: { start: false, stop: false, connect: false, cancel: true, disconnect: false, controls: false },
  },
  Connecting: {
    view: "connecting",
    tone: "progress",
    status: "Connecting…",
    detail: "Opening the direct peer connection.",
    can: { start: false, stop: false, connect: false, cancel: true, disconnect: false, controls: false },
  },
  Connected: {
    view: "session",
    tone: "good",
    status: "Session live",
    detail: "The viewer window shows the remote desktop.",
    can: { start: false, stop: false, connect: false, cancel: false, disconnect: true, controls: true },
  },
  Disconnected: {
    view: "ended",
    tone: "bad",
    status: "Session ended",
    detail: "The control session ended.",
    can: { start: true, stop: false, connect: false, cancel: false, disconnect: false, controls: false },
  },
};

export function hostView(state: HostStateName): HostView {
  const view = HOST_VIEWS[state];
  if (view) {
    return view;
  }
  // Defensive: the machine contract is closed, but a future state name
  // must degrade to "unknown" rather than crash the shell.
  return {
    view: "idle",
    tone: "neutral",
    status: "Unknown host state",
    detail: `The engine reported an unmapped state (${String(state)}).`,
    can: { start: false, stop: false, accept: false, reject: false },
  };
}

export function controllerView(state: ControllerStateName): ControllerView {
  const view = CONTROLLER_VIEWS[state];
  if (view) {
    return view;
  }
  return {
    view: "idle",
    tone: "neutral",
    status: "Unknown controller state",
    detail: `The engine reported an unmapped state (${String(state)}).`,
    can: { start: false, stop: false, connect: false, cancel: false, disconnect: false, controls: false },
  };
}

/**
 * User-facing copy for disconnect causes. Codes come from the engine's
 * `disconnect_copy` (and `DisconnectCause` Debug strings).
 */
export function disconnectCopy(code: string): { title: string; hint: string | null } {
  switch (code) {
    case "user_disconnect":
      return { title: "You ended the session.", hint: null };
    case "peer_disconnect":
      return { title: "The other machine ended the session.", hint: null };
    case "timeout":
      return {
        title: "The session timed out before the direct connection opened.",
        hint: DIRECT_ONLY_HINT,
      };
    case "rejected":
      return { title: "The host declined the connection.", hint: null };
    case "canceled":
      return { title: "The connection attempt was canceled.", hint: null };
    case "collision":
      return {
        title: "Both machines tried to connect at once; the tie-break canceled this side.",
        hint: null,
      };
    case "transport_error":
      return {
        title: "The direct connection failed or dropped.",
        hint: DIRECT_ONLY_HINT,
      };
    default:
      return { title: "The session ended.", hint: null };
  }
}

export const DIRECT_ONLY_HINT =
  "This build supports direct connections only (no relay). If both machines are behind " +
  "symmetric NAT or UDP is blocked, the connection cannot be established until TURN is " +
  "added (deferred by the MVP plan).";

/** Which machine-state transition triggers correspond to which UI action. */
export const TRANSITION_TRIGGERS = {
  host: {
    start: "Start", // Idle/Disconnected → Registering
    stop: "Stop", // Online..Connected → Disconnected
    accept: "ConsentAccepted", // ConsentPrompted → Exchanging
    reject: "ConsentRejected", // ConsentPrompted → Online
  },
  controller: {
    start: "Start", // Idle/Disconnected → Registering
    stop: "Stop (no re-register)",
    connect: "Connect", // Online → Requesting
    cancel: "Cancel", // Requesting/Offering/Connecting → Disconnected
    disconnect: "Disconnect", // Connected → Disconnected
  },
} as const;

export const QUALITY_LABELS: Record<QualityPresetName, string> = {
  auto: "Auto",
  low: "Low (720p30, 2 Mbps)",
  balanced: "Balanced (1080p60, 6 Mbps)",
  high: "High (1440p60, 12 Mbps)",
};

export const SCALE_LABELS: Record<ScaleModeName, string> = {
  fit: "Fit to window",
  one_to_one: "1:1 pixels",
};

export function formatMonitorLabel(
  monitor: { monitor_id: string; label: string; is_primary: boolean },
  index: number,
): string {
  const primary = monitor.is_primary ? " (primary)" : "";
  const fallback = `${monitor.monitor_id} — display ${index + 1}`;
  return `${monitor.label || fallback}${primary}`;
}
