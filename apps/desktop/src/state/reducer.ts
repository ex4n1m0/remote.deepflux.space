/**
 * The engine-UI reducer: engine events (and status polls) in, one state
 * object out. Pure and unit-tested — the hook only wires transport.
 */

import type {
  CapsEvent,
  ConsentEvent,
  ControllerStateName,
  DiagSnapshot,
  EngineStatus,
  ErrorEvent,
  HostStateName,
  MonitorInfo,
  PeerEvent,
  SessionEndedEvent,
  ViewerInfo,
} from "../types";

export interface EngineUiState {
  hostState: HostStateName;
  controllerState: ControllerStateName;
  sessionId: string | null;
  /** Device id (= connection code) of the live session's peer, when the
   * engine reported it — drives "is this machine's assistant reachable"
   * for the Conversation toggle (host-side sessions especially). */
  sessionPeer: string | null;
  consent: ConsentEvent | null;
  lastEnd: SessionEndedEvent | null;
  /** device id → last known online flag (session indicator). */
  peerOnline: Record<string, boolean>;
  hostMonitors: MonitorInfo[];
  peerMonitors: MonitorInfo[];
  diagnostics: DiagSnapshot | null;
  lastError: ErrorEvent | null;
  lastInfo: string | null;
  viewer: ViewerInfo;
  activeMonitor: string | null;
  quality: string;
  /** Agent session: engine says the viewer is suppressed (chat-only). */
  viewerSuppressed: boolean;
  /** This controller session was initiated with the Agent verb. */
  sessionAgent: boolean;
  /** Host side: the connected controller asked us not to stream video. */
  streamingSuppressed: boolean;
  engineStarted: boolean;
}

export function initialUiState(): EngineUiState {
  return {
    hostState: "Idle",
    controllerState: "Idle",
    sessionId: null,
    sessionPeer: null,
    consent: null,
    lastEnd: null,
    peerOnline: {},
    hostMonitors: [],
    peerMonitors: [],
    diagnostics: null,
    lastError: null,
    lastInfo: null,
    viewer: { created: false, fullscreen: false, focused: false, scale: "fit" },
    activeMonitor: null,
    quality: "balanced",
    viewerSuppressed: false,
    sessionAgent: false,
    streamingSuppressed: false,
    engineStarted: false,
  };
}

export type UiAction =
  | { type: "engine-started" }
  | { type: "state"; machine: "host" | "controller"; state: string; session_id: string | null }
  | { type: "consent"; event: ConsentEvent }
  | { type: "session-established"; session_id: string; peer: string | null }
  | { type: "session-ended"; event: SessionEndedEvent }
  | { type: "peer"; event: PeerEvent }
  | { type: "caps"; event: CapsEvent }
  | { type: "diagnostics"; snapshot: DiagSnapshot }
  | { type: "error"; event: ErrorEvent }
  | { type: "info"; message: string }
  | { type: "poll"; status: EngineStatus };

export function engineReducer(state: EngineUiState, action: UiAction): EngineUiState {
  switch (action.type) {
    case "engine-started":
      return { ...state, engineStarted: true };
    case "state":
      if (action.machine === "host") {
        return { ...state, hostState: action.state as HostStateName };
      }
      return { ...state, controllerState: action.state as ControllerStateName };
    case "consent":
      return { ...state, consent: action.event };
    case "session-established":
      return { ...state, sessionId: action.session_id, sessionPeer: action.peer, consent: null };
    case "session-ended":
      return {
        ...state,
        lastEnd: action.event,
        consent: null,
        sessionId: null,
        sessionPeer: null,
      };
    case "peer": {
      const peerOnline = { ...state.peerOnline, [action.event.device_id]: action.event.online };
      return { ...state, peerOnline };
    }
    case "caps":
      return action.event.origin === "host"
        ? { ...state, hostMonitors: action.event.monitors }
        : { ...state, peerMonitors: action.event.monitors };
    case "diagnostics":
      return { ...state, diagnostics: action.snapshot };
    case "error":
      return { ...state, lastError: action.event };
    case "info":
      return { ...state, lastInfo: action.message };
    case "poll": {
      const status = action.status;
      return {
        ...state,
        // Pull is authoritative: reconcile any missed push events.
        hostState: status.host_state,
        controllerState: status.controller_state,
        sessionId: status.session_id,
        hostMonitors: status.host_monitors.length > 0 ? status.host_monitors : state.hostMonitors,
        peerMonitors: status.peer_monitors.length > 0 ? status.peer_monitors : state.peerMonitors,
        viewer: status.viewer,
        activeMonitor: status.active_monitor,
        quality: status.quality,
        viewerSuppressed: status.viewer_suppressed,
        sessionAgent: status.session_agent,
        streamingSuppressed: status.streaming_suppressed,
        engineStarted: true,
      };
    }
    default:
      return state;
  }
}
