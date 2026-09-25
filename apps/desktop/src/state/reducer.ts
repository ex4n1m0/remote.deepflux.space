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
  consent: ConsentEvent | null;
  lastEnd: SessionEndedEvent | null;
  /** device id → last known online flag (favorites indicator). */
  peerOnline: Record<string, boolean>;
  hostMonitors: MonitorInfo[];
  peerMonitors: MonitorInfo[];
  diagnostics: DiagSnapshot | null;
  lastError: ErrorEvent | null;
  lastInfo: string | null;
  viewer: ViewerInfo;
  activeMonitor: string | null;
  quality: string;
  engineStarted: boolean;
}

export function initialUiState(): EngineUiState {
  return {
    hostState: "Idle",
    controllerState: "Idle",
    sessionId: null,
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
    engineStarted: false,
  };
}

export type UiAction =
  | { type: "engine-started" }
  | { type: "state"; machine: "host" | "controller"; state: string; session_id: string | null }
  | { type: "consent"; event: ConsentEvent }
  | { type: "session-established"; session_id: string }
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
      return { ...state, sessionId: action.session_id, consent: null };
    case "session-ended":
      return { ...state, lastEnd: action.event, consent: null, sessionId: null };
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
        engineStarted: true,
      };
    }
    default:
      return state;
  }
}
