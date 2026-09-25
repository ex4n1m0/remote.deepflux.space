/** Reducer tests: engine events (and polls) drive every UI state change. */
import { describe, expect, it } from "vitest";
import { engineReducer, initialUiState } from "./reducer";
import type { EngineStatus } from "../types";

const poll = (patch: Partial<EngineStatus>): EngineStatus => ({
  device_id: "dev",
  host_state: "Idle",
  controller_state: "Idle",
  session_id: null,
  viewer: { created: false, fullscreen: false, focused: false, scale: "fit" },
  host_monitors: [],
  peer_monitors: [],
  active_monitor: null,
  quality: "balanced",
  encoder: null,
  counters: {
    input_sent_fast: 0,
    input_sent_reliable: 0,
    input_all_keys_up_sent: 0,
    frames_captured: 0,
    frames_encoded: 0,
    frames_presented: 0,
    keyframes: 0,
    monitor_switches: 0,
    encoder_rebuilds: 0,
  },
  ...patch,
});

describe("engineReducer", () => {
  it("tracks state changes per machine", () => {
    let state = initialUiState();
    state = engineReducer(state, { type: "state", machine: "host", state: "Registering", session_id: null });
    expect(state.hostState).toBe("Registering");
    state = engineReducer(state, { type: "state", machine: "controller", state: "Online", session_id: null });
    expect(state.controllerState).toBe("Online");
    expect(state.hostState).toBe("Registering");
  });

  it("shows and clears the consent prompt", () => {
    let state = initialUiState();
    state = engineReducer(state, {
      type: "consent",
      event: { controller_device_id: "ctrl-1", session_id: "s1" },
    });
    expect(state.consent?.controller_device_id).toBe("ctrl-1");
    state = engineReducer(state, { type: "session-established", session_id: "s1" });
    expect(state.consent).toBeNull();
    expect(state.sessionId).toBe("s1");
  });

  it("marks the peer online on consent and offline on session end", () => {
    let state = initialUiState();
    state = engineReducer(state, { type: "peer", event: { device_id: "ctrl-1", online: true } });
    expect(state.peerOnline["ctrl-1"]).toBe(true);
    state = engineReducer(state, {
      type: "session-ended",
      event: { cause: "User", code: "user_disconnect", message: "x", hint: null },
    });
    expect(state.sessionId).toBeNull();
    expect(state.lastEnd?.code).toBe("user_disconnect");
    state = engineReducer(state, { type: "peer", event: { device_id: "ctrl-1", online: false } });
    expect(state.peerOnline["ctrl-1"]).toBe(false);
  });

  it("stores caps per origin and diagnostics snapshots", () => {
    let state = initialUiState();
    const monitor = {
      monitor_id: "\\\\.\\DISPLAY1",
      label: "1920x1080",
      width_px: 1920,
      height_px: 1080,
      is_primary: true,
      desktop_left: 0,
      desktop_top: 0,
    };
    state = engineReducer(state, { type: "caps", event: { origin: "peer", monitors: [monitor] } });
    expect(state.peerMonitors).toHaveLength(1);
    state = engineReducer(state, {
      type: "diagnostics",
      snapshot: {
        session_id: "s1",
        origin: "controller",
        stages_ms: { decode_to_present: { p50_ms: 2.5, p95_ms: 4.1, count: 90 } },
        fps: { present: 60 },
        link: null,
        queues: {},
        input: {
          applied: 3,
          suppressed: 0,
          gaps: 0,
          all_keys_up: 1,
          held: 0,
          inject_errors: 0,
        },
        encoder: null,
        encoder_kind: "hardware",
        encoder_rebuilds: 1,
        viewer_input_dropped: 0,
      },
    });
    expect(state.diagnostics?.fps.present).toBe(60);
    expect(state.diagnostics?.encoder_kind).toBe("hardware");
  });

  it("poll reconciles state authoritatively", () => {
    let state = initialUiState();
    state = engineReducer(state, { type: "state", machine: "host", state: "Online", session_id: null });
    state = engineReducer(state, { type: "poll", status: poll({ host_state: "Connected", controller_state: "Connected", session_id: "s9" }) });
    expect(state.hostState).toBe("Connected");
    expect(state.sessionId).toBe("s9");
    expect(state.engineStarted).toBe(true);
  });

  it("surfaces engine errors and info lines", () => {
    let state = initialUiState();
    state = engineReducer(state, {
      type: "error",
      event: { code: "transport_error", message: "peer connection failed", hint: "x" },
    });
    expect(state.lastError?.code).toBe("transport_error");
    state = engineReducer(state, { type: "info", message: "quality preset set to high" });
    expect(state.lastInfo).toContain("quality");
  });
});
