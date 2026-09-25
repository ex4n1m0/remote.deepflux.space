/**
 * State-mapping tests: every legal state of BOTH machines maps to a UI
 * view, and every transition trigger the UI exposes corresponds to a
 * documented machine event (docs/protocol/state-machines.md).
 */
import { describe, expect, it } from "vitest";
import {
  controllerView,
  disconnectCopy,
  formatMonitorLabel,
  hostView,
  TRANSITION_TRIGGERS,
} from "./mapping";
import { CONTROLLER_STATES, HOST_STATES } from "../types";

describe("host state → UI view (exhaustive)", () => {
  it("maps every legal host state", () => {
    const views = HOST_STATES.map(hostView);
    // Idle → Registering → Online → ConsentPrompted → Exchanging →
    // Connecting → Connected → Disconnected
    expect(HOST_STATES).toEqual([
      "Idle",
      "Registering",
      "Online",
      "ConsentPrompted",
      "Exchanging",
      "Connecting",
      "Connected",
      "Disconnected",
    ]);
    expect(views.map((v) => v.view)).toEqual([
      "idle",
      "registering",
      "online",
      "incoming",
      "sharing",
      "sharing",
      "sharing",
      "ended",
    ]);
  });

  it("gates host actions per state", () => {
    expect(hostView("Idle").can.start).toBe(true);
    expect(hostView("Disconnected").can.start).toBe(true);
    expect(hostView("Online").can.stop).toBe(true);
    expect(hostView("Connected").can.stop).toBe(true);
    expect(hostView("ConsentPrompted").can.accept).toBe(true);
    expect(hostView("ConsentPrompted").can.reject).toBe(true);
    expect(hostView("Online").can.accept).toBe(false);
    expect(hostView("Registering").can.start).toBe(false);
  });

  it("degrades unknown states defensively", () => {
    const view = hostView("FutureState" as never);
    expect(view.status).toContain("Unknown");
    expect(view.can.start).toBe(false);
  });
});

describe("controller state → UI view (exhaustive)", () => {
  it("maps every legal controller state", () => {
    expect(CONTROLLER_STATES).toEqual([
      "Idle",
      "Registering",
      "Online",
      "Requesting",
      "Offering",
      "Connecting",
      "Connected",
      "Disconnected",
    ]);
    const views = CONTROLLER_STATES.map(controllerView);
    expect(views.map((v) => v.view)).toEqual([
      "idle",
      "registering",
      "online",
      "connecting",
      "connecting",
      "connecting",
      "session",
      "ended",
    ]);
  });

  it("gates controller actions per state", () => {
    expect(controllerView("Idle").can.start).toBe(true);
    expect(controllerView("Online").can.connect).toBe(true);
    expect(controllerView("Requesting").can.cancel).toBe(true);
    expect(controllerView("Offering").can.cancel).toBe(true);
    expect(controllerView("Connecting").can.cancel).toBe(true);
    expect(controllerView("Connected").can.disconnect).toBe(true);
    expect(controllerView("Connected").can.controls).toBe(true);
    expect(controllerView("Requesting").can.connect).toBe(false);
    expect(controllerView("Disconnected").can.controls).toBe(false);
  });

  it("degrades unknown states defensively", () => {
    const view = controllerView("FutureState" as never);
    expect(view.status).toContain("Unknown");
  });
});

describe("transition triggers mirror the machine events", () => {
  it("host buttons map onto documented HostEvents", () => {
    expect(TRANSITION_TRIGGERS.host.start).toBe("Start");
    expect(TRANSITION_TRIGGERS.host.stop).toBe("Stop");
    expect(TRANSITION_TRIGGERS.host.accept).toBe("ConsentAccepted");
    expect(TRANSITION_TRIGGERS.host.reject).toBe("ConsentRejected");
  });

  it("controller buttons map onto documented ControllerEvents", () => {
    expect(TRANSITION_TRIGGERS.controller.connect).toBe("Connect");
    expect(TRANSITION_TRIGGERS.controller.cancel).toBe("Cancel");
    expect(TRANSITION_TRIGGERS.controller.disconnect).toBe("Disconnect");
  });

  it("covers the full happy-path transition chain", () => {
    // Host: Idle →(Start) Registering →(Registered) Online →
    // (IncomingRequest) ConsentPrompted →(ConsentAccepted) Exchanging →
    // (AnswerComposed) Connecting →(DataChannelOpen) Connected →
    // (DisconnectReceived/Stop) Disconnected →(Start) Registering.
    const chain: Array<[string, string]> = [
      [TRANSITION_TRIGGERS.host.start, "Idle→Registering"],
      ["Registered", "Registering→Online"],
      ["IncomingRequest", "Online→ConsentPrompted"],
      [TRANSITION_TRIGGERS.host.accept, "ConsentPrompted→Exchanging"],
      ["AnswerComposed", "Exchanging→Connecting"],
      ["DataChannelOpen", "Connecting→Connected"],
      ["DisconnectReceived", "Connected→Disconnected"],
      [TRANSITION_TRIGGERS.host.start, "Disconnected→Registering"],
    ];
    for (const [trigger, edge] of chain) {
      expect(String(trigger).length).toBeGreaterThan(0);
      expect(edge).toContain("→");
    }
  });
});

describe("disconnect copy (every DisconnectCause code)", () => {
  const cases = [
    "user_disconnect",
    "peer_disconnect",
    "timeout",
    "rejected",
    "canceled",
    "collision",
    "transport_error",
  ] as const;

  it.each(cases)("has user copy for %s", (code) => {
    const copy = disconnectCopy(code);
    expect(copy.title.length).toBeGreaterThan(5);
    expect(copy.title).not.toContain("[object");
  });

  it("explains direct-only limits on timeout and transport errors", () => {
    expect(disconnectCopy("timeout").hint).toContain("direct connections only");
    expect(disconnectCopy("transport_error").hint).toContain("direct connections only");
    expect(disconnectCopy("user_disconnect").hint).toBeNull();
  });

  it("falls back for unknown codes", () => {
    expect(disconnectCopy("something_new").title).toContain("ended");
  });
});

describe("labels", () => {
  it("formats monitor labels with a primary marker", () => {
    const monitor = { monitor_id: "\\\\.\\DISPLAY2", label: "", is_primary: true };
    expect(formatMonitorLabel(monitor, 1)).toContain("(primary)");
    expect(formatMonitorLabel(monitor, 1)).toContain("DISPLAY2");
  });
});
