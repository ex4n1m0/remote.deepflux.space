/** ADR-006 directory-state tests: reducer transitions + error copy. */

import { describe, expect, it } from "vitest";
import {
  CIRCLE_OFFLINE_HINT,
  circleErrorCopy,
  directoryReducer,
  initialDirectoryState,
} from "./directory";
import type { CircleStatus } from "../types";

const status = (over: Partial<CircleStatus>): CircleStatus => ({
  joined: false,
  circle_id: null,
  share_in_circle: false,
  family_build: false,
  machines: [],
  loaded: true,
  ...over,
});

describe("directoryReducer", () => {
  it("loads status into state", () => {
    const s = directoryReducer(initialDirectoryState(), {
      type: "status",
      status: status({
        joined: true,
        circle_id: "a1".repeat(32),
        share_in_circle: true,
        family_build: true,
        machines: [
          { device: "0123456789abcdef", name: "Mom's PC", online: true, refreshed_ms: 1, is_self: false },
        ],
      }),
    });
    expect(s.joined).toBe(true);
    expect(s.shareInCircle).toBe(true);
    expect(s.familyBuild).toBe(true);
    expect(s.machines).toHaveLength(1);
    expect(s.loaded).toBe(true);
  });

  it("push updates machines without touching membership", () => {
    let s = directoryReducer(initialDirectoryState(), {
      type: "status",
      status: status({ joined: true }),
    });
    s = directoryReducer(s, {
      type: "machines",
      machines: [
        { device: "x", name: "y", online: false, refreshed_ms: 2, is_self: true },
      ],
    });
    expect(s.machines).toHaveLength(1);
    expect(s.joined).toBe(true);
  });

  it("busy clears errors; error clears busy", () => {
    let s = directoryReducer(initialDirectoryState(), { type: "busy" });
    expect(s.busy).toBe(true);
    s = directoryReducer(s, { type: "error", error: "boom" });
    expect(s.busy).toBe(false);
    expect(s.error).toBe("boom");
  });
});

describe("circleErrorCopy", () => {
  it("maps the known shapes to friendly copy", () => {
    expect(circleErrorCopy("invite code must be 64 hex")).toContain("64-character");
    expect(circleErrorCopy("Already in a circle")).toContain("already in a circle");
    expect(circleErrorCopy("service error 409 circle_full")).toContain("full");
    expect(circleErrorCopy("network error: dial")).toContain("signaling service");
    expect(circleErrorCopy("something else")).toBe("something else");
  });

  it("explains 401/unauthorized as offline, not an auth problem", () => {
    // The service authenticates (device, token) via live presence — an
    // offline machine's toggle comes back 401.
    expect(circleErrorCopy("service error 401 unauthorized")).toBe(CIRCLE_OFFLINE_HINT);
    expect(circleErrorCopy("service error 401 unauthorized")).toContain("once this machine is online");
    expect(circleErrorCopy("unauthorized")).toBe(CIRCLE_OFFLINE_HINT);
  });

  it("maps rate limiting to wait-a-minute copy", () => {
    const copy = circleErrorCopy("service error 429 rate_limited");
    expect(copy).toContain("Too many attempts");
    expect(copy).toContain("wait a minute");
  });
});
