/** ADR-006 directory-state tests: reducer transitions + error copy +
 * the account-gate circle bypass. */

import { describe, expect, it } from "vitest";
import {
  circleErrorCopy,
  directoryReducer,
  initialDirectoryState,
} from "./directory";
import { accountGate } from "./account";
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
});

describe("accountGate circle bypass (ADR-006)", () => {
  const anon = { status: "logged_out" as const, loaded: true };
  it("a circle member goes straight to the app", () => {
    expect(accountGate(anon, false, false, { circleJoined: true })).toBe("app");
  });
  it("non-members see the onboarding unchanged", () => {
    expect(accountGate(anon, false, false, { circleJoined: false })).toBe("onboarding");
    expect(accountGate(anon, false, false)).toBe("onboarding");
    expect(accountGate(anon, true, false)).toBe("app");
  });
});
