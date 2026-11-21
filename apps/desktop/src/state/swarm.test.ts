/** Pure-helper tests for the swarm UI state (ADR-013): the rail chip, the
 * join-entry decision, the status line, and the join-modal countdown. */

import { describe, expect, it } from "vitest";
import {
  joinCountdownText,
  sessionExpiryText,
  shouldCloseJoinModal,
  swarmChipText,
  swarmJoinable,
  swarmStatusLine,
} from "./swarm";
import type { SwarmState } from "../types";

describe("swarmChipText", () => {
  it("joins the chip label from the installation id's first 8 chars", () => {
    const joined: SwarmState = {
      status: "joined",
      installation_id: "9ZkdqFPeqQFMbAtgS2M8b1aVvzGk4TQsN1WjnUpeTXW2",
      session_expires_at_ms: 1,
    };
    expect(swarmChipText(joined)).toBe("swarm · 9ZkdqFPe…");
  });

  it("is null for every non-joined state (and no state yet)", () => {
    expect(swarmChipText(null)).toBeNull();
    expect(swarmChipText({ status: "not_joined" })).toBeNull();
    expect(
      swarmChipText({ status: "joining", user_code: "AB2CDEFG", expires_at_ms: 1 }),
    ).toBeNull();
    expect(swarmChipText({ status: "needs_rejoin", reason: "revoked" })).toBeNull();
    expect(swarmChipText({ status: "failed", reason: "x" })).toBeNull();
  });
});

describe("swarmJoinable", () => {
  it("offers the join entry before membership, after failures, and on rejoin", () => {
    expect(swarmJoinable(null)).toBe(true);
    expect(swarmJoinable({ status: "not_joined" })).toBe(true);
    expect(swarmJoinable({ status: "needs_rejoin", reason: "expired" })).toBe(true);
    expect(swarmJoinable({ status: "failed", reason: "offline" })).toBe(true);
  });

  it("never offers a second join while one is live or the machine is joined", () => {
    expect(
      swarmJoinable({ status: "joining", user_code: "AB2CDEFG", expires_at_ms: 1 }),
    ).toBe(false);
    expect(
      swarmJoinable({
        status: "joined",
        installation_id: "9ZkdqFPeqQFMbAtgS2M8b1aVvzGk4TQsN1WjnUpeTXW2",
        session_expires_at_ms: 1,
      }),
    ).toBe(false);
  });
});

describe("swarmStatusLine", () => {
  it("words each state for the Config section", () => {
    expect(swarmStatusLine(null)).toMatch(/Checking/i);
    expect(swarmStatusLine({ status: "not_joined" })).toMatch(/isn't in a swarm/i);
    expect(
      swarmStatusLine({ status: "joining", user_code: "AB2CDEFG", expires_at_ms: 1 }),
    ).toContain("AB2CDEFG");
    expect(
      swarmStatusLine({
        status: "joined",
        installation_id: "9ZkdqFPeqQFMbAtgS2M8b1aVvzGk4TQsN1WjnUpeTXW2",
        session_expires_at_ms: 1,
      }),
    ).toContain("9ZkdqFPe");
    // needs_rejoin/failed surface the backend's reason verbatim.
    expect(swarmStatusLine({ status: "needs_rejoin", reason: "revoked on the website" })).toBe(
      "revoked on the website",
    );
    expect(swarmStatusLine({ status: "failed", reason: "swarm enroll: HTTP 502" })).toBe(
      "swarm enroll: HTTP 502",
    );
  });
});

describe("joinCountdownText", () => {
  const expires = 1_000_000;

  it("counts down minutes and zero-padded seconds", () => {
    expect(joinCountdownText(expires, expires - 59_500)).toBe("1:00");
    expect(joinCountdownText(expires, expires - 9_000)).toBe("0:09");
    expect(joinCountdownText(expires, expires - 60_000)).toBe("1:00");
    expect(joinCountdownText(expires, expires - 599_000)).toBe("9:59");
    expect(joinCountdownText(expires, expires - 600_000)).toBe("10:00");
  });

  it("hits expired at and past the boundary", () => {
    expect(joinCountdownText(expires, expires)).toBe("expired");
    expect(joinCountdownText(expires, expires + 1)).toBe("expired");
  });
});

describe("sessionExpiryText", () => {
  it("renders the local time of the 24 h session end", () => {
    const text = sessionExpiryText(Date.UTC(2026, 10, 19, 12, 0, 0));
    expect(text).toContain("2026");
  });
});

describe("shouldCloseJoinModal", () => {
  it("closes when an open join resolves (leaving joining)", () => {
    expect(shouldCloseJoinModal("joining", "joined")).toBe(true);
    expect(shouldCloseJoinModal("joining", "failed")).toBe(true);
    expect(shouldCloseJoinModal("joining", "not_joined")).toBe(true);
  });

  it("closes on a terminal failure that never entered joining (failed start)", () => {
    expect(shouldCloseJoinModal("not_joined", "failed")).toBe(true);
    expect(shouldCloseJoinModal(undefined, "failed")).toBe(true);
  });

  it("stays open while the start POST is in flight (not joining yet)", () => {
    // The modal opens before the joining state lands — "not joining"
    // alone must never close it.
    expect(shouldCloseJoinModal("not_joined", "not_joined")).toBe(false);
    expect(shouldCloseJoinModal(undefined, "not_joined")).toBe(false);
    expect(shouldCloseJoinModal("not_joined", "joining")).toBe(false);
  });

  it("stays open through non-terminal states", () => {
    expect(shouldCloseJoinModal("joining", "joining")).toBe(false);
    expect(shouldCloseJoinModal("joined", "joined")).toBe(false);
    expect(shouldCloseJoinModal("not_joined", "needs_rejoin")).toBe(false);
  });
});
