/** Swarm-enrollment UI state helpers (ADR-013): pure functions over the
 * `SwarmState` DTO — display copy, the join-modal countdown, and the
 * rail-chip/entry decisions. Transport lives in `useSwarm`; this module
 * stays testable with plain values. */

import type { SwarmState, SwarmStatusName } from "../types";

/** The tracker's account dashboard, where the user approves a pairing
 * code. Production constant (the Rust side's DEEPFLUX_TRACKER_URL env
 * override exists for dev/test loops, not for the shipped UI). */
export const SWARM_DASHBOARD_URL = "https://modelswarm.deepflux.space/account";

/** The rail's "This machine" chip when Joined: `swarm · <first 8>…`. */
export function swarmChipText(state: SwarmState | null): string | null {
  if (state?.status !== "joined") return null;
  return `swarm · ${state.installation_id.slice(0, 8)}…`;
}

/** Whether the rail/config should offer "Join a swarm" — any state except
 * an in-flight join (code shown or claim confirmation pending) or an
 * existing membership. */
export function swarmJoinable(state: SwarmState | null): boolean {
  return (
    state === null ||
    (state.status !== "joining" && state.status !== "confirm_claim" && state.status !== "joined")
  );
}

/** One-line status copy for the Config → Swarm section. */
export function swarmStatusLine(state: SwarmState | null): string {
  switch (state?.status) {
    case undefined:
      return "Checking this machine's swarm membership…";
    case "not_joined":
      return "This machine isn't in a swarm yet.";
    case "joining":
      return `Waiting for approval — enter ${state.user_code} on the website.`;
    case "confirm_claim":
      return `Account ${state.claimed_by} wants to add this machine — confirm here.`;
    case "joined":
      return `Joined as ${state.installation_id.slice(0, 8)}…`;
    case "needs_rejoin":
      return state.reason;
    case "failed":
      return state.reason;
  }
}

/** Countdown label for the join modal: `m:ss` from `expires_at_ms`, or
 * "expired" at/past the boundary (the Rust poller stops at the same
 * instant, so the label never lingers on a dead code). */
export function joinCountdownText(expiresAtMs: number, nowMs: number): string {
  const remaining = Math.max(0, expiresAtMs - nowMs);
  if (remaining === 0) return "expired";
  const totalSeconds = Math.ceil(remaining / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${seconds.toString().padStart(2, "0")}`;
}

/** Whether an OPEN join modal must auto-close on a status transition:
 * any terminal `failed` — including one reached without ever entering
 * "joining" (the start POST itself failed) — or an open join resolving
 * (approved / expired). "Not joining" alone must NOT close: the modal
 * opens before the joining state lands, while the start call is in
 * flight. The joining ↔ confirm_claim handshake also keeps it open —
 * the claim prompt and the code screen are the same enrollment. */
export function shouldCloseJoinModal(
  prev: SwarmStatusName | undefined,
  status: SwarmStatusName | undefined,
): boolean {
  if (status === "failed") return true;
  if (prev !== "joining" && prev !== "confirm_claim") return false;
  return status !== "joining" && status !== "confirm_claim";
}

/** The local time the 24 h session ends (Config section, joined state). */
export function sessionExpiryText(expiresAtMs: number): string {
  return new Date(expiresAtMs).toLocaleString();
}
