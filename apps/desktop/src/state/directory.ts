/** Circle-directory UI state (ADR-006): the app-layer sibling of the
 * account state — never engine state (the engine knows nothing about
 * circles). Pure reducer, wired to transport by `useDirectory`. */

import type { CircleStatus, DirectoryMachine } from "../types";

export interface DirectoryUiState {
  loaded: boolean;
  busy: boolean;
  joined: boolean;
  circleId: string | null;
  shareInCircle: boolean;
  familyBuild: boolean;
  machines: DirectoryMachine[];
  invite: string | null;
  error: string | null;
}

export function initialDirectoryState(): DirectoryUiState {
  return {
    loaded: false,
    busy: false,
    joined: false,
    circleId: null,
    shareInCircle: false,
    familyBuild: false,
    machines: [],
    invite: null,
    error: null,
  };
}

export type DirectoryAction =
  | { type: "status"; status: CircleStatus }
  | { type: "machines"; machines: DirectoryMachine[] }
  | { type: "invite"; invite: string | null }
  | { type: "busy" }
  | { type: "error"; error: string | null };

export function directoryReducer(
  state: DirectoryUiState,
  action: DirectoryAction,
): DirectoryUiState {
  switch (action.type) {
    case "status":
      return {
        ...state,
        loaded: true,
        busy: false,
        error: null,
        joined: action.status.joined,
        circleId: action.status.circle_id,
        shareInCircle: action.status.share_in_circle,
        familyBuild: action.status.family_build,
        machines: action.status.machines,
      };
    case "machines":
      return { ...state, machines: action.machines };
    case "invite":
      return { ...state, invite: action.invite };
    case "busy":
      return { ...state, busy: true, error: null };
    case "error":
      return { ...state, busy: false, error: action.error };
  }
}

/** "Joined but the service can't see us" — the put was refused because
 * presence is gone (machine offline). Shared by the error copy and the
 * joined-but-not-loaded hint in CircleSettings. */
export const CIRCLE_OFFLINE_HINT =
  "You'll show up in the circle once this machine is online — click Share this machine or restart the app.";

/** Friendly copy for circle errors (the `accountErrorCopy` pattern). */
export function circleErrorCopy(raw: string): string {
  if (raw.includes("64 hex")) {
    return "That invite code doesn't look right — copy the whole 64-character code from the circle owner's Settings.";
  }
  if (raw.includes("Already in a circle")) {
    return "This machine is already in a circle — leave it first (Settings → Family circle).";
  }
  if (raw.includes("circle_full")) {
    return "The circle is full (128 machines). Ask the owner to remove unused machines or create a new circle.";
  }
  // The service authenticates (device, token) via live presence — an
  // offline machine's puts come back 401. That is an "offline" state,
  // not an auth problem to troubleshoot.
  if (raw.includes("unauthorized") || raw.includes("401")) {
    return CIRCLE_OFFLINE_HINT;
  }
  if (raw.includes("rate_limited")) {
    return "Too many attempts — wait a minute and try again.";
  }
  if (raw.includes("network") || raw.includes("Connection") || raw.includes("http")) {
    return "Couldn't reach the signaling service — check your connection and try again.";
  }
  return raw;
}
