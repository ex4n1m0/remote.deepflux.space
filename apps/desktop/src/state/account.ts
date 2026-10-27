/**
 * Account state: the reducer for the accounts phase (post-MVP), plus the
 * two pure helpers the shell gates on. Mirrors the `state/reducer.ts`
 * pattern — the hook (`hooks/useAccount.ts`) only wires transport.
 */

import type { AccountState, AccountStatus, Computer, ComputersList } from "../types";

export interface AccountUiState {
  status: AccountStatus;
  username: string | null;
  /** ADR-007 display name (null while logged out / name-less legacy). */
  displayName: string | null;
  expiresMs: number | null;
  /** First account_state fetch resolved (gates the onboarding flash). */
  loaded: boolean;
  computers: Computer[];
  serverVersion: number;
  /** Codes the presence poll last saw online. */
  online: string[];
  /** An operation is in flight (submit buttons disable). */
  busy: boolean;
  error: string | null;
}

export function initialAccountState(): AccountUiState {
  return {
    status: "logged_out",
    username: null,
    displayName: null,
    expiresMs: null,
    loaded: false,
    computers: [],
    serverVersion: 0,
    online: [],
    busy: false,
    error: null,
  };
}

export type AccountAction =
  | { type: "state"; state: AccountState }
  | { type: "computers"; list: ComputersList }
  | { type: "presence"; online: string[] }
  | { type: "busy"; on: boolean }
  | { type: "error"; message: string | null };

export function accountReducer(state: AccountUiState, action: AccountAction): AccountUiState {
  switch (action.type) {
    case "state": {
      const { status, username, display_name: displayName, expires_ms } = action.state;
      if (status === "logged_in") {
        return {
          ...state,
          status,
          username,
          displayName,
          expiresMs: expires_ms,
          loaded: true,
          error: null,
        };
      }
      // Any non-logged-in state drops the decrypted list + presence (the
      // roster is only readable while logged in).
      return {
        ...state,
        status,
        username,
        displayName: null,
        expiresMs: null,
        loaded: true,
        computers: [],
        serverVersion: 0,
        online: [],
      };
    }
    case "computers":
      return { ...state, computers: action.list.computers, serverVersion: action.list.server_version };
    case "presence":
      return { ...state, online: action.online };
    case "busy":
      return { ...state, busy: action.on };
    case "error":
      return { ...state, error: action.message };
    default:
      return state;
  }
}

/** Which screen the shell shows. */
export type AccountGate = "loading" | "onboarding" | "unlock" | "app";

/**
 * The onboarding gate (pure, unit-tested):
 * - `logged_in` → the main UI (Computers panel replaces Favorites);
 * - a saved account that has not been skipped → the one-field unlock card
 *   ("Welcome back, @user" — the roster stays encrypted until unlock);
 * - otherwise first-run onboarding unless the user skipped it;
 * - `signInOpen` (the header's Sign-in button) re-opens either card.
 */
export function accountGate(
  account: { status: AccountStatus; loaded: boolean },
  skippedOnboarding: boolean,
  signInOpen: boolean,
  opts: { circleJoined?: boolean } = {},
): AccountGate {
  if (!account.loaded) {
    return "loading";
  }
  if (account.status === "logged_in") {
    return "app";
  }
  // An EXPLICIT sign-in request always wins — including on circle-joined
  // (family-build) machines, where the ADR-007 control gate makes the
  // header "Sign in" button and the blocked-Control card the path to a
  // named account. Checked before the circle short-circuit below.
  if (signInOpen) {
    return account.status === "saved_account" ? "unlock" : "onboarding";
  }
  // ADR-006: a family circle member goes straight to the app — the circle
  // is the identity that matters on family machines (the family build
  // auto-joins on first run); accounts stay reachable via Sign in.
  if (opts.circleJoined) {
    return "app";
  }
  if (!skippedOnboarding) {
    return account.status === "saved_account" ? "unlock" : "onboarding";
  }
  return "app";
}

/**
 * Friendly copy for service/validation errors. The Rust side keeps the
 * machine-readable code embedded in the message; map on it and fall back
 * to the raw text.
 */
export function accountErrorCopy(raw: string): string {
  const text = raw.toLowerCase();
  if (text.includes("username_taken")) {
    return "That username is already taken — try another.";
  }
  if (text.includes("invalid_credentials")) {
    return "Wrong username or password.";
  }
  if (text.includes("rate_limited")) {
    return "Too many attempts — wait a minute and try again.";
  }
  if (text.includes("unsupported_action")) {
    // New client action hitting an old server (deploy-order window).
    return "The account service needs an update — try again in a few minutes.";
  }
  if (text.includes("network error") || text.includes("could not reach")) {
    return "Could not reach the account service. Check your connection and the service URL in Config → Settings.";
  }
  return raw;
}

/** Rust's `ControlGate::message()` prefix — the connect command refuses
 * nameless control with a marker so this layer can open the right card
 * instead of a raw error banner. */
export const CONTROL_GATE_MARKER = "[control-needs-account]";
