/** Account state tests: reducer transitions, the onboarding gate, and
 * error-copy mapping (pure — no Tauri imports). */
import { describe, expect, it } from "vitest";
import {
  accountErrorCopy,
  accountGate,
  accountReducer,
  initialAccountState,
} from "./account";
import type { Computer } from "../types";

const computer = (id: string, code: string, isSelf = false): Computer => ({
  id,
  name: `PC ${id}`,
  code,
  added_at_ms: 1,
  updated_at_ms: 2,
  is_self: isSelf,
});

describe("accountReducer", () => {
  it("tracks logged-in state and clears it on logout", () => {
    let state = initialAccountState();
    state = accountReducer(state, {
      type: "state",
      state: { status: "logged_in", username: "alice", expires_ms: 123 },
    });
    expect(state.loaded).toBe(true);
    expect(state.username).toBe("alice");
    expect(state.expiresMs).toBe(123);

    state = accountReducer(state, {
      type: "computers",
      list: { computers: [computer("f1", "aaaa")], server_version: 3 },
    });
    expect(state.computers).toHaveLength(1);
    expect(state.serverVersion).toBe(3);

    state = accountReducer(state, {
      type: "state",
      state: { status: "saved_account", username: "alice", expires_ms: null },
    });
    expect(state.status).toBe("saved_account");
    expect(state.computers).toHaveLength(0);
    expect(state.online).toHaveLength(0);
    expect(state.expiresMs).toBeNull();
  });

  it("stores presence and busy/error flags", () => {
    let state = initialAccountState();
    state = accountReducer(state, { type: "presence", online: ["aaaa"] });
    expect(state.online).toEqual(["aaaa"]);
    state = accountReducer(state, { type: "busy", on: true });
    expect(state.busy).toBe(true);
    state = accountReducer(state, { type: "error", message: "boom" });
    expect(state.error).toBe("boom");
    state = accountReducer(state, { type: "error", message: null });
    expect(state.error).toBeNull();
  });
});

describe("accountGate", () => {
  it("waits for the first account_state before deciding", () => {
    expect(accountGate({ status: "logged_out", loaded: false }, false, false)).toBe("loading");
  });

  it("first run without a saved account shows onboarding", () => {
    expect(accountGate({ status: "logged_out", loaded: true }, false, false)).toBe("onboarding");
  });

  it("a saved account shows the unlock card until skipped", () => {
    expect(accountGate({ status: "saved_account", loaded: true }, false, false)).toBe("unlock");
    expect(accountGate({ status: "saved_account", loaded: true }, true, false)).toBe("app");
  });

  it("signed-in always shows the app; Sign in re-opens the card", () => {
    expect(accountGate({ status: "logged_in", loaded: true }, false, false)).toBe("app");
    expect(accountGate({ status: "logged_out", loaded: true }, true, true)).toBe("onboarding");
    expect(accountGate({ status: "saved_account", loaded: true }, true, true)).toBe("unlock");
  });
});

describe("accountErrorCopy", () => {
  it("maps the machine-readable service codes to friendly copy", () => {
    expect(accountErrorCopy("service error 409 username_taken: nope")).toContain("already taken");
    expect(accountErrorCopy("service error 401 invalid_credentials")).toContain("Wrong username");
    expect(accountErrorCopy("service error 429 rate_limited")).toContain("Too many attempts");
    expect(accountErrorCopy("network error: dns blew up")).toContain("Could not reach");
  });

  it("passes specific local copy through untouched", () => {
    expect(accountErrorCopy("account key material damaged — re-register required")).toContain(
      "key material damaged",
    );
    expect(accountErrorCopy("Password must be 8–128 characters.")).toContain("8–128");
  });
});
