/**
 * useAccount: account state + roster + presence wiring (the accounts-phase
 * counterpart of useEngine). Loads account_state at mount, refreshes the
 * computer list after every authenticated action, and polls presence every
 * 30 s — ONLY while logged in with a non-empty roster (bounded: one timer,
 * torn down on logout).
 */

import {
  useCallback,
  useEffect,
  useReducer,
  useRef,
  type Dispatch,
} from "react";
import { api } from "../ipc";
import { accountReducer, initialAccountState, type AccountAction, type AccountUiState } from "../state/account";

export interface AccountBinding {
  ui: [AccountUiState, Dispatch<AccountAction>];
  refresh: () => Promise<void>;
  register: (username: string, password: string) => Promise<string | null>;
  login: (username: string, password: string) => Promise<string | null>;
  unlock: (password: string) => Promise<string | null>;
  logout: () => Promise<void>;
  addComputer: (name: string, code: string) => Promise<string | null>;
  addThisComputer: () => Promise<string | null>;
  removeComputer: (id: string) => Promise<string | null>;
  renameComputer: (id: string, name: string) => Promise<string | null>;
  clearError: () => void;
}

export function useAccount(): AccountBinding {
  const [ui, dispatch] = useReducer(accountReducer, undefined, initialAccountState);
  const dispatchRef = useRef(dispatch);
  dispatchRef.current = dispatch;

  const refresh = useCallback(async () => {
    try {
      const state = await api.accountState();
      dispatchRef.current({ type: "state", state });
    } catch (err) {
      dispatchRef.current({ type: "error", message: String(err) });
    }
  }, []);

  const refreshComputers = useCallback(async () => {
    try {
      const list = await api.computersList();
      dispatchRef.current({ type: "computers", list });
    } catch {
      // Not signed in (or transient): account_state remains authoritative.
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  /** Run an authenticated account action: busy + error + state refresh.
   * Resolves to the error string (null = success) so panels can surface
   * friendly copy in their own error areas. */
  const run = useCallback(
    async (fn: () => Promise<unknown>): Promise<string | null> => {
      dispatchRef.current({ type: "busy", on: true });
      dispatchRef.current({ type: "error", message: null });
      try {
        await fn();
        await refresh();
        // No-ops unless the action left us logged in (the command rejects
        // otherwise and the catch path skips it).
        await refreshComputers();
        return null;
      } catch (err) {
        const message = String(err);
        dispatchRef.current({ type: "error", message });
        return message;
      } finally {
        dispatchRef.current({ type: "busy", on: false });
      }
    },
    [refresh, refreshComputers],
  );

  const register = useCallback(
    (username: string, password: string) =>
      run(() => api.accountRegister(username, password)),
    [run],
  );
  const login = useCallback(
    (username: string, password: string) => run(() => api.accountLogin(username, password)),
    [run],
  );
  const unlock = useCallback((password: string) => run(() => api.accountUnlock(password)), [run]);
  const logout = useCallback(async () => {
    await run(() => api.accountLogout());
  }, [run]);

  const addComputer = useCallback(
    (name: string, code: string) => run(() => api.computerAdd(name, code)),
    [run],
  );
  const addThisComputer = useCallback(() => run(() => api.computerAddThis()), [run]);
  const removeComputer = useCallback((id: string) => run(() => api.computerRemove(id)), [run]);
  const renameComputer = useCallback(
    (id: string, name: string) => run(() => api.computerRename(id, name)),
    [run],
  );

  // Presence poll: 30 s while logged in with a roster; one bounded timer.
  useEffect(() => {
    if (ui.status !== "logged_in" || ui.computers.length === 0) {
      return;
    }
    let cancelled = false;
    const poll = () => {
      api
        .computersPresence()
        .then((result) => {
          if (!cancelled) {
            dispatchRef.current({ type: "presence", online: result.online });
          }
        })
        .catch(() => {
          // Transient (network/offline) — the next tick retries.
        });
    };
    poll();
    const timer = setInterval(poll, 30_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [ui.status, ui.computers.length]);

  return {
    ui: [ui, dispatch],
    refresh,
    register,
    login,
    unlock,
    logout,
    addComputer,
    addThisComputer,
    removeComputer,
    renameComputer,
    clearError: () => dispatchRef.current({ type: "error", message: null }),
  };
}
