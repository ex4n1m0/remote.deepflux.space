/** Circle-directory hook (ADR-006): pulls `circle_status`, refreshes on
 * the `app://directory` push, and exposes the membership actions. Pull is
 * authoritative, push is convenience — the `useEngine` doctrine. */

import { useEffect, useReducer } from "react";
import { listen } from "@tauri-apps/api/event";
import { api } from "../ipc";
import {
  directoryReducer,
  initialDirectoryState,
  type DirectoryAction,
  type DirectoryUiState,
} from "../state/directory";
import type { CircleStatus } from "../types";

export interface DirectoryBinding {
  ui: [DirectoryUiState, React.Dispatch<DirectoryAction>];
  refresh: () => Promise<void>;
  create: () => Promise<void>;
  join: (invite: string) => Promise<void>;
  leave: () => Promise<void>;
  setShared: (share: boolean) => Promise<void>;
  showInvite: () => Promise<void>;
}

export function useDirectory(): DirectoryBinding {
  const [state, dispatch] = useReducer(directoryReducer, undefined, initialDirectoryState);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    void (async () => {
      try {
        dispatch({ type: "status", status: (await api.circleStatus()) as CircleStatus });
      } catch {
        dispatch({ type: "error", error: "Couldn't load the family circle status." });
      }
      try {
        unlisten = await listen<{ machines: import("../types").DirectoryMachine[] }>(
          "app://directory",
          (event) => dispatch({ type: "machines", machines: event.payload.machines }),
        );
      } catch {
        /* jsdom/tests have no Tauri bridge — the pull above still ran */
      }
    })();
    return () => unlisten?.();
  }, []);

  const run = async (action: () => Promise<CircleStatus>) => {
    dispatch({ type: "busy" });
    try {
      dispatch({ type: "status", status: await action() });
    } catch (err) {
      dispatch({ type: "error", error: String(err) });
    }
  };

  return {
    ui: [state, dispatch],
    refresh: () => run(() => api.directoryRefresh().then(() => api.circleStatus())),
    create: () => run(() => api.circleCreate()),
    join: (invite) => run(() => api.circleJoin(invite)),
    leave: () => run(() => api.circleLeave()),
    setShared: (share) => run(() => api.circleSetShared(share)),
    showInvite: async () => {
      try {
        dispatch({ type: "invite", invite: await api.circleInvite() });
      } catch (err) {
        dispatch({ type: "error", error: String(err) });
      }
    },
  };
}
