/** Discovery-list hook (ADR-010): pulls `directory_machines`, refreshes on
 * the `app://directory` push. Pull is authoritative, push is convenience —
 * the `useEngine` doctrine. No membership actions: the family installer
 * auto-joins from its embedded key, and visibility rides the
 * `host_sharing` setting. */

import { useEffect, useReducer } from "react";
import { listen } from "@tauri-apps/api/event";
import { api } from "../ipc";
import {
  directoryReducer,
  initialDirectoryState,
  type DirectoryAction,
  type DirectoryUiState,
} from "../state/directory";
import type { DirectoryMachine } from "../types";

export interface DirectoryBinding {
  ui: [DirectoryUiState, React.Dispatch<DirectoryAction>];
  refresh: () => Promise<void>;
}

export function useDirectory(): DirectoryBinding {
  const [state, dispatch] = useReducer(directoryReducer, undefined, initialDirectoryState);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    void (async () => {
      try {
        dispatch({ type: "machines", machines: await api.directoryMachines() });
        dispatch({ type: "loaded" });
      } catch {
        /* jsdom/tests have no Tauri bridge; the poller push still feeds us */
      }
      try {
        unlisten = await listen<{ machines: DirectoryMachine[] }>(
          "app://directory",
          (event) => {
            dispatch({ type: "machines", machines: event.payload.machines });
            dispatch({ type: "loaded" });
          },
        );
      } catch {
        /* same — the pull above already ran where it could */
      }
    })();
    return () => unlisten?.();
  }, []);

  return {
    ui: [state, dispatch],
    refresh: async () => {
      try {
        await api.directoryRefresh();
      } catch {
        /* offline: stale beats empty — the poller retries */
      }
    },
  };
}
