/** Account directory hook (ADR-013 P2): pulls `account_directory_machines`,
 * refreshes on the `app://account-directory` push (the swarm heartbeat
 * thread's 30 s tracker poll). Pull is authoritative, push is convenience —
 * the `useEngine` doctrine. Empty until the machine joins an account (the
 * rail then shows the trusted pairings only). */

import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, ACCOUNT_DIRECTORY_EVENT } from "../ipc";
import type { AccountMachine } from "../types";

export interface AccountDirectoryBinding {
  machines: AccountMachine[];
  loaded: boolean;
}

export function useAccountDirectory(): AccountDirectoryBinding {
  const [machines, setMachines] = useState<AccountMachine[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    void (async () => {
      try {
        setMachines(await api.accountDirectoryMachines());
        setLoaded(true);
      } catch {
        /* jsdom/tests: no Tauri bridge — the poller push still feeds us */
      }
      try {
        unlisten = await listen<AccountMachine[]>(ACCOUNT_DIRECTORY_EVENT, (event) => {
          setMachines(event.payload);
          setLoaded(true);
        });
      } catch {
        /* same — the pull above already ran where it could */
      }
    })();
    return () => unlisten?.();
  }, []);

  return { machines, loaded };
}
