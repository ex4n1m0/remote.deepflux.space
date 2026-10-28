/** Automatic-update binding (ADR-008): the updater's `update://state`
 * events + initial snapshot, with the three user verbs (check, download,
 * install) and Later. The Rust side owns the state machine — this hook
 * only mirrors it and forwards presses. In jsdom/tests there is no
 * bridge: state stays null and the verbs are inert. */
import { useEffect, useState } from "react";
import { api, UPDATE_EVENT, type UpdateState } from "../ipc";

export interface UpdateBinding {
  state: UpdateState | null;
  check: () => void;
  download: () => void;
  install: () => void;
  dismiss: () => void;
}

export function useUpdate(): UpdateBinding {
  const [state, setState] = useState<UpdateState | null>(null);

  useEffect(() => {
    let stop: (() => void) | null = null;
    void (async () => {
      try {
        setState(await api.updateState());
        const { listen } = await import("@tauri-apps/api/event");
        const unlisten = await listen<UpdateState>(UPDATE_EVENT, (event) =>
          setState(event.payload),
        );
        stop = unlisten;
      } catch {
        /* jsdom/tests: no Tauri bridge */
      }
    })();
    return () => stop?.();
  }, []);

  const run = (action: () => Promise<void>) => {
    void action().catch(() => {
      /* failures land in state.error via the updater's own event */
    });
  };

  return {
    state,
    check: () => run(api.updateCheck),
    download: () => run(api.updateDownload),
    install: () => run(api.updateInstall),
    dismiss: () => run(api.updateDismiss),
  };
}
