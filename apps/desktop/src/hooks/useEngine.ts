/**
 * useEngine: wires the reducer to Tauri events + a 1 Hz status poll (the
 * pull is authoritative; pushes are conveniences that may drop). Also owns
 * identity/settings/favorites loading.
 */

import {
  useCallback,
  useEffect,
  useReducer,
  useRef,
  useState,
  type Dispatch,
} from "react";
import { EVENT, api } from "../ipc";
import { engineReducer, initialUiState } from "../state/reducer";
import type { EngineUiState, UiAction } from "../state/reducer";
import type { EngineStatus, Favorite, Identity, Settings } from "../types";

export interface EngineBinding {
  ui: [EngineUiState, Dispatch<UiAction>];
  identity: Identity | null;
  settings: Settings | null;
  favorites: Favorite[];
  refreshFavorites: () => Promise<void>;
  saveSettings: (patch: Settings) => Promise<Settings | null>;
  commandError: string | null;
  clearCommandError: () => void;
  /** Run a command, surfacing its error string in the UI. */
  run: (fn: () => Promise<unknown>) => Promise<void>;
}

export function useEngine(): EngineBinding {
  const [ui, dispatch] = useReducer(engineReducer, undefined, initialUiState);
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [favorites, setFavorites] = useState<Favorite[]>([]);
  const [commandError, setCommandError] = useState<string | null>(null);
  const dispatchRef = useRef(dispatch);
  dispatchRef.current = dispatch;

  const refreshFavorites = useCallback(async () => {
    try {
      setFavorites(await api.listFavorites());
    } catch (err) {
      setCommandError(String(err));
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [identity, settings] = await Promise.all([api.getIdentity(), api.getSettings()]);
        if (!cancelled) {
          setIdentity(identity);
          setSettings(settings);
        }
        await refreshFavorites();
      } catch (err) {
        if (!cancelled) {
          setCommandError(String(err));
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [refreshFavorites]);

  const saveSettings = useCallback(async (patch: Settings) => {
    try {
      const next = await api.setSettings(patch);
      setSettings(next);
      return next;
    } catch (err) {
      setCommandError(String(err));
      return null;
    }
  }, []);

  const run = useCallback(async (fn: () => Promise<unknown>) => {
    try {
      await fn();
      setCommandError(null);
    } catch (err) {
      setCommandError(String(err));
    }
  }, []);

  // Engine events (push). The unlisten cleanup array is ref-stable.
  const unlisten = useRef<Array<() => void>>([]);
  useEffect(() => {
    let cancelled = false;
    const listeners: Array<() => void> = [];
    const on = (name: string, handler: (payload: unknown) => void) => {
      import("@tauri-apps/api/event").then(({ listen }) =>
        listen(name, (event) => handler(event.payload)).then((stop) => {
          if (cancelled) {
            stop();
          } else {
            listeners.push(stop);
          }
        }),
      );
    };
    const d = dispatchRef.current;
    on(EVENT.state, (p) =>
      d({
        type: "state",
        machine: (p as { machine: "host" | "controller" }).machine,
        state: (p as { state: string }).state,
        session_id: (p as { session_id: string | null }).session_id ?? null,
      }),
    );
    on(EVENT.consent, (p) => d({ type: "consent", event: p as never }));
    on(EVENT.sessionEstablished, (p) =>
      d({ type: "session-established", session_id: (p as { session_id: string }).session_id }),
    );
    on(EVENT.sessionEnded, (p) => d({ type: "session-ended", event: p as never }));
    on(EVENT.peer, (p) => d({ type: "peer", event: p as never }));
    on(EVENT.caps, (p) => d({ type: "caps", event: p as never }));
    on(EVENT.diagnostics, (p) =>
      d({ type: "diagnostics", snapshot: (p as { snapshot: never }).snapshot }),
    );
    on(EVENT.error, (p) => d({ type: "error", event: p as never }));
    on(EVENT.info, (p) => d({ type: "info", message: (p as { message: string }).message }));
    unlisten.current = listeners;
    return () => {
      cancelled = true;
      for (const stop of listeners) {
        stop();
      }
    };
  }, []);

  // 1 Hz status poll (authoritative reconciliation).
  useEffect(() => {
    const timer = setInterval(() => {
      api
        .engineStatus()
        .then((status: EngineStatus) => dispatchRef.current({ type: "poll", status }))
        .catch(() => {
          // Engine not started yet — the poll is best-effort.
        });
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  return {
    ui: [ui, dispatch],
    identity,
    settings,
    favorites,
    refreshFavorites,
    saveSettings,
    commandError,
    clearCommandError: () => setCommandError(null),
    run,
  };
}
