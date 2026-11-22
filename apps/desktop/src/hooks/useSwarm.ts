/** Swarm-enrollment bindings (ADR-013): the `swarm://state` events + an
 * initial snapshot, with the user verbs (join, cancel, leave). The Rust
 * side owns the state machine — these hooks only mirror it and forward
 * presses. In jsdom/tests there is no bridge: state stays null and the
 * verbs are inert. */

import { useEffect, useReducer, useRef, useState } from "react";
import { api, SWARM_EVENT } from "../ipc";
import { shouldCloseJoinModal } from "../state/swarm";
import type { SwarmState, SwarmStatusName } from "../types";

export interface SwarmBinding {
  state: SwarmState | null;
  /** Start the join flow. The Rust command returns as soon as the join
   * thread is spawned — failures arrive later as `failed` states (the
   * modal closes on them), and a rejection here means the invoke itself
   * failed (App closes the modal on it). */
  join: () => Promise<void>;
  cancelJoin: () => void;
  leave: () => void;
  /** Answer a pending account claim (gate (a)): the join thread picks the
   * answer up and posts the signed confirm. Rejections are swallowed —
   * the claim prompt stays until a later state transition. */
  claimAnswer: (accept: boolean) => void;
  /** Gate (d) recovery: mint a fresh device identity (new installation
   * id) and drop the local session; the returned id is the new one. */
  rekey: () => Promise<string>;
}

export interface SwarmJoinModalBinding {
  open: boolean;
  /** Open the modal and fire the join. */
  openJoin: () => void;
  /** The modal's Cancel verb: abandon the join and close. */
  cancel: () => void;
}

export function useSwarm(): SwarmBinding {
  const [ui, dispatch] = useReducer(swarmReducer, { state: null });

  useEffect(() => {
    let stop: (() => void) | null = null;
    void (async () => {
      try {
        dispatch({ type: "state", state: await api.swarmStatus() });
        const { listen } = await import("@tauri-apps/api/event");
        stop = await listen<SwarmState>(SWARM_EVENT, (event) =>
          dispatch({ type: "state", state: event.payload }),
        );
        // Startup-race cover (security review): an emit during the
        // dynamic-import window above was missed by the just-installed
        // listener — re-pull once now that it is armed, so a restored
        // session (Rust already Joined) never shows as NotJoined for the
        // next 24 h. Pull stays authoritative.
        dispatch({ type: "state", state: await api.swarmStatus() });
      } catch {
        /* jsdom/tests: no Tauri bridge */
      }
    })();
    return () => stop?.();
  }, []);

  const run = (action: () => Promise<void>) => {
    void action().catch(() => {
      /* membership changes land as swarm://state events */
    });
  };

  return {
    state: ui.state,
    join: () => api.swarmJoin(),
    cancelJoin: () => run(api.swarmCancelJoin),
    leave: () => run(api.swarmLeave),
    claimAnswer: (accept: boolean) => run(() => api.swarmClaimAnswer(accept)),
    rekey: () => api.swarmRekey(),
  };
}

interface SwarmUiState {
  state: SwarmState | null;
}

type SwarmAction = { type: "state"; state: SwarmState };

function swarmReducer(_current: SwarmUiState, action: SwarmAction): SwarmUiState {
  return { state: action.state };
}

/** Join-modal open/close wiring (ADR-013): opens on the join verb (the
 * modal shows "Starting…" while the start POST runs, then the userCode),
 * and closes on Cancel, on the join promise REJECTING (invoke-level
 * failure), and via [`shouldCloseJoinModal`] — an open join resolving,
 * or any terminal `failed` even one that never entered "joining". */
export function useSwarmJoinModal(swarm: SwarmBinding): SwarmJoinModalBinding {
  const [open, setOpen] = useState(false);
  const prevStatus = useRef<SwarmStatusName | undefined>(undefined);
  const status = swarm.state?.status;
  useEffect(() => {
    const prev = prevStatus.current;
    prevStatus.current = status;
    if (open && shouldCloseJoinModal(prev, status)) {
      setOpen(false);
    }
  }, [open, status]);

  return {
    open,
    openJoin: () => {
      setOpen(true);
      swarm.join().then(
        () => {
          /* joining → the poll resolves it; the effect above closes */
        },
        () => setOpen(false), // the invoke itself failed — no state will come
      );
    },
    cancel: () => {
      swarm.cancelJoin();
      setOpen(false);
    },
  };
}
