/** Join-a-swarm modal (ADR-013): the tracker's device-code enrollment,
 * app side. The Rust side POSTs `/auth/device/start` and polls
 * `/auth/device/complete`; this modal is the one thing the user has to do
 * — read the 8-char code and approve it on the website dashboard. It
 * auto-closes when the state leaves `joining` (approved → the rail chip
 * appears; failure → the shell's error banner carries the reason — that
 * closing is App's effect, per the component-props doctrine). */

import { useEffect, useState } from "react";
import { CopyButton } from "./Common";
import { SWARM_DASHBOARD_URL, joinCountdownText } from "../state/swarm";
import type { SwarmState } from "../types";

export function SwarmJoinModal({
  state,
  onCancel,
}: {
  /** Current swarm state; the modal is only mounted while the join is
   * live (App unmounts it on joined/failed). */
  state: SwarmState | null;
  onCancel: () => void;
}) {
  // Countdown ticks locally (the expiry comes from the Rust state).
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const joining = state?.status === "joining" ? state : null;
  const countdown = joining ? joinCountdownText(joining.expires_at_ms, now) : "—";

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div
        className="modal swarm-join-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Join a swarm"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="modal-head">
          <h2>Join a swarm</h2>
        </header>
        <p className="muted">
          Approve this machine on the website — sign in and enter this code
          on your machines page:
        </p>
        <div className="row swarm-code-row">
          <code className="join-code">{joining ? joining.user_code : "…"}</code>
          <CopyButton value={joining ? joining.user_code : ""} label="pairing code" />
        </div>
        <p className="hint" role="status">
          {joining
            ? `The code expires in ${countdown}.`
            : "Starting…"}
        </p>
        <div className="row">
          <button
            type="button"
            className="primary"
            onClick={() => void openDashboard()}
            title="Open the ModelSwarm website's account page in your browser"
          >
            Approve it on the website
          </button>
          <button type="button" className="ghost" onClick={onCancel} autoFocus>
            Cancel
          </button>
        </div>
        <p className="hint">
          Approving binds this machine to your account — its user can always
          remove it later from the same page.
        </p>
      </div>
    </div>
  );
}

async function openDashboard(): Promise<void> {
  // MenuBar precedent: no opener plugin — the site opens in the default
  // browser via target=_blank.
  window.open(SWARM_DASHBOARD_URL, "_blank", "noopener");
}
