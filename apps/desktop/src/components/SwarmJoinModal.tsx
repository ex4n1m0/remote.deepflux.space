/** Join-a-swarm modal (ADR-013): the tracker's device-code enrollment,
 * app side. The Rust side POSTs `/auth/device/start` and polls
 * `/auth/device/complete`; this modal is the one thing the user has to do
 * — read the 8-char code and approve it on the website dashboard. Since
 * the gate (a) claim handshake the approval step surfaces here a second
 * time: the website's claim only PENDS until this machine confirms the
 * claiming account (Allow binds, Deny frees the code for the right
 * owner). The modal auto-closes when the state leaves the
 * joining/confirm_claim handshake (approved → the rail chip appears;
 * failure → the shell's error banner carries the reason — that closing
 * is App's effect, per the component-props doctrine). */

import { useEffect, useState } from "react";
import { CopyButton } from "./Common";
import { SWARM_DASHBOARD_URL, joinCountdownText } from "../state/swarm";
import type { SwarmState } from "../types";

export function SwarmJoinModal({
  state,
  onCancel,
  onClaimAnswer,
}: {
  /** Current swarm state; the modal is only mounted while the join is
   * live (App unmounts it on joined/failed). */
  state: SwarmState | null;
  onCancel: () => void;
  /** Allow/Deny a pending account claim (IPC `swarm_claim_answer`). */
  onClaimAnswer: (accept: boolean) => void;
}) {
  // Countdown ticks locally (the expiry comes from the Rust state).
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const joining = state?.status === "joining" ? state : null;
  const claim = state?.status === "confirm_claim" ? state : null;
  const expiresAtMs = joining?.expires_at_ms ?? claim?.expires_at_ms ?? 0;
  const countdown = joinCountdownText(expiresAtMs, now);

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
          <h2>{claim ? "Add this machine to an account?" : "Join a swarm"}</h2>
        </header>
        {claim ? (
          <>
            <p className="muted">
              Someone entered this machine's pairing code on the website.
              Only proceed if that was you or someone you trust at this
              machine:
            </p>
            <p>
              <strong>Claimed by account {claim.claimed_by}</strong>
            </p>
            <p className="hint" role="status">
              {`The code expires in ${countdown}.`}
            </p>
            <div className="row">
              <button type="button" className="primary" onClick={() => onClaimAnswer(true)} autoFocus>
                Allow — add this machine
              </button>
              <button type="button" className="ghost" onClick={() => onClaimAnswer(false)}>
                Deny
              </button>
            </div>
            <p className="hint">
              Denying returns the pairing code to pending so the right
              account can claim it. Allowing binds this machine to that
              account — its user can always remove it later from the
              website's machines page.
            </p>
          </>
        ) : (
          <>
            <p className="muted">
              Approve this machine on the website — sign in and enter this code
              on your machines page:
            </p>
            <div className="row swarm-code-row">
              <code className="join-code">{joining ? joining.user_code : "…"}</code>
              <CopyButton value={joining ? joining.user_code : ""} label="pairing code" />
            </div>
            <p className="hint" role="status">
              {joining ? `The code expires in ${countdown}.` : "Starting…"}
            </p>
            <div className="row">
              <button
                type="button"
                className="primary"
                onClick={() => void openDashboard()}
                title="Open the website's account page in your browser"
              >
                Approve it on the website
              </button>
              <button type="button" className="ghost" onClick={onCancel} autoFocus>
                Cancel
              </button>
            </div>
            <p className="hint">
              After you enter the code there, this window asks you to confirm
              the claiming account — the machine joins only when you allow it
              here.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

async function openDashboard(): Promise<void> {
  // MenuBar precedent: no opener plugin — the site opens in the default
  // browser via target=_blank.
  window.open(SWARM_DASHBOARD_URL, "_blank", "noopener");
}
