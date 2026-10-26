/** Host-side consent prompt (extracted from App.tsx by ADR-006).
 *
 * The ADR-005 §5 "remember this device" choice lives here: accept
 * once vs accept-and-remember (pairing + silent reconnect + the
 * controller's favorite). The device code is ALWAYS shown beside the
 * self-chosen nickname — nicknames are advisory; the code is the
 * identity that cannot be impersonated inside the prompt.
 *
 * A paired-and-proven controller renders the passive status card instead
 * (no dialog at all); a claimed-trusted request without a valid proof
 * renders the warning variant (fail open to the human). */

import { useState } from "react";
import type { ConsentEvent } from "../types";

export function consentCopy(consent: {
  controller_device_id: string;
  requester_name: string | null;
  ai_session: boolean;
  paired: boolean;
  pairing_proof_ok: boolean;
}): { title: string; detail: string; rememberLabel: string; rememberHint: string } {
  const who = consent.requester_name
    ? `${consent.requester_name} (${consent.controller_device_id})`
    : consent.controller_device_id;
  if (consent.ai_session) {
    return {
      title: `${who} requests AI-agent control of this machine.`,
      detail:
        "An AI agent will see the screen and drive mouse/keyboard for this one session. You can watch and take over at any time; the agent cannot type your passwords.",
      rememberLabel: "Remember this machine — let its agent start without asking next time",
      rememberHint:
        "Remembering means an AI agent on that machine can begin controlling this computer without a prompt whenever it is on.",
    };
  }
  return {
    title: `${who} asks to control this machine.`,
    detail:
      "Accepting hands over screen viewing and keyboard/mouse control for this one session. The other side sees nothing until you accept.",
    rememberLabel: "Remember this machine — skip this prompt next time",
    rememberHint: "You can remove it anytime in Settings → Trusted machines.",
  };
}

export function ConsentDialog({
  consent,
  onAccept,
  onReject,
}: {
  consent: ConsentEvent;
  onAccept: (remember: boolean) => void;
  onReject: () => void;
}) {
  // Default ON for humans (family-support scenario, ADR-005 §5); the
  // AI-session variant defaults OFF (an agent remembering is a bigger
  // grant — the blunt copy says so).
  const [remember, setRemember] = useState(!consent.ai_session);
  const copy = consentCopy(consent);

  return (
    <>
      {/* Incoming-request announcement for screen readers: the card below
       * is NOT a modal alertdialog (no focus trap/Escape — the shell stays
       * usable), so the request itself is spoken via this polite region. */}
      <p className="sr-only" aria-live="polite">
        {copy.title}
      </p>
      <div className="consent center-card" role="dialog" aria-label="Connection request">
        <p>
          <strong>{copy.title}</strong>
        </p>
        {consent.paired && !consent.pairing_proof_ok ? (
          <p className="hint" role="note">
            This machine claims to be trusted but could not prove it — treat it
            as a new machine. (Someone may be reusing its code.)
          </p>
        ) : null}
        <p className="muted">{copy.detail}</p>
        <label className="consent-remember">
          <input
            type="checkbox"
            checked={remember}
            onChange={(e) => setRemember(e.target.checked)}
          />
          <span>
            {copy.rememberLabel}
            <br />
            <span className="hint">{copy.rememberHint}</span>
          </span>
        </label>
        <div className="row">
          <button
            type="button"
            className="primary"
            autoFocus
            onClick={() => onAccept(remember)}
          >
            {remember ? "Accept & remember" : "Accept once"}
          </button>
          <button type="button" onClick={() => onReject()}>
            Reject
          </button>
        </div>
      </div>
    </>
  );
}

/** Passive card for a paired-and-proven reconnect (no decision needed —
 * the app layer already auto-accepted; this is visible reassurance). */
export function TrustedConnectCard({
  consent,
}: {
  consent: ConsentEvent;
}) {
  const who = consent.requester_name
    ? `${consent.requester_name} (${consent.controller_device_id})`
    : consent.controller_device_id;
  return (
    <div className="center-card" role="status">
      <p>
        <strong>{who}</strong> is connecting — trusted machine, no approval
        needed.
      </p>
    </div>
  );
}
