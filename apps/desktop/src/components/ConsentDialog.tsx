/** Host-side consent prompt (extracted from App.tsx by ADR-006).
 *
 * UX-simplify pass (user feedback, 2026-10-26): ONE simple request —
 * title, one explanatory line, and three plain verbs. "Allow once" is
 * the primary; "Always allow this machine" is the deliberate, explicit
 * remember action (the old checkbox + changing button label asked the
 * user to read a form before answering). The device code is ALWAYS
 * shown beside the self-chosen nickname — nicknames are advisory; the
 * code is the identity that cannot be impersonated inside the prompt.
 *
 * A paired-and-proven controller renders the passive status card instead
 * (no dialog at all); a claimed-trusted request without a valid proof
 * renders the warning variant (fail open to the human). */

import type { ConsentEvent } from "../types";

export function consentCopy(consent: {
  controller_device_id: string;
  requester_name: string | null;
  ai_session: boolean;
}): { who: string; title: string; detail: string; alwaysHint: string } {
  const who = consent.requester_name
    ? consent.requester_name
    : consent.controller_device_id;
  // The device id is ALWAYS shown — names are advisory; the code is the
  // identity that cannot be impersonated inside the prompt. `title`
  // (with the code) is for the screen-reader announcement; the dialog
  // renders the name and the code as SEPARATE lines so a crafted name
  // cannot visually masquerade as the code (0.10.2 security review).
  const whoWithCode = consent.requester_name
    ? `${consent.requester_name} (${consent.controller_device_id})`
    : consent.controller_device_id;
  if (consent.ai_session) {
    // With a name: whose assistant it is. Without: the code only.
    const aiTitle = consent.requester_name
      ? `${who}'s AI assistant (${consent.controller_device_id}) asks to control this computer.`
      : `An AI assistant (${consent.controller_device_id}) asks to control this computer.`;
    return {
      who: whoWithCode,
      title: aiTitle,
      detail:
        "It will see the screen and drive the mouse and keyboard to help. Your family can watch and take over at any time; it's instructed never to type passwords — if a screen asks for one, it stops.",
      alwaysHint:
        "Always allow means that machine's AI assistant can connect without asking, whenever it is on.",
    };
  }
  return {
    who: whoWithCode,
    title: `${whoWithCode} asks to control this computer.`,
    detail:
      "They'll see your screen and use the mouse and keyboard. You can watch everything and stop it at any time.",
    alwaysHint:
      "Always allow remembers this machine — it connects without asking next time. Manage it in Config → Trusted machines.",
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
          <strong>{copy.who === consent.controller_device_id ? copy.who : `${copy.who} asks to control this computer.`}</strong>
        </p>
        {copy.who !== consent.controller_device_id ? (
          <p className="muted">
            machine code <code className="code">{consent.controller_device_id}</code>
          </p>
        ) : null}
        {consent.paired && !consent.pairing_proof_ok ? (
          <p className="hint" role="note">
            This machine claims to be trusted but could not prove it — treat it
            as a new machine. (Someone may be reusing its code.)
          </p>
        ) : null}
        <p className="muted">{copy.detail}</p>
        <div className="row">
          <button type="button" className="primary" autoFocus onClick={() => onAccept(false)}>
            Allow once
          </button>
          <button type="button" onClick={() => onAccept(true)}>
            Always allow this machine
          </button>
          <button type="button" className="ghost" onClick={() => onReject()}>
            Decline
          </button>
        </div>
        <p className="hint">{copy.alwaysHint}</p>
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
  const who = consent.requester_name ?? consent.controller_device_id;
  return (
    <div className="center-card" role="status">
      <p>
        <strong>{who}</strong> is connecting — remembered machine, no approval
        needed.
      </p>
      <p className="muted">
        machine code <code className="code">{consent.controller_device_id}</code>
      </p>
    </div>
  );
}
