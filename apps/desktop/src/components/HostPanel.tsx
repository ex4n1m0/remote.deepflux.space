/** Host panel: role state, consent prompt, sharing controls. */
import { Section, StatusChip } from "./Common";
import { hostView } from "../state/mapping";
import type { ConsentEvent, HostStateName } from "../types";

export function HostPanel({
  hostState,
  consent,
  connectionCode,
  onStart,
  onStop,
  onAccept,
  onReject,
}: {
  hostState: HostStateName;
  consent: ConsentEvent | null;
  connectionCode: string;
  onStart: () => void;
  onStop: () => void;
  onAccept: () => void;
  onReject: () => void;
}) {
  const view = hostView(hostState);
  return (
    <Section
      title="Share this machine"
      actions={<StatusChip tone={view.tone} label="Host" text={view.status} />}
    >
      <p className="muted">{view.detail}</p>
      {view.view === "online" || view.view === "ended" ? (
        <p className="muted">
          Your connection code: <code className="code">{connectionCode}</code>
        </p>
      ) : null}
      {view.can.accept && consent ? (
        <div className="consent" role="alertdialog" aria-label="Connection request">
          <p>
            <strong>{consent.controller_device_id}</strong> asks to control this machine.
          </p>
          <p className="muted">
            Accepting hands over screen viewing and keyboard/mouse control for this one
            session. The other side sees nothing until you accept.
          </p>
          <div className="row">
            <button type="button" className="primary" onClick={onAccept} autoFocus>
              Accept
            </button>
            <button type="button" onClick={onReject}>
              Reject
            </button>
          </div>
        </div>
      ) : null}
      <div className="row">
        {view.can.start ? (
          <button type="button" className="primary" onClick={onStart}>
            Share this machine
          </button>
        ) : null}
        {view.can.stop ? (
          <button type="button" className="danger" onClick={onStop}>
            Stop sharing
          </button>
        ) : null}
      </div>
    </Section>
  );
}
