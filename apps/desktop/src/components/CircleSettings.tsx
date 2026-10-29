/** Family-circle + trusted-machines settings (ADR-006). Two sections:
 *
 * - CircleSection: membership (create → copyable invite, join by pasted
 *   invite, leave with a two-step confirm), the "show this machine in the
 *   circle" sharing toggle, and the machine list state.
 * - TrustedMachinesSection: the pairing list finally wired (ADR-005 §5's
 *   dormant revocation), grouped by plain-language capability. */

import { useEffect, useState } from "react";
import { CopyButton, Section } from "./Common";
import { api } from "../ipc";
import { CIRCLE_OFFLINE_HINT, circleErrorCopy } from "../state/directory";
import type { DirectoryBinding } from "../hooks/useDirectory";
import type { PairingInfo } from "../types";

export function CircleSection({ directory }: { directory: DirectoryBinding }) {
  const [state] = directory.ui;
  const [inviteInput, setInviteInput] = useState("");
  const [confirmLeave, setConfirmLeave] = useState(false);

  return (
    <Section title="Family circle">
      {!state.joined ? (
        <>
          <p className="muted">
            A family circle is one shared, searchable list of everyone's
            machines. Create one and share the invite with family, or paste
            an invite you received.
          </p>
          <div className="row">
            <button
              type="button"
              className="primary small"
              disabled={state.busy}
              onClick={() => {
                void directory.create().then(() => void directory.showInvite());
              }}
            >
              Create a circle
            </button>
          </div>
          <form
            className="circle-join"
            onSubmit={(event) => {
              event.preventDefault();
              const invite = inviteInput.trim();
              if (invite) void directory.join(invite).then(() => setInviteInput(""));
            }}
          >
            <label>
              Join with an invite
              <input
                value={inviteInput}
                onChange={(event) => setInviteInput(event.target.value)}
                placeholder="paste the 64-character invite"
                spellCheck={false}
                autoComplete="off"
              />
            </label>
            <button type="submit" className="small" disabled={state.busy || !inviteInput.trim()}>
              Join
            </button>
          </form>
        </>
      ) : (
        <>
          <p className="muted">
            This machine {state.shareInCircle ? "appears in" : "is hidden from"} the family
            circle ({state.machines.length} machine{state.machines.length === 1 ? "" : "s"}).
            {state.familyBuild ? " Joined automatically by the family installer." : ""}
          </p>
          {!state.loaded ? (
            <p className="hint" role="status">
              {CIRCLE_OFFLINE_HINT}
            </p>
          ) : null}
          <div className="row">
            <button
              type="button"
              className="ghost small"
              onClick={() => void directory.showInvite()}
            >
              Show my invite code
            </button>
            <label className="circle-share">
              <input
                type="checkbox"
                checked={state.shareInCircle}
                onChange={(event) => void directory.setShared(event.target.checked)}
              />
              Show this machine in the circle
            </label>
          </div>
          {state.invite ? (
            <div className="invite-box">
              <p className="hint">
                Share this invite with family — anyone holding it can see the
                circle's machines:
              </p>
              <code className="code invite-code">{state.invite}</code>{" "}
              <CopyButton value={state.invite ?? ""} label="Copy invite" />
            </div>
          ) : null}
          {confirmLeave ? (
            <div className="row">
              <span className="hint">
                Leave the circle? Machines in it will no longer see this PC.
              </span>
              <button
                type="button"
                className="danger small"
                onClick={() => {
                  setConfirmLeave(false);
                  void directory.leave();
                }}
              >
                Yes, leave
              </button>
              <button
                type="button"
                className="ghost small"
                onClick={() => setConfirmLeave(false)}
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              type="button"
              className="danger small"
              onClick={() => setConfirmLeave(true)}
            >
              Leave the circle…
            </button>
          )}
        </>
      )}
      {state.error ? (
        <p className="hint" role="alert">
          {circleErrorCopy(state.error)}
        </p>
      ) : null}
    </Section>
  );
}

export function TrustedMachinesSection({
  onRevoked,
}: {
  onRevoked?: () => void;
}) {
  const [pairings, setPairings] = useState<PairingInfo[] | null>(null);

  const refresh = async () => {
    try {
      setPairings(await api.pairingsList());
    } catch {
      setPairings([]);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const established = (pairings ?? []).filter((p) => !p.pending_ack);
  const pending = (pairings ?? []).filter((p) => p.pending_ack);

  return (
    <Section title="Trusted machines">
      <p className="muted">
        ONE list — these machines chat and connect without asking again.
        Removing one brings back the approval request.
      </p>
      {pairings === null ? (
        <p className="muted" role="status">
          Loading…
        </p>
      ) : established.length + pending.length === 0 ? (
        <p className="muted">
          No trusted machines yet — they appear here when you answer a
          connection request with "Always allow this machine".
        </p>
      ) : (
        <>
          <ul className="trusted-list">
            {established.map((p) => (
              <TrustedRow key={p.code} pairing={p} onRevoked={onRevoked} setPairings={setPairings} />
            ))}
          </ul>
          {pending.length > 0 ? (
            <>
              <p className="hint">Waiting for their approval (offer sent — no answer yet)</p>
              <ul className="trusted-list">
                {pending.map((p) => (
                  <TrustedRow key={p.code} pairing={p} onRevoked={onRevoked} setPairings={setPairings} />
                ))}
              </ul>
            </>
          ) : null}
        </>
      )}
    </Section>
  );
}

function TrustedRow({
  pairing,
  onRevoked,
  setPairings,
}: {
  pairing: PairingInfo;
  onRevoked?: () => void;
  setPairings: (p: PairingInfo[]) => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [renaming, setRenaming] = useState(false);
  const [draft, setDraft] = useState(pairing.name ?? "");
  const [busy, setBusy] = useState(false);
  const refresh = async () => {
    try {
      setPairings(await api.pairingsList());
    } catch {
      setPairings([]);
    }
  };
  const revoke = async () => {
    await api.pairingRemove(pairing.code);
    await refresh();
    onRevoked?.();
  };
  const saveName = async () => {
    const name = draft.trim();
    if (!name) return;
    setBusy(true);
    try {
      await api.pairingRename(pairing.code, name);
      setRenaming(false);
      await refresh();
    } finally {
      setBusy(false);
    }
  };
  return (
    <li>
      {renaming ? (
        <form
          className="trusted-rename"
          onSubmit={(event) => {
            event.preventDefault();
            void saveName();
          }}
        >
          <input
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            aria-label={`Name for ${pairing.name ?? pairing.code}`}
            autoFocus
            disabled={busy}
          />
          <button type="submit" className="primary small" disabled={busy || !draft.trim()}>
            Save
          </button>
          <button
            type="button"
            className="ghost small"
            onClick={() => {
              setRenaming(false);
              setDraft(pairing.name ?? "");
            }}
          >
            Cancel
          </button>
        </form>
      ) : (
        <span>
          <strong>{pairing.name ?? <code className="code">{pairing.code}</code>}</strong>{" "}
          <span className="muted">
            {pairing.name ? <code className="code">{pairing.code}</code> : null}
          </span>
        </span>
      )}
      {confirming ? (
        <>
          <button type="button" className="danger small" onClick={() => void revoke()}>
            Remove
          </button>
          <button type="button" className="ghost small" onClick={() => setConfirming(false)}>
            Cancel
          </button>
        </>
      ) : renaming ? null : (
        <>
          <button type="button" className="ghost small" onClick={() => setRenaming(true)}>
            Rename…
          </button>
          <button type="button" className="ghost small" onClick={() => setConfirming(true)}>
            Remove…
          </button>
        </>
      )}
    </li>
  );
}
