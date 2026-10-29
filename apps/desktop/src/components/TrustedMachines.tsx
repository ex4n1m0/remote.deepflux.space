/** Trusted machines (ADR-006 pairing ceremony, promoted by ADR-009 to THE
 * machine list): the pairings list with cached display names, grouped by
 * plain-language capability, with inline rename and two-step removal. */

import { useEffect, useState } from "react";
import { Section } from "./Common";
import { api } from "../ipc";
import type { PairingInfo } from "../types";

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
