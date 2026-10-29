/** Machines rail (ADR-005, simplified by ADR-009): the IM-style left
 * column and THE machine list — the trusted-host list (pairings), nothing
 * else. Every row is both a chat and a remote-control target; machines
 * enter the list through the one-time connection code + the host's
 * "Always allow". The connect box under the header is the only discovery
 * mechanism: enter a code, press Control (visual) or Agent (chat-only).
 * Also home to the pinned "This machine" card (host role). */
import { useState } from "react";
import { hostView } from "../state/mapping";
import type { HostStateName, PairingInfo } from "../types";

export interface MachineRow {
  id: string;
  name: string;
  code: string;
  online: boolean | null;
  active: boolean;
  /** Established pairing — connects without asking again. */
  trusted: boolean;
  /** Controller-side offer sent, host has not acked yet. */
  pending: boolean;
}

/** The trusted-host list as rail rows: name cached from the wire (or the
 * bare code), online only while a session with the machine is live
 * (ADR-009: no roster/directory presence — honest and minimal). */
export function machinesFromPairings(
  pairings: PairingInfo[],
  peerOnline: Record<string, boolean>,
  selectedCode: string | null,
): MachineRow[] {
  return pairings.map((p) => ({
    id: p.code,
    name: p.name ?? p.code,
    code: p.code,
    online: peerOnline[p.code] ?? null,
    active: selectedCode === p.code,
    trusted: !p.pending_ack,
    pending: p.pending_ack,
  }));
}

/** Machine-page removal (ADR-009): two-step confirm — forgetting a
 * machine brings back its approval request. */
export function RemoveMachineButton({
  name,
  onRemove,
}: {
  name: string;
  onRemove: () => void;
}) {
  const [confirming, setConfirming] = useState(false);
  if (!confirming) {
    return (
      <button
        type="button"
        className="ghost small machine-remove"
        onClick={() => setConfirming(true)}
      >
        Remove…
      </button>
    );
  }
  return (
    <span className="machine-remove-confirm" role="alertdialog" aria-label="Remove machine">
      <span className="hint">Remove {name}?</span>
      <button
        type="button"
        className="danger small"
        onClick={() => {
          setConfirming(false);
          onRemove();
        }}
      >
        Remove
      </button>
      <button type="button" className="ghost small" onClick={() => setConfirming(false)}>
        Cancel
      </button>
    </span>
  );
}

/** Client-side search: case-insensitive name or code substring. */
export function filterMachines(rows: MachineRow[], query: string): MachineRow[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;
  return rows.filter(
    (m) => m.name.toLowerCase().includes(q) || m.code.toLowerCase().includes(q),
  );
}

export function MachinesRail({
  machines,
  thisCode,
  hostState,
  sharing,
  onPick,
  onConnect,
  onShare,
  onStopShare,
}: {
  machines: MachineRow[];
  thisCode: string;
  hostState: HostStateName;
  sharing: boolean;
  onPick: (code: string) => void;
  onConnect: (code: string, agent: boolean) => void;
  onShare: () => void;
  onStopShare: () => void;
}) {
  const [code, setCode] = useState("");
  const [query, setQuery] = useState("");
  const host = hostView(hostState);

  const dial = (agent: boolean) => {
    const c = code.trim().toLowerCase();
    if (!c) return;
    setCode("");
    onConnect(c, agent);
  };

  const visible = filterMachines(machines, query);
  const filtering = query.trim().length > 0;
  const trusted = visible.filter((m) => m.trusted);
  const pending = visible.filter((m) => !m.trusted);

  return (
    <nav className="rail" aria-label="Machines">
      <div className="rail-head">
        <span>Machines</span>
      </div>
      <p className="rail-sub muted">message or control — same list</p>

      <div className="rail-add">
        <input
          value={code}
          placeholder="connection code"
          onChange={(e) => setCode(e.target.value)}
          aria-label="Connection code"
          onKeyDown={(e) => {
            if (e.key === "Enter") dial(false);
          }}
        />
        <div className="row">
          <button
            type="button"
            className="primary small"
            disabled={!code.trim()}
            onClick={() => dial(false)}
            title="Ask to control this machine — its user allows it once"
          >
            Control
          </button>
          <button
            type="button"
            className="ghost small"
            disabled={!code.trim()}
            onClick={() => dial(true)}
            title="Connect chat-only: give this machine's assistant instructions without opening the screen"
          >
            Agent
          </button>
        </div>
        <p className="hint">the code is on the other machine's "This machine" card</p>
      </div>

      <input
        type="search"
        className="rail-search"
        value={query}
        placeholder="Search machines"
        aria-label="Search machines"
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Escape") setQuery("");
        }}
      />
      {filtering ? (
        <p className="hint" role="status">
          {visible.length} machine{visible.length === 1 ? "" : "s"}
        </p>
      ) : null}

      <ul className="rail-list">
        {trusted.map((m) => (
          <MachineRowView key={m.code} row={m} onPick={onPick} onConnect={onConnect} />
        ))}
        {pending.length > 0 ? (
          <li className="rail-group-hint">Waiting for their approval</li>
        ) : null}
        {pending.map((m) => (
          <MachineRowView key={m.code} row={m} onPick={onPick} onConnect={onConnect} />
        ))}
      </ul>
      {machines.length === 0 ? (
        <p className="rail-empty muted">
          No machines yet — one list is for messaging and remote control.
          Enter a connection code above; its user answers{" "}
          {"\""}Always allow{"\""} once and it stays in this list.
        </p>
      ) : null}

      <div className="rail-this">
        <div className="rail-head">
          <span>This machine</span>
          <span className={`dot ${sharing ? "on" : "off"}`} aria-hidden="true" />
        </div>
        <span className="chip chip-neutral">{host.status}</span>
        <code className="code">{thisCode}</code>
        {host.can.start ? (
          <button type="button" className="primary small" onClick={onShare}>
            Share this machine
          </button>
        ) : null}
        {host.can.stop ? (
          <button type="button" className="danger small" onClick={onStopShare}>
            Stop sharing
          </button>
        ) : null}
      </div>
    </nav>
  );
}

function MachineRowView({
  row,
  onPick,
  onConnect,
}: {
  row: MachineRow;
  onPick: (code: string) => void;
  onConnect: (code: string, agent: boolean) => void;
}) {
  return (
    <li className={`rail-row-wrap${row.pending ? " pending" : ""}`}>
      <button
        type="button"
        className={`rail-row${row.active ? " active" : ""}`}
        onClick={() => onPick(row.code)}
        title={row.pending ? "Waiting for their approval" : "Open this machine"}
      >
        <span
          className={`dot ${row.online === true ? "on" : row.online === false ? "off" : "unknown"}`}
          aria-hidden="true"
        />
        <span className="rail-name">{row.name}</span>
        {row.trusted ? (
          <span className="trusted-shield" title="Trusted — connects without asking again">
            ✓
          </span>
        ) : null}
      </button>
      <button
        type="button"
        className="ghost small rail-connect"
        onClick={() => onConnect(row.code, false)}
        title={row.trusted ? "Trusted machine — connects without asking again" : "They'll be asked to allow it"}
        aria-label={`Control ${row.name}${row.online === false ? " (offline)" : ""}`}
      >
        Control
      </button>
    </li>
  );
}
