/** Machines rail (ADR-005, simplified by ADR-009, discovery restored by
 * ADR-010): the IM-style left column and THE machine list — the
 * trusted-host list (pairings) plus the discovery list (the sealed circle
 * directory), merged one-row-per-machine. Every row is both a chat and a
 * remote-control target; paired machines connect silently, discovered
 * machines connect through the ordinary consent prompt (asked once —
 * "Always allow" makes it permanent). The connect box under the header
 * still reaches any machine by code. Also home to the pinned "This
 * machine" card (host role). */
import { useState } from "react";
import { hostView } from "../state/mapping";
import { CopyButton } from "./Common";
import type { DirectoryMachine, HostStateName, PairingInfo } from "../types";

/** A connection code is exactly 16 hex characters (the peer's device id). */
export function looksLikeCode(value: string): boolean {
  return /^[0-9a-f]{16}$/.test(value.trim().toLowerCase());
}

export const BAD_CODE_HINT =
  "That doesn't look like a connection code — it's 16 letters and numbers, on the other machine's \"This machine\" card.";

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
  /** ADR-010: surfaced by the discovery list (not paired yet). */
  fromDirectory: boolean;
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
    fromDirectory: false,
  }));
}

/** ADR-010: trusted list + discovery list, ONE row per machine — the
 * merge is keyed by device code, so a machine can never appear twice.
 * Pairings win: a paired row keeps its cached name (a placeholder name
 * that is just the bare code adopts the discovered name instead).
 * Presence: a `true` from either source wins — a live session shows
 * online even before the directory catches up, and the directory's live
 * flag (refreshed every 30 s) clears the session-scoped `false` that a
 * past disconnect left behind (sticky-offline bug: only an app restart
 * used to clear it, so a trusted peer showed offline forever). */
export function unifiedMachines(
  pairings: PairingInfo[],
  peerOnline: Record<string, boolean>,
  selectedCode: string | null,
  directory: DirectoryMachine[] | null,
): MachineRow[] {
  const rows = machinesFromPairings(pairings, peerOnline, selectedCode);
  if (!directory) return rows;
  const byCode = new Map(rows.map((r) => [r.code, r]));
  for (const d of directory) {
    const existing = byCode.get(d.device);
    if (existing) {
      if (existing.name === existing.code && d.name) {
        existing.name = d.name; // placeholder name — the discovered one is real
      }
      existing.online = existing.online === true || d.online === true;
      continue;
    }
    const row: MachineRow = {
      id: `dir:${d.device}`,
      name: d.name || d.device,
      code: d.device,
      online: d.online,
      active: selectedCode === d.device,
      trusted: false,
      pending: false,
      fromDirectory: true,
    };
    byCode.set(d.device, row);
    rows.push(row);
  }
  return rows;
}

/** Self is not a contact: directory rows for THIS machine never reach the
 * merged list (the pinned "This machine" card represents self). Matches by
 * the backend's `is_self` flag and, belt-and-braces, by device id. */
export function excludeSelf(
  machines: DirectoryMachine[],
  thisDevice: string | null,
): DirectoryMachine[] {
  return machines.filter((m) => !m.is_self && m.device !== thisDevice);
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
      <span className="hint">
        Remove {name} from your list? It asks for approval again next time.
      </span>
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
  thisName,
  hostState,
  sharing,
  swarmChip,
  swarmJoinable,
  onJoinSwarm,
  onPick,
  onConnect,
  onShare,
  onStopShare,
}: {
  machines: MachineRow[];
  thisCode: string;
  /** ADR-009: this machine's display name — the identity family sees. */
  thisName: string | null;
  hostState: HostStateName;
  sharing: boolean;
  /** ADR-013: "swarm · <id first 8>…" when this machine is joined to the
   * account swarm (null otherwise). */
  swarmChip: string | null;
  /** ADR-013: whether to offer "Join a swarm" under the connect box. */
  swarmJoinable: boolean;
  onJoinSwarm: () => void;
  onPick: (code: string) => void;
  onConnect: (code: string, agent: boolean) => void;
  onShare: () => void;
  onStopShare: () => void;
}) {
  const [code, setCode] = useState("");
  const [codeError, setCodeError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const host = hostView(hostState);

  const dial = (agent: boolean) => {
    const c = code.trim().toLowerCase();
    if (!c) return;
    // 0.10.2 UX review: catch typos HERE — a bad shape used to reach the
    // service and come back as a wrong "machine isn't online" diagnosis.
    if (!looksLikeCode(c)) {
      setCodeError(BAD_CODE_HINT);
      return;
    }
    setCodeError(null);
    setCode("");
    onConnect(c, agent);
  };

  const visible = filterMachines(machines, query);
  const filtering = query.trim().length > 0;
  const trusted = visible.filter((m) => m.trusted);
  const pending = visible.filter((m) => !m.trusted && m.pending);
  const discovered = visible.filter((m) => !m.trusted && !m.pending);

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
          aria-label="Connection code"
          aria-invalid={codeError ? true : undefined}
          onChange={(e) => {
            setCode(e.target.value);
            setCodeError(null);
          }}
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
        {codeError ? (
          <p className="form-error" role="alert">
            {codeError}
          </p>
        ) : (
          <p className="hint">the code is on the other machine's "This machine" card</p>
        )}
        {swarmJoinable ? (
          <button
            type="button"
            className="ghost small rail-join-swarm"
            onClick={onJoinSwarm}
            title="Bind this machine to your ModelSwarm account — approve an 8-character code on the website"
          >
            Join a swarm
          </button>
        ) : null}
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
        {discovered.length > 0 ? (
          <li className="rail-group-hint">Found for you — not paired yet</li>
        ) : null}
        {discovered.map((m) => (
          <MachineRowView key={m.code} row={m} onPick={onPick} onConnect={onConnect} />
        ))}
      </ul>
      {machines.length === 0 ? (
        <p className="rail-empty muted">
          No machines yet. Other machines running this app appear here on
          their own; you can also enter a connection code above. Their user
          answers {"\""}Always allow{"\""} once and it stays in this list.
        </p>
      ) : null}

      <div className="rail-this">
        <div className="rail-head">
          <span>This machine</span>
          <span className={`dot ${sharing ? "on" : "off"}`} aria-hidden="true" />
        </div>
        {thisName ? <strong>{thisName}</strong> : null}{" "}
        <span className="chip chip-neutral">{host.status}</span>
        {swarmChip ? (
          <span className="chip chip-neutral swarm-chip" title="This machine is joined to your ModelSwarm account">
            {swarmChip}
          </span>
        ) : null}
        <div className="row">
          <code className="code">{thisCode}</code>
          <CopyButton value={thisCode} label="code" />
        </div>
        <p className="hint">family enter this code to reach you</p>
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
        title={
          row.pending
            ? "Waiting for their approval"
            : row.fromDirectory
              ? "Found via the discovery list — Control asks their user once"
              : "Open this machine"
        }
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
        ) : row.fromDirectory ? (
          <span className="dir-tag" title="Discovered — pair it once and it stays" aria-hidden="true">
            ◦
          </span>
        ) : null}
      </button>
      <button
        type="button"
        className="ghost small rail-connect"
        onClick={() => onConnect(row.code, false)}
        title={
          row.trusted
            ? "Trusted machine — connects without asking again"
            : row.fromDirectory
              ? "They'll be asked to allow it — once, then it's saved"
              : "They'll be asked to allow it"
        }
        aria-label={`Control ${row.name}${row.online === false ? " (offline)" : ""}`}
      >
        Control
      </button>
    </li>
  );
}
