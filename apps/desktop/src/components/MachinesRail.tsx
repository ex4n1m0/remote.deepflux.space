/** Machines rail (ADR-005, simplified by ADR-009, discovery restored by
 * ADR-010, re-sourced by ADR-013 P2): the IM-style left column and THE
 * machine list — the trusted-host list (pairings) plus the account
 * directory (the website account's machines), merged one-row-per-machine.
 * Every row is both a chat and a remote-control target; paired machines
 * connect silently, account machines connect through the account-proof
 * path (asked once — "Always allow" makes it permanent; the controller
 * proves its installation, the host checks its account). The connect box
 * under the header still reaches any machine by code. Also home to the
 * pinned "This machine" card (host role). */
import { useState } from "react";
import { hostView } from "../state/mapping";
import { CopyButton } from "./Common";
import { ACCOUNT_ONLINE_WINDOW_MS } from "../types";
import type { AccountMachine, HostStateName, PairingInfo } from "../types";

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

/** ADR-013 P2: trusted list + account directory, ONE row per machine —
 * the merge is keyed by signaling device code, so a machine can never
 * appear twice. Pairings win: a paired row keeps its cached name (a
 * placeholder name that is just the bare code adopts the account label
 * instead). Presence: a `true` from either source wins — a live session
 * shows online even before the poll catches up, and the directory's
 * last-seen flag (refreshed every 30 s) clears the session-scoped `false`
 * that a past disconnect left behind. Rows without a shared signaling id
 * (sharing off, or the account machine predates the mapping) stay out —
 * they cannot be reached at all. */
export function unifiedMachines(
  pairings: PairingInfo[],
  peerOnline: Record<string, boolean>,
  selectedCode: string | null,
  account: AccountMachine[] | null,
  nowMs: number = Date.now(),
): MachineRow[] {
  const rows = machinesFromPairings(pairings, peerOnline, selectedCode);
  if (!account) return rows;
  const byCode = new Map(rows.map((r) => [r.code, r]));
  for (const m of account) {
    if (m.is_self) continue;
    const device = m.signaling_device_id;
    if (!device) continue; // online-but-not-controllable: no row
    const online =
      m.last_seen_at_ms !== null && nowMs - m.last_seen_at_ms < ACCOUNT_ONLINE_WINDOW_MS;
    const name = m.label || `${m.installation_id.slice(0, 8)}…`;
    const existing = byCode.get(device);
    if (existing) {
      if (existing.name === existing.code && m.label) {
        existing.name = m.label; // placeholder name — the account's label is real
      }
      existing.online = existing.online === true || online;
      continue;
    }
    const row: MachineRow = {
      id: `acct:${m.installation_id}`,
      name,
      code: device,
      online,
      active: selectedCode === device,
      trusted: false,
      pending: false,
      fromDirectory: true,
    };
    byCode.set(device, row);
    rows.push(row);
  }
  return rows;
}

/** Self is not a contact: the account row for THIS machine never reaches
 * the merged list (the pinned "This machine" card represents self). The
 * `is_self` flag is authoritative; the caller keeps this belt-and-braces
 * filter for older payloads. */
export function excludeSelfAccount(
  machines: AccountMachine[],
  thisInstallationId: string | null,
): AccountMachine[] {
  return machines.filter((m) => !m.is_self && m.installation_id !== thisInstallationId);
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
