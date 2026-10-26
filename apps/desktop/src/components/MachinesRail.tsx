/** Machines rail (ADR-005 / study §4.1, widened by ADR-006): the IM-style
 * left column. ONE merged contact list — the ADR-003 union (local
 * favorites + signed-in roster computers) plus the family-circle
 * directory, union-by-code with name precedence roster > favorite >
 * circle nickname. Same list for messaging AND remote control (the
 * simplify pass made that explicit): open a row for its page, or hit
 * Control for one-step remote control. Search filters by name and code
 * client-side; trusted (paired) rows carry the shield badge; circle-only
 * rows carry the circle tag. Also home to the pinned "This machine" card
 * (host role). */
import { useState } from "react";
import { hostView } from "../state/mapping";
import type { Computer, DirectoryMachine, Favorite, HostStateName } from "../types";

export interface MachineRow {
  id: string;
  name: string;
  code: string;
  online: boolean | null;
  active: boolean;
  /** ADR-006: proven pairing — connects without asking again. */
  trusted: boolean;
  /** ADR-006: surfaced by the circle directory (not a saved machine). */
  fromCircle: boolean;
}

/** The ADR-003 union + the ADR-006 circle merge. Circle rows that are not
 * saved machines appear with the circle tag; a circle nickname beats a
 * favorite whose name is just the bare code (the auto-favorite
 * placeholder) but never a real roster/favorite name. */
export function unifiedMachines(
  favorites: Favorite[],
  computers: Computer[] | null,
  onlineCodes: string[],
  peerOnline: Record<string, boolean>,
  selectedCode: string | null,
  directory: DirectoryMachine[] | null = null,
  trustedCodes: ReadonlySet<string> = new Set(),
): MachineRow[] {
  const onlineSet = new Set(onlineCodes);
  const seen = new Set<string>();
  const rows: MachineRow[] = [];
  const push = (row: Omit<MachineRow, "trusted" | "active">) => {
    seen.add(row.code);
    rows.push({
      ...row,
      trusted: trustedCodes.has(row.code),
      active: selectedCode === row.code,
    });
  };
  if (computers) {
    for (const c of computers) {
      push({
        id: c.id,
        name: c.name || c.code,
        code: c.code,
        online: onlineSet.has(c.code) ? true : peerOnline[c.code] ?? null,
        fromCircle: false,
      });
    }
  }
  for (const f of favorites) {
    if (seen.has(f.code)) continue;
    push({
      id: f.id,
      name: f.name,
      code: f.code,
      online: peerOnline[f.code] ?? null,
      fromCircle: false,
    });
  }
  if (directory) {
    for (const d of directory) {
      if (seen.has(d.device)) {
        // Saved machine with a placeholder name (the bare code — the
        // auto-favorite path): the circle nickname is the better label.
        const row = rows.find((r) => r.code === d.device);
        if (row && row.name === d.device && d.name) {
          row.name = d.name;
        }
        continue;
      }
      push({
        id: `circle:${d.device}`,
        name: d.name || d.device,
        code: d.device,
        online: d.online,
        fromCircle: true,
      });
    }
  }
  return rows;
}

export function machinesFromFavorites(
  favorites: Favorite[],
  peerOnline: Record<string, boolean>,
  selectedCode: string | null,
): MachineRow[] {
  return unifiedMachines(favorites, null, [], peerOnline, selectedCode);
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

/** Client-side search over the merged list: case-insensitive name or code
 * substring. Empty query returns everything. */
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
  onAdd,
  onShare,
  onStopShare,
}: {
  machines: MachineRow[];
  thisCode: string;
  hostState: HostStateName;
  sharing: boolean;
  onPick: (code: string) => void;
  onConnect: (code: string) => void;
  onAdd: (name: string, code: string) => Promise<void>;
  onShare: () => void;
  onStopShare: () => void;
}) {
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  const submitAdd = async (thenControl: boolean) => {
    const c = code.trim().toLowerCase();
    if (!c) return;
    setError(null);
    try {
      await onAdd(name.trim() || c, c);
      setName("");
      setCode("");
      setAdding(false);
      if (thenControl) {
        onConnect(c);
      }
    } catch (err) {
      setError(String(err));
    }
  };

  const visible = filterMachines(machines, query);
  const filtering = query.trim().length > 0;

  return (
    <nav className="rail" aria-label="Machines">
      <div className="rail-head">
        <span>Machines</span>
        <button
          type="button"
          className="ghost small"
          onClick={() => setAdding((v) => !v)}
          aria-expanded={adding}
        >
          + Add
        </button>
      </div>
      <p className="rail-sub muted">message or control — same list</p>

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

      {adding ? (
        <div className="rail-add">
          <input
            value={name}
            placeholder={'Name (e.g. "Mom\'s PC")'}
            onChange={(e) => setName(e.target.value)}
            aria-label="Machine name"
          />
          <input
            value={code}
            placeholder="connection code"
            onChange={(e) => setCode(e.target.value)}
            aria-label="Connection code"
          />
          {error ? <p className="hint" role="alert">{error}</p> : null}
          <div className="row">
            <button
              type="button"
              className="primary small"
              onClick={() => void submitAdd(true)}
            >
              Save &amp; control
            </button>
            <button type="button" className="small" onClick={() => void submitAdd(false)}>
              Save
            </button>
            <button type="button" className="ghost small" onClick={() => setAdding(false)}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      <ul className="rail-list">
        {visible.length === 0 ? (
          <li className="rail-empty muted">
            {filtering
              ? "No machines match that search."
              : "No machines yet. This one list is for messaging and remote control — add a machine with its connection code, join a family circle in Settings, or ask the assistant."}
          </li>
        ) : (
          visible.map((m) => (
            /* One interactive element per row (a11y): select and control are
             * sibling buttons, never nested. */
            <li key={m.id} className="rail-item">
              <button
                type="button"
                className={`rail-row${m.active ? " active" : ""}`}
                onClick={() => onPick(m.code)}
                aria-current={m.active || undefined}
              >
                <span
                  className={`dot ${m.online === true ? "on" : m.online === false ? "off" : "unknown"}`}
                  aria-hidden="true"
                  title={m.online === true ? "online" : m.online === false ? "offline" : "unknown"}
                />
                <span className="rail-name">{m.name}</span>
                {m.trusted ? (
                  <span className="chip chip-good rail-badge" title="Trusted — connects without asking again">
                    ✓
                  </span>
                ) : null}
                {m.fromCircle && !m.trusted ? <span className="rail-circle-tag muted">circle</span> : null}
              </button>
              <button
                type="button"
                className="ghost small rail-connect"
                aria-label={`Control ${m.name}${m.online === false ? " (offline)" : ""}`}
                title={
                  m.online === false
                    ? "Offline — the app isn't running there; you can still try"
                    : "Ask to control this machine"
                }
                onClick={() => onConnect(m.code)}
              >
                Control
              </button>
            </li>
          ))
        )}
      </ul>

      <div className="rail-this">
        <div className="rail-head">
          <span>This machine</span>
          <span className="chip chip-neutral">{hostView(hostState).status}</span>
        </div>
        <p className="muted">
          code <code className="code">{thisCode}</code>
        </p>
        {sharing ? (
          <button type="button" className="danger small" onClick={onStopShare}>
            Stop sharing
          </button>
        ) : (
          <button type="button" className="primary small" onClick={onShare}>
            Share this machine
          </button>
        )}
      </div>
    </nav>
  );
}
