/** Machines rail (ADR-005 / study §4.1): the IM-style left column. One
 * unified list — the ADR-003 union (local favorites + signed-in roster
 * computers, union-by-code) — plus the pinned "This machine" card (host
 * role) and add-machine. The selected machine drives the center pane. */
import { useState } from "react";
import type { Computer, Favorite } from "../types";

export interface MachineRow {
  id: string;
  name: string;
  code: string;
  online: boolean | null;
  active: boolean;
}

/** ADR-003 union: roster computers and local favorites merged by code
 * (roster name wins for shared entries; favorites-only entries kept). */
export function unifiedMachines(
  favorites: Favorite[],
  computers: Computer[] | null,
  onlineCodes: string[],
  peerOnline: Record<string, boolean>,
  selectedCode: string | null,
): MachineRow[] {
  const onlineSet = new Set(onlineCodes);
  const seen = new Set<string>();
  const rows: MachineRow[] = [];
  if (computers) {
    for (const c of computers) {
      seen.add(c.code);
      rows.push({
        id: c.id,
        name: c.name || c.code,
        code: c.code,
        online: onlineSet.has(c.code) ? true : peerOnline[c.code] ?? null,
        active: selectedCode === c.code,
      });
    }
  }
  for (const f of favorites) {
    if (seen.has(f.code)) continue;
    rows.push({
      id: f.id,
      name: f.name,
      code: f.code,
      online: peerOnline[f.code] ?? null,
      active: selectedCode === f.code,
    });
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

export function MachinesRail({
  machines,
  thisCode,
  hostState,
  sharing,
  canConnect,
  onPick,
  onConnect,
  onAdd,
  onShare,
  onStopShare,
}: {
  machines: MachineRow[];
  thisCode: string;
  hostState: string;
  sharing: boolean;
  canConnect: boolean;
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

  const submitAdd = async () => {
    const c = code.trim().toLowerCase();
    if (!c) return;
    setError(null);
    try {
      await onAdd(name.trim() || c, c);
      setName("");
      setCode("");
      setAdding(false);
    } catch (err) {
      setError(String(err));
    }
  };

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
            <button type="button" className="primary small" onClick={() => void submitAdd()}>
              Save
            </button>
            <button type="button" className="ghost small" onClick={() => setAdding(false)}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      <ul className="rail-list">
        {machines.length === 0 ? (
          <li className="rail-empty muted">
            No machines yet — add one with its connection code, or ask the
            assistant to do it.
          </li>
        ) : (
          machines.map((m) => (
            <li key={m.id}>
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
                <span
                  className="rail-connect ghost small"
                  role="button"
                  tabIndex={0}
                  aria-label={`Connect to ${m.name}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    onConnect(m.code);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.stopPropagation();
                      onConnect(m.code);
                    }
                  }}
                >
                  Connect
                </span>
              </button>
            </li>
          ))
        )}
      </ul>
      {!canConnect ? (
        <p className="hint">connecting unavailable in the current state</p>
      ) : null}

      <div className="rail-this">
        <div className="rail-head">
          <span>This machine</span>
          <span className="chip chip-neutral">{hostState}</span>
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
