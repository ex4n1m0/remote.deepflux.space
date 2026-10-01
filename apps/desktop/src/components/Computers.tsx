/** Computers: the signed-in replacement for the Favorites panel — the
 * encrypted, server-synced roster. Rows show name/code/online dot, rename,
 * remove, connect; this machine's own entry carries a "This computer"
 * badge instead of Connect. Props-only (component tests run without
 * Tauri). */
import { useState } from "react";
import { CopyButton, Section } from "./Common";
import { normalizeCode } from "../ipc";
import type { Computer } from "../types";

export interface ComputersProps {
  computers: Computer[];
  /** Codes the presence poll last saw online. */
  online: string[];
  canConnect: boolean;
  onConnect: (code: string) => void;
  onAdd: (name: string, code: string) => Promise<void>;
  onAddThis: () => void;
  onRemove: (id: string) => void;
  onRename: (id: string, name: string) => void;
  /** Scroll to the identity card ("Sharing — view code"). */
  onViewCode: () => void;
}

export function Computers({
  computers,
  online,
  canConnect,
  onConnect,
  onAdd,
  onAddThis,
  onRemove,
  onRename,
  onViewCode,
}: ComputersProps) {
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");
  const selfAdded = computers.some((computer) => computer.is_self);

  return (
    <Section
      title="Your computers"
      actions={
        selfAdded ? (
          <button type="button" className="ghost" onClick={onViewCode}>
            Sharing — view code
          </button>
        ) : (
          <button type="button" onClick={onAddThis} aria-label="Add this computer">
            + Add this computer
          </button>
        )
      }
    >
      <p className="muted">
        Encrypted and synced with your account. "Add this computer" makes this machine shareable
        from your other machines.
      </p>
      <form
        className="favorites-form"
        onSubmit={async (event) => {
          event.preventDefault();
          const normalized = normalizeCode(code);
          if (normalized.length === 0) {
            setError("Enter a connection code.");
            return;
          }
          try {
            await onAdd(name, normalized);
            setName("");
            setCode("");
            setError(null);
          } catch (err) {
            setError(String(err));
          }
        }}
      >
        <label>
          Name
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Living room PC"
          />
        </label>
        <label>
          Connection code
          <input
            value={code}
            onChange={(event) => setCode(event.target.value)}
            placeholder="e.g. 1a2b3c4d5e6f7788"
            spellCheck={false}
          />
        </label>
        <button type="submit">Add by code</button>
      </form>
      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}
      {computers.length === 0 ? (
        <p className="muted">No computers yet — add this one, or a remote machine by code.</p>
      ) : (
        <ul className="favorites" role="list">
          {computers.map((computer) => {
            const isOnline = online.includes(computer.code);
            return (
              <li key={computer.id} className="favorite">
                {renaming === computer.id ? (
                  <form
                    className="rename-form"
                    onSubmit={(event) => {
                      event.preventDefault();
                      onRename(computer.id, renameValue);
                      setRenaming(null);
                    }}
                  >
                    <input
                      value={renameValue}
                      onChange={(event) => setRenameValue(event.target.value)}
                      aria-label={`New name for ${computer.name || computer.code}`}
                      autoFocus
                    />
                    <button type="submit">Save</button>
                    <button type="button" className="ghost" onClick={() => setRenaming(null)}>
                      Cancel
                    </button>
                  </form>
                ) : (
                  <>
                    {computer.is_self ? (
                      <span className="badge" aria-label="this computer">
                        This computer
                      </span>
                    ) : isOnline ? (
                      <span className="dot dot-on" title="Online" aria-label="online" />
                    ) : (
                      <span className="dot" title="Offline" aria-label="offline" />
                    )}
                    <span className="favorite-name">{computer.name || computer.code}</span>
                    <code className="code favorite-code">{computer.code}</code>
                    <CopyButton value={computer.code} label={`code for ${computer.name || computer.code}`} />
                    {computer.is_self ? null : (
                      <button
                        type="button"
                        disabled={!canConnect}
                        onClick={() => onConnect(computer.code)}
                        aria-label={`Connect to ${computer.name || computer.code}`}
                      >
                        Connect
                      </button>
                    )}
                    <button
                      type="button"
                      className="ghost"
                      onClick={() => {
                        setRenaming(computer.id);
                        setRenameValue(computer.name);
                      }}
                      aria-label={`Rename ${computer.name || computer.code}`}
                    >
                      Rename
                    </button>
                    <button
                      type="button"
                      className="ghost danger"
                      onClick={() => onRemove(computer.id)}
                      aria-label={`Remove ${computer.name || computer.code}`}
                    >
                      Remove
                    </button>
                  </>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Section>
  );
}
