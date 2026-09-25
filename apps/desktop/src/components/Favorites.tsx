/** Favorites: local-only persistence (RD-011). Add / rename / remove /
 * connect, with a peer-online indicator when the engine reports one. */
import { useState } from "react";
import { Section } from "./Common";
import { normalizeCode } from "../ipc";
import type { Favorite } from "../types";

export interface FavoritesProps {
  favorites: Favorite[];
  peerOnline: Record<string, boolean>;
  canConnect: boolean;
  onConnect: (code: string) => void;
  onAdd: (name: string, code: string) => Promise<void>;
  onRemove: (id: string) => void;
  onRename: (id: string, name: string) => void;
}

export function Favorites({
  favorites,
  peerOnline,
  canConnect,
  onConnect,
  onAdd,
  onRemove,
  onRename,
}: FavoritesProps) {
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");

  return (
    <Section title="Favorites">
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
        <button type="submit">Add favorite</button>
      </form>
      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}
      {favorites.length === 0 ? (
        <p className="muted">No favorites yet. Favorites stay on this machine only.</p>
      ) : (
        <ul className="favorites" role="list">
          {favorites.map((favorite) => {
            const online = peerOnline[favorite.code] === true;
            return (
              <li key={favorite.id} className="favorite">
                {renaming === favorite.id ? (
                  <form
                    className="rename-form"
                    onSubmit={(event) => {
                      event.preventDefault();
                      onRename(favorite.id, renameValue);
                      setRenaming(null);
                    }}
                  >
                    <input
                      value={renameValue}
                      onChange={(event) => setRenameValue(event.target.value)}
                      aria-label={`New name for ${favorite.name}`}
                      autoFocus
                    />
                    <button type="submit">Save</button>
                    <button type="button" className="ghost" onClick={() => setRenaming(null)}>
                      Cancel
                    </button>
                  </form>
                ) : (
                  <>
                    <span
                      className={`dot ${online ? "dot-on" : ""}`}
                      title={online ? "Online" : "Offline"}
                      aria-label={online ? "online" : "offline"}
                    />
                    <span className="favorite-name">{favorite.name || favorite.code}</span>
                    <code className="code favorite-code">{favorite.code}</code>
                    <button
                      type="button"
                      disabled={!canConnect}
                      onClick={() => onConnect(favorite.code)}
                      aria-label={`Connect to ${favorite.name || favorite.code}`}
                    >
                      Connect
                    </button>
                    <button
                      type="button"
                      className="ghost"
                      onClick={() => {
                        setRenaming(favorite.id);
                        setRenameValue(favorite.name);
                      }}
                      aria-label={`Rename ${favorite.name || favorite.code}`}
                    >
                      Rename
                    </button>
                    <button
                      type="button"
                      className="ghost danger"
                      onClick={() => onRemove(favorite.id)}
                      aria-label={`Remove ${favorite.name || favorite.code}`}
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
