/** Join-a-room modal (ADR-013 D4/P3): the humans-only E2E chat's one user
 * step — type the room word. Everyone who enters the same word (on the same
 * app build) lands in the same end-to-end-encrypted room; the word itself
 * never crosses the network, only hashes of it do. The modal closes on a
 * successful join (App's effect, per the component-props doctrine) and on
 * Cancel; an invoke-level rejection surfaces inline. */

import { useState } from "react";

export function HumanRoomJoinModal({
  onJoin,
  onCancel,
}: {
  /** Join the room with this word. Rejects on an invoke-level failure
   * (empty word / bridge down) — the modal shows the reason inline. */
  onJoin: (word: string) => Promise<void>;
  onCancel: () => void;
}) {
  const [word, setWord] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    const trimmed = word.trim();
    if (!trimmed || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onJoin(trimmed);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onCancel}>
      <div
        className="modal human-room-join-modal"
        role="dialog"
        aria-modal="true"
        aria-label="Join a human chat room"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="modal-head">
          <h2>Join a room</h2>
        </header>
        <p className="muted">
          Human chat is end-to-end encrypted — only people in the room can
          read it, never the server and never the assistant. Enter the room
          word; everyone who types the same word joins the same room.
        </p>
        <input
          value={word}
          placeholder="room word"
          aria-label="Room word"
          aria-invalid={error ? true : undefined}
          autoFocus
          onChange={(e) => {
            setWord(e.target.value);
            setError(null);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") void submit();
          }}
        />
        {error ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : (
          <p className="hint">
            Pick a long, hard-to-guess word and share it only with the people
            you want in the room.
          </p>
        )}
        <div className="row">
          <button
            type="button"
            className="primary"
            disabled={!word.trim() || busy}
            onClick={() => void submit()}
          >
            {busy ? "Joining…" : "Join room"}
          </button>
          <button type="button" className="ghost" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
