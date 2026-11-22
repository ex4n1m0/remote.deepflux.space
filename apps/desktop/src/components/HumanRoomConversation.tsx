/** Human-room conversation pane (ADR-013 D4/P3): the center column's
 * humans-only E2E chat. Reuses the machine Conversation styling (the
 * `.conversation` / `.chat-msg` / `.conversation-compose` tokens) but is a
 * SEPARATE surface — room messages never mix with machine chat, and no agent
 * tool reads or posts here (D4). The epoch indicator shows the current key
 * epoch and bumps on a rotation; only the host can rotate. */

import { useEffect, useRef, useState } from "react";
import type { HumanRoomsBinding } from "../hooks/useHumanRooms";

/** Short, readable label for a peer id (the room's member names ride the
 * state's peers list; a bare id is the fallback). */
function peerLabel(peer: string, names: Map<string, string>): string {
  const name = names.get(peer);
  if (name && name.trim()) return name;
  return `${peer.slice(0, 8)}…`;
}

export function HumanRoomConversation({
  rooms,
  onClose,
}: {
  rooms: HumanRoomsBinding;
  onClose: () => void;
}) {
  const [draft, setDraft] = useState("");
  const logRef = useRef<HTMLDivElement | null>(null);
  const state = rooms.state;
  const joined = !!state?.joined;
  // Ready to send once the node has reported the room (RoomReady): before
  // that the node is still searching/joining and would refuse a send.
  const ready = joined && !!state?.room;
  const names = new Map((state?.peers ?? []).map((p) => [p.peer, p.name]));

  useEffect(() => {
    logRef.current?.scrollTo?.({ top: logRef.current.scrollHeight });
  }, [rooms.messages.length]);

  const submit = async () => {
    const text = draft.trim();
    if (!text || !ready) return;
    setDraft("");
    await rooms.send(text);
  };

  const lastLog = rooms.logs.length > 0 ? rooms.logs[rooms.logs.length - 1] : null;

  return (
    <div className="conversation human-conversation">
      <div className="human-room-head">
        <div className="human-room-title">
          <h2>Human chat</h2>
          <span className="chip chip-neutral human-epoch" title="Current key epoch — bumps when the host rotates the room key">
            epoch {state?.epoch ?? 0}
          </span>
          {joined ? (
            <span className="chip chip-neutral" role="status">
              {state?.status ?? "connecting"}
            </span>
          ) : null}
          {joined ? (
            <span className="muted small">
              {(state?.peers.length ?? 0)} member{(state?.peers.length ?? 0) === 1 ? "" : "s"}
            </span>
          ) : null}
        </div>
        <div className="row">
          {state?.we_are_host ? (
            <button
              type="button"
              className="ghost small"
              onClick={rooms.rotate}
              disabled={!ready}
              title="Rotate the room key — everyone re-keys to a new epoch; only the host can do this"
            >
              Rotate key
            </button>
          ) : null}
          {joined ? (
            <button type="button" className="danger small" onClick={rooms.leave}>
              Leave
            </button>
          ) : null}
          <button type="button" className="ghost small" onClick={onClose} aria-label="Close human chat">
            Close
          </button>
        </div>
      </div>

      <div className="conversation-log" ref={logRef}>
        {!joined ? (
          <p className="muted">
            You're not in a room. Join one from the rail to chat
            end-to-end with other people.
          </p>
        ) : rooms.messages.length === 0 ? (
          <p className="muted">
            No messages yet. Say hello — everything here is end-to-end
            encrypted between the people in the room.
          </p>
        ) : (
          rooms.messages.map((m, i) => (
            <div
              key={`${m.epoch}-${m.sender}-${i}`}
              className={`chat-msg ${m.mine ? "outgoing" : "incoming"}`}
            >
              <span className="chat-who">
                {m.mine ? "you" : peerLabel(m.sender, names)}
                {m.via_site ? " · via site" : ""}
              </span>
              {m.body}
            </div>
          ))
        )}
      </div>

      {joined && !ready ? (
        <p className="hint human-room-status" role="status">
          {state?.status === "failed"
            ? (state.error ?? "Couldn't start the room node.")
            : `Room is ${state?.status ?? "connecting"}… messages can be sent once it's ready.`}
        </p>
      ) : lastLog ? (
        <p className="hint human-room-status" role="status">
          {lastLog}
        </p>
      ) : null}

      <div className="conversation-compose">
        <input
          value={draft}
          placeholder={ready ? "message the room…" : "join a room first"}
          disabled={!ready}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void submit();
            }
          }}
          aria-label="Room message"
        />
        <button
          type="button"
          className="primary"
          disabled={!draft.trim() || !ready}
          onClick={() => void submit()}
        >
          Send
        </button>
      </div>
    </div>
  );
}
