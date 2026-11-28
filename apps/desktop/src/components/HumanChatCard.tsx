/** Human-chat rail card (ADR-013 D4/P3): the humans-only E2E chat's entry
 * in the machine rail — "Human chat / join a room". Joined rooms show their
 * status + epoch and an Open verb (the center pane's conversation); otherwise
 * a Join verb opens the word modal. A separate user surface from the machine
 * list above it — no agent tool reads or posts into rooms (D4). */

import type { HumanRoomState } from "../types";
import { Icon } from "./Icon";

export function HumanChatCard({
  room,
  active,
  onJoin,
  onOpen,
}: {
  room: HumanRoomState | null;
  /** The center pane is currently showing this room's conversation. */
  active: boolean;
  onJoin: () => void;
  onOpen: () => void;
}) {
  const joined = !!room?.joined;
  return (
    <div className={`rail-this rail-human${active ? " active" : ""}`}>
      <div className="rail-head">
        <span>Human chat</span>
        <span className={`dot ${joined ? "on" : "off"}`} aria-hidden="true" />
      </div>
      {joined ? (
        <>
          <span className="chip chip-neutral" role="status">
            {room?.status ?? "connecting"}
          </span>{" "}
          <span className="chip chip-neutral human-epoch" title="Current key epoch">
            epoch {room?.epoch ?? 0}
          </span>
          <p className="hint">
            encrypted · {room?.peers.length ?? 0} member
            {(room?.peers.length ?? 0) === 1 ? "" : "s"}
          </p>
          <button type="button" className="primary small" onClick={onOpen}>
            {active ? "Viewing room" : "Open room"}
          </button>
        </>
      ) : (
        <button
          type="button"
          className="ghost small rail-join-human"
          onClick={onJoin}
          title="Chat with other people, end to end — never the server, never the assistant"
        >
          <Icon name="users" />
          Join a room
        </button>
      )}
    </div>
  );
}
