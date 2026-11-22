/** Human-chat bindings (ADR-013 D4/P3): the humans-only E2E word rooms over
 * the pinned OnlyHumans protocol. Mirrors the Rust node's state push
 * (`human-chat://state`), accumulates the live message tail
 * (`human-chat://message`), and forwards the user verbs (join/send/rotate/
 * leave). The Rust side owns the node lifecycle — this hook only mirrors it
 * and reports presses. In jsdom/tests there is no bridge: state stays null
 * and the verbs are inert (the useSwarm doctrine). */

import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import {
  api,
  HUMAN_ROOM_LOG_EVENT,
  HUMAN_ROOM_MESSAGE_EVENT,
  HUMAN_ROOM_STATE_EVENT,
} from "../ipc";
import type { HumanRoomLog, HumanRoomMessage, HumanRoomState } from "../types";

/** Bound on the live message tail the pane renders (the node's own store
 * keeps the durable history). Oldest lines drop off past the cap. */
const MESSAGE_CAP = 500;
/** Bound on the retained node log lines (the status footer's tail). */
const LOG_CAP = 50;

export interface HumanRoomsBinding {
  state: HumanRoomState | null;
  messages: HumanRoomMessage[];
  logs: string[];
  /** Join (or re-join) a word room. Rejects on an invoke-level failure
   * (empty word / bridge down); progress arrives as state events. */
  join: (word: string) => Promise<void>;
  /** Send a line to the joined room. */
  send: (text: string) => Promise<void>;
  /** Rotate the room key (host only — the node refuses for guests). */
  rotate: () => void;
  /** Leave the room (tears the node down, clears the persisted word). */
  leave: () => void;
}

export function useHumanRooms(): HumanRoomsBinding {
  const [state, setState] = useState<HumanRoomState | null>(null);
  const [messages, setMessages] = useState<HumanRoomMessage[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  // The room the message tail belongs to — a new room (or a leave) clears
  // the tail so one room's lines never bleed into another's pane.
  const roomRef = useRef<string | null>(null);

  const applyState = useCallback((next: HumanRoomState) => {
    setState(next);
    const room = next.joined ? next.room : null;
    if (room !== roomRef.current) {
      roomRef.current = room;
      setMessages([]);
    }
  }, []);

  useEffect(() => {
    const stops: Array<() => void> = [];
    let cancelled = false;
    void (async () => {
      try {
        applyState(await api.roomsState());
      } catch {
        /* jsdom/tests: no Tauri bridge — the push still feeds us */
      }
      try {
        stops.push(
          await listen<HumanRoomState>(HUMAN_ROOM_STATE_EVENT, (event) =>
            applyState(event.payload),
          ),
        );
        stops.push(
          await listen<HumanRoomMessage>(HUMAN_ROOM_MESSAGE_EVENT, (event) => {
            // Our own lines are appended optimistically on send (the node
            // does not echo them back); skip any mine echo to avoid a double.
            if (event.payload.mine) return;
            setMessages((prev) => [...prev, event.payload].slice(-MESSAGE_CAP));
          }),
        );
        stops.push(
          await listen<HumanRoomLog>(HUMAN_ROOM_LOG_EVENT, (event) => {
            setLogs((prev) => [...prev, event.payload.message].slice(-LOG_CAP));
          }),
        );
        // Startup-race cover (the useSwarm lesson): an emit during the
        // listener-install window was missed — re-pull once now armed.
        if (!cancelled) {
          applyState(await api.roomsState());
        }
      } catch {
        /* same — the pull above already ran where it could */
      }
    })();
    return () => {
      cancelled = true;
      for (const stop of stops) stop();
    };
  }, [applyState]);

  const run = (action: () => Promise<void>) => {
    void action().catch(() => {
      /* room changes land as human-chat://state events */
    });
  };

  // The node does not emit a Message event for our OWN sends (it seals and
  // fans out to peers), so the sender's line is appended optimistically once
  // the invoke resolves — the useChat doctrine. Incoming peer lines ride the
  // message event above.
  const send = async (text: string) => {
    await api.roomsSend(text);
    const body = text.trim();
    if (!body) return;
    setMessages((prev) =>
      [
        ...prev,
        {
          room: state?.room ?? "",
          sender: state?.my_peer ?? "you",
          body,
          epoch: state?.epoch ?? 0,
          mine: true,
          via_site: false,
        },
      ].slice(-MESSAGE_CAP),
    );
  };

  return {
    state,
    messages,
    logs,
    join: (word: string) => api.roomsJoin(word),
    send,
    rotate: () => run(api.roomsRotate),
    leave: () => run(api.roomsLeave),
  };
}
