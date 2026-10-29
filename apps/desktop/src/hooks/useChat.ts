/**
 * useChat: conversation state for one machine (RD-022). Loads persisted
 * history, appends live `engine://chat` events for that peer, and sends
 * through `chat_send` (which routes in-session or via the sealed inbox).
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, CHAT_EVENT } from "../ipc";
import type { ChatLine } from "../ipc";
import { listen } from "@tauri-apps/api/event";

export interface ChatBinding {
  lines: ChatLine[];
  sending: boolean;
  /** Send a line to this machine. `toAgent` addresses the peer's
   * assistant (the AgentChat box) — allowed only while a session
   * with that machine is live (the backend refuses otherwise). */
  send: (text: string, toAgent?: boolean) => Promise<void>;
  refresh: () => Promise<void>;
}

export function useChat(code: string | null): ChatBinding {
  const [lines, setLines] = useState<ChatLine[]>([]);
  const [sending, setSending] = useState(false);
  const codeRef = useRef(code);
  codeRef.current = code;

  const refresh = useCallback(async () => {
    if (!code) {
      setLines([]);
      return;
    }
    try {
      setLines(await api.chatHistory(code));
    } catch {
      setLines([]);
    }
  }, [code]);

  useEffect(() => {
    void refresh();
    const unbind = listen(CHAT_EVENT, (event) => {
      const payload = event.payload as { peer: string; sender: string; body: string; id: number; ts_ms: number };
      if (codeRef.current && payload.peer === codeRef.current) {
        setLines((prev) =>
          prev.some((l) => l.id === payload.id)
            ? prev
            : [
                ...prev,
                {
                  id: payload.id,
                  ts_ms: payload.ts_ms,
                  sender: `peer-${payload.sender}`,
                  body: payload.body,
                },
              ],
        );
      }
    });
    return () => {
      void unbind.then((fn) => fn());
    };
  }, [refresh]);

  const send = useCallback(
    async (text: string, toAgent = false) => {
      const trimmed = text.trim();
      if (!trimmed || !code || sending) return;
      setSending(true);
      const sender = toAgent ? "to-agent" : "user";
      try {
        await api.chatSend(code, trimmed, toAgent);
        setLines((prev) =>
          prev.some((l) => l.body === trimmed && l.sender === sender)
            ? prev
            : [
                ...prev,
                { id: Date.now(), ts_ms: Date.now(), sender, body: trimmed },
              ],
        );
      } finally {
        setSending(false);
      }
    },
    [code, sending],
  );

  return { lines, sending, send, refresh };
}
