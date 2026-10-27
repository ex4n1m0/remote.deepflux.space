/**
 * useAssistant: the in-app agent chat binding (ADR-005). Listens to the
 * `assistant://*` events the Rust worker emits, exposes the message log
 * (user / assistant / tool cards), busy state, provider status, and the
 * send/configure/reset actions. The API key is never held here — it goes
 * straight to the Rust side (Credential Manager).
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ASSISTANT_EVENT } from "../ipc";
import { listen } from "@tauri-apps/api/event";

export type AssistantMessage =
  | { kind: "user"; content: string; id: number }
  | { kind: "assistant"; content: string; id: number }
  | { kind: "tool"; name: string; summary: string; id: number }
  | { kind: "error"; message: string; id: number };

export interface AssistantStatus {
  configured: boolean;
  busy: boolean;
  base_url: string;
  model: string;
}

/** A pending human-confirmation request from the assistant. */
export interface AssistantConfirm {
  id: number;
  question: string;
  detail: string;
}

export interface AssistantBinding {
  messages: AssistantMessage[];
  status: AssistantStatus | null;
  busy: boolean;
  confirm: AssistantConfirm | null;
  /** Answer the pending confirmation card (Allow / Always allow / Deny). */
  answerConfirm: (allow: boolean, remember: boolean) => Promise<void>;
  send: (text: string) => Promise<void>;
  /** Resolves false when the configure call failed (the Config section
   * shows its own feedback; errors still land in the chat log). */
  configure: (args: { apiKey?: string; baseUrl?: string; model?: string }) => Promise<boolean>;
  reset: () => Promise<void>;
}

/** Distributive Omit so each union member keeps its own fields. */
type WithoutId<T> = T extends { id: number } ? Omit<T, "id"> : never;

export function useAssistant(): AssistantBinding {
  const [messages, setMessages] = useState<AssistantMessage[]>([]);
  const [status, setStatus] = useState<AssistantStatus | null>(null);
  const [confirm, setConfirm] = useState<AssistantConfirm | null>(null);
  const idRef = useRef(1);

  const push = useCallback((m: WithoutId<AssistantMessage>) => {
    setMessages((prev) => [...prev, { ...m, id: idRef.current++ } as AssistantMessage]);
  }, []);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await api.agentStatus());
    } catch {
      setStatus(null);
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
    let active = true;
    const unbinds: Array<Promise<() => void>> = [];
    const on = (event: string, handler: (payload: unknown) => void) => {
      unbinds.push(
        listen(event, (e) => handler(e.payload)) as unknown as Promise<() => void>,
      );
    };

    on(ASSISTANT_EVENT.message, (payload) => {
      const p = payload as { role: string; content: string };
      if (!active) return;
      if (p.role === "user") {
        push({ kind: "user", content: p.content });
      } else {
        push({ kind: "assistant", content: p.content });
      }
    });
    on(ASSISTANT_EVENT.tool, (payload) => {
      const p = payload as { name: string; summary: string };
      if (active) push({ kind: "tool", name: p.name, summary: p.summary });
    });
    on(ASSISTANT_EVENT.error, (payload) => {
      const p = payload as { message: string };
      if (active) push({ kind: "error", message: p.message });
    });
    on(ASSISTANT_EVENT.busy, (payload) => {
      const p = payload as { on: boolean };
      if (active && status) setStatus({ ...status, busy: p.on });
    });
    on(ASSISTANT_EVENT.confirm, (payload) => {
      const p = payload as { id: number; question: string; detail: string };
      if (active) setConfirm({ id: p.id, question: p.question, detail: p.detail });
    });
    on(ASSISTANT_EVENT.confirmDone, () => {
      if (active) setConfirm(null);
    });

    return () => {
      active = false;
      void Promise.all(unbinds).then((fns) => fns.forEach((fn) => fn()));
    };
    // status in deps would rebind listeners each busy flip; bind once.
  }, []);

  // Keep busy in sync via polling status (the push above may race mount).
  useEffect(() => {
    const t = setInterval(() => void refreshStatus(), 2000);
    return () => clearInterval(t);
  }, [refreshStatus]);

  const send = useCallback(
    async (text: string) => {
      // A rejected agent_send (worker stopped / queue full) must surface in
      // the log — nothing else would show it (the 0.4.2 lesson: silent
      // failures read as "no results").
      try {
        await api.agentSend(text);
      } catch (e) {
        push({ kind: "error", message: e instanceof Error ? e.message : String(e) });
      }
    },
    [push],
  );

  const configure = useCallback(
    async (args: { apiKey?: string; baseUrl?: string; model?: string }) => {
      try {
        await api.agentConfigure(args);
      } catch (e) {
        push({ kind: "error", message: e instanceof Error ? e.message : String(e) });
        return false;
      }
      await refreshStatus();
      return true;
    },
    [push, refreshStatus],
  );

  const reset = useCallback(async () => {
    try {
      await api.agentReset();
    } catch (e) {
      push({ kind: "error", message: e instanceof Error ? e.message : String(e) });
      return;
    }
    setMessages([]);
  }, [push]);

  const answerConfirm = useCallback(
    async (allow: boolean, remember: boolean) => {
      const pending = confirm;
      setConfirm(null);
      if (!pending) return;
      try {
        await api.agentConfirm(pending.id, allow, remember);
      } catch (e) {
        push({ kind: "error", message: e instanceof Error ? e.message : String(e) });
      }
    },
    [confirm, push],
  );

  return {
    messages,
    status,
    busy: status?.busy ?? false,
    confirm,
    answerConfirm,
    send,
    configure,
    reset,
  };
}
