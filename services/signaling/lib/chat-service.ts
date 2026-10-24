/**
 * Machine-chat inbox service core (ADR-005 RD-022).
 *
 * Pure logic over the `Store` seam — no sockets, no authoritative memory.
 * The inbox is a bounded, TTL'd, ciphertext-only mailbox per device:
 *
 *   chat:{device}   JSON array of sealed envelopes (cap CHAT_INBOX_CAP,
 *                   TTL CHAT_INBOX_TTL_SEC, refreshed on append)
 *   chatlock:{d}    append lock (SETNX, TTL 2 s) so two senders cannot
 *                   lose each other's envelope in a read-modify-write race
 *
 * Auth: the caller proves device ownership with the signaling presence
 * token (`service.authenticate`-equivalent: presence `th` field ==
 * sha256(token)) — reusing lib/service.ts's presence records read-only.
 */
import { createHash } from 'node:crypto';
import type { Store } from './store.ts';
import { log } from './log.ts';
import { CHAT_PROTOCOL_VERSION, type ChatEnvelope } from './chat-schema.ts';

/** Inbox depth cap (per device). Oldest dropped on overflow. */
export const CHAT_INBOX_CAP = 32;
/** Inbox TTL: an offline machine's messages wait up to a day. */
export const CHAT_INBOX_TTL_SEC = 24 * 60 * 60;
/** Append-lock TTL (self-healing on a crashed writer). */
export const CHAT_LOCK_TTL_SEC = 2;

const sha256hex = (value: string) =>
  createHash('sha256').update(value, 'utf8').digest('hex');

interface PresenceRecord {
  th: string;
}

const parsePresence = (raw: string | null): PresenceRecord | null => {
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as PresenceRecord;
    return typeof parsed.th === 'string' ? parsed : null;
  } catch {
    return null;
  }
};

export type ChatCallResult =
  | { ok: true; envelopes?: ChatEnvelope[] }
  | { ok: false; status: number; error: string; retry_after_s?: number };

export class ChatService {
  constructor(private readonly store: Store) {}

  /** Presence-token auth (read-only over lib/service.ts records). */
  async authenticate(device: string, token: string): Promise<boolean> {
    const rec = parsePresence(await this.store.get(`sg1:p:${device}`));
    return rec !== null && rec.th === sha256hex(token);
  }

  /** Append one sealed envelope to the target's inbox. */
  async put(to: string, envelope: ChatEnvelope): Promise<ChatCallResult> {
    if (envelope.from === to) {
      return { ok: false, status: 400, error: 'self_send_forbidden' };
    }
    const lockKey = `sg1:chatlock:${to}`;
    const acquired = await this.store.setNxEx(lockKey, '1', CHAT_LOCK_TTL_SEC);
    if (!acquired) {
      // Bounded retry story: tell the sender to come back in a second
      // (two senders raced; the mailbox keeps the other's message).
      return { ok: false, status: 429, error: 'inbox_busy', retry_after_s: 1 };
    }
    try {
      const raw = await this.store.get(`sg1:chat:${to}`);
      let list: ChatEnvelope[] = [];
      if (raw !== null) {
        try {
          list = JSON.parse(raw) as ChatEnvelope[];
        } catch {
          list = []; // corrupt inbox: reset rather than poison the device
        }
      }
      list.push(envelope);
      if (list.length > CHAT_INBOX_CAP) {
        list = list.slice(list.length - CHAT_INBOX_CAP);
      }
      await this.store.setEx(`sg1:chat:${to}`, JSON.stringify(list), CHAT_INBOX_TTL_SEC);
      return { ok: true };
    } finally {
      await this.store.del(lockKey);
    }
  }

  /** Destructively drain the caller's inbox. */
  async drain(device: string): Promise<ChatCallResult> {
    const key = `sg1:chat:${device}`;
    const raw = await this.store.get(key);
    let envelopes: ChatEnvelope[] = [];
    if (raw !== null) {
      try {
        envelopes = JSON.parse(raw) as ChatEnvelope[];
      } catch {
        envelopes = [];
      }
      await this.store.del(key);
    }
    log.debug('chat drain', { device, count: envelopes.length });
    return { ok: true, envelopes };
  }
}

export { CHAT_PROTOCOL_VERSION };
