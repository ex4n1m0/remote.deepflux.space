/**
 * Machine-chat inbox unit tests (ADR-005 RD-022) — the service core over
 * an in-memory Store seam. Pins: append + cap + drain-destructive, the
 * self-send refusal, corrupt-inbox recovery, lock-busy behavior, and
 * presence-token auth (sha256(token) against the signaling presence
 * record).
 *
 * Run: node --import tsx --test tests/unit/chat-service.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import {
  ChatService,
  CHAT_INBOX_CAP,
} from '../../lib/chat-service.ts';
import type { Store } from '../../lib/store.ts';
import type { ChatEnvelope } from '../../lib/chat-schema.ts';

/** The success shape of `drain` (envelopes present on drain results). */
type Drained = { ok: true; envelopes: ChatEnvelope[] };

class MemoryStore implements Store {
  map = new Map<string, string>();
  async get(key: string) {
    return this.map.get(key) ?? null;
  }
  async setNxEx(key: string, value: string, _ttlSec: number) {
    if (this.map.has(key)) return false;
    this.map.set(key, value);
    return true;
  }
  async setEx(key: string, value: string, _ttlSec: number) {
    this.map.set(key, value);
  }
  async setExMany(entries: ReadonlyArray<[string, string, number]>) {
    for (const [k, v] of entries) this.map.set(k, v);
  }
  async expire() {
    return true;
  }
  async del(...keys: string[]) {
    let n = 0;
    for (const k of keys) {
      if (this.map.delete(k)) n += 1;
    }
    return n;
  }
  async incr() {
    return 1;
  }
  async expireAfterIncr() {}
  async zadd() {}
  async zrangebyscore() {
    return [];
  }
  async zoldest() {
    return [];
  }
  async zremrangebyscoreMax() {
    return 0;
  }
  async ztrimToNewest() {}
  async zrem() {
    return 0;
  }
}

const sha256hex = (v: string) =>
  createHash('sha256').update(v, 'utf8').digest('hex');

function makeEnv(i: number, from = 'a'.repeat(16)): ChatEnvelope {
  return {
    v: 1,
    from,
    nonce_hex: 'n'.repeat(24),
    ct_hex: 'ab'.repeat(4 + i),
    ts_ms: 1_000 + i,
  };
}

function service() {
  const store = new MemoryStore();
  const chat = new ChatService(store);
  // Register presence for device 'a…' under token 'tok-a'.
  void store.setEx(`sg1:p:${'a'.repeat(16)}`, JSON.stringify({ th: sha256hex('tok-a') }), 60);
  return { chat, store };
}

test('authenticate checks the presence token hash', async () => {
  const { chat } = service();
  assert.equal(await chat.authenticate('a'.repeat(16), 'tok-a'), true);
  assert.equal(await chat.authenticate('a'.repeat(16), 'wrong'), false);
  assert.equal(await chat.authenticate('b'.repeat(16), 'tok-a'), false);
});

test('put then drain is destructive; second drain is empty', async () => {
  const { chat } = service();
  const to = 'b'.repeat(16);
  assert.equal((await chat.put(to, makeEnv(0))).ok, true);
  assert.equal((await chat.put(to, makeEnv(1))).ok, true);
  const drained = (await chat.drain(to)) as Drained;
  assert.equal(drained.envelopes.length, 2);
  assert.equal(drained.envelopes[0]?.ts_ms, 1_000);
  const again = (await chat.drain(to)) as Drained;
  assert.equal(again.envelopes.length, 0);
});

test('self-send is refused', async () => {
  const { chat } = service();
  const a = 'a'.repeat(16);
  const result = await chat.put(a, makeEnv(0, a));
  assert.equal(result.ok, false);
  if (!result.ok) assert.equal(result.status, 400);
});

test('inbox keeps only the newest CHAT_INBOX_CAP envelopes', async () => {
  const { chat } = service();
  const to = 'b'.repeat(16);
  for (let i = 0; i < CHAT_INBOX_CAP + 5; i += 1) {
    const r = await chat.put(to, makeEnv(i));
    assert.equal(r.ok, true, `put ${i}`);
  }
  const drained = (await chat.drain(to)) as Drained;
  assert.equal(drained.envelopes.length, CHAT_INBOX_CAP);
  // Oldest five dropped; the first kept envelope is index 5.
  assert.equal(drained.envelopes[0]?.ts_ms, 1_005);
});

test('concurrent append (lock held) answers 429 inbox_busy', async () => {
  const { chat, store } = service();
  const to = 'b'.repeat(16);
  await store.setNxEx(`sg1:chatlock:${to}`, '1', 2); // simulate a live writer
  const result = await chat.put(to, makeEnv(0));
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.equal(result.status, 429);
    assert.equal(result.error, 'inbox_busy');
    assert.equal(result.retry_after_s, 1);
  }
});

test('corrupt inbox resets instead of poisoning the device', async () => {
  const { chat, store } = service();
  const to = 'b'.repeat(16);
  await store.setEx(`sg1:chat:${to}`, 'not json', 60);
  const put = await chat.put(to, makeEnv(0));
  assert.equal(put.ok, true);
  const drained = (await chat.drain(to)) as Drained;
  assert.equal(drained.envelopes.length, 1);
});
