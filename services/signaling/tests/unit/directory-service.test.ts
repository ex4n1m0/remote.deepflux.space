/**
 * Circle-directory service core unit tests (ADR-006) — over an in-memory
 * Store seam with REAL ZSET semantics. Pins: presence-pair auth, own-row
 * put/replace, sealed-entry size gate, the member cap with
 * existing-member refresh exemption, the list presence join, corrupt-row
 * skipping, idempotent remove, and stale-score pruning.
 *
 * Run: node --import tsx --test tests/unit/directory-service.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { DirectoryService } from '../../lib/directory-service.ts';
import { loadConfig, type SignalingConfig } from '../../lib/config.ts';
import type { Store } from '../../lib/store.ts';

const sha256hex = (value: string) =>
  createHash('sha256').update(value, 'utf8').digest('hex');

/** In-memory Store with real ZSET + TTL-less semantics (scores matter). */
class MemoryStore implements Store {
  map = new Map<string, string>();
  zsets = new Map<string, Array<{ score: number; member: string }>>();
  counters = new Map<string, number>();

  async get(key: string) {
    return this.map.get(key) ?? null;
  }
  async mget(...keys: string[]) {
    return keys.map((k) => this.map.get(k) ?? null);
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
      if (this.zsets.delete(k)) n += 1;
    }
    return n;
  }
  async incr(key: string) {
    const n = (this.counters.get(key) ?? 0) + 1;
    this.counters.set(key, n);
    return n;
  }
  async expireAfterIncr() {}
  async zadd(key: string, score: number, member: string) {
    const z = this.zsets.get(key) ?? [];
    z.push({ score, member });
    this.zsets.set(key, z);
  }
  async zrangebyscore(key: string, min: number, limit: number) {
    const z = this.zsets.get(key) ?? [];
    return z
      .filter((e) => e.score > min)
      .sort((a, b) => a.score - b.score)
      .slice(0, limit)
      .map((e) => e.member);
  }
  async zoldest(key: string, limit: number) {
    const z = this.zsets.get(key) ?? [];
    return z
      .slice()
      .sort((a, b) => a.score - b.score)
      .slice(0, limit)
      .map((e) => e.member);
  }
  async zremrangebyscoreMax(key: string, maxInclusive: number) {
    const z = this.zsets.get(key);
    if (!z) return 0;
    const before = z.length;
    const keep = z.filter((e) => e.score <= maxInclusive ? false : true);
    this.zsets.set(key, keep);
    return before - keep.length;
  }
  async ztrimToNewest() {}
  async zrem(key: string, ...members: string[]) {
    const z = this.zsets.get(key);
    if (!z) return 0;
    const before = z.length;
    this.zsets.set(
      key,
      z.filter((e) => !members.includes(e.member)),
    );
    return before - this.zsets.get(key)!.length;
  }
}

function cfg(overrides: Partial<SignalingConfig> = {}): SignalingConfig {
  return { ...loadConfig(), ...overrides };
}

const CIRCLE = 'a1'.repeat(32);
const DEV_A = '0123456789abcdef';
const DEV_B = 'fedcba9876543210';
const TOKEN_A = 'aa'.repeat(32);
const TOKEN_B = 'bb'.repeat(32);

function seededService(overrides: Partial<SignalingConfig> = {}) {
  const store = new MemoryStore();
  const service = new DirectoryService(store, cfg(overrides));
  // Presence records exactly as lib/service.ts writes them.
  void store.setEx(`sg1:p:${DEV_A}`, JSON.stringify({ th: sha256hex(TOKEN_A) }), 45);
  void store.setEx(`sg1:p:${DEV_B}`, JSON.stringify({ th: sha256hex(TOKEN_B) }), 45);
  return { store, service };
}

function putReq(device: string, ct = '5f'.repeat(32)) {
  return {
    protocol_version: 1 as const,
    action: 'put' as const,
    device,
    circle_id: CIRCLE,
    ciphertext_hex: ct,
    nonce_hex: '6a'.repeat(12),
  };
}

test('authenticate checks the presence token pair', async () => {
  const { service } = seededService();
  assert.equal(await service.authenticate(DEV_A, TOKEN_A), true);
  assert.equal(await service.authenticate(DEV_A, TOKEN_B), false);
  assert.equal(await service.authenticate(DEV_B, 'cc'.repeat(32)), false);
  assert.equal(await service.authenticate('ffffffffffffffff', TOKEN_A), false);
});

test('put stores one row per device; re-put replaces it', async () => {
  const { service } = seededService();
  const r1 = await service.call(putReq(DEV_A), { ip: '1.2.3.4', token: TOKEN_A });
  assert.equal(r1.ok, true);
  const r2 = await service.call(putReq(DEV_A, '7c'.repeat(40)), { ip: '1.2.3.4', token: TOKEN_A });
  assert.equal(r2.ok, true);
  const list = await service.call(
    { protocol_version: 1 as const, action: 'list', device: DEV_A, circle_id: CIRCLE },
    { ip: '1.2.3.4', token: TOKEN_A },
  );
  assert.ok(list.ok);
  if (list.ok) {
    assert.equal(list.body.entries?.length, 1);
    assert.equal(list.body.entries?.[0]?.ciphertext_hex, '7c'.repeat(40));
  }
});

test('put with the wrong device token is unauthorized', async () => {
  const { service } = seededService();
  const r = await service.call(putReq(DEV_A), { ip: '1.2.3.4', token: TOKEN_B });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.error, 'unauthorized');
});

test('oversize sealed entry is rejected before the store', async () => {
  const { service } = seededService();
  const r = await service.call(putReq(DEV_A, 'ab'.repeat(2049)), {
    ip: '1.2.3.4',
    token: TOKEN_A,
  });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.error, 'entry_too_large');
});

test('member cap rejects new devices but never refreshes', async () => {
  const { store, service } = seededService({ directoryMaxMembers: 1 });
  assert.equal((await service.call(putReq(DEV_A), { ip: '1', token: TOKEN_A })).ok, true);
  const full = await service.call(putReq(DEV_B), { ip: '1', token: TOKEN_B });
  assert.equal(full.ok, false);
  if (!full.ok) assert.equal(full.error, 'circle_full');
  // Refresh by the existing member always passes.
  const refresh = await service.call(putReq(DEV_A, '9d'.repeat(32)), {
    ip: '1',
    token: TOKEN_A,
  });
  assert.equal(refresh.ok, true);
  assert.equal((store.zsets.get(`sg1:dir:${CIRCLE}`) ?? []).length, 1);
});

test('list joins presence flags and skips corrupt rows', async () => {
  const { store, service } = seededService();
  await service.call(putReq(DEV_A), { ip: '1', token: TOKEN_A });
  await service.call(putReq(DEV_B), { ip: '1', token: TOKEN_B });
  // Corrupt row injected straight into the ZSET (chat's corrupt-inbox rule).
  await store.zadd(`sg1:dir:${CIRCLE}`, Date.now(), '{not json');
  // DEV_B goes offline.
  await store.del(`sg1:p:${DEV_B}`);

  const list = await service.call(
    { protocol_version: 1 as const, action: 'list', device: DEV_A, circle_id: CIRCLE },
    { ip: '1', token: TOKEN_A },
  );
  assert.ok(list.ok);
  if (list.ok) {
    const entries = list.body.entries ?? [];
    assert.equal(entries.length, 2, 'corrupt row skipped, both live rows kept');
    const online = new Map(entries.map((e) => [e.device, e.online]));
    assert.equal(online.get(DEV_A), true);
    assert.equal(online.get(DEV_B), false);
  }
});

test('remove deletes only the caller row and is idempotent', async () => {
  const { store, service } = seededService();
  await service.call(putReq(DEV_A), { ip: '1', token: TOKEN_A });
  await service.call(putReq(DEV_B), { ip: '1', token: TOKEN_B });
  const r = await service.call(
    { protocol_version: 1 as const, action: 'remove', device: DEV_A, circle_id: CIRCLE },
    { ip: '1', token: TOKEN_A },
  );
  assert.equal(r.ok, true);
  const rows = store.zsets.get(`sg1:dir:${CIRCLE}`) ?? [];
  assert.equal(rows.length, 1);
  assert.ok(rows[0]!.member.includes(DEV_B));
  // Removing again (row absent) is still a success.
  const again = await service.call(
    { protocol_version: 1 as const, action: 'remove', device: DEV_A, circle_id: CIRCLE },
    { ip: '1', token: TOKEN_A },
  );
  assert.equal(again.ok, true);
});

test('list prunes stale-score members lazily', async () => {
  const { store, service } = seededService();
  await service.call(putReq(DEV_A), { ip: '1', token: TOKEN_A });
  const staleMs = Date.now() - 40 * 24 * 60 * 60 * 1000;
  await store.zadd(`sg1:dir:${CIRCLE}`, staleMs, JSON.stringify({
    v: 1,
    device: DEV_B,
    ciphertext_hex: '7c'.repeat(32),
    nonce_hex: '8d'.repeat(12),
    ts_ms: staleMs,
  }));
  const list = await service.call(
    { protocol_version: 1 as const, action: 'list', device: DEV_A, circle_id: CIRCLE },
    { ip: '1', token: TOKEN_A },
  );
  assert.ok(list.ok);
  if (list.ok) assert.equal(list.body.entries?.length, 1, 'stale member pruned on read');
});
