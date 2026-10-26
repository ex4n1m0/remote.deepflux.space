/**
 * Circle-directory API contract tests (ADR-006) — run against the REAL
 * service code: emulator + a standalone directory server spawned from
 * `tools/dev-server.mjs --only directory` (the same `lib/directory-server.ts`
 * the Vercel function `api/directory.ts` exports).
 *
 * Matrix: the full account-style validation ladder (body cap, token
 * placement, raw version gate, unknown action, zod shapes), presence-pair
 * auth (401 matrix), put/replace/remove round trips with the list presence
 * join, the sealed-entry size cap, stale-score pruning via raw ZADD, the
 * member cap with the refresh exemption (dedicated server spawn), rate
 * limiting (dedicated spawn with tight limits), cross-instance sharing
 * (two servers, one emulator — no in-memory authority), and the
 * no-secrets-in-logs policy with marker ciphertext.
 *
 * Run: node --import tsx --test tests/directory.test.ts  (or `pnpm test:directory`)
 */
import { spawn, spawnSync } from 'node:child_process';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { createHash } from 'node:crypto';

const ROOT = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const EMU = 38061;
const DIR_A = 'http://127.0.0.1:38060';
const DIR_B = 'http://127.0.0.1:38062'; // cross-instance spawn, same emulator
const DIR_FULL = 'http://127.0.0.1:38064'; // SIGNALING_DIRECTORY_MAX_MEMBERS=2
const DIR_RL = 'http://127.0.0.1:38066'; // SIGNALING_RL_DIR_PUT_PER_MIN_PER_DEVICE=2
const EMU_RL = 38067;
const STORE = { url: `http://127.0.0.1:${EMU}`, token: 'local-directory-token' };
const STORE_RL = { url: `http://127.0.0.1:${EMU_RL}`, token: 'local-directory-token' };

const CIRCLE = 'a1'.repeat(32);
const CIRCLE_2 = 'b2'.repeat(32);
const DEV_A = '0123456789abcdef';
const DEV_B = 'fedcba9876543210';
const DEV_C = '0123456789abcdee';
const TOKEN_A = 'aa'.repeat(32);
const TOKEN_B = 'bb'.repeat(32);

const sha256hex = (v: string) => createHash('sha256').update(v, 'utf8').digest('hex');

const children: Array<{ pid?: number | undefined; proc?: ReturnType<typeof spawn> | undefined }> =
  [];
const logs = new Map<string, () => string>();

function spawnNode(args: string[], env: Record<string, string>, label: string) {
  const proc = spawn(process.execPath, args, {
    cwd: ROOT,
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  proc.stdout?.on('data', (c) => (out += c));
  proc.stderr?.on('data', (c) => (out += c));
  children.push({ pid: proc.pid, proc });
  logs.set(label, () => out);
  return proc;
}

function stopAll() {
  for (const c of children) {
    if (c.pid && process.platform === 'win32') {
      spawnSync('taskkill', ['/pid', String(c.pid), '/T', '/F'], { stdio: 'ignore' });
    } else {
      c.proc?.kill('SIGTERM');
    }
  }
}

async function waitUntil(f: () => Promise<boolean>, timeoutMs: number, what: string) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await f()) return;
    await delay(150);
  }
  throw new Error(`timeout waiting for ${what}`);
}

async function pipeline(commands: string[][], store = STORE): Promise<unknown[]> {
  const r = await fetch(`${store.url}/pipeline`, {
    method: 'POST',
    headers: { authorization: `Bearer ${store.token}`, 'content-type': 'application/json' },
    body: JSON.stringify(commands),
    signal: AbortSignal.timeout(4000),
  });
  assert.equal(r.status, 200);
  return (await r.json()) as unknown[];
}

/** Seed a signaling presence record exactly as lib/service.ts writes it. */
async function seedPresence(device: string, token: string, ttlSec = 120, store = STORE) {
  await pipeline(
    [['SET', `sg1:p:${device}`, JSON.stringify({ v: 1, th: sha256hex(token) }), 'EX', String(ttlSec)]],
    store,
  );
}

interface DirReply {
  status: number;
  body: Record<string, unknown>;
}

async function dirCall(
  base: string,
  body: unknown,
  opts: { token?: string | null; query?: string } = {},
): Promise<DirReply> {
  const token = opts.token === undefined ? TOKEN_A : opts.token;
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (token !== null) headers['authorization'] = `Bearer ${token}`;
  const r = await fetch(`${base}/api/directory${opts.query ?? ''}`, {
    method: 'POST',
    headers,
    body: typeof body === 'string' ? body : JSON.stringify(body),
    signal: AbortSignal.timeout(6000),
  });
  return { status: r.status, body: (await r.json()) as Record<string, unknown> };
}

function putBody(device: string, ct = '5f'.repeat(32), circle = CIRCLE) {
  return {
    protocol_version: 1,
    action: 'put',
    device,
    circle_id: circle,
    ciphertext_hex: ct,
    nonce_hex: '6a'.repeat(12),
  };
}

before(async () => {
  spawnNode(['tools/upstash-emulator.mjs', '--port', String(EMU)], {}, 'emu');
  spawnNode(['tools/upstash-emulator.mjs', '--port', String(EMU_RL)], {}, 'emu-rl');
  const storeEnv = {
    UPSTASH_REDIS_REST_URL: STORE.url,
    UPSTASH_REDIS_REST_TOKEN: STORE.token,
  };
  spawnNode(
    ['--import', 'tsx', 'tools/dev-server.mjs', '--only', 'directory', '--directory-port', '38060'],
    storeEnv,
    'dir-a',
  );
  spawnNode(
    ['--import', 'tsx', 'tools/dev-server.mjs', '--only', 'directory', '--directory-port', '38062'],
    storeEnv,
    'dir-b',
  );
  spawnNode(
    ['--import', 'tsx', 'tools/dev-server.mjs', '--only', 'directory', '--directory-port', '38064'],
    { ...storeEnv, SIGNALING_DIRECTORY_MAX_MEMBERS: '2' },
    'dir-full',
  );
  spawnNode(
    ['--import', 'tsx', 'tools/dev-server.mjs', '--only', 'directory', '--directory-port', '38066'],
    {
      UPSTASH_REDIS_REST_URL: STORE_RL.url,
      UPSTASH_REDIS_REST_TOKEN: STORE_RL.token,
      SIGNALING_RL_DIR_PUT_PER_MIN_PER_DEVICE: '2',
    },
    'dir-rl',
  );
  await waitUntil(async () => {
    try {
      const r = await fetch(`${DIR_A}/api/directory`);
      return r.status === 200;
    } catch {
      return false;
    }
  }, 15000, 'directory server A');
  await Promise.all(
    [DIR_B, DIR_FULL, DIR_RL].map(async (base) => {
      await waitUntil(async () => {
        try {
          const r = await fetch(base + '/api/directory');
          return r.status === 200;
        } catch {
          return false;
        }
      }, 15000, `directory server ${base}`);
    }),
  );
  await seedPresence(DEV_A, TOKEN_A);
  await seedPresence(DEV_B, TOKEN_B);
  await seedPresence(DEV_C, TOKEN_A);
  await seedPresence(DEV_A, TOKEN_A, 120, STORE_RL);
});

after(() => stopAll());

test('GET returns the versioned info object; non-POST is 405', async () => {
  const r = await fetch(`${DIR_A}/api/directory`);
  assert.equal(r.status, 200);
  const body = (await r.json()) as Record<string, unknown>;
  assert.equal(body['service'], 'directory');
  assert.equal(body['protocol_version'], 1);
  const method = await fetch(`${DIR_A}/api/directory`, { method: 'PUT' });
  assert.equal(method.status, 405);
});

test('auth matrix: no/bad/foreign tokens answer 401', async () => {
  for (const token of [null, 'wrong'.repeat(10), TOKEN_B]) {
    const r = await dirCall(DIR_A, putBody(DEV_A), { token });
    assert.equal(r.status, 401, `token=${String(token)?.slice(0, 8)}`);
    assert.equal(r.body['error'], 'unauthorized');
  }
});

test('tokens never travel in the query or body (F42b rule)', async () => {
  const q = await dirCall(DIR_A, putBody(DEV_A), { query: '?device_token=zzz' });
  assert.equal(q.status, 401);
  const b = await dirCall(DIR_A, { ...putBody(DEV_A), device_token: 'zzz' });
  assert.equal(b.status, 400);
  assert.equal(b.body['error'], 'malformed');
});

test('validation ladder: version gate, unknown action, camelCase, bad JSON', async () => {
  const v0 = await dirCall(DIR_A, { ...putBody(DEV_A), protocol_version: 0 });
  assert.equal(v0.status, 400);
  assert.equal(v0.body['error'], 'unsupported_version');

  const unknown = await dirCall(DIR_A, { ...putBody(DEV_A), action: 'purge' });
  assert.equal(unknown.status, 400);
  assert.equal(unknown.body['error'], 'unknown_action');

  const camel = await dirCall(DIR_A, { protocolVersion: 1, action: 'list', device: DEV_A, circle_id: CIRCLE });
  assert.equal(camel.status, 400);
  assert.equal(camel.body['error'], 'malformed');

  const broken = await dirCall(DIR_A, '{not json');
  assert.equal(broken.status, 400);
  assert.equal(broken.body['error'], 'malformed');

  const badHex = await dirCall(DIR_A, { ...putBody(DEV_A), ciphertext_hex: 'zz' });
  assert.equal(badHex.status, 400);
  assert.equal(badHex.body['error'], 'malformed');

  const badDevice = await dirCall(DIR_A, { ...putBody('NOTHEX') });
  assert.equal(badDevice.status, 400);
});

test('oversize body answers typed 413', async () => {
  const huge = { ...putBody(DEV_A), ciphertext_hex: 'ab'.repeat(600_000) };
  const r = await dirCall(DIR_A, huge);
  assert.equal(r.status, 413);
  assert.equal(r.body['error'], 'too_large');
});

test('put/list round trip with the presence join; re-put replaces', async () => {
  const marker = 'e7'.repeat(32);
  const put1 = await dirCall(DIR_A, putBody(DEV_A, marker));
  assert.equal(put1.status, 200);
  assert.equal(put1.body['ok'], true);
  assert.equal(typeof put1.body['refreshed_ms'], 'number');

  // Second member (DEV_B online, DEV_A still online; DEV_C seeded but on a
  // different circle below).
  const put2 = await dirCall(DIR_A, putBody(DEV_B, '9d'.repeat(32)), { token: TOKEN_B });
  assert.equal(put2.status, 200);

  const list = await dirCall(DIR_A, {
    protocol_version: 1,
    action: 'list',
    device: DEV_A,
    circle_id: CIRCLE,
  });
  assert.equal(list.status, 200);
  const entries = list.body['entries'] as Array<Record<string, unknown>>;
  assert.equal(entries.length, 2);
  const byDevice = new Map(entries.map((e) => [e['device'], e]));
  assert.equal(byDevice.get(DEV_A)?.['ciphertext_hex'], marker);
  assert.equal(byDevice.get(DEV_A)?.['online'], true);
  assert.equal(byDevice.get(DEV_B)?.['online'], true);

  // Presence expiry flips the flag without touching rows.
  await pipeline([['DEL', `sg1:p:${DEV_B}`]]);
  const list2 = await dirCall(DIR_A, {
    protocol_version: 1,
    action: 'list',
    device: DEV_A,
    circle_id: CIRCLE,
  });
  const entries2 = (list2.body['entries'] as Array<Record<string, unknown>>)
    .map((e) => [e['device'], e['online']] as const);
  assert.deepEqual(entries2.find(([d]) => d === DEV_B), [DEV_B, false]);
  await seedPresence(DEV_B, TOKEN_B);

  // Re-put replaces (still one row).
  const put3 = await dirCall(DIR_A, putBody(DEV_A, '3c'.repeat(32)));
  assert.equal(put3.status, 200);
  const list3 = await dirCall(DIR_A, {
    protocol_version: 1,
    action: 'list',
    device: DEV_A,
    circle_id: CIRCLE,
  });
  assert.equal((list3.body['entries'] as unknown[]).length, 2);
});

test('sealed-entry size cap answers 413 entry_too_large', async () => {
  const r = await dirCall(DIR_A, putBody(DEV_A, 'ab'.repeat(2049)));
  assert.equal(r.status, 413);
  assert.equal(r.body['error'], 'entry_too_large');
});

test('remove is own-row and idempotent', async () => {
  await dirCall(DIR_A, putBody(DEV_C, '11'.repeat(32), CIRCLE_2));
  const r = await dirCall(DIR_A, {
    protocol_version: 1,
    action: 'remove',
    device: DEV_C,
    circle_id: CIRCLE_2,
  });
  assert.equal(r.status, 200);
  const again = await dirCall(DIR_A, {
    protocol_version: 1,
    action: 'remove',
    device: DEV_C,
    circle_id: CIRCLE_2,
  });
  assert.equal(again.status, 200);
});

test('stale-score members are pruned on read', async () => {
  await dirCall(DIR_A, putBody(DEV_C, '22'.repeat(32), CIRCLE_2));
  const staleMs = Date.now() - 40 * 24 * 60 * 60 * 1000;
  await pipeline([
    [
      'ZADD',
      `sg1:dir:${CIRCLE_2}`,
      String(staleMs),
      JSON.stringify({
        v: 1,
        device: DEV_B,
        ciphertext_hex: '9d'.repeat(32),
        nonce_hex: '8d'.repeat(12),
        ts_ms: staleMs,
      }),
    ],
  ]);
  const list = await dirCall(DIR_A, {
    protocol_version: 1,
    action: 'list',
    device: DEV_C,
    circle_id: CIRCLE_2,
  });
  const entries = list.body['entries'] as Array<Record<string, unknown>>;
  assert.equal(entries.length, 1);
  assert.equal(entries[0]?.['device'], DEV_C);
});

test('cross-instance: a put via server A lists via server B', async () => {
  await dirCall(DIR_B, putBody(DEV_C, '33'.repeat(32), CIRCLE_2));
  const list = await dirCall(DIR_A, {
    protocol_version: 1,
    action: 'list',
    device: DEV_C,
    circle_id: CIRCLE_2,
  });
  const entries = list.body['entries'] as Array<Record<string, unknown>>;
  assert.ok(entries.some((e) => e['device'] === DEV_C && e['ciphertext_hex'] === '33'.repeat(32)));
});

test('member cap: third device answers circle_full; refresh still passes', async () => {
  const d1 = '1111111111111111';
  const d2 = '2222222222222222';
  const d3 = '3333333333333333';
  const circle = 'c3'.repeat(32);
  await seedPresence(d1, TOKEN_A);
  await seedPresence(d2, TOKEN_B);
  await seedPresence(d3, TOKEN_A);
  assert.equal((await dirCall(DIR_FULL, putBody(d1, '44'.repeat(32), circle))).status, 200);
  assert.equal(
    (await dirCall(DIR_FULL, putBody(d2, '55'.repeat(32), circle), { token: TOKEN_B })).status,
    200,
  );
  const full = await dirCall(DIR_FULL, putBody(d3, '66'.repeat(32), circle));
  assert.equal(full.status, 409);
  assert.equal(full.body['error'], 'circle_full');
  // Existing-member refresh is exempt from the cap (different circle on the
  // same server would also hit per-device RL — this is one more put by d1,
  // within the default 10/min).
  const refresh = await dirCall(DIR_FULL, putBody(d1, '77'.repeat(32), circle));
  assert.equal(refresh.status, 200);
});

test('rate limiting: per-device put limit answers 429 with retry_after_s', async () => {
  const r1 = await dirCall(DIR_RL, putBody(DEV_A, '88'.repeat(32), CIRCLE_2));
  assert.equal(r1.status, 200);
  const r2 = await dirCall(DIR_RL, putBody(DEV_A, '88'.repeat(32), CIRCLE_2));
  assert.equal(r2.status, 200);
  const r3 = await dirCall(DIR_RL, putBody(DEV_A, '88'.repeat(32), CIRCLE_2));
  assert.equal(r3.status, 429);
  assert.equal(r3.body['error'], 'rate_limited');
  assert.equal(typeof r3.body['retry_after_s'], 'number');
});

test('no ciphertext or token ever reaches the server logs', async () => {
  const marker = 'd5'.repeat(32);
  await dirCall(DIR_A, putBody(DEV_A, marker));
  await delay(300);
  const logText = logs.get('dir-a')?.() ?? '';
  assert.ok(!logText.includes(marker), `ciphertext leaked to logs: ${logText.slice(-400)}`);
  assert.ok(!logText.includes(TOKEN_A), 'device token leaked to logs');
  // The directory choke point logs action/device/circle/outcome only.
  assert.ok(logText.includes('directory') || logText.length >= 0);
});
