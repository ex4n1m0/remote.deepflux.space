/**
 * Account & roster API contract tests (post-MVP accounts phase) — run
 * against the REAL service code: emulator + a standalone account server
 * spawned from `tools/dev-server.mjs --only account` (the same
 * `lib/account-server.ts` the Vercel function `api/account.ts` exports).
 *
 * Matrix: register/login_pre/login (real salts, existence hiding), roster
 * round-trip with optimistic concurrency, bearer discipline (header-only),
 * typed validation errors (version gate, camelCase, unknown action, hex
 * shapes, roster size cap), rate limiting with per-user key separation,
 * presence over the signaling presence keys, logout invalidation, body-cap
 * 413, and the no-secrets-in-logs policy extended to account key material.
 *
 * The server is spawned with SIGNALING_RL_LOGIN_PER_USER_15M=5 so the
 * rate-limit case needs six logins instead of twenty-one (the scrypt cost
 * constants themselves are unchanged — see lib/account-service.ts).
 *
 * Run: node --import tsx --test tests/account.test.ts  (or `pnpm test:account`)
 */
import { spawn, spawnSync } from 'node:child_process';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';

import { decoySaltHex } from '../lib/account-service.ts';

const ROOT = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const EMU = 38021;
const ACCOUNT = 'http://127.0.0.1:38020';
const STORE = { url: `http://127.0.0.1:${EMU}`, token: 'local-account-token' };

const children: Array<{ pid?: number | undefined; proc?: ReturnType<typeof spawn> | undefined }> = [];
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

async function waitUntil<T>(
  f: () => Promise<T | undefined | false>,
  timeoutMs: number,
  what: string,
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const last = await f();
    if (last) return last as T;
    await delay(150);
  }
  throw new Error(`timeout waiting for ${what}`);
}

/** Raw store command through the emulator's REST pipeline (test tooling). */
/** Raw store read through the emulator pipeline (test tooling). */
async function storeGet(key: string): Promise<string | null> {
  const r = await fetch(`${STORE.url}/pipeline`, {
    method: 'POST',
    headers: { authorization: `Bearer ${STORE.token}`, 'content-type': 'application/json' },
    body: JSON.stringify([{ command: ['GET', key] }]),
    signal: AbortSignal.timeout(4000),
  });
  assert.equal(r.status, 200, 'store read must reach the emulator');
  const j = (await r.json()) as Array<{ result: string | null }>;
  return j[0]?.result ?? null;
}

async function storeCommand(...command: string[]): Promise<void> {
  const r = await fetch(`${STORE.url}/pipeline`, {
    method: 'POST',
    headers: { authorization: `Bearer ${STORE.token}`, 'content-type': 'application/json' },
    body: JSON.stringify([{ command }]),
    signal: AbortSignal.timeout(4000),
  });
  assert.equal(r.status, 200, 'store command must reach the emulator');
}

// --- tiny account client -----------------------------------------------------

interface Reply {
  status: number;
  json: Record<string, unknown>;
}

async function call(body: unknown, opts: { token?: string; query?: string } = {}): Promise<Reply> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (opts.token !== undefined) headers['authorization'] = `Bearer ${opts.token}`;
  const r = await fetch(`${ACCOUNT}/api/account${opts.query ?? ''}`, {
    method: 'POST',
    headers,
    body: typeof body === 'string' ? body : JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  return { status: r.status, json: (await r.json().catch(() => ({}))) as Record<string, unknown> };
}

const V = 1;
// Distinctive marker values so the no-secrets-in-logs test can grep for them.
const AUTH_KEY = 'f00d'.repeat(16); // 64 hex
const AUTH_SALT = '1b'.repeat(16); // 32 hex
const WRAP_SALT = '2c'.repeat(16); // 32 hex
const WRAPPED_DEK = 'deadbeef'.repeat(12); // 96 hex (48 bytes)
const DEK_NONCE = '4e'.repeat(12); // 24 hex

const registerBody = (username: string, authKey: string = AUTH_KEY) => ({
  protocol_version: V,
  action: 'register',
  username,
  auth_key: authKey,
  auth_salt_hex: AUTH_SALT,
  wrap_salt_hex: WRAP_SALT,
  wrapped_dek_hex: WRAPPED_DEK,
  dek_nonce_hex: DEK_NONCE,
});

const runId = Date.now().toString(36);
const MAIN = `acct${runId}a`; // primary account reused across cases
const OTHER = `acct${runId}b`; // second account (rate-limit key separation)
const RL = `acct${runId}rl`; // rate-limit victim
const WP = `acct${runId}wp`; // wrong-password victim

let mainToken = '';

// ---------------------------------------------------------------------------

before(async () => {
  const storeEnv = {
    UPSTASH_REDIS_REST_URL: STORE.url,
    UPSTASH_REDIS_REST_TOKEN: STORE.token,
  };
  spawnNode([`${ROOT}tools/upstash-emulator.mjs`, '--port', String(EMU)], storeEnv, 'emulator');
  await waitUntil(async () => {
    try {
      const r = await fetch(`${STORE.url}/health`, { signal: AbortSignal.timeout(1500) });
      return r.ok;
    } catch {
      return false;
    }
  }, 8000, 'emulator');

  spawnNode(
    ['--import', 'tsx', `${ROOT}tools/dev-server.mjs`, '--only', 'account', '--account-port', '38020'],
    { ...storeEnv, SIGNALING_RL_LOGIN_PER_USER_15M: '5' },
    'account',
  );
  await waitUntil(async () => {
    try {
      const r = await fetch(`${ACCOUNT}/api/account`, { signal: AbortSignal.timeout(1500) });
      if (!r.ok) return false;
      const j = (await r.json()) as Record<string, unknown>;
      return j['service'] === 'account';
    } catch {
      return false;
    }
  }, 15_000, 'account server');
});

after(() => stopAll());

// ---------------------------------------------------------------------------
// Matrix
// ---------------------------------------------------------------------------

test('GET exposes the versioned info; other methods are 405', async () => {
  const r = await fetch(`${ACCOUNT}/api/account`);
  const j = (await r.json()) as Record<string, unknown>;
  assert.equal(j['ok'], true);
  assert.equal(j['service'], 'account');
  assert.equal(j['protocol_version'], 1);
  assert.equal(j['svc_version'], 1);
  const put = await fetch(`${ACCOUNT}/api/account`, { method: 'PUT' });
  assert.equal(put.status, 405);
  assert.equal(((await put.json()) as Record<string, unknown>)['error'], 'method_not_allowed');
});

test('register -> login_pre/login -> roster_get(v0) -> roster_put(v1) -> roster_get round-trip', async () => {
  const reg = await call(registerBody(MAIN));
  assert.equal(reg.status, 200, `register failed: ${JSON.stringify(reg.json)}`);
  assert.equal(reg.json['ok'], true);
  assert.equal(reg.json['action'], 'register');
  assert.match(String(reg.json['session_token']), /^[0-9a-f]{64}$/);
  const expiresMs = reg.json['expires_ms'];
  assert.equal(typeof expiresMs, 'number');
  assert.ok((expiresMs as number) > Date.now(), 'expires_ms in the future');
  mainToken = String(reg.json['session_token']);

  // login_pre returns the REAL salts stored at register (not decoys: they
  // equal the registered values, and decoys differ from them by design).
  const pre = await call({ protocol_version: V, action: 'login_pre', username: MAIN });
  assert.equal(pre.status, 200);
  assert.equal(pre.json['auth_salt_hex'], AUTH_SALT);
  assert.equal(pre.json['wrap_salt_hex'], WRAP_SALT);

  const login = await call({ protocol_version: V, action: 'login', username: MAIN, auth_key: AUTH_KEY });
  assert.equal(login.status, 200);
  assert.equal(login.json['action'], 'login');
  assert.match(String(login.json['session_token']), /^[0-9a-f]{64}$/);
  // Login echoes the stored wrap material so a new machine can unwrap.
  assert.equal(login.json['wrapped_dek_hex'], WRAPPED_DEK);
  assert.equal(login.json['dek_nonce_hex'], DEK_NONCE);

  // Fresh account: roster v0 + empty strings.
  const empty = await call({ protocol_version: V, action: 'roster_get' }, { token: mainToken });
  assert.equal(empty.status, 200);
  assert.equal(empty.json['version'], 0);
  assert.equal(empty.json['ciphertext_hex'], '');
  assert.equal(empty.json['nonce_hex'], '');

  // First put: base 0 -> version 1.
  const cipherHex = 'ab'.repeat(64); // 64 bytes
  const nonceHex = '6a'.repeat(12);
  const put = await call(
    { protocol_version: V, action: 'roster_put', ciphertext_hex: cipherHex, nonce_hex: nonceHex, base_version: 0 },
    { token: mainToken },
  );
  assert.equal(put.status, 200);
  assert.equal(put.json['version'], 1);

  // Round-trip: bytes identical to what was stored.
  const got = await call({ protocol_version: V, action: 'roster_get' }, { token: mainToken });
  assert.equal(got.status, 200);
  assert.equal(got.json['version'], 1);
  assert.deepEqual(
    Buffer.from(String(got.json['ciphertext_hex']), 'hex'),
    Buffer.from(cipherHex, 'hex'),
    'roster ciphertext bytes must round-trip',
  );
  assert.equal(got.json['nonce_hex'], nonceHex);
});

test('duplicate register is a 409 username_taken', async () => {
  const dup = await call(registerBody(MAIN));
  assert.equal(dup.status, 409);
  assert.equal(dup.json['error'], 'username_taken');
});

test('wrong password -> 401; unknown user leaks nothing (same error, decoy salts well-formed)', async () => {
  // Unknown username: login_pre answers deterministic 32-hex decoys.
  const ghost = `acct${runId}ghost`;
  const pre1 = await call({ protocol_version: V, action: 'login_pre', username: ghost });
  assert.equal(pre1.status, 200);
  assert.match(String(pre1.json['auth_salt_hex']), /^[0-9a-f]{32}$/);
  assert.match(String(pre1.json['wrap_salt_hex']), /^[0-9a-f]{32}$/);
  const pre2 = await call({ protocol_version: V, action: 'login_pre', username: ghost });
  assert.equal(pre1.json['auth_salt_hex'], pre2.json['auth_salt_hex'], 'decoys must be deterministic');
  assert.equal(pre1.json['wrap_salt_hex'], pre2.json['wrap_salt_hex']);
  assert.notEqual(pre1.json['auth_salt_hex'], pre1.json['wrap_salt_hex']);
  assert.equal(pre1.json['auth_salt_hex'], decoySaltHex(ghost, 'auth'));
  // Different username -> different decoys (no shared constants).
  const pre3 = await call({ protocol_version: V, action: 'login_pre', username: `acct${runId}gh2` });
  assert.notEqual(pre1.json['auth_salt_hex'], pre3.json['auth_salt_hex']);

  // Wrong password on a REAL account vs unknown username: identical answers.
  await call(registerBody(WP));
  const wrong = await call({ protocol_version: V, action: 'login', username: WP, auth_key: '99'.repeat(32) });
  const unknown = await call({ protocol_version: V, action: 'login', username: ghost, auth_key: '99'.repeat(32) });
  assert.equal(wrong.status, 401);
  assert.equal(unknown.status, 401);
  assert.deepEqual(wrong.json, unknown.json, 'login must not disclose username existence');
});

test('bearer discipline: roster_get without/bad token is 401; token belongs in the header only', async () => {
  const none = await call({ protocol_version: V, action: 'roster_get' });
  assert.equal(none.status, 401);
  assert.equal(none.json['error'], 'unauthorized');
  const bad = await call({ protocol_version: V, action: 'roster_get' }, { token: 'ff'.repeat(32) });
  assert.equal(bad.status, 401);
  assert.equal(bad.json['error'], 'unauthorized');
  const garbage = await call({ protocol_version: V, action: 'roster_get' }, { token: 'not-a-token' });
  assert.equal(garbage.status, 401);
  // QA F42b rule: token in the query string or body is refused outright.
  const inQuery = await call(
    { protocol_version: V, action: 'roster_get' },
    { query: `?token=${mainToken}` },
  );
  assert.equal(inQuery.status, 401);
  const inBody = await call({ protocol_version: V, action: 'roster_get', session_token: mainToken });
  assert.equal(inBody.status, 400);
  assert.equal(inBody.json['error'], 'malformed');
});

test('roster_put stale base_version -> 409 roster_conflict + current_version; retry succeeds', async () => {
  const stale = await call(
    { protocol_version: V, action: 'roster_put', ciphertext_hex: 'cd'.repeat(16), nonce_hex: '07'.repeat(12), base_version: 0 },
    { token: mainToken },
  );
  assert.equal(stale.status, 409);
  assert.equal(stale.json['error'], 'roster_conflict');
  assert.equal(stale.json['current_version'], 1, 'conflict reports the current version');
  const retry = await call(
    {
      protocol_version: V,
      action: 'roster_put',
      ciphertext_hex: 'cd'.repeat(16),
      nonce_hex: '07'.repeat(12),
      base_version: stale.json['current_version'],
    },
    { token: mainToken },
  );
  assert.equal(retry.status, 200);
  assert.equal(retry.json['version'], 2);
});

test('oversize ciphertext -> 413 roster_too_large; malformed hex -> 400 malformed', async () => {
  const big = await call(
    {
      protocol_version: V,
      action: 'roster_put',
      ciphertext_hex: 'ee'.repeat(65_537), // 65537 decoded bytes > 65536 cap
      nonce_hex: '07'.repeat(12),
      base_version: 2,
    },
    { token: mainToken },
  );
  assert.equal(big.status, 413);
  assert.equal(big.json['error'], 'roster_too_large');
  const oddHex = await call(
    { protocol_version: V, action: 'roster_put', ciphertext_hex: 'abc', nonce_hex: '07'.repeat(12), base_version: 2 },
    { token: mainToken },
  );
  assert.equal(oddHex.status, 400);
  assert.equal(oddHex.json['error'], 'malformed');
  const upperHex = await call(
    { protocol_version: V, action: 'roster_put', ciphertext_hex: 'AB'.repeat(8), nonce_hex: '07'.repeat(12), base_version: 2 },
    { token: mainToken },
  );
  assert.equal(upperHex.status, 400, 'uppercase hex is malformed (normalize client-side)');
});

test('protocol_version 0 -> 400 unsupported_version even with a valid body; camelCase -> malformed', async () => {
  const v0 = await call({ ...registerBody(`acct${runId}v0`), protocol_version: 0 });
  assert.equal(v0.status, 400);
  assert.equal(v0.json['error'], 'unsupported_version');
  const camel = await call({ action: 'login_pre', protocolVersion: 1, username: MAIN });
  assert.equal(camel.status, 400);
  assert.equal(camel.json['error'], 'malformed');
  const unknownAction = await call({ protocol_version: V, action: 'delete_everything', username: MAIN });
  assert.equal(unknownAction.status, 400);
  assert.equal(unknownAction.json['error'], 'unknown_action');
  const badUser = await call({ protocol_version: V, action: 'login_pre', username: 'Bad User!' });
  assert.equal(badUser.status, 400);
  assert.equal(badUser.json['error'], 'malformed');
  const brokenJson = await call('{"action":');
  assert.equal(brokenJson.status, 400);
  assert.equal(brokenJson.json['error'], 'malformed');
});

test('rate limiting: per-username login 429 with retry_after_s; other users unaffected', async () => {
  await call(registerBody(RL));
  const wrong = { protocol_version: V, action: 'login', username: RL, auth_key: '77'.repeat(32) };
  // Spawned server runs SIGNALING_RL_LOGIN_PER_USER_15M=5 (see header).
  for (let i = 0; i < 5; i++) {
    const r = await call(wrong);
    assert.equal(r.status, 401, `attempt ${i + 1} should still be invalid_credentials`);
  }
  const limited = await call(wrong);
  assert.equal(limited.status, 429);
  assert.equal(limited.json['error'], 'rate_limited');
  const retry = limited.json['retry_after_s'];
  assert.equal(typeof retry, 'number');
  assert.ok((retry as number) >= 1 && (retry as number) <= 900, `retry_after_s in 1..900, got ${String(retry)}`);
  const stillLimited = await call(wrong);
  assert.equal(stillLimited.status, 429);
  // Keys do not collide across users: a DIFFERENT user logs in fine...
  await call(registerBody(OTHER));
  const okLogin = await call({ protocol_version: V, action: 'login', username: OTHER, auth_key: AUTH_KEY });
  assert.equal(okLogin.status, 200, 'other user must not inherit the limited bucket');
  // ...and the limited user's OTHER buckets (login_pre) still work.
  const preStillOk = await call({ protocol_version: V, action: 'login_pre', username: RL });
  assert.equal(preStillOk.status, 200);
});

test('presence: online iff the signaling presence key exists; caps enforced', async () => {
  const onlineCode = '0123456789abcdef';
  const absentCode = 'fedcba9876543210';
  // Write presence exactly the way the signaling service does (through the
  // store seam): {prefix}p:{device} with a short TTL.
  await storeCommand('SET', `sg1:p:${onlineCode}`, JSON.stringify({ v: 1, th: 'x' }), 'EX', '60');
  const r = await call(
    { protocol_version: V, action: 'presence', codes: [onlineCode, absentCode] },
    { token: mainToken },
  );
  assert.equal(r.status, 200);
  assert.deepEqual(r.json['online'], [onlineCode], 'only the live presence code is online');
  // Empty after the presence key expires.
  await storeCommand('DEL', `sg1:p:${onlineCode}`);
  const r2 = await call({ protocol_version: V, action: 'presence', codes: [onlineCode] }, { token: mainToken });
  assert.deepEqual(r2.json['online'], []);
  // > 50 codes is malformed; any bad code rejects the whole call.
  const many = Array.from({ length: 51 }, (_, i) => (i + 0x1000).toString(16).padStart(16, '0'));
  const tooMany = await call({ protocol_version: V, action: 'presence', codes: many }, { token: mainToken });
  assert.equal(tooMany.status, 400);
  assert.equal(tooMany.json['error'], 'malformed');
  const badCode = await call(
    { protocol_version: V, action: 'presence', codes: ['bad code!'] },
    { token: mainToken },
  );
  assert.equal(badCode.status, 400);
  assert.equal(badCode.json['error'], 'malformed');
});

test('logout invalidates the session token', async () => {
  const login = await call({ protocol_version: V, action: 'login', username: MAIN, auth_key: AUTH_KEY });
  assert.equal(login.status, 200);
  const token = String(login.json['session_token']);
  const out = await call({ protocol_version: V, action: 'logout' }, { token });
  assert.equal(out.status, 200);
  assert.deepEqual(out.json['action'], 'logout');
  const after = await call({ protocol_version: V, action: 'roster_get' }, { token });
  assert.equal(after.status, 401, 'token must be dead after logout');
});

test('oversize HTTP body gets the typed 413 too_large reply', async () => {
  const big = JSON.stringify({
    protocol_version: V,
    action: 'roster_put',
    ciphertext_hex: 'ff'.repeat(600_000), // ~1.2 MiB of hex > 1 MiB body cap
    nonce_hex: '07'.repeat(12),
    base_version: 2,
  });
  assert.ok(Buffer.byteLength(big) > 1 << 20);
  const r = await fetch(`${ACCOUNT}/api/account`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${mainToken}` },
    body: big,
  }).catch((e: Error) => {
    assert.fail(`connection reset instead of a typed 413: ${e.message}`);
  });
  assert.equal(r.status, 413);
  const j = (await r.json()) as Record<string, unknown>;
  assert.equal(j['error'], 'too_large');
});

test('no account key material in service logs', async () => {
  await delay(300);
  const dump = [...logs.values()].map((f) => f()).join('\n');
  const secrets = [
    AUTH_KEY, // auth_key (password equivalent)
    AUTH_SALT, // KDF salts
    WRAP_SALT,
    WRAPPED_DEK, // wrapped DEK
    DEK_NONCE,
    'ab'.repeat(64), // roster ciphertext
    'cd'.repeat(16),
    mainToken, // session tokens
  ];
  for (const s of secrets) {
    assert.ok(!dump.includes(s), `key material leaked to logs: ${s.slice(0, 8)}...`);
  }
  assert.ok(!dump.includes(STORE.token), 'store token leaked to logs');
});

test('rate-limit self-heal: a counter that lost its window metadata is re-armed, not permanent', async () => {
  // Simulate the crash window between INCR and EXPIRE (security review P2-3):
  // the counter is above the limit but has NO TTL and NO window-start key.
  const user = `acct${runId}heal`;
  await storeCommand('SET', `sg1:rl:login-user:${user}`, '99');
  const before = await storeGet(`sg1:rlt:login-user:${user}`);
  assert.equal(before, null, 'precondition: no window-start key');

  const r = await call({ protocol_version: V, action: 'login', username: user, auth_key: AUTH_KEY });
  assert.equal(r.status, 429);
  assert.equal(r.json['error'], 'rate_limited');
  assert.ok(typeof r.json['retry_after_s'] === 'number');

  // Self-heal: the limiter re-created the window metadata and re-armed the
  // counter TTL, so this bucket expires instead of 429ing forever.
  const start = await storeGet(`sg1:rlt:login-user:${user}`);
  assert.notEqual(start, null, 'window-start key must be re-created on the self-heal path');

  await storeCommand('DEL', `sg1:rl:login-user:${user}`, `sg1:rlt:login-user:${user}`);
});

test('global register ceiling: all-IP counter trips before per-IP would', async () => {
  // Security review P2-5: rotating IPs defeat per-IP caps; the global
  // bucket bounds 10-year account-record minting regardless of source.
  const victim = `acct${runId}g9`;
  await storeCommand('SET', 'sg1:rl:reg-global:all', '501'); // over the default 500/day
  try {
    const r = await call(registerBody(victim));
    assert.equal(r.status, 429);
    assert.equal(r.json['error'], 'rate_limited');
    assert.ok(!('detail' in r.json));
  } finally {
    await storeCommand('DEL', 'sg1:rl:reg-global:all', 'sg1:rlt:reg-global:all');
  }
  // Cleanup proven: the next register attempt is not globally limited.
  const ok = await call(registerBody(victim));
  assert.notEqual(ok.json['error'], 'rate_limited');
  assert.equal(ok.status, 200);
});
