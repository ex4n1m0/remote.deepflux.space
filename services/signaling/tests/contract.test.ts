/**
 * M3 contract tests (RD-009/RD-010 + QA F37–F45) — run against the REAL
 * service code:
 *
 *   - `pnpm test:contract` (default): emulator + 2× `vercel dev --local`
 *     (cross-instance spans the two Vercel pipelines) + standalone WS
 *     instance + short-TTL instance.
 *   - `pnpm test:contract:headless` (CONTRACT_NO_VERCEL=1): emulator +
 *     standalone instances only — no Vercel auth/toolchain needed; used by
 *     scripts/test.sh so the merge gate covers the contract matrix.
 *
 * Matrix: stale presence, duplicate delivery, reconnect/resume, timeout
 * (TTL), cross-instance, mailbox TTL expiry, session-secret single-use,
 * unauthorized/bogus-target rejection, protocol v0 rejection, WS/HTTP
 * parity, maxDuration bye, no-secrets-in-logs — plus the QA fix-package
 * cases: mailbox-era crossing (F37), ack purge (F38a), token-takeover
 * refusal (F38b/F39), oversize-body typed 413 (F42c), WS header-only auth
 * (F42b), and dedupe crash-window repair (F45).
 */
import { spawn, spawnSync } from 'node:child_process';
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import WebSocket from 'ws';

const HEADLESS = process.env.CONTRACT_NO_VERCEL === '1';
const ROOT = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const EMU = 38001;
const STANDALONE = 'http://127.0.0.1:38013';
const SHORT_TTL = 'http://127.0.0.1:38014';
const STANDALONE2 = 'http://127.0.0.1:38015';
const VDEV_A = HEADLESS ? STANDALONE : 'http://127.0.0.1:38011';
const VDEV_B = HEADLESS ? STANDALONE2 : 'http://127.0.0.1:38012';
const STORE = { url: `http://127.0.0.1:${EMU}`, token: 'local-contract-token' };

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

async function waitReady(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${url}/api/health`, { signal: AbortSignal.timeout(2000) });
      if (r.ok) return;
    } catch {
      /* not up yet */
    }
    await delay(400);
  }
  throw new Error(`service at ${url} not ready in ${timeoutMs}ms`);
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
    await delay(120);
  }
  throw new Error(`timeout waiting for ${what}`);
}

// --- tiny service client ----------------------------------------------------

const tokenOf = (d: string) => `tok-${d}`;
const hdr = (d: string, token?: string) => ({
  'content-type': 'application/json',
  authorization: `Bearer ${token ?? tokenOf(d)}`,
});

async function send(base: string, device: string, envelope: object, token?: string) {
  const r = await fetch(`${base}/api/signal?device_id=${device}`, {
    method: 'POST',
    headers: hdr(device, token),
    body: JSON.stringify({ op: 'send', envelope }),
    signal: AbortSignal.timeout(8000),
  });
  return { status: r.status, json: (await r.json()) as Record<string, unknown> };
}

async function poll(base: string, device: string, after = 0, max = 64, token?: string) {
  const r = await fetch(`${base}/api/signal?device_id=${device}`, {
    method: 'POST',
    headers: hdr(device, token),
    body: JSON.stringify({ op: 'poll', device_id: device, after_seq: after, max }),
    signal: AbortSignal.timeout(8000),
  });
  return { status: r.status, json: (await r.json()) as Record<string, unknown> };
}

async function ack(base: string, device: string, seq: number) {
  const r = await fetch(`${base}/api/signal?device_id=${device}`, {
    method: 'POST',
    headers: hdr(device),
    body: JSON.stringify({ op: 'ack', device_id: device, seq }),
    signal: AbortSignal.timeout(8000),
  });
  return r.status;
}

/** Raw store command through the emulator's REST pipeline (test tooling). */
async function storeCommand(...command: string[]): Promise<void> {
  const r = await fetch(`${STORE.url}/pipeline`, {
    method: 'POST',
    headers: { authorization: `Bearer ${STORE.token}`, 'content-type': 'application/json' },
    body: JSON.stringify([{ command }]),
    signal: AbortSignal.timeout(4000),
  });
  assert.equal(r.status, 200, 'store command must reach the emulator');
}

const CAPS = { encoders: [], monitors: [], max_bitrate_kbps: 1000, features: 0 };
const MID = (() => {
  let n = 0;
  return () => `ct-${++n}`;
})();

function envelope(from: string, to: string, id: string, extra: object, session: string | null = null) {
  return {
    protocol_version: 1,
    message_id: id,
    session_id: session,
    from_device_id: from,
    to_device_id: to,
    timestamp_ms: 1,
    ...extra,
  };
}

const registerEnvelope = (from: string) =>
  envelope(from, 'signaling', MID(), { type: 'register', capabilities: CAPS });
const heartbeatEnvelope = (from: string) =>
  envelope(from, 'signaling', MID(), { type: 'heartbeat' });

async function register(base: string, device: string, token?: string) {
  const { status, json } = await send(base, device, registerEnvelope(device), token);
  assert.equal(status, 200, `register ${device} on ${base}`);
  assert.equal(json.ok, true);
}

// --- WS client wrapper (header auth only — F42b) ------------------------------

interface WsSession {
  frames: Array<Record<string, unknown>>;
  next(op: string, timeoutMs?: number): Promise<Record<string, unknown>>;
  send(obj: unknown): void;
  ack(seq: number): void;
  close(): void;
  closed: Promise<void>;
}

function wsConnect(
  base: string,
  device: string,
  resume = 0,
  opts: { token?: string; tokenInQuery?: boolean } = {},
): Promise<WsSession> {
  const token = opts.token ?? tokenOf(device);
  const url = `${base.replace('http', 'ws')}/api/signal?device_id=${device}${
    opts.tokenInQuery ? `&token=${token}` : ''
  }`;
  const ws = new WebSocket(url, {
    headers: opts.tokenInQuery ? {} : { authorization: `Bearer ${token}` },
  });
  const frames: Array<Record<string, unknown>> = [];
  const waiters: Array<{ op: string; resolve: (f: Record<string, unknown>) => void }> = [];
  let closedResolve: () => void;
  const closed = new Promise<void>((r) => (closedResolve = r));
  const session: WsSession = {
    frames,
    next: (op: string, timeoutMs = 5000) =>
      new Promise((resolve, reject) => {
        const existing = frames.find((f) => f.op === op);
        if (existing) {
          frames.splice(frames.indexOf(existing), 1);
          return resolve(existing);
        }
        const timer = setTimeout(
          () =>
            reject(
              new Error(`ws frame ${op} timeout; have ${frames.map((f) => f.op).join(',')}`),
            ),
          timeoutMs,
        );
        waiters.push({
          op,
          resolve: (f) => {
            clearTimeout(timer);
            resolve(f);
          },
        });
      }),
    send: (obj) => ws.send(JSON.stringify(obj)),
    ack: (seq: number) => ws.send(JSON.stringify({ op: 'ack', seq })),
    close: () => ws.close(),
    closed: closed as Promise<void>,
  };
  ws.on('message', (m: unknown) => {
    const f = JSON.parse(String(m)) as Record<string, unknown>;
    const w = waiters.findIndex((x) => x.op === f.op);
    if (w !== -1) waiters.splice(w, 1)[0]!.resolve(f);
    else frames.push(f);
  });
  ws.on('close', () => closedResolve());
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('ws connect timeout')), 6000);
    ws.on('open', () => {
      clearTimeout(t);
      ws.send(JSON.stringify({ op: 'hello', device_id: device, resume_seq: resume, svc_version: 1 }));
      resolve(session);
    });
    ws.on('error', (e: Error) => {
      clearTimeout(t);
      reject(e);
    });
  });
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

before(async () => {
  const storeEnv = {
    UPSTASH_REDIS_REST_URL: STORE.url,
    UPSTASH_REDIS_REST_TOKEN: STORE.token,
  };
  spawnNode([`${ROOT}tools/upstash-emulator.mjs`, '--port', String(EMU)], storeEnv, 'emulator');
  await waitUntil(async () => {
    try {
      const r = await fetch(`${STORE.url}/health`);
      return r.ok;
    } catch {
      return false;
    }
  }, 8000, 'emulator');

  const normal = {
    ...storeEnv,
    SIGNALING_TTL_DEVICE_SECONDS: '45',
    SIGNALING_TTL_MAILBOX_SECONDS: '180',
    SIGNALING_TTL_SESSION_SECONDS: '480',
    SIGNALING_TTL_DEDUPE_SECONDS: '120',
    SIGNALING_WS_POLL_MS: '100',
  };
  const short = {
    ...storeEnv,
    SIGNALING_TTL_DEVICE_SECONDS: '1',
    SIGNALING_TTL_MAILBOX_SECONDS: '2',
    SIGNALING_TTL_SESSION_SECONDS: '1',
    SIGNALING_TTL_DEDUPE_SECONDS: '1',
    SIGNALING_WS_POLL_MS: '80',
    SIGNALING_MAX_CONNECTION_SECONDS: '3',
  };

  const jobs: Array<Promise<void>> = [
    waitReady(STANDALONE, 20_000),
    waitReady(SHORT_TTL, 20_000),
    waitReady(VDEV_A, 20_000),
    waitReady(VDEV_B, 20_000),
  ];
  spawnNode(
    ['--import', 'tsx', `${ROOT}tools/dev-server.mjs`, '--port', '38013'],
    normal,
    'standalone',
  );
  spawnNode(['--import', 'tsx', `${ROOT}tools/dev-server.mjs`, '--port', '38014'], short, 'short');
  if (HEADLESS) {
    // Cross-instance spans two independent standalone processes.
    spawnNode(
      ['--import', 'tsx', `${ROOT}tools/dev-server.mjs`, '--port', '38015'],
      normal,
      'standalone2',
    );
  } else {
    // Two INDEPENDENT vercel dev servers -> cross-instance through the
    // Vercel pipeline (project-local CLI; --local, no project link).
    spawnNode(
      [`${ROOT}node_modules/vercel/dist/vc.js`, 'dev', '--local', '--listen', '127.0.0.1:38011'],
      normal,
      'vdev-a',
    );
    spawnNode(
      [`${ROOT}node_modules/vercel/dist/vc.js`, 'dev', '--local', '--listen', '127.0.0.1:38012'],
      normal,
      'vdev-b',
    );
  }
  await Promise.all([
    waitReady(STANDALONE, 20_000),
    waitReady(SHORT_TTL, 20_000),
    waitReady(VDEV_A, HEADLESS ? 20_000 : 90_000),
    waitReady(VDEV_B, HEADLESS ? 20_000 : 90_000),
  ]);
});

after(() => stopAll());

// ---------------------------------------------------------------------------
// Matrix
// ---------------------------------------------------------------------------

test('health probes expose the versioned contract', async () => {
  for (const base of [VDEV_A, VDEV_B, STANDALONE]) {
    const r = await fetch(`${base}/api/health`);
    const j = (await r.json()) as Record<string, unknown>;
    assert.equal(j.protocol_version, 1);
    assert.equal(j.svc_version, 1);
  }
});

test('register creates presence; wrong token is unauthorized (poll and rebind)', async () => {
  await register(VDEV_A, 'ct-a');
  const bad = await poll(VDEV_A, 'ct-a', 0, 10, 'wrong-token');
  assert.equal(bad.status, 401);
  // Same token: refresh ok.
  const again = await send(VDEV_A, 'ct-a', registerEnvelope('ct-a'));
  assert.equal(again.json.ok, true);
  // F39: DIFFERENT token against a live presence — register AND heartbeat
  // refusal branches.
  const regB = await send(VDEV_A, 'ct-a', registerEnvelope('ct-a'), 'attacker-token');
  assert.equal(regB.status, 401, 'register with a different token must be refused');
  assert.equal(regB.json.error, 'unauthorized');
  const hbB = await send(VDEV_A, 'ct-a', heartbeatEnvelope('ct-a'), 'attacker-token');
  assert.equal(hbB.status, 401, 'heartbeat with a different token must be refused');
  // The refusal must not have disturbed the owner.
  const owner = await send(VDEV_A, 'ct-a', heartbeatEnvelope('ct-a'));
  assert.equal(owner.json.ok, true);
});

test('peer send + HTTP poll delivery', async () => {
  await register(VDEV_A, 'ct-a');
  await register(VDEV_A, 'ct-b');
  const s = await send(VDEV_A, 'ct-a', envelope('ct-a', 'ct-b', MID(), { type: 'offer', sdp: 'v=0 ct' }, 'sess-1'));
  assert.equal(s.status, 200);
  const got = await waitUntil(async () => {
    const p = await poll(VDEV_A, 'ct-b');
    const list = (p.json.envelopes ?? []) as Array<{ seq: number; envelope: Record<string, unknown> }>;
    return list.find((e) => e.envelope.type === 'offer');
  }, 5000, 'offer delivery');
  assert.equal(got.envelope.message_id !== undefined, true);
});

test('duplicate delivery: one entry; ack purges it (F38a)', async () => {
  await register(VDEV_A, 'ct-dup-a');
  await register(VDEV_A, 'ct-dup-b');
  const env = envelope(
    'ct-dup-a',
    'ct-dup-b',
    MID(),
    { type: 'ice_candidate', candidate: 'c', sdp_mid: '0', sdp_mline_index: 0 },
    'sess-dup',
  );
  const first = await send(VDEV_A, 'ct-dup-a', env);
  const second = await send(VDEV_A, 'ct-dup-a', env);
  assert.equal(first.json.duplicate, false);
  assert.equal(second.status, 200);
  assert.equal(second.json.duplicate, true, 'service reports the dedupe hit');
  const p = await poll(VDEV_A, 'ct-dup-b', 0, 64);
  const list = (p.json.envelopes ?? []) as Array<{ seq: number; envelope: Record<string, unknown> }>;
  const ice = list.filter((e) => e.envelope.type === 'ice_candidate');
  assert.equal(ice.length, 1, 'exactly one mailbox entry for the duplicated message_id');
  const seq = ice[0]!.seq;
  // F38a: acking purges — a later poll from 0 must NOT see the entry again
  // (accepted SDP/secret material does not linger for the mailbox TTL).
  assert.equal(await ack(VDEV_A, 'ct-dup-b', seq), 200);
  const after = await poll(VDEV_A, 'ct-dup-b', 0, 64);
  const afterList = (after.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
  assert.equal(
    afterList.filter((e) => e.envelope.type === 'ice_candidate').length,
    0,
    'acked entry must be purged from the mailbox',
  );
});

test('protocol v0 is rejected with a typed error envelope', async () => {
  await register(VDEV_A, 'ct-v0');
  await register(VDEV_A, 'ct-v0-peer');
  const v0 = envelope('ct-v0', 'ct-v0-peer', MID(), { type: 'offer', sdp: 'v=0' }, 'sess-v0');
  (v0 as Record<string, unknown>).protocol_version = 0;
  const r = await send(VDEV_A, 'ct-v0', v0);
  assert.equal(r.status, 400);
  assert.equal(r.json.error, 'unsupported_version');
  const err = await waitUntil(async () => {
    const p = await poll(VDEV_A, 'ct-v0');
    const list = (p.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
    return list.find((e) => e.envelope.type === 'error');
  }, 5000, 'typed v0 error envelope');
  assert.equal(err.envelope.code, 400);
  assert.match(String(err.envelope.detail), /unsupported protocol_version 0/);
  const peer = await poll(VDEV_A, 'ct-v0-peer');
  assert.equal(((peer.json.envelopes ?? []) as unknown[]).length, 0);
});

test('bogus target and forged sender are rejected', async () => {
  await register(VDEV_A, 'ct-att');
  const bogus = await send(VDEV_A, 'ct-att', envelope('ct-att', 'no-such-device', MID(), { type: 'offer', sdp: 'x' }, 'sess-x'));
  assert.equal(bogus.status, 404);
  assert.equal(bogus.json.error, 'unknown_target');
  const err = await waitUntil(async () => {
    const p = await poll(VDEV_A, 'ct-att');
    const list = (p.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
    return list.find((e) => e.envelope.code === 404);
  }, 5000, 'unknown-target error envelope');
  assert.match(String(err.envelope.detail), /unknown target no-such-device/);

  const forged = await send(VDEV_A, 'ct-att', envelope('someone-else', 'ct-att', MID(), { type: 'offer', sdp: 'x' }, 'sess-f'));
  assert.equal(forged.status, 403);
  assert.equal(forged.json.error, 'forged_from');

  const r401 = await fetch(`${VDEV_A}/api/signal?device_id=ct-att`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer nope' },
    body: JSON.stringify({ op: 'poll', device_id: 'ct-att', after_seq: 0 }),
  });
  assert.equal(r401.status, 401);
});

test('session-scoped types require session_id', async () => {
  await register(VDEV_A, 'ct-sess');
  await register(VDEV_A, 'ct-sess-b');
  const r = await send(VDEV_A, 'ct-sess', envelope('ct-sess', 'ct-sess-b', MID(), { type: 'answer', sdp: 'x' }, null));
  assert.equal(r.status, 400);
  assert.equal(r.json.error, 'missing_session_id');
});

test('cross-instance: two independent servers route via the shared store', async () => {
  await register(VDEV_A, 'ct-x-a');
  await register(VDEV_B, 'ct-x-b');
  const toB = await send(VDEV_A, 'ct-x-a', envelope('ct-x-a', 'ct-x-b', MID(), { type: 'connect_request', capabilities: CAPS }, 'sess-x1'));
  assert.equal(toB.status, 200);
  const gotB = await waitUntil(async () => {
    const p = await poll(VDEV_B, 'ct-x-b');
    const list = (p.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
    return list.find((e) => e.envelope.type === 'connect_request');
  }, 6000, 'cross-instance A->B');
  assert.equal(gotB.envelope.from_device_id, 'ct-x-a');
  const toA = await send(VDEV_B, 'ct-x-b', envelope('ct-x-b', 'ct-x-a', MID(), { type: 'accept', session_secret: 'cross-secret' }, 'sess-x1'));
  assert.equal(toA.status, 200);
  const gotA = await waitUntil(async () => {
    const p = await poll(VDEV_A, 'ct-x-a');
    const list = (p.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
    return list.find((e) => e.envelope.type === 'accept');
  }, 6000, 'cross-instance B->A');
  assert.equal(gotA.envelope.from_device_id, 'ct-x-b');
});

test('WS: hello, register, live push, ack, resume-from-cursor', async () => {
  await register(STANDALONE, 'ct-ws-a');
  const ws = await wsConnect(STANDALONE, 'ct-ws-b');
  const hello = await ws.next('hello_ok');
  assert.equal(hello.authed, false, 'fresh device is not yet registered');
  ws.send({ op: 'send', envelope: registerEnvelope('ct-ws-b') });
  const res = await ws.next('send_result');
  assert.equal(res.ok, true);
  const s = await send(STANDALONE, 'ct-ws-a', envelope('ct-ws-a', 'ct-ws-b', MID(), { type: 'offer', sdp: 'v=0 ws' }, 'sess-ws'));
  assert.equal(s.status, 200);
  const deliver = await ws.next('deliver', 6000);
  const denv = deliver.envelope as Record<string, unknown>;
  assert.equal(denv.type, 'offer');
  const seq = deliver.seq as number;
  ws.ack(seq);
  await delay(300);
  ws.close();
  await ws.closed;
  const ws2 = await wsConnect(STANDALONE, 'ct-ws-b', 0);
  const hello2 = await ws2.next('hello_ok');
  assert.equal(hello2.resume_seq, seq, 'server resume point is the acked cursor');
  const pushed = await ws2.next('deliver', 1500).then(
    () => true,
    () => false,
  );
  assert.equal(pushed, false, 'no redelivery below the acked cursor');
  ws2.close();
});

test('WS: un-acked deliveries redeliver on reconnect (at-least-once)', async () => {
  await register(STANDALONE, 'ct-ws-c');
  await register(STANDALONE, 'ct-ws-d');
  const ws = await wsConnect(STANDALONE, 'ct-ws-d');
  await ws.next('hello_ok');
  ws.send({ op: 'send', envelope: registerEnvelope('ct-ws-d') });
  await ws.next('send_result');
  await send(STANDALONE, 'ct-ws-c', envelope('ct-ws-c', 'ct-ws-d', MID(), { type: 'cancel', reason: 'user' }, 'sess-rd'));
  const d1 = await ws.next('deliver', 6000);
  ws.close(); // NO ack
  await ws.closed;
  await delay(300);
  const ws2 = await wsConnect(STANDALONE, 'ct-ws-d', 0);
  await ws2.next('hello_ok');
  const d2 = await ws2.next('deliver', 6000);
  assert.equal(
    (d2.envelope as Record<string, unknown>).type,
    'cancel',
    'un-acked envelope redelivered after reconnect',
  );
  ws2.ack(d2.seq as number);
  ws2.close();
});

test('WS: maxDuration bye forces a clean resume (short-TTL instance)', async () => {
  await register(SHORT_TTL, 'ct-bye');
  const ws = await wsConnect(SHORT_TTL, 'ct-bye');
  await ws.next('hello_ok');
  ws.send({ op: 'send', envelope: registerEnvelope('ct-bye') });
  await ws.next('send_result');
  const bye = await ws.next('bye', 8000);
  assert.equal(bye.reason, 'max_duration');
  await ws.closed;
  const ws2 = await wsConnect(SHORT_TTL, 'ct-bye');
  const h2 = await ws2.next('hello_ok');
  assert.equal(h2.authed, false, 'short device TTL expired during the bye window');
  ws2.send({ op: 'send', envelope: registerEnvelope('ct-bye') });
  const r2 = await ws2.next('send_result');
  assert.equal(r2.ok, true, 're-register after bye works');
  ws2.close();
});

test('stale presence: expired target is a typed unknown_target', async () => {
  const a = 'ct-stale-a';
  const b = 'ct-stale-b';
  await register(SHORT_TTL, a);
  await register(SHORT_TTL, b);
  await delay(1600);
  await register(SHORT_TTL, a);
  const r = await send(SHORT_TTL, a, envelope(a, b, MID(), { type: 'offer', sdp: 'v=0 stale' }, 'sess-stale'));
  assert.equal(r.status, 404);
  assert.equal(r.json.error, 'unknown_target');
  const err = await waitUntil(async () => {
    const p = await poll(SHORT_TTL, a);
    const list = (p.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
    return list.find((e) => e.envelope.code === 404);
  }, 4000, 'stale-presence error envelope');
  assert.match(String(err.envelope.detail), /ct-stale-b/);
});

test('mailbox TTL expiry: undelivered entries vanish', async () => {
  const a = 'ct-mbttl-a';
  const b = 'ct-mbttl-b';
  await register(SHORT_TTL, a);
  await register(SHORT_TTL, b);
  const s = await send(SHORT_TTL, a, envelope(a, b, MID(), { type: 'ice_candidate', candidate: 'x', sdp_mid: '0', sdp_mline_index: 0 }, 'sess-mbttl'));
  assert.equal(s.status, 200);
  await delay(2600);
  await register(SHORT_TTL, b);
  const p = await poll(SHORT_TTL, b, 0, 64);
  const list = (p.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
  assert.equal(
    list.filter((e) => e.envelope.type === 'ice_candidate').length,
    0,
    'expired entries are not delivered',
  );
});

test('mailbox-era crossing: stale cursors must not hide new mail (F37)', async () => {
  const a = 'ct-era-a';
  const b = 'ct-era-b';
  await register(SHORT_TTL, a);
  await register(SHORT_TTL, b);
  // Era 1: one entry, seen + acked by b.
  const s1 = await send(SHORT_TTL, a, envelope(a, b, MID(), { type: 'offer', sdp: 'v=0 era1' }, 'sess-era'));
  assert.equal(s1.status, 200);
  const era1 = await waitUntil(async () => {
    const p = await poll(SHORT_TTL, b);
    const list = (p.json.envelopes ?? []) as Array<{ seq: number; envelope: Record<string, unknown> }>;
    return list.find((e) => e.envelope.type === 'offer');
  }, 4000, 'era-1 delivery');
  assert.equal(await ack(SHORT_TTL, b, era1.seq), 200);
  // Idle past the mailbox TTL: mb/mbseq/mbc expire together, seq restarts.
  await delay(2600);
  await register(SHORT_TTL, a);
  await register(SHORT_TTL, b);
  // Era 2: new mail lands at seq 1 again.
  const s2 = await send(SHORT_TTL, a, envelope(a, b, MID(), { type: 'connect_request', capabilities: CAPS }, 'sess-era2'));
  assert.equal(s2.status, 200);
  // HTTP poll with a STALE cursor (from era 1): must be clamped to 0.
  const stale = await poll(SHORT_TTL, b, 99, 64);
  const staleList = (stale.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
  assert.equal(
    staleList.filter((e) => e.envelope.type === 'connect_request').length,
    1,
    'era-2 entry delivered despite the stale cursor (F37)',
  );
  // WS reconnect with a stale resume: hello_ok must reset to 0 and deliver.
  const ws = await wsConnect(SHORT_TTL, b, 99);
  const hello = await ws.next('hello_ok');
  assert.equal(hello.resume_seq, 0, 'stale resume is reset to the current era');
  const deliver = await ws.next('deliver', 6000);
  assert.equal((deliver.envelope as Record<string, unknown>).type, 'connect_request');
  ws.ack(deliver.seq as number);
  ws.close();
});

test('token takeover after presence expiry is refused inside the tombstone window (F38b)', async () => {
  const v = 'ct-take-v';
  await register(SHORT_TTL, v, 'victim-token');
  // Presence TTL on this instance is 1 s; the previous-owner tombstone
  // lives for the mailbox TTL (2 s) after the last successful write.
  await delay(1300);
  // Attacker (different token) cannot rebind while the tombstone lives.
  const attackReg = await send(SHORT_TTL, v, registerEnvelope(v), 'attacker-token');
  assert.equal(attackReg.status, 401, 'attacker register after expiry must be refused');
  const attackHb = await send(SHORT_TTL, v, heartbeatEnvelope(v), 'attacker-token');
  assert.equal(attackHb.status, 401, 'attacker heartbeat after expiry must be refused');
  const attackPoll = await poll(SHORT_TTL, v, 0, 10, 'attacker-token');
  assert.equal(attackPoll.status, 401, 'attacker cannot read the mailbox');
  // The legitimate owner rebinds immediately (same token).
  const owner = await send(SHORT_TTL, v, heartbeatEnvelope(v), 'victim-token');
  assert.equal(owner.json.ok, true, 'owner rebind must succeed');
  // After the tombstone itself expires (2 s after the owner's last write
  // above), a new token MAY claim the id — the documented bounded window.
  await delay(2300);
  const newcomer = await send(SHORT_TTL, v, registerEnvelope(v), 'new-token');
  assert.equal(newcomer.json.ok, true, 'post-tombstone claim is allowed (documented window)');
});

test('session-secret single-use: one accept entry, duplicates suppressed', async () => {
  const c = 'ct-sec-c';
  const h = 'ct-sec-h';
  await register(VDEV_A, c);
  await register(VDEV_A, h);
  const secret = 'SECR-never-log-me-3141';
  const req = await send(VDEV_A, c, envelope(c, h, MID(), { type: 'connect_request', capabilities: CAPS }, 'sess-sec'));
  assert.equal(req.status, 200);
  const acceptEnv = envelope(h, c, 'ct-sec-h-accept-1', { type: 'accept', session_secret: secret }, 'sess-sec');
  const first = await send(VDEV_A, h, acceptEnv);
  assert.equal(first.json.duplicate, false);
  const dup = await send(VDEV_A, h, acceptEnv);
  assert.equal(dup.json.duplicate, true);
  const got = await waitUntil(async () => {
    const p = await poll(VDEV_A, c);
    const list = (p.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
    return list.find((e) => e.envelope.type === 'accept');
  }, 5000, 'accept delivery');
  assert.equal(got.envelope.session_secret, secret);
  const p = await poll(VDEV_A, c, 0, 64);
  const list = (p.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
  const accepts = list.filter((e) => e.envelope.type === 'accept');
  assert.equal(accepts.length, 1, 'exactly one accept entry ever (idempotency by messageId)');
  const d = await send(VDEV_A, c, envelope(c, h, MID(), { type: 'disconnect', reason: 'user' }, 'sess-sec'));
  assert.equal(d.status, 200);
  await waitUntil(async () => {
    const ph = await poll(VDEV_A, h);
    const hl = (ph.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
    return hl.find((e) => e.envelope.type === 'disconnect');
  }, 5000, 'disconnect propagation');
});

test('WS/HTTP parity: same semantics over the fallback transport', async () => {
  await register(STANDALONE, 'ct-par-a');
  const ws = await wsConnect(STANDALONE, 'ct-par-b');
  await ws.next('hello_ok');
  ws.send({ op: 'send', envelope: registerEnvelope('ct-par-b') });
  await ws.next('send_result');
  await send(STANDALONE, 'ct-par-a', envelope('ct-par-a', 'ct-par-b', MID(), { type: 'reject', reason: 'busy' }, 'sess-par'));
  const d = await ws.next('deliver', 6000);
  assert.equal((d.envelope as Record<string, unknown>).type, 'reject');
  ws.send({
    op: 'send',
    envelope: envelope('ct-par-b', 'ct-par-a', MID(), { type: 'ice_complete' }, 'sess-par'),
  });
  const sr = await ws.next('send_result');
  assert.equal(sr.ok, true);
  const got = await waitUntil(async () => {
    const p = await poll(STANDALONE, 'ct-par-a');
    const list = (p.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
    return list.find((e) => e.envelope.type === 'ice_complete');
  }, 5000, 'ws->http delivery');
  assert.equal(got.envelope.from_device_id, 'ct-par-b');
  ws.close();
});

test('WS auth is header-only: token in the query string is rejected (F42b)', async () => {
  await register(STANDALONE, 'ct-hdr');
  const ws = await wsConnect(STANDALONE, 'ct-hdr', 0, { tokenInQuery: true }).catch(
    () => null,
  );
  if (ws !== null) {
    // If the upgrade slipped through, the session must never reach hello_ok:
    // an error frame or close must arrive instead.
    const outcome = await Promise.race([
      ws.next('hello_ok').then((f) => f.op),
      ws.next('error').then((f) => f.op),
      ws.closed.then(() => 'closed'),
    ]).catch(() => 'closed');
    assert.notEqual(outcome, 'hello_ok', 'query-token session must be refused');
    ws.close();
  }
  // Header auth still works on the same device.
  const ok = await wsConnect(STANDALONE, 'ct-hdr');
  await ok.next('hello_ok');
  ok.close();
});

test('oversize HTTP body gets a typed 413 JSON reply, not a reset (F42c)', async () => {
  // Targeted at the standalone instance: the vercel dev bridge reports a
  // 500 when the function answers before consuming the request body (a dev
  // proxy artifact; the function itself returns the typed 413 — verified
  // directly against the same lib/server.ts here).
  await register(STANDALONE, 'ct-big');
  const big = JSON.stringify({
    op: 'send',
    envelope: envelope('ct-big', 'signaling', MID(), {
      type: 'offer',
      sdp: 'x'.repeat(2 * 1024 * 1024), // 2 MiB >> the 1 MiB body cap
    }),
  });
  const r = await fetch(`${STANDALONE}/api/signal?device_id=ct-big`, {
    method: 'POST',
    headers: hdr('ct-big'),
    body: big,
  }).catch((e: Error) => {
    // A socket reset would land here — the finding's old behavior.
    assert.fail(`connection reset instead of a typed 413: ${e.message}`);
  });
  assert.equal(r.status, 413);
  const j = (await r.json()) as Record<string, unknown>;
  assert.equal(j.error, 'too_large');
});

test('dedupe crash window: vanished entry is repaired, not swallowed (F45)', async () => {
  const a = 'ct-f45-a';
  const b = 'ct-f45-b';
  await register(STANDALONE, a);
  await register(STANDALONE, b);
  const mid = MID();
  const env = envelope(a, b, mid, { type: 'offer', sdp: 'v=0 f45' }, 'sess-f45');
  const first = await send(STANDALONE, a, env);
  assert.equal(first.json.duplicate, false);
  // Simulate the crash window: the tombstone exists (with the assigned seq)
  // but the mailbox entry is gone (here: DEL via the emulator's REST API —
  // the same primitive a crash between SETNX and ZADD would leave).
  await storeCommand('DEL', 'sg1:mb:ct-f45-b');
  // The client retries the SAME message_id: must be re-enqueued (repaired),
  // not answered duplicate:true with the message lost.
  const retry = await send(STANDALONE, a, env);
  assert.equal(retry.status, 200);
  assert.equal(retry.json.duplicate, false, 'vanished entry must be re-enqueued (F45 repair)');
  const got = await waitUntil(async () => {
    const p = await poll(STANDALONE, b);
    const list = (p.json.envelopes ?? []) as Array<{ envelope: Record<string, unknown> }>;
    return list.find((e) => e.envelope.message_id === mid);
  }, 5000, 'repaired delivery');
  assert.equal(got.envelope.message_id, mid);
});

test('no secrets or SDP material in service logs', async () => {
  await delay(300);
  const dump = [...logs.values()].map((f) => f()).join('\n');
  assert.ok(!dump.includes('SECR-never-log-me-3141'), 'session secret leaked to logs');
  assert.ok(!dump.includes('v=0 ws') && !dump.includes('v=0 ct'), 'SDP material leaked to logs');
  assert.ok(!dump.includes('local-contract-token'), 'store token leaked to logs');
});
