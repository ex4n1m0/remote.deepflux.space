#!/usr/bin/env node
/**
 * Local Upstash Redis REST emulator (M3 local-dev store).
 *
 * Why this exists: this machine has no Docker, WSL, redis-server, or
 * Memurai, and Upstash's managed REST API cannot be pointed at a local
 * Redis binary. Instead of a second (RESP-based) driver that would only
 * run locally, the service speaks ONE protocol — the documented Upstash
 * REST pipeline format — and this emulator implements exactly that subset
 * out-of-process, with real TTLs:
 *
 *   POST /pipeline
 *   Authorization: Bearer <any non-empty>
 *   [["SET","key","value","EX","30"], ...]
 *   -> [{"result":"OK"}] | [{"error":"ERR ..."}]
 *
 * Running it as a separate process is the point: `vercel dev` function
 * instances come and go, but the store (like production Upstash) survives
 * them, which is what the cross-instance and resume contract tests prove.
 *
 * Supported commands (the service's full usage):
 *   SET key val [EX s] [NX]   GET   DEL k...   EXISTS   EXPIRE key s
 *   INCR   ZADD key score member
 *   ZRANGE key start stop                     (numeric indexes, ascending)
 *   ZRANGEBYSCORE key (min +INF LIMIT o n     (exclusive-min form)
 *   ZREMRANGEBYSCORE key -INF max
 *   ZREMRANGEBYRANK key start stop
 *   ZREM key member...
 *
 * Usage: node tools/upstash-emulator.mjs [--port 38001] [--ttl-sweep-ms 250]
 * Exit: SIGINT/SIGTERM shut down cleanly. Nothing is persisted — it is an
 * EPHEMERAL store, matching production semantics.
 */
import http from 'node:http';

const args = process.argv.slice(2);
function arg(name, def) {
  const i = args.indexOf(`--${name}`);
  if (i === -1) return def;
  const v = args[i + 1];
  return v && !v.startsWith('--') ? Number(v) : def;
}
const PORT = arg('port', Number(process.env.EMULATOR_PORT || 38001));
const SWEEP_MS = arg('ttl-sweep-ms', 250);
const BODY_MAX = 4 << 20; // 4 MiB pipeline bound

const strings = new Map(); // key -> { value, expiresAt }
const zsets = new Map(); // key -> { map: Map<member, score>, expiresAt }

const nowMs = () => Date.now();

function getAlive(map, key) {
  const e = map.get(key);
  if (e === undefined) return null;
  if (e.expiresAt !== 0 && e.expiresAt <= nowMs()) {
    map.delete(key);
    return null;
  }
  return e;
}

function ttlArg(tokens) {
  let ex = 0;
  let nx = false;
  let i = 0;
  for (;;) {
    const t = tokens[i];
    if (t === 'EX') {
      ex = Number(tokens[i + 1]);
      i += 2;
    } else if (t === 'NX') {
      nx = true;
      i += 1;
    } else {
      break;
    }
  }
  return { ex, nx };
}

function zsetSorted(key) {
  const e = getAlive(zsets, key);
  if (!e) return [];
  return [...e.map.entries()]
    .sort((a, b) => a[1] - b[1] || (a[0] < b[0] ? -1 : 1))
    .map(([member, score]) => ({ member, score }));
}

function run(command) {
  const [cmd, ...rest] = command;
  switch (cmd) {
    case 'PING':
      return 'PONG';
    case 'SET': {
      const [key, value, ...tokens] = rest;
      const { ex, nx } = ttlArg(tokens);
      const existing = getAlive(strings, key);
      if (nx && existing) return null; // NX on existing key -> null result
      const expiresAt = ex > 0 ? nowMs() + ex * 1000 : 0;
      strings.set(key, { value, expiresAt });
      return 'OK';
    }
    case 'GET': {
      const e = getAlive(strings, rest[0]);
      return e ? e.value : null;
    }
    case 'DEL': {
      let n = 0;
      for (const k of rest) {
        if (strings.delete(k)) n++;
        if (zsets.delete(k)) n++;
      }
      return n;
    }
    case 'EXISTS': {
      let n = 0;
      for (const k of rest) {
        if (getAlive(strings, k)) n++;
        else if (getAlive(zsets, k)) n++;
      }
      return n;
    }
    case 'EXPIRE': {
      const [key, s] = rest;
      const e = getAlive(strings, key) ?? getAlive(zsets, key);
      if (!e) return 0;
      e.expiresAt = nowMs() + Number(s) * 1000;
      return 1;
    }
    case 'INCR': {
      const key = rest[0];
      const e = getAlive(strings, key);
      const cur = e && Number(e.value) ? Number(e.value) : 0;
      const next = cur + 1;
      strings.set(key, {
        value: String(next),
        expiresAt: e && e.expiresAt ? e.expiresAt : 0,
      });
      return next;
    }
    case 'ZADD': {
      const [key, score, member] = rest;
      let e = getAlive(zsets, key);
      if (!e) {
        e = { map: new Map(), expiresAt: 0 };
        zsets.set(key, e);
      }
      const isNew = !e.map.has(member);
      e.map.set(member, Number(score));
      return isNew ? 1 : 0;
    }
    case 'ZRANGE': {
      const [key, startS, stopS] = rest;
      const items = zsetSorted(key);
      const n = items.length;
      let start = Number(startS);
      let stop = Number(stopS);
      if (start < 0) start = Math.max(0, n + start);
      if (stop < 0) stop = n + stop;
      const out = [];
      for (let i = Math.max(0, start); i <= Math.min(stop, n - 1); i++) out.push(items[i].member);
      return out;
    }
    case 'ZRANGEBYSCORE': {
      const [key, minS, maxS, ...tokens] = rest;
      const items = zsetSorted(key);
      const exclusiveMin = minS.startsWith('(');
      const min = exclusiveMin ? Number(minS.slice(1)) : Number(minS);
      const max = maxS === '+INF' ? Number.POSITIVE_INFINITY : Number(maxS);
      const filtered = items.filter(({ score }) =>
        exclusiveMin ? score > min : score >= min && score <= max,
      );
      let offset = 0;
      let count = filtered.length;
      const li = tokens.indexOf('LIMIT');
      if (li !== -1) {
        offset = Number(tokens[li + 1]);
        count = Number(tokens[li + 2]);
      }
      return filtered.slice(offset, offset + count).map((x) => x.member);
    }
    case 'ZREMRANGEBYSCORE': {
      const [key, minS, maxS] = rest;
      const e = getAlive(zsets, key);
      if (!e) return 0;
      const min = minS === '-INF' ? Number.NEGATIVE_INFINITY : Number(minS);
      const max = maxS === '+INF' ? Number.POSITIVE_INFINITY : Number(maxS);
      let n = 0;
      for (const [member, score] of e.map) {
        if (score >= min && score <= max) {
          e.map.delete(member);
          n++;
        }
      }
      return n;
    }
    case 'ZREMRANGEBYRANK': {
      const [key, startS, stopS] = rest;
      const e = getAlive(zsets, key);
      if (!e) return 0;
      const items = zsetSorted(key);
      const n = items.length;
      let start = Number(startS);
      let stop = Number(stopS);
      if (start < 0) start = n + start;
      if (stop < 0) stop = n + stop;
      let removed = 0;
      for (let i = Math.max(0, start); i >= 0 && i <= Math.min(stop, n - 1); i++) {
        if (e.map.delete(items[i].member)) removed++;
      }
      return removed;
    }
    case 'ZREM': {
      const [key, ...members] = rest;
      const e = getAlive(zsets, key);
      if (!e) return 0;
      let n = 0;
      for (const m of members) if (e.map.delete(m)) n++;
      return n;
    }
    case 'DBSIZE':
      return strings.size + zsets.size;
    default:
      throw new Error(`unknown command '${cmd}'`);
  }
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url === '/health')) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({ ok: true, emulator: 'upstash-rest', keys: strings.size + zsets.size }),
    );
    return;
  }
  if (req.method !== 'POST' || !req.url.startsWith('/pipeline')) {
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
    return;
  }
  const auth = req.headers.authorization || '';
  if (!auth.toLowerCase().startsWith('bearer ') || auth.slice(7).trim().length === 0) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'unauthorized' }));
    return;
  }
  let body = '';
  req.on('data', (c) => {
    body += c;
    if (body.length > BODY_MAX) req.destroy();
  });
  req.on('end', () => {
    try {
      const parsed = JSON.parse(body);
      if (!Array.isArray(parsed)) throw new Error('pipeline body must be an array');
      const out = parsed.map((command) => {
        // Production-faithful shape (verified on real Upstash,
        // 2026-10-01): every entry is itself a command array. The old
        // [{command:[...]}] object shape is REJECTED here on purpose —
        // the emulator must not accept what production refuses.
        const ok = Array.isArray(command) && command.every((c) => typeof c === 'string');
        if (!ok) return { error: 'ERR each pipeline entry must be a command array' };
        try {
          return { result: run(command) };
        } catch (err) {
          return { error: `ERR ${String(err && err.message ? err.message : err)}` };
        }
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(out));
    } catch (err) {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: `bad pipeline body: ${String(err).slice(0, 80)}` }));
    }
  });
});

const sweeper = setInterval(() => {
  const now = nowMs();
  for (const [k, e] of strings) if (e.expiresAt !== 0 && e.expiresAt <= now) strings.delete(k);
  for (const [k, e] of zsets) if (e.expiresAt !== 0 && e.expiresAt <= now) zsets.delete(k);
}, SWEEP_MS);

server.listen(PORT, '127.0.0.1', () => {
  process.stdout.write(`upstash-rest emulator listening on http://127.0.0.1:${PORT}\n`);
});

function shutdown() {
  clearInterval(sweeper);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 500).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
