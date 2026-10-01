#!/usr/bin/env node
/**
 * Standalone runner for the REAL service servers (the same modules the
 * Vercel functions export), for WebSocket-path testing and local dev.
 *
 * Why: `vercel dev`'s local bridge does not forward WebSocket upgrades
 * (the @vercel/node dev handler proxies plain HTTP only), so the WS
 * contract tests and the Rust client's WS integration run against this
 * standalone instance of the exact same `lib/server.ts` code path. The
 * deployed Vercel function is `api/signal.ts`, which calls the same
 * factory. HTTP-path contract tests run against `vercel dev` proper.
 *
 * Since the accounts phase the process serves BOTH servers (each on its
 * own listener/port):
 *   - signaling: `lib/server.ts` (HTTP fallback + WS upgrade)
 *   - account:   `lib/account-server.ts` (POST /api/account)
 *
 * Usage:
 *   node tools/dev-server.mjs [--port 38013] [--account-port 39013]
 *                             [--only signal|account]
 * Account port defaults to signal port + 1000 so several instances spawned
 * side by side (contract matrix) never collide.
 * Env: same as the functions (UPSTASH_REDIS_REST_URL/TOKEN, SIGNALING_*).
 */
import { createSignalingServer } from '../lib/server.ts';
import { createAccountServer } from '../lib/account-server.ts';

const args = process.argv.slice(2);

function argValue(name, def) {
  // --name=value form first, then --name value (when the value exists and is
  // not itself a flag).
  const eq = args.find((a) => a.startsWith(`--${name}=`));
  if (eq !== undefined) return eq.slice(name.length + 3);
  const i = args.indexOf(`--${name}`);
  if (i === -1) return def;
  const v = args[i + 1];
  return v && !v.startsWith('--') ? v : def;
}

const only = argValue('only', 'both'); // 'signal' | 'account' | 'both'
const port = Number(argValue('port', process.env.PORT || 38013));
const accountPort = Number(argValue('account-port', process.env.ACCOUNT_PORT || port + 1000));

const closers = [];

if (only === 'both' || only === 'signal') {
  const signaling = createSignalingServer();
  signaling.server.listen(port, '127.0.0.1', () => {
    process.stdout.write(`signaling standalone dev server on http://127.0.0.1:${port} (ws upgrade on the same port)\n`);
  });
  closers.push(() => signaling.close());
}

if (only === 'both' || only === 'account') {
  const account = createAccountServer();
  account.server.listen(accountPort, '127.0.0.1', () => {
    process.stdout.write(`account standalone dev server on http://127.0.0.1:${accountPort} (POST /api/account)\n`);
  });
  closers.push(() => account.close());
}

function shutdown() {
  void Promise.allSettled(closers.map((close) => close())).then(() => process.exit(0));
  setTimeout(() => process.exit(0), 1000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
