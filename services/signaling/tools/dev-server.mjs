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
 * Since the accounts phase the process can serve every HTTP surface (each
 * on its own listener/port):
 *   - signaling:  `lib/server.ts` (HTTP fallback + WS upgrade)      +0
 *   - account:    `lib/account-server.ts` (POST /api/account)     +1000
 *   - chat:       `lib/chat-server.ts` (PUT/GET /api/chat)       +2000
 *   - directory:  `lib/directory-server.ts` (POST /api/directory) +3000
 *
 * Usage:
 *   node tools/dev-server.mjs [--port 38013] [--account-port 39013]
 *                             [--chat-port …] [--directory-port …]
 *                             [--only signal|account|chat|directory|all]
 * Per-surface port offsets default to the signal port + the offsets above
 * so several instances spawned side by side (contract matrix) never
 * collide. `--only all` (and the legacy `--only both`) serve all four.
 * Env: same as the functions (UPSTASH_REDIS_REST_URL/TOKEN, SIGNALING_*).
 */
import { createSignalingServer } from '../lib/server.ts';
import { createAccountServer } from '../lib/account-server.ts';
import { createChatServer } from '../lib/chat-server.ts';
import { createDirectoryServer } from '../lib/directory-server.ts';

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

const only = argValue('only', 'all'); // 'signal'|'account'|'chat'|'directory'|'both'|'all'
const all = only === 'all' || only === 'both';
const port = Number(argValue('port', process.env.PORT || 38013));
const accountPort = Number(argValue('account-port', process.env.ACCOUNT_PORT || port + 1000));
const chatPort = Number(argValue('chat-port', process.env.CHAT_PORT || port + 2000));
const directoryPort = Number(argValue('directory-port', process.env.DIRECTORY_PORT || port + 3000));

const closers = [];

if (all || only === 'signal') {
  const signaling = createSignalingServer();
  signaling.server.listen(port, '127.0.0.1', () => {
    process.stdout.write(`signaling standalone dev server on http://127.0.0.1:${port} (ws upgrade on the same port)\n`);
  });
  closers.push(() => signaling.close());
}

if (all || only === 'account') {
  const account = createAccountServer();
  account.server.listen(accountPort, '127.0.0.1', () => {
    process.stdout.write(`account standalone dev server on http://127.0.0.1:${accountPort} (POST /api/account)\n`);
  });
  closers.push(() => account.close());
}

if (all || only === 'chat') {
  const chat = createChatServer();
  chat.server.listen(chatPort, '127.0.0.1', () => {
    process.stdout.write(`chat standalone dev server on http://127.0.0.1:${chatPort} (PUT/GET /api/chat)\n`);
  });
  closers.push(() => new Promise((resolve) => chat.server.close(() => resolve())));
}

if (all || only === 'directory') {
  const directory = createDirectoryServer();
  directory.server.listen(directoryPort, '127.0.0.1', () => {
    process.stdout.write(`directory standalone dev server on http://127.0.0.1:${directoryPort} (POST /api/directory)\n`);
  });
  closers.push(() => directory.close());
}

function shutdown() {
  void Promise.allSettled(closers.map((close) => close())).then(() => process.exit(0));
  setTimeout(() => process.exit(0), 1000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
