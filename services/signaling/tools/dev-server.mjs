#!/usr/bin/env node
/**
 * Standalone runner for the REAL service server (same module the Vercel
 * function exports), for WebSocket-path testing.
 *
 * Why: `vercel dev`'s local bridge does not forward WebSocket upgrades
 * (the @vercel/node dev handler proxies plain HTTP only), so the WS
 * contract tests and the Rust client's WS integration run against this
 * standalone instance of the exact same `lib/server.ts` code path. The
 * deployed Vercel function is `api/signal.ts`, which calls the same
 * factory. HTTP-path contract tests run against `vercel dev` proper.
 *
 * Usage:
 *   node tools/dev-server.mjs [--port 38013]
 * Env: same as the function (UPSTASH_REDIS_REST_URL/TOKEN, SIGNALING_*).
 */
import { createSignalingServer } from '../lib/server.ts';

const args = process.argv.slice(2);
const i = args.indexOf('--port');
const port = i !== -1 ? Number(args[i + 1]) : Number(process.env.PORT || 38013);

const signaling = createSignalingServer();
signaling.server.listen(port, '127.0.0.1', () => {
  process.stdout.write(
    `signaling standalone dev server on http://127.0.0.1:${port} (ws upgrade on the same port)\n`,
  );
});

function shutdown() {
  void signaling.close().then(() => process.exit(0));
  setTimeout(() => process.exit(0), 1000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
