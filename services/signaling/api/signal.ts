/**
 * The signaling endpoint (Vercel function, Node runtime).
 *
 * Serves the HTTP fallback ops and the WebSocket transport on one path
 * (`/api/signal`). All authoritative state lives in the external store
 * (Upstash Redis REST); this instance holds only sockets and timers.
 */
import { createSignalingServer } from '../lib/server.ts';

const signaling = createSignalingServer();

// The Vercel runtime bridges an exported http.Server directly (WS +
// HTTP fallback on one path). Do NOT call `listen()` here: with no
// arguments it binds a random port and keeps the worker alive, which
// surfaces in production as INTERNAL_FUNCTION_INVOCATION_FAILED (first
// deploy, 2026-10-01). `vercel dev` and the standalone dev server wrap
// this same export without it.
export default signaling.server;
