/**
 * The signaling endpoint (Vercel function, Node runtime).
 *
 * Serves the HTTP fallback ops and the WebSocket transport on one path
 * (`/api/signal`). All authoritative state lives in the external store
 * (Upstash Redis REST); this instance holds only sockets and timers.
 */
import { createSignalingServer } from '../lib/server.ts';

const signaling = createSignalingServer();

// The @vercel/node dev builder and the Vercel runtime capture the exported
// server by intercepting `listen` — no real bind happens in either place.
signaling.server.listen();

export default signaling.server;
