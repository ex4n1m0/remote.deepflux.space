/**
 * Cheap liveness/config probe (no store access, no auth).
 * GET /api/health
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { SIGNALING_PROTOCOL_VERSION } from '../lib/envelope.ts';
import { SERVICE_PROTOCOL_VERSION } from '../lib/frames.ts';

export default function handler(_req: IncomingMessage, res: ServerResponse): void {
  const payload = JSON.stringify({
    ok: true,
    service: 'signaling',
    protocol_version: SIGNALING_PROTOCOL_VERSION,
    svc_version: SERVICE_PROTOCOL_VERSION,
  });
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(payload);
}
