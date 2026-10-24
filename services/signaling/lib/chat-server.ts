/**
 * The machine-chat inbox endpoint (Vercel function, Node runtime; ADR-005
 * RD-022). Sealed envelopes only — see lib/chat-schema.ts.
 *
 *   PUT /api/chat            Bearer <device_token>  body { to, envelope }
 *   GET  /api/chat?device=…  Bearer <device_token>  (destructive drain)
 *
 * Same discipline as lib/account-server.ts: body cap 1 MiB, Bearer-header
 * auth only, typed JSON errors, no authoritative memory.
 */
import http from 'node:http';
import { UpstashRestStore } from './upstash.ts';
import { ChatService } from './chat-service.ts';
import {
  CHAT_PROTOCOL_VERSION,
  chatPutRequestSchema,
} from './chat-schema.ts';

const BODY_CAP = 1 << 20;

export function createChatServer(): { server: http.Server } {
  const store = UpstashRestStore.fromEnv();
  const chat = new ChatService(store);

  const server = http.createServer((req, res) => {
    const respond = (status: number, body: unknown) => {
      const payload = JSON.stringify(body);
      res.writeHead(status, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
      });
      res.end(payload);
    };

    if (req.method === 'GET' && req.url?.startsWith('/api/chat')) {
      const device = new URL(req.url, 'http://localhost').searchParams.get('device') ?? '';
      const token = bearer(req.headers.authorization);
      if (!token) return respond(401, { ok: false, error: 'unauthorized' });
      if (!/^[0-9a-f]{16}$/.test(device)) {
        return respond(400, { ok: false, error: 'malformed' });
      }
      void chat
        .authenticate(device, token)
        .then((authed) => {
          if (!authed) return respond(401, { ok: false, error: 'unauthorized' });
          return chat.drain(device).then((result) => {
            if (!result.ok) {
              return respond(result.status, { ok: false, error: result.error });
            }
            respond(200, { ok: true, envelopes: result.envelopes ?? [] });
          });
        })
        .catch(() => respond(503, { ok: false, error: 'store_unavailable' }));
      return;
    }

    if (req.method !== 'PUT') {
      return respond(405, { ok: false, error: 'method_not_allowed' });
    }

    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > BODY_CAP) {
        chunks.length = 0;
        req.resume();
        respond(413, { ok: false, error: 'too_large' });
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        return respond(400, { ok: false, error: 'malformed' });
      }
      const token = bearer(req.headers.authorization);
      if (!token) return respond(401, { ok: false, error: 'unauthorized' });
      const versioned = parsed as { protocol_version?: number };
      if (
        versioned.protocol_version !== undefined &&
        versioned.protocol_version !== CHAT_PROTOCOL_VERSION
      ) {
        return respond(400, { ok: false, error: 'unsupported_version' });
      }
      const parsedBody = chatPutRequestSchema.safeParse({
        ...(parsed as Record<string, unknown>),
        protocol_version: CHAT_PROTOCOL_VERSION,
      });
      if (!parsedBody.success) {
        return respond(400, { ok: false, error: 'malformed' });
      }
      const { to, envelope } = parsedBody.data;
      void chat
        .authenticate(envelope.from, token)
        .then((authed) => {
          if (!authed) return respond(401, { ok: false, error: 'unauthorized' });
          return chat.put(to, envelope).then((result) => {
            if (!result.ok) {
              const extra = result.retry_after_s !== undefined
                ? { retry_after_s: result.retry_after_s }
                : {};
              return respond(result.status, { ok: false, error: result.error, ...extra });
            }
            respond(200, { ok: true });
          });
        })
        .catch(() => respond(503, { ok: false, error: 'store_unavailable' }));
    });
  });

  return { server };
}

function bearer(header: string | undefined): string | null {
  if (!header?.startsWith('Bearer ')) return null;
  const token = header.slice('Bearer '.length).trim();
  return token.length > 0 ? token : null;
}
