/**
 * The account/roster server: one Node `http.Server` serving `POST /api/account`
 * (plain HTTP request/response — no WebSocket transport on this surface).
 *
 * Same structure discipline as `lib/server.ts`: body cap 1 MiB (typed 413
 * JSON, drained so the client sees the reply), invalid JSON -> 400
 * `malformed`, non-POST -> 405 `method_not_allowed`, GET -> the versioned
 * info object. All authoritative state lives in the external store; this
 * instance holds nothing.
 *
 * Validation order (each stage has its own typed error, mirroring the
 * signaling envelope gate):
 *   1. body cap            -> 413 too_large
 *   2. JSON parse          -> 400 malformed
 *   3. token placement     -> 400 malformed / 401 unauthorized
 *      (Bearer header ONLY — `?token=`/`?session_token=` in the query and
 *      `session_token` in the body are rejected; QA F42b rule)
 *   4. raw protocol_version (PRESENT number != 1) -> 400 unsupported_version
 *      — checked BEFORE body validation; a missing version falls through to
 *      the schema and fails as `malformed` (what the camelcase fixture pins)
 *   5. action discriminant -> 400 unknown_action
 *   6. zod schema          -> 400 malformed
 *   7. service.call        -> rate limits, auth, business logic
 */
import http from 'node:http';
import { loadConfig, type SignalingConfig } from './config.ts';
import { UpstashRestStore } from './upstash.ts';
import { AccountService, type AccountCallResult } from './account-service.ts';
import {
  ACCOUNT_PROTOCOL_VERSION,
  KNOWN_ACCOUNT_ACTIONS,
  accountRequestSchema,
  accountStatusFor,
  type AccountRequest,
} from './account-schema.ts';
import { SERVICE_PROTOCOL_VERSION } from './frames.ts';
import { log } from './log.ts';

const HTTP_BODY_MAX = 1 << 20; // 1 MiB request bound (invariant 3)

function bearerToken(req: http.IncomingMessage): string | null {
  const h = req.headers.authorization;
  if (typeof h === 'string' && h.toLowerCase().startsWith('bearer ')) {
    return h.slice(7).trim() || null;
  }
  return null;
}

/**
 * Client IP: the LAST `x-forwarded-for` entry (the hop closest to us when
 * proxies append), else the socket's remote address (the dev server path —
 * no proxy in front). `::ffff:` IPv4-mapped prefixes are normalized away so
 * rate-limit keys agree between transports.
 */
function clientIp(req: http.IncomingMessage): string {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    const last = xff.split(',').pop()?.trim();
    if (last) return last.replace(/^::ffff:/, '');
  }
  return (req.socket.remoteAddress ?? 'unknown').replace(/^::ffff:/, '');
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
    'cache-control': 'no-store',
  });
  res.end(payload);
}

export interface AccountServer {
  server: http.Server;
  config: SignalingConfig;
  service: AccountService;
  close(): Promise<void>;
}

export function createAccountServer(cfgIn?: SignalingConfig): AccountServer {
  const config = cfgIn ?? loadConfig();
  const store = UpstashRestStore.fromEnv();
  const service = new AccountService(store, config);

  function sendResult(res: http.ServerResponse, result: AccountCallResult): void {
    if (result.ok) {
      // result.body always carries its `action` discriminant.
      sendJson(res, 200, {
        ok: true,
        protocol_version: ACCOUNT_PROTOCOL_VERSION,
        ...result.body,
      });
      return;
    }
    const body: Record<string, unknown> = {
      ok: false,
      error: result.error,
    };
    if (result.detail !== undefined) body['detail'] = result.detail;
    if (result.retry_after_s !== undefined) body['retry_after_s'] = result.retry_after_s;
    if (result.current_version !== undefined) body['current_version'] = result.current_version;
    sendJson(res, accountStatusFor(result.error), body);
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://local');
    if (req.method === 'GET') {
      sendJson(res, 200, {
        ok: true,
        service: 'account',
        protocol_version: ACCOUNT_PROTOCOL_VERSION,
        svc_version: SERVICE_PROTOCOL_VERSION,
      });
      return;
    }
    if (req.method !== 'POST') {
      sendJson(res, 405, { ok: false, error: 'method_not_allowed' });
      return;
    }

    // Header-only auth discipline (QA F42b rule): tokens in the query string
    // leak into intermediary logs; tokens in the body defeat the auth model.
    if (url.searchParams.has('token') || url.searchParams.has('session_token')) {
      sendJson(res, 401, {
        ok: false,
        error: 'unauthorized',
        detail: 'session_token must be the Authorization: Bearer header',
      });
      return;
    }

    const body = await readBody(req);
    if (body === null) {
      // Oversize body: typed 413 JSON, then bounded drain (same reasoning as
      // lib/server.ts — destroying immediately races the unfinished upload).
      sendJson(res, 413, {
        ok: false,
        error: 'too_large',
        detail: `body exceeds ${HTTP_BODY_MAX} bytes`,
      });
      let drained = 0;
      req.on('data', (chunk: Buffer) => {
        drained += chunk.length;
        if (drained > HTTP_BODY_MAX * 8) {
          req.destroy();
        }
      });
      req.resume();
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      sendJson(res, 400, { ok: false, error: 'malformed' });
      return;
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      sendJson(res, 400, { ok: false, error: 'malformed' });
      return;
    }
    const raw = parsed as Record<string, unknown>;
    if ('session_token' in raw) {
      sendJson(res, 400, {
        ok: false,
        error: 'malformed',
        detail: 'session_token must be the Authorization: Bearer header',
      });
      return;
    }

    // Version gate on the RAW value before any body validation (the signaling
    // envelope rule): a present numeric protocol_version != 1 is the typed
    // version error. A MISSING version is left to the schema (-> malformed),
    // which is what the camelcase reject fixture pins.
    if (typeof raw['protocol_version'] === 'number' && raw['protocol_version'] !== ACCOUNT_PROTOCOL_VERSION) {
      sendJson(res, 400, {
        ok: false,
        error: 'unsupported_version',
        detail: `unsupported protocol_version ${raw['protocol_version']} (service speaks ${ACCOUNT_PROTOCOL_VERSION})`,
      });
      return;
    }

    const action = raw['action'];
    if (typeof action !== 'string') {
      sendJson(res, 400, { ok: false, error: 'malformed', detail: 'action discriminant required' });
      return;
    }
    if (!(KNOWN_ACCOUNT_ACTIONS as readonly string[]).includes(action)) {
      sendJson(res, 400, { ok: false, error: 'unknown_action', detail: `unknown action ${action}` });
      return;
    }

    const check = accountRequestSchema.safeParse(raw);
    if (!check.success) {
      const first = check.error.issues[0];
      const where = first ? `${first.path.join('.')}` : 'unknown';
      sendJson(res, 400, { ok: false, error: 'malformed', detail: `validation failed at ${where}` });
      return;
    }
    const request = check.data as AccountRequest;

    const result = await service.call(request, { ip: clientIp(req), token: bearerToken(req) });
    sendResult(res, result);
  }

  function readBody(req: http.IncomingMessage): Promise<string | null> {
    return new Promise((resolve) => {
      let size = 0;
      let over = false;
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => {
        if (over) return;
        size += chunk.length;
        if (size > HTTP_BODY_MAX) {
          over = true;
          // Stop consuming; the caller writes the 413 and destroys after.
          req.pause();
          resolve(null);
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => {
        if (!over) resolve(Buffer.concat(chunks).toString('utf8'));
      });
      req.on('error', () => resolve(null));
      // If the socket dies mid-read, still unblock the caller.
      req.on('close', () => resolve(null));
    });
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      log.error('account_http_failed', { err: String(err).slice(0, 120) }, 'account');
      if (!res.headersSent) {
        sendJson(res, 500, { ok: false, error: 'internal' });
      } else {
        res.end();
      }
    });
  });

  return {
    server,
    config,
    service,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  };
}
