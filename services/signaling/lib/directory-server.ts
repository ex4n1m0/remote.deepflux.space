/**
 * The circle-directory server: one Node `http.Server` serving
 * `POST /api/directory` (ADR-006). Plain HTTP request/response.
 *
 * Same structure and validation ladder as `lib/account-server.ts`:
 *   1. body cap            -> 413 too_large (bounded drain after)
 *   2. JSON parse          -> 400 malformed
 *   3. token placement     -> 400/401 (Bearer header ONLY — F42b rule)
 *   4. raw protocol_version (present number != 1) -> 400 unsupported_version
 *   5. action discriminant -> 400 unknown_action
 *   6. zod schema          -> 400 malformed
 *   7. service.call        -> auth (presence pair), size, rate limits, business
 *
 * Logging goes through one choke point and carries action/device/circle_id/
 * outcome only — never ciphertext, nonces, or tokens.
 */
import http from 'node:http';
import { loadConfig, type SignalingConfig } from './config.ts';
import { UpstashRestStore } from './upstash.ts';
import { DirectoryService, type DirectoryCallResult } from './directory-service.ts';
import {
  DIRECTORY_PROTOCOL_VERSION,
  KNOWN_DIRECTORY_ACTIONS,
  directoryRequestSchema,
  directoryStatusFor,
  type DirectoryRequest,
} from './directory-schema.ts';
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

/** Last XFF hop (closest to us), else socket address — the account rule. */
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

export interface DirectoryServer {
  server: http.Server;
  config: SignalingConfig;
  service: DirectoryService;
  close(): Promise<void>;
}

export function createDirectoryServer(cfgIn?: SignalingConfig): DirectoryServer {
  const config = cfgIn ?? loadConfig();
  const store = UpstashRestStore.fromEnv();
  const service = new DirectoryService(store, config);

  function sendResult(res: http.ServerResponse, result: DirectoryCallResult): void {
    if (result.ok) {
      sendJson(res, 200, {
        ok: true,
        protocol_version: DIRECTORY_PROTOCOL_VERSION,
        ...result.body,
      });
      return;
    }
    const body: Record<string, unknown> = { ok: false, error: result.error };
    if (result.detail !== undefined) body['detail'] = result.detail;
    if (result.retry_after_s !== undefined) body['retry_after_s'] = result.retry_after_s;
    sendJson(res, directoryStatusFor(result.error), body);
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://local');
    if (req.method === 'GET') {
      sendJson(res, 200, {
        ok: true,
        service: 'directory',
        protocol_version: DIRECTORY_PROTOCOL_VERSION,
        svc_version: SERVICE_PROTOCOL_VERSION,
      });
      return;
    }
    if (req.method !== 'POST') {
      sendJson(res, 405, { ok: false, error: 'method_not_allowed' });
      return;
    }

    // Header-only auth discipline (QA F42b rule).
    if (url.searchParams.has('token') || url.searchParams.has('device_token')) {
      sendJson(res, 401, {
        ok: false,
        error: 'unauthorized',
        detail: 'device token must be the Authorization: Bearer header',
      });
      return;
    }

    const body = await readBody(req);
    if (body === null) {
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
    if ('device_token' in raw) {
      sendJson(res, 400, {
        ok: false,
        error: 'malformed',
        detail: 'device token must be the Authorization: Bearer header',
      });
      return;
    }

    // Version gate on the RAW value before body validation (account rule):
    // present-and-wrong is the typed version error; missing falls to zod.
    if (
      typeof raw['protocol_version'] === 'number' &&
      raw['protocol_version'] !== DIRECTORY_PROTOCOL_VERSION
    ) {
      sendJson(res, 400, {
        ok: false,
        error: 'unsupported_version',
        detail: `unsupported protocol_version ${raw['protocol_version']} (service speaks ${DIRECTORY_PROTOCOL_VERSION})`,
      });
      return;
    }

    const action = raw['action'];
    if (typeof action !== 'string') {
      sendJson(res, 400, { ok: false, error: 'malformed', detail: 'action discriminant required' });
      return;
    }
    if (!(KNOWN_DIRECTORY_ACTIONS as readonly string[]).includes(action)) {
      sendJson(res, 400, { ok: false, error: 'unknown_action', detail: `unknown action ${action}` });
      return;
    }

    const check = directoryRequestSchema.safeParse(raw);
    if (!check.success) {
      const first = check.error.issues[0];
      const where = first ? `${first.path.join('.')}` : 'unknown';
      sendJson(res, 400, { ok: false, error: 'malformed', detail: `validation failed at ${where}` });
      return;
    }
    const request = check.data as DirectoryRequest;

    const result = await service.call(request, { ip: clientIp(req), token: bearerToken(req) });
    log.debug(
      'directory_call',
      {
        action: request.action,
        device: request.device,
        circle_id: request.circle_id,
        ok: result.ok ? 1 : 0,
      },
      'directory',
    );
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
      req.on('close', () => resolve(null));
    });
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      log.error('directory_http_failed', { err: String(err).slice(0, 120) }, 'directory');
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
