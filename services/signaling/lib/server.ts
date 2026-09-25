/**
 * The signaling server: one Node `http.Server` serving BOTH transports on
 * one endpoint —
 *
 *  - plain HTTP POST ops (`send`/`poll`/`ack`): the polling fallback that
 *    works everywhere (and through `vercel dev`'s local bridge, which does
 *    not forward WebSocket upgrades);
 *  - `ws` upgrades on the same path: the primary live transport.
 *
 * Vercel deployment shape (current docs): default-export this server from
 * `api/signal.ts` after calling `server.listen()` — the platform (and the
 * @vercel/node dev builder) intercepts `listen` to capture the instance.
 *
 * INSTANCE-LOCAL STATE POLICY (risk register: "WS beta instance-local
 * sockets"): the only things kept in this process are the sockets, their
 * poll timers, and each connection's last-delivered seq — all
 * reconstructable from the store. Every authoritative fact (presence,
 * mailbox, cursors, dedupe, sessions) lives in the external store, so
 * instance restarts and cross-instance routing are correct by construction.
 * Live delivery is a short-poll of the mailbox per connection (Upstash REST
 * has no push); latency is bounded by SIGNALING_WS_POLL_MS (default 250 ms).
 */
import http from 'node:http';
import { WebSocketServer, type WebSocket } from 'ws';
import { loadConfig, type SignalingConfig } from './config.ts';
import { UpstashRestStore } from './upstash.ts';
import { SignalingService } from './service.ts';
import {
  ERROR_CODES,
  SIGNALING_PROTOCOL_VERSION,
  SIGNALING_SERVICE_ID,
} from './envelope.ts';
import {
  SERVICE_PROTOCOL_VERSION,
  clientFrameSchema,
  httpAckSchema,
  httpPollSchema,
  httpSendSchema,
  type ByeFrame,
  type DeliverFrame,
  type ErrorFrame,
  type HelloOkFrame,
  type HttpPollResponse,
  type HttpSendResponse,
  type SendResultFrame,
  type ServerFrame,
} from './frames.ts';
import { log } from './log.ts';

const HTTP_BODY_MAX = 1 << 20; // 1 MiB request bound (invariant 3)
const HELLO_TIMEOUT_MS = 5_000;
const DEVICE_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;

function bearerToken(req: http.IncomingMessage): string | null {
  const h = req.headers.authorization;
  if (typeof h === 'string' && h.toLowerCase().startsWith('bearer ')) {
    return h.slice(7).trim() || null;
  }
  return null;
}

function sendFrame(ws: WebSocket, frame: ServerFrame): void {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(frame));
  }
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

export interface SignalingServer {
  server: http.Server;
  config: SignalingConfig;
  service: SignalingService;
  /** Live connections per device (instance-local, diagnostics only). */
  localConnections(): number;
  close(): Promise<void>;
}

export function createSignalingServer(cfgIn?: SignalingConfig): SignalingServer {
  const config = cfgIn ?? loadConfig();
  const store = UpstashRestStore.fromEnv();
  const service = new SignalingService(store, config);

  let liveSockets = 0;

  // -------------------------------------------------------------------------
  // HTTP fallback + health
  // -------------------------------------------------------------------------

  async function handleHttp(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://local');
    if (req.method === 'GET') {
      sendJson(res, 200, {
        ok: true,
        service: 'signaling',
        protocol_version: SIGNALING_PROTOCOL_VERSION,
        svc_version: SERVICE_PROTOCOL_VERSION,
        service_id: SIGNALING_SERVICE_ID,
      });
      return;
    }
    if (req.method !== 'POST') {
      sendJson(res, 405, { ok: false, error: 'method_not_allowed' });
      return;
    }

    const token = bearerToken(req);
    if (token === null) {
      sendJson(res, 401, { ok: false, error: 'unauthorized' });
      return;
    }
    const body = await readBody(req);
    if (body === null) {
      sendJson(res, 413, { ok: false, error: 'too_large' });
      return;
    }
    let op: unknown;
    try {
      op = JSON.parse(body);
    } catch {
      sendJson(res, 400, { ok: false, error: 'malformed' });
      return;
    }

    const send = httpSendSchema.safeParse(op);
    if (send.success) {
      const device = headerDevice(req, url);
      if (!device) {
        sendJson(res, 400, { ok: false, error: 'missing_device' });
        return;
      }
      const outcome = await service.sendEnvelope(device, token, JSON.stringify(send.data.envelope));
      const reply: HttpSendResponse =
        outcome.ok ? { ok: true, duplicate: outcome.duplicate } : { ok: false, error: outcome.error };
      const status = outcome.ok ? 200 : httpStatusFor(outcome.error);
      sendJson(res, status, reply);
      return;
    }

    const poll = httpPollSchema.safeParse(op);
    if (poll.success) {
      const { device_id, after_seq, max } = poll.data;
      if (!(await service.authenticate(device_id, token))) {
        sendJson(res, 401, { ok: false, error: 'unauthorized' });
        return;
      }
      const drained = await service.drain(device_id, after_seq, max);
      const reply: HttpPollResponse = {
        ok: true,
        envelopes: drained.entries,
        latest_seq: drained.latestSeq,
      };
      sendJson(res, 200, reply);
      return;
    }

    const ack = httpAckSchema.safeParse(op);
    if (ack.success) {
      const { device_id, seq } = ack.data;
      if (!(await service.authenticate(device_id, token))) {
        sendJson(res, 401, { ok: false, error: 'unauthorized' });
        return;
      }
      await service.ack(device_id, seq);
      sendJson(res, 200, { ok: true });
      return;
    }

    sendJson(res, 400, { ok: false, error: 'unknown_op' });
  }

  function headerDevice(req: http.IncomingMessage, url: URL): string | null {
    const q = url.searchParams.get('device_id');
    if (q && DEVICE_ID_RE.test(q)) return q;
    return null;
  }

  function httpStatusFor(error: string): number {
    switch (error) {
      case 'unauthorized':
        return 401;
      case 'forged_from':
        return 403;
      case 'unknown_target':
        return 404;
      case 'too_large':
        return 413;
      case 'unsupported_version':
      case 'malformed':
      case 'self_target':
      case 'not_service_directed':
      case 'missing_session_id':
        return 400;
      default:
        return 500;
    }
  }

  function readBody(req: http.IncomingMessage): Promise<string | null> {
    return new Promise((resolve) => {
      let size = 0;
      const chunks: Buffer[] = [];
      req.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > HTTP_BODY_MAX) {
          resolve(null);
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', () => resolve(null));
    });
  }

  const server = http.createServer((req, res) => {
    handleHttp(req, res).catch((err) => {
      log.error('http_handler_failed', { err: String(err).slice(0, 120) });
      if (!res.headersSent) {
        sendJson(res, 500, { ok: false, error: 'internal' });
      } else {
        res.end();
      }
    });
  });

  // -------------------------------------------------------------------------
  // WebSocket transport
  // -------------------------------------------------------------------------

  const wss = new WebSocketServer({ server, path: undefined, maxPayload: HTTP_BODY_MAX });

  wss.on('connection', (ws, req) => {
    liveSockets += 1;
    handleSocket(ws, req).catch((err) => {
      log.warn('ws_session_failed', { err: String(err).slice(0, 120) });
      const bye: ByeFrame = { op: 'bye', reason: 'shutdown' };
      sendFrame(ws, bye);
      try {
        ws.close();
      } catch {
        /* already closing */
      }
    });
  });

  async function handleSocket(ws: WebSocket, req: http.IncomingMessage): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://local');
    const token = bearerToken(req) ?? url.searchParams.get('token');
    const device = url.searchParams.get('device_id') ?? '';
    if (!DEVICE_ID_RE.test(device) || token === null || token.length === 0) {
      const frame: ErrorFrame = { op: 'error', error: 'unauthorized', detail: 'device_id and token required' };
      sendFrame(ws, frame);
      ws.close(4001, 'unauthorized');
      return;
    }

    // Buffer everything from the first frame: the store round-trips below
    // are asynchronous, and frames arriving between the hello listener
    // detaching and the session handler attaching must never be dropped
    // (a Register racing hello_ok is the normal client pattern).
    const earlyFrames: Array<{ data: unknown }> = [];
    const earlyCollector = (data: unknown, isBinary?: boolean): void => {
      earlyFrames.push({ data });
      void isBinary;
    };
    ws.on('message', earlyCollector);

    // hello frame first (resume point comes from the client's own bookkeeping).
    const hello = await waitHello(ws);
    if (hello === null) {
      ws.close(4002, 'hello_timeout');
      return;
    }
    if (hello.device_id !== device) {
      const frame: ErrorFrame = { op: 'error', error: 'forged_from', detail: 'hello device mismatch' };
      sendFrame(ws, frame);
      ws.close(4003, 'forged_from');
      return;
    }

    // Token vs live presence: a mismatching token on a LIVE presence is a
    // hijack; an absent presence is fine — the client registers on-socket.
    const storedCursor = await service.cursor(device);
    const resumeSeq = Math.max(hello.resume_seq, storedCursor);
    let authed = await service.authenticate(device, token);
    const helloOk: HelloOkFrame = {
      op: 'hello_ok',
      svc_version: SERVICE_PROTOCOL_VERSION,
      device_id: device,
      resume_seq: resumeSeq,
      latest_seq: await service.latestSeq(device),
      ttl_device_s: config.ttlDeviceSec,
      authed,
    };
    sendFrame(ws, helloOk);

    let lastSentSeq = resumeSeq;
    let closed = false;
    const onClosed: Array<() => void> = [];
    ws.on('close', () => {
      closed = true;
      liveSockets -= 1;
      for (const fn of onClosed) fn();
    });
    ws.on('error', () => {
      /* close handler runs cleanup */
    });

    ws.off('message', earlyCollector);

    // Delivery loop: poll the shared mailbox after everything this
    // connection has already sent. Nothing instance-local is authoritative.
    const deliverDue = async (): Promise<void> => {
      if (closed || ws.readyState !== ws.OPEN) return;
      if (!authed) return; // wait for Register/Heartbeat on this socket
      const drained = await service.drain(device, lastSentSeq, config.mailboxBatch);
      for (const entry of drained.entries) {
        if (entry.seq <= lastSentSeq) continue; // benign cross-conn race
        const frame: DeliverFrame = { op: 'deliver', seq: entry.seq, envelope: entry.envelope };
        ws.send(JSON.stringify(frame));
        lastSentSeq = entry.seq;
      }
    };
    const pollTimer = setInterval(() => {
      deliverDue().catch((err) => {
        log.warn('ws_drain_failed', { device, err: String(err).slice(0, 120) });
      });
    }, config.wsPollMs);
    onClosed.push(() => clearInterval(pollTimer));
    void deliverDue();

    // Graceful max-lifetime: tell the client to resume a fresh connection
    // before the platform's maxDuration cuts us off (risk-register item).
    const byeTimer = setTimeout(() => {
      const bye: ByeFrame = { op: 'bye', reason: 'max_duration' };
      sendFrame(ws, bye);
      ws.close(1000, 'max_duration');
    }, config.maxConnectionSec * 1000);
    onClosed.push(() => clearTimeout(byeTimer));

    const handleMessageFrame = async (data: unknown): Promise<void> => {
      if (closed) return;
      let raw: unknown;
      try {
        raw = JSON.parse(String(data));
      } catch {
        const frame: ErrorFrame = { op: 'error', error: 'malformed' };
        sendFrame(ws, frame);
        return;
      }
      const frame = clientFrameSchema.safeParse(raw);
      if (!frame.success) {
        const err: ErrorFrame = { op: 'error', error: 'malformed', detail: 'unknown op or shape' };
        sendFrame(ws, err);
        return;
      }
      switch (frame.data.op) {
        case 'send': {
          const outcome = await service.sendEnvelope(
            device,
            token as string,
            JSON.stringify(frame.data.envelope),
          );
          const sentType = (frame.data.envelope as { type?: string }).type;
          if (outcome.ok && (sentType === 'register' || sentType === 'heartbeat')) {
            // Register/Heartbeat bound or refreshed presence for this
            // token: start delivering now.
            authed = true;
          }
          const result: SendResultFrame = {
            op: 'send_result',
            message_id: String((frame.data.envelope as { message_id?: unknown }).message_id ?? ''),
            ok: outcome.ok,
            ...(outcome.ok ? { duplicate: outcome.duplicate } : { error: outcome.error }),
          };
          sendFrame(ws, result);
          if (!outcome.ok && outcome.error === 'unauthorized') {
            // Token lost the presence (expired + rebound elsewhere).
            const bye: ByeFrame = { op: 'bye', reason: 'unauthorized' };
            sendFrame(ws, bye);
            ws.close(4001, 'unauthorized');
          }
          void deliverDue();
          return;
        }
        case 'ack': {
          if (!authed) {
            const err: ErrorFrame = { op: 'error', error: 'unauthorized' };
            sendFrame(ws, err);
            return;
          }
          await service.ack(device, frame.data.seq);
          return;
        }
        case 'poll': {
          await deliverDue();
          return;
        }
        case 'hello': {
          const err: ErrorFrame = { op: 'error', error: 'already_helloed' };
          sendFrame(ws, err);
          return;
        }
      }
    };
    ws.on('message', (data) => {
      void handleMessageFrame(data).catch((err) => {
        log.warn('ws_frame_failed', { device, err: String(err).slice(0, 120) });
      });
    });
    // Drain frames that raced the async setup above (see earlyCollector):
    // a Register sent immediately after hello must not be lost. The hello
    // itself was consumed by waitHello's own listener, so skip it here.
    for (const early of earlyFrames.splice(0)) {
      try {
        const probe = JSON.parse(String(early.data)) as { op?: unknown };
        if (probe && probe.op === 'hello') continue;
      } catch {
        /* fall through: handler reports the malformed frame */
      }
      void handleMessageFrame(early.data).catch(() => undefined);
    }
  }

  function waitHello(ws: WebSocket): Promise<{ device_id: string; resume_seq: number } | null> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        ws.off('message', onMessage);
        resolve(null);
      }, HELLO_TIMEOUT_MS);
      const onMessage = (data: unknown): void => {
        try {
          const parsed = clientFrameSchema.safeParse(JSON.parse(String(data)));
          if (parsed.success && parsed.data.op === 'hello') {
            clearTimeout(timer);
            ws.off('message', onMessage);
            resolve({ device_id: parsed.data.device_id, resume_seq: parsed.data.resume_seq });
          }
        } catch {
          /* keep waiting for a valid hello */
        }
      };
      ws.on('message', onMessage);
    });
  }

  return {
    server,
    config,
    service,
    localConnections: () => liveSockets,
    close: () =>
      new Promise<void>((resolve) => {
        for (const client of wss.clients) client.terminate();
        wss.close(() => resolve());
        server.close(() => resolve());
      }),
  };
}
