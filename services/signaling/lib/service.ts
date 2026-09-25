/**
 * Signaling service core: presence, idempotent routing, bounded mailbox,
 * session bookkeeping. Pure logic over the `Store` seam — no sockets, no
 * HTTP, no authoritative memory. Both transports (WS handler, HTTP
 * fallback) call into this, which is what makes cross-instance behavior
 * correct: any function instance seeing a request computes everything from
 * the shared store.
 *
 * Delivery contract: AT-LEAST-ONCE until the consumer acks a mailbox seq;
 * the desktop clients' state machines dedupe on `message_id` (the pinned
 * `crates/session` contract). The service additionally suppresses exact
 * re-ENQUEUE of a recently seen (from_device, message_id) pair so sender
 * retries after an ambiguous write do not duplicate mailbox entries — the
 * "idempotency by messageId" requirement (RD-010).
 *
 * Invariants honored here:
 *  - nothing is stored without a TTL (presence/mailbox/session/dedupe/cursor),
 *  - the mailbox is capped (ZREMRANGEBYRANK) AND logically expired per entry,
 *  - envelopes are forwarded verbatim; only `Error` envelopes are minted,
 *  - SDP bodies / session secrets transit but are never logged.
 */
import { createHash } from 'node:crypto';
import type { SignalingConfig } from './config.ts';
import type { Store } from './store.ts';
import {
  ERROR_CODES,
  SIGNALING_PROTOCOL_VERSION,
  SIGNALING_SERVICE_ID,
  isSessionScoped,
  isServiceDirected,
  mintErrorEnvelope,
  signalingEnvelopeSchema,
  type MintedError,
  type SignalingEnvelope,
} from './envelope.ts';
import { log } from './log.ts';

export type SendError =
  | 'malformed'
  | 'unsupported_version'
  | 'unauthorized'
  | 'forged_from'
  | 'self_target'
  | 'unknown_target'
  | 'not_service_directed'
  | 'missing_session_id'
  | 'too_large'
  | 'internal';

export type SendOutcome = { ok: true; duplicate: boolean } | { ok: false; error: SendError };

export interface MailboxEntry {
  seq: number;
  envelope: unknown;
}

export interface DrainResult {
  entries: MailboxEntry[];
  latestSeq: number;
}

interface PresenceRecord {
  v: 1;
  /** sha256 hex of the device token — the raw token is never stored. */
  th: string;
}

interface MailboxMember {
  /** Assigned seq (unique per device, monotonic). */
  s: number;
  /** Enqueue wall-clock ms — drives per-entry logical expiry. */
  q: number;
  /** The verbatim envelope object. */
  e: unknown;
}

interface SessionRecord {
  v: 1;
  /** Controller side (session ids are controller-minted). */
  a: string;
  /** Host side. */
  b: string;
  t: number;
}

function sha256hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

export class SignalingService {
  constructor(
    private readonly store: Store,
    private readonly cfg: SignalingConfig,
  ) {}

  private k(device: string, kind: 'p' | 'mbseq' | 'mb' | 'mbc' | 's' | 'dd'): string {
    return `${this.cfg.prefix}${kind}:${device}`;
  }

  // -------------------------------------------------------------------------
  // Presence / auth
  // -------------------------------------------------------------------------

  private parsePresence(raw: string | null): PresenceRecord | null {
    if (raw === null) return null;
    try {
      const rec = JSON.parse(raw) as PresenceRecord;
      return rec && rec.v === 1 && typeof rec.th === 'string' ? rec : null;
    } catch {
      return null;
    }
  }

  /** Verify a device's token against stored presence. */
  async authenticate(device: string, token: string): Promise<boolean> {
    const rec = this.parsePresence(await this.store.get(this.k(device, 'p')));
    return rec !== null && rec.th === sha256hex(token);
  }

  /**
   * Register (bind or rebind) presence. A live presence owned by a different
   * token is a hijack attempt: refused until it expires.
   */
  async register(device: string, token: string): Promise<SendOutcome> {
    const key = this.k(device, 'p');
    const existing = this.parsePresence(await this.store.get(key));
    const th = sha256hex(token);
    if (existing !== null && existing.th !== th) {
      return { ok: false, error: 'unauthorized' };
    }
    const rec: PresenceRecord = { v: 1, th };
    await this.store.setEx(key, JSON.stringify(rec), this.cfg.ttlDeviceSec);
    return { ok: true, duplicate: false };
  }

  /**
   * Heartbeat: refresh presence TTL. A heartbeat for an expired presence
   * re-binds the same token (idempotent re-register after TTL lapse).
   */
  async heartbeat(device: string, token: string): Promise<SendOutcome> {
    const key = this.k(device, 'p');
    const existing = this.parsePresence(await this.store.get(key));
    const th = sha256hex(token);
    if (existing !== null && existing.th !== th) {
      return { ok: false, error: 'unauthorized' };
    }
    if (existing === null) {
      await this.store.setEx(key, JSON.stringify({ v: 1, th }), this.cfg.ttlDeviceSec);
    } else if (!(await this.store.expire(key, this.cfg.ttlDeviceSec))) {
      // Expired between GET and EXPIRE — re-bind.
      await this.store.setEx(key, JSON.stringify({ v: 1, th }), this.cfg.ttlDeviceSec);
    }
    return { ok: true, duplicate: false };
  }

  // -------------------------------------------------------------------------
  // Mailbox
  // -------------------------------------------------------------------------

  /** Enqueue one envelope for `device` (verbatim; service-minted errors included). */
  private async enqueue(device: string, envelope: unknown): Promise<number> {
    const seq = await this.store.incr(this.k(device, 'mbseq'));
    await this.store.expireAfterIncr(this.k(device, 'mbseq'), this.cfg.ttlMailboxSec);
    const member: MailboxMember = { s: seq, q: Date.now(), e: envelope };
    const key = this.k(device, 'mb');
    await this.store.zadd(key, seq, JSON.stringify(member));
    await this.store.ztrimToNewest(key, this.cfg.mailboxMax);
    await this.store.expire(key, this.cfg.ttlMailboxSec);
    return seq;
  }

  /**
   * Deliver entries after `afterSeq` (exclusive), at most `max`, sweeping
   * logically expired entries first. Redelivery below the acked cursor is
   * the client's resume mechanism — entries stay until acked or expired.
   */
  async drain(device: string, afterSeq: number, max: number): Promise<DrainResult> {
    const key = this.k(device, 'mb');
    await this.sweepExpired(device);
    const raw = await this.store.zrangebyscore(key, afterSeq, Number.POSITIVE_INFINITY, max);
    const entries: MailboxEntry[] = [];
    for (const line of raw) {
      try {
        const m = JSON.parse(line) as MailboxMember;
        if (typeof m.s === 'number') {
          entries.push({ seq: m.s, envelope: m.e });
        }
      } catch {
        // Corrupt member (should not happen): drop it.
        await this.store.zrem(key, line);
      }
    }
    return { entries, latestSeq: await this.latestSeq(device) };
  }

  /** Drop entries older than the mailbox TTL (lazy cleanup pass). */
  private async sweepExpired(device: string): Promise<void> {
    const key = this.k(device, 'mb');
    const cutoff = Date.now() - this.cfg.ttlMailboxSec * 1000;
    const page = await this.store.zoldest(key, this.cfg.mailboxBatch);
    const expired: string[] = [];
    for (const line of page) {
      try {
        const m = JSON.parse(line) as MailboxMember;
        if (typeof m.q === 'number' && m.q <= cutoff) {
          expired.push(line);
        } else {
          break; // ascending by seq ~ enqueue time: stop at first fresh one
        }
      } catch {
        expired.push(line);
      }
    }
    if (expired.length > 0) {
      await this.store.zrem(key, ...expired);
      log.debug('mailbox_swept', { device, removed: expired.length });
    }
  }

  async latestSeq(device: string): Promise<number> {
    const raw = await this.store.get(this.k(device, 'mbseq'));
    const n = raw === null ? 0 : Number(raw);
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  /** Advance the device's acked-seq cursor (monotonic; benign races only lag). */
  async ack(device: string, seq: number): Promise<void> {
    const key = this.k(device, 'mbc');
    const raw = await this.store.get(key);
    const cur = raw === null ? 0 : Number(raw) || 0;
    if (seq > cur) {
      await this.store.setEx(key, String(seq), this.cfg.ttlMailboxSec);
    }
  }

  /** Resume point: the stored cursor (0 when unknown). */
  async cursor(device: string): Promise<number> {
    const raw = await this.store.get(this.k(device, 'mbc'));
    const n = raw === null ? 0 : Number(raw) || 0;
    return n > 0 ? n : 0;
  }

  // -------------------------------------------------------------------------
  // Sending
  // -------------------------------------------------------------------------

  /**
   * Validate, dedupe and route one inbound envelope sent by `fromDevice`
   * (authenticated identity). `rawJson` is the request body substring so a
   * size cap can reject before parsing.
   */
  async sendEnvelope(fromDevice: string, token: string, rawJson: string): Promise<SendOutcome> {
    if (Buffer.byteLength(rawJson, 'utf8') > this.cfg.envelopeMaxBytes) {
      return { ok: false, error: 'too_large' };
    }
    // Authenticate up front: a caller that cannot prove the device identity
    // must not be able to mint Error envelopes into anyone's mailbox. The
    // only exempt path is service-directed Register/Heartbeat below — those
    // ARE the auth bootstrap (they bind or verify the token themselves).
    const authed = await this.authenticate(fromDevice, token);
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawJson);
    } catch {
      return this.failWith(fromDevice, 'malformed', 'envelope is not valid JSON', authed);
    }
    if (parsed === null || typeof parsed !== 'object') {
      return this.failWith(fromDevice, 'malformed', 'envelope must be a JSON object', authed);
    }

    // Version gate on the RAW value before body validation, so a v0 payload
    // is answered with the typed version error rather than a field mismatch.
    const rawVersion = (parsed as { protocol_version?: unknown }).protocol_version;
    if (rawVersion !== SIGNALING_PROTOCOL_VERSION) {
      const found = typeof rawVersion === 'number' ? rawVersion : -1;
      return this.failWith(
        fromDevice,
        'unsupported_version',
        `unsupported protocol_version ${found} (service speaks ${SIGNALING_PROTOCOL_VERSION})`,
        authed,
        ERROR_CODES.BAD_VERSION,
      );
    }

    const check = signalingEnvelopeSchema.safeParse(parsed);
    if (!check.success) {
      const first = check.error.issues[0];
      const where = first ? `${first.path.join('.')}` : 'unknown';
      return this.failWith(fromDevice, 'malformed', `envelope validation failed at ${where}`, authed);
    }
    const env = check.data as SignalingEnvelope;

    // Sender identity: the envelope must be sent by its claimed author.
    if (env.from_device_id !== fromDevice) {
      return this.failWith(
        fromDevice,
        'forged_from',
        'from_device_id does not match the authenticated sender',
        authed,
        ERROR_CODES.FORBIDDEN_FROM,
      );
    }
    if (env.to_device_id === env.from_device_id) {
      return this.failWith(fromDevice, 'self_target', 'cannot signal yourself', authed);
    }

    if (isServiceDirected(env)) {
      if (env.type !== 'register' && env.type !== 'heartbeat') {
        return this.failWith(
          fromDevice,
          'not_service_directed',
          `type ${env.type} cannot be addressed to the service`,
          authed,
        );
      }
      return env.type === 'register'
        ? this.register(fromDevice, token)
        : this.heartbeat(fromDevice, token);
    }

    if (env.type === 'register' || env.type === 'heartbeat') {
      return this.failWith(
        fromDevice,
        'not_service_directed',
        `${env.type} must be addressed to ${SIGNALING_SERVICE_ID}`,
        authed,
      );
    }
    if (!authed) {
      return { ok: false, error: 'unauthorized' };
    }
    if (isSessionScoped(env.type) && env.session_id === null) {
      return this.failWith(
        fromDevice,
        'missing_session_id',
        `${env.type} requires session_id`,
        authed,
      );
    }

    // Stale presence check: the target must be registered RIGHT NOW.
    const targetPresent = this.parsePresence(await this.store.get(this.k(env.to_device_id, 'p')));
    if (targetPresent === null) {
      await this.enqueue(
        fromDevice,
        mintErrorEnvelope(
          fromDevice,
          ERROR_CODES.UNKNOWN_TARGET,
          `unknown target ${env.to_device_id} (not registered or presence expired)`,
          env.session_id,
        ),
      );
      return { ok: false, error: 'unknown_target' };
    }

    // Idempotency by messageId: suppress exact re-enqueue within the window.
    const fresh = await this.store.setNxEx(
      this.k(`${fromDevice}:${env.message_id}`, 'dd'),
      '1',
      this.cfg.ttlDedupeSec,
    );
    if (!fresh) {
      return { ok: true, duplicate: true };
    }

    await this.enqueue(env.to_device_id, env);

    if (env.session_id !== null) {
      if (env.type === 'disconnect') {
        // One-sided teardown visibility: the session record disappears, so a
        // later reconnecting peer sees "no such session" rather than a ghost.
        await this.store.del(this.k(env.session_id, 's'));
      } else {
        await this.touchSession(env);
      }
    }
    return { ok: true, duplicate: false };
  }

  /** Minimal session bookkeeping (no policy — the machines own the protocol). */
  private async touchSession(env: SignalingEnvelope): Promise<void> {
    const key = this.k(env.session_id as string, 's');
    const existing = await this.store.get(key);
    if (existing === null) {
      const host = env.type === 'accept' || env.type === 'reject' || env.type === 'answer'
        ? env.from_device_id
        : env.to_device_id;
      const controller = host === env.from_device_id ? env.to_device_id : env.from_device_id;
      const rec: SessionRecord = {
        v: 1,
        a: controller,
        b: host,
        t: Date.now(),
      };
      await this.store.setEx(key, JSON.stringify(rec), this.cfg.ttlSessionSec);
    } else {
      await this.store.expire(key, this.cfg.ttlSessionSec);
    }
  }

  /** Mint a typed Error envelope to the sender and return the failure. */
  private async failWith(
    device: string,
    error: SendError,
    detail: string,
    authed: boolean,
    code: number = ERROR_CODES.MALFORMED,
  ): Promise<SendOutcome> {
    if (authed) {
      // Only proven senders get mailbox error envelopes — an unauthenticated
      // caller must not be able to fill anyone's mailbox.
      const minted: MintedError = mintErrorEnvelope(device, code, detail);
      await this.enqueue(device, minted);
    }
    log.debug('send_rejected', { device, error, code });
    return { ok: false, error };
  }
}
