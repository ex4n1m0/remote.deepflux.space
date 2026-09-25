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

  private k(
    device: string,
    kind: 'p' | 'po' | 'mbseq' | 'mb' | 'mbc' | 's' | 'dd',
  ): string {
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
   * Bind/refresh presence (QA F38b): a LIVE presence owned by a different
   * token is refused, and so is a rebind of an EXPIRED presence by a
   * different token while the previous-owner tombstone (`po:{device}`,
   * TTL = mailbox TTL, refreshed on every successful presence write) is
   * still alive. Only after the owner has been silent for the mailbox TTL
   * can a new token claim the id. The legitimate owner always rebinds
   * immediately (same token matches the tombstone). Residual MVP risk
   * (documented): once the tombstone expires, a device-id squatter can
   * claim the id and DoS the real owner — inherent to the no-accounts
   * model; acked mail is purged (F38a), so only future mail is exposed.
   */
  private async bindPresence(device: string, th: string): Promise<SendOutcome> {
    const key = this.k(device, 'p');
    const ownerKey = this.k(device, 'po');
    const existing = this.parsePresence(await this.store.get(key));
    if (existing !== null && existing.th !== th) {
      return { ok: false, error: 'unauthorized' };
    }
    if (existing === null) {
      const previousOwner = await this.store.get(ownerKey);
      if (previousOwner !== null && previousOwner !== th) {
        // Takeover attempt inside the tombstone window.
        log.warn('rebind_refused', { device });
        return { ok: false, error: 'unauthorized' };
      }
    }
    const rec: PresenceRecord = { v: 1, th };
    await this.store.setEx(key, JSON.stringify(rec), this.cfg.ttlDeviceSec);
    await this.store.setEx(ownerKey, th, this.cfg.ttlMailboxSec);
    return { ok: true, duplicate: false };
  }

  async register(device: string, token: string): Promise<SendOutcome> {
    return this.bindPresence(device, sha256hex(token));
  }

  /**
   * Heartbeat: refresh presence TTL under the same takeover policy as
   * register (a heartbeat used to be the free-rebind path — QA F38b).
   */
  async heartbeat(device: string, token: string): Promise<SendOutcome> {
    return this.bindPresence(device, sha256hex(token));
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
    // Era safety (QA F37): when the mailbox key set expires together
    // (idle >= mailbox TTL), the per-device seq counter restarts at 1
    // while callers may still hold cursors from the previous era. A cursor
    // above the current latestSeq can only come from an older era, so it
    // is clamped to 0 here — the single choke point both transports use —
    // and the machines' message_id dedupe absorbs any redelivery.
    const latest = await this.latestSeq(device);
    if (afterSeq > latest) {
      afterSeq = 0;
    }
    const raw = await this.store.zrangebyscore(key, afterSeq, max);
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
    return { entries, latestSeq: latest };
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

  /**
   * Advance the device's acked-seq cursor and PURGE everything at or below
   * it (QA F38a): accepted envelopes — including SDP bodies and any
   * one-time session secret inside an `accept` — must not linger in the
   * store for the mailbox TTL after the consumer has taken them. The
   * cursor write is compare-then-set; a concurrent-ack regression is
   * benign (extra redelivery, machine-deduped) and the purge is
   * monotonic-safe in every interleaving.
   */
  async ack(device: string, seq: number): Promise<void> {
    const key = this.k(device, 'mbc');
    const raw = await this.store.get(key);
    const cur = raw === null ? 0 : Number(raw) || 0;
    if (seq > cur) {
      await this.store.setEx(key, String(seq), this.cfg.ttlMailboxSec);
      const mbKey = this.k(device, 'mb');
      // Before purging, mark each consumed entry's dedupe tombstone as
      // ACKED (value 'A'): a later retry of that message_id is a true
      // duplicate (the consumer took it), NOT the F45 crash window —
      // the entry's absence from the mailbox is now expected.
      const batch: Array<[string, string, number]> = [];
      const doomed = await this.store.zrangebyscore(mbKey, -1, this.cfg.mailboxMax);
      for (const line of doomed) {
        try {
          const m = JSON.parse(line) as MailboxMember;
          if (m.s > seq) continue;
          const env = m.e as
            | { message_id?: unknown; from_device_id?: unknown }
            | null;
          if (
            env &&
            typeof env.message_id === 'string' &&
            typeof env.from_device_id === 'string'
          ) {
            batch.push([
              this.k(`${env.from_device_id}:${env.message_id}`, 'dd'),
              'A',
              this.cfg.ttlDedupeSec,
            ]);
          }
        } catch {
          /* skip unreadable member */
        }
      }
      await this.store.setExMany(batch);
      await this.store.zremrangebyscoreMax(mbKey, seq);
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

    // Idempotency by messageId (QA F45): the tombstone is written BEFORE
    // the enqueue with the value 'P' (pending) and updated to the assigned
    // seq after. On a duplicate hit we VERIFY the recorded seq is still in
    // the target mailbox — if the writer crashed between SETNX and ZADD
    // (or the entry was trimmed/expired), the retry re-enqueues instead of
    // silently swallowing the message.
    const ddKey = this.k(`${fromDevice}:${env.message_id}`, 'dd');
    const fresh = await this.store.setNxEx(ddKey, 'P', this.cfg.ttlDedupeSec);
    if (!fresh) {
      const prior = await this.store.get(ddKey);
      if (prior === 'A') {
        // Consumed by the recipient (ack-purged): a true duplicate.
        return { ok: true, duplicate: true };
      }
      const priorSeq = prior === null ? Number.NaN : Number(prior);
      if (prior !== 'P' && Number.isInteger(priorSeq) && priorSeq > 0) {
        const stillThere = (
          await this.store.zrangebyscore(this.k(env.to_device_id, 'mb'), priorSeq - 1, 2)
        ).some((line) => {
          try {
            return (JSON.parse(line) as MailboxMember).s === priorSeq;
          } catch {
            return false;
          }
        });
        if (stillThere) {
          return { ok: true, duplicate: true };
        }
      }
      // Crash window or vanished entry: repair by re-enqueueing under a
      // fresh pending tombstone.
      await this.store.setEx(ddKey, 'P', this.cfg.ttlDedupeSec);
    }

    const seq = await this.enqueue(env.to_device_id, env);
    await this.store.setEx(ddKey, String(seq), this.cfg.ttlDedupeSec);

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
