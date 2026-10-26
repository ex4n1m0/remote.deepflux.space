/**
 * Circle-directory service core (ADR-006).
 *
 * Pure logic over the `Store` seam — no sockets, no authoritative memory.
 * One circle is one ZSET (the mailbox pattern), keyed by the unguessable
 * `circle_id` hash; members are JSON rows carrying ciphertext only:
 *
 *   dir:{circle_id}   ZSET, score = server-minted ts_ms, member =
 *                     {v:1, device, ciphertext_hex, nonce_hex, ts_ms};
 *                     TTL 30 d refreshed on every put, pruned on write.
 *
 * Timestamps are ALWAYS server-minted (house rule from `roster_put`): the
 * score drives pruning and the member cap, so a client-supplied future time
 * would permanently occupy a cap slot.
 *
 * Auth: `(device, token)` against the signaling presence record — the same
 * read-only check `lib/chat-service.ts` does. Every action applies to the
 * caller's OWN row: `device` must match the authenticated id.
 *
 * Rate limits bound per-device abuse, per-IP minting (device ids are free),
 * and per-circle aggregates (list fan-out, junk-fill of the member cap).
 */
import { createHash } from 'node:crypto';
import type { SignalingConfig } from './config.ts';
import type { Store } from './store.ts';
import { log } from './log.ts';
import {
  DIRECTORY_ERROR_CODES,
  DIRECTORY_ENTRY_MAX_BYTES,
  type DirectoryRequest,
} from './directory-schema.ts';

const sha256hex = (value: string) =>
  createHash('sha256').update(value, 'utf8').digest('hex');

interface PresenceRecord {
  th: string;
}

const parsePresence = (raw: string | null): PresenceRecord | null => {
  if (raw === null) return null;
  try {
    const parsed = JSON.parse(raw) as PresenceRecord;
    return typeof parsed.th === 'string' ? parsed : null;
  } catch {
    return null;
  }
};

interface DirectoryMember {
  v: 1;
  device: string;
  ciphertext_hex: string;
  nonce_hex: string;
  ts_ms: number;
}

export type DirectoryCallResult =
  | {
      ok: true;
      body: { action: string; refreshed_ms?: number; entries?: DirectoryRowOut[]; truncated?: boolean };
    }
  | { ok: false; error: string; detail?: string; retry_after_s?: number };

export interface DirectoryRowOut {
  device: string;
  ciphertext_hex: string;
  nonce_hex: string;
  refreshed_ms: number;
  online: boolean;
}

export class DirectoryService {
  constructor(
    private readonly store: Store,
    private readonly cfg: SignalingConfig,
  ) {}

  private k(circleId: string): string {
    return `${this.cfg.prefix}dir:${circleId}`;
  }

  /** Presence-token auth, read-only over lib/service.ts records. */
  async authenticate(device: string, token: string): Promise<boolean> {
    const rec = parsePresence(await this.store.get(`${this.cfg.prefix}p:${device}`));
    return rec !== null && rec.th === sha256hex(token);
  }

  async call(
    req: DirectoryRequest,
    ctx: { ip: string; token: string | null },
  ): Promise<DirectoryCallResult> {
    if (ctx.token === null) {
      return { ok: false, error: DIRECTORY_ERROR_CODES.UNAUTHORIZED };
    }
    if (!(await this.authenticate(req.device, ctx.token))) {
      return { ok: false, error: DIRECTORY_ERROR_CODES.UNAUTHORIZED };
    }
    switch (req.action) {
      case 'put':
        return this.put(req, ctx.ip);
      case 'list':
        return this.list(req);
      case 'remove':
        return this.remove(req);
    }
  }

  private async put(
    req: Extract<DirectoryRequest, { action: 'put' }>,
    ip: string,
  ): Promise<DirectoryCallResult> {
    // Size gate BEFORE any store access (shape is the schema's job).
    if (req.ciphertext_hex.length / 2 > this.cfg.directoryEntryMaxBytes) {
      return {
        ok: false,
        error: DIRECTORY_ERROR_CODES.ENTRY_TOO_LARGE,
        detail: `entry exceeds ${this.cfg.directoryEntryMaxBytes} decoded bytes`,
      };
    }

    const key = this.k(req.circle_id);
    const now = Date.now();

    const limitedDevice = await this.rateLimit(
      `dir-put:${req.device}`,
      this.cfg.rlDirPutPerMinPerDevice,
      60,
    );
    if (limitedDevice !== null) {
      return rateLimited(limitedDevice);
    }
    const limitedIp = await this.rateLimit(`dir-put-ip:${ipKey(ip)}`, this.cfg.rlDirPutPerMinPerIp, 60);
    if (limitedIp !== null) {
      return rateLimited(limitedIp);
    }

    // Prune stale members, then read the live set (one shape, two calls).
    await this.store.zremrangebyscoreMax(key, now - this.cfg.ttlDirectorySec * 1000);
    const rawMembers = await this.store.zrangebyscore(
      key,
      now - this.cfg.ttlDirectorySec * 1000,
      this.cfg.directoryMaxMembers,
    );
    const members = parseMembers(rawMembers);
    const existing = members.find((m) => m.device === req.device);

    if (existing === undefined) {
      // New member: circle aggregate caps (junk-fill defense).
      const limitedNewPerDay = await this.rateLimit(
        `dir-put-new:${req.circle_id}`,
        this.cfg.rlDirPutNewMembersPerDayPerCircle,
        86_400,
      );
      if (limitedNewPerDay !== null) {
        return rateLimited(limitedNewPerDay);
      }
      if (members.length >= this.cfg.directoryMaxMembers) {
        return {
          ok: false,
          error: DIRECTORY_ERROR_CODES.CIRCLE_FULL,
          detail: `circle is at ${this.cfg.directoryMaxMembers} machines`,
        };
      }
    }

    // Replace-or-insert, then refresh the key TTL as part of the write (a
    // missed EXPIRE would leak an immortal circle; every later put re-arms).
    const next: DirectoryMember = {
      v: 1,
      device: req.device,
      ciphertext_hex: req.ciphertext_hex,
      nonce_hex: req.nonce_hex,
      ts_ms: now,
    };
    try {
      if (existing !== undefined) {
        await this.store.zrem(key, JSON.stringify(existing));
      }
      await this.store.zadd(key, now, JSON.stringify(next));
      await this.store.expire(key, this.cfg.ttlDirectorySec);
    } catch (err) {
      log.error('directory_put_failed', { err: String(err).slice(0, 120) }, 'directory');
      return { ok: false, error: DIRECTORY_ERROR_CODES.INTERNAL };
    }
    return { ok: true, body: { action: 'put', refreshed_ms: now } };
  }

  private async list(
    req: Extract<DirectoryRequest, { action: 'list' }>,
  ): Promise<DirectoryCallResult> {
    const limitedDevice = await this.rateLimit(
      `dir-list:${req.device}`,
      this.cfg.rlDirListPerMinPerDevice,
      60,
    );
    if (limitedDevice !== null) {
      return rateLimited(limitedDevice);
    }
    const limitedCircle = await this.rateLimit(
      `dir-list-circle:${req.circle_id}`,
      this.cfg.rlDirListPerMinPerCircle,
      60,
    );
    if (limitedCircle !== null) {
      return rateLimited(limitedCircle);
    }

    const key = this.k(req.circle_id);
    const now = Date.now();
    // Same lazy prune as put: read-time sweep keeps idle circles bounded
    // even if nobody writes.
    await this.store.zremrangebyscoreMax(key, now - this.cfg.ttlDirectorySec * 1000);
    const rawMembers = await this.store.zrangebyscore(
      key,
      now - this.cfg.ttlDirectorySec * 1000,
      this.cfg.directoryMaxMembers + 1,
    );
    const members = parseMembers(rawMembers);
    const truncated = members.length > this.cfg.directoryMaxMembers;

    // Presence join in ONE pipeline (≤128 tiny GETs — fine on REST; the
    // boolean is the only thing that crosses, never `th`).
    const presence = await this.store.mget(
      ...members.map((m) => `${this.cfg.prefix}p:${m.device}`),
    );
    const entries: DirectoryRowOut[] = members.map((m, i) => ({
      device: m.device,
      ciphertext_hex: m.ciphertext_hex,
      nonce_hex: m.nonce_hex,
      refreshed_ms: m.ts_ms,
      online: presence[i] !== null,
    }));
    return {
      ok: true,
      body: {
        action: 'list',
        entries,
        truncated,
      },
    };
  }

  private async remove(
    req: Extract<DirectoryRequest, { action: 'remove' }>,
  ): Promise<DirectoryCallResult> {
    const limitedDevice = await this.rateLimit(
      `dir-remove:${req.device}`,
      this.cfg.rlDirRemovePerMinPerDevice,
      60,
    );
    if (limitedDevice !== null) {
      return rateLimited(limitedDevice);
    }
    const key = this.k(req.circle_id);
    const rawMembers = await this.store.zrangebyscore(key, 0, this.cfg.directoryMaxMembers + 1);
    const mine = parseMembers(rawMembers).find((m) => m.device === req.device);
    if (mine !== undefined) {
      await this.store.zrem(key, JSON.stringify(mine));
    }
    // Idempotent: absent row is still a success (logout precedent).
    return { ok: true, body: { action: 'remove' } };
  }

  /**
   * Fixed-window limiter — the account-service helper, duplicated per the
   * per-service pattern (extraction is a separate refactor). Self-heals a
   * counter that outlived its window metadata (P2-3).
   */
  private async rateLimit(bucketAndKey: string, limit: number, windowSec: number): Promise<number | null> {
    const countKey = `${this.cfg.prefix}rl:${bucketAndKey}`;
    const startKey = `${this.cfg.prefix}rlt:${bucketAndKey}`;
    const n = await this.store.incr(countKey);
    if (n === 1) {
      await this.store.expireAfterIncr(countKey, windowSec);
      await this.store.setNxEx(startKey, String(Date.now()), windowSec);
    }
    if (n > limit) {
      const start = await this.store.get(startKey);
      const startedAt = start === null ? Number.NaN : Number(start);
      let retryAfterS = windowSec;
      if (Number.isFinite(startedAt) && startedAt > 0) {
        retryAfterS = Math.max(1, Math.ceil((startedAt + windowSec * 1000 - Date.now()) / 1000));
      } else {
        await this.store.expireAfterIncr(countKey, windowSec);
        await this.store.setNxEx(startKey, String(Date.now()), windowSec);
      }
      const clamped = Math.min(retryAfterS, windowSec);
      log.warn('directory_rate_limited', { bucket: bucketAndKey.split(':')[0] ?? '-', retry_after_s: clamped }, 'directory');
      return clamped;
    }
    return null;
  }
}

function rateLimited(retryAfterS: number): DirectoryCallResult {
  return { ok: false, error: DIRECTORY_ERROR_CODES.RATE_LIMITED, retry_after_s: retryAfterS };
}

/** Corrupt member lines are skipped, never fatal (chat's corrupt-inbox rule). */
function parseMembers(raw: string[]): DirectoryMember[] {
  const out: DirectoryMember[] = [];
  for (const line of raw) {
    try {
      const m = JSON.parse(line) as DirectoryMember;
      if (
        m &&
        m.v === 1 &&
        typeof m.device === 'string' &&
        typeof m.ciphertext_hex === 'string' &&
        typeof m.ts_ms === 'number'
      ) {
        out.push(m);
      }
    } catch {
      // skip
    }
  }
  return out;
}

/** Rate-limit keys must be filesystem-ish; sanitize the raw IP into one. */
function ipKey(ip: string): string {
  return ip.replace(/[^A-Za-z0-9._-]/g, '_');
}
