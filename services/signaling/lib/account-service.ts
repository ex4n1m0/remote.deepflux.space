/**
 * Account & roster service core (post-MVP accounts phase, 2026-10-01).
 *
 * Pure logic over the `Store` seam — no sockets, no HTTP, no authoritative
 * memory — mirroring `lib/service.ts`'s discipline: any function instance
 * computes everything from the shared external store, so restarts and
 * cross-instance routing are correct by construction.
 *
 * Server-side crypto (node:crypto only):
 *  - at register the server mints a 16-byte `server_salt` and stores only
 *    `scrypt(auth_key, server_salt)` as the verifier — a store leak grants
 *    neither login nor roster access (the DEK itself never leaves the client);
 *  - session tokens are 32 random bytes (hex); the store holds them ONLY as
 *    `sha256(token)` keys, never in the clear;
 *  - username-existence hiding: unknown `login` runs one dummy scrypt so the
 *    error shape AND latency match the real path; `login_pre` answers
 *    deterministic decoy salts derived from the username.
 *
 * Invariants honored here (mirroring AGENTS.md on the control plane):
 *  - every stored record has an explicit TTL (accounts/rosters deliberately
 *    long-lived: 10-year default — the one DURABLE store surface),
 *  - no key material is ever logged (see lib/log.ts policy),
 *  - the roster lock is bounded (5 s) so a crashed writer cannot deadlock
 *    the username.
 *
 * Store key shapes (all under the shared `sg1:` prefix):
 *   acct:{username}        account record (create-once via SETNX)
 *   roster:{username}      encrypted roster + monotonic version
 *   rosterlock:{username}  optimistic-concurrency lock (SETNX, TTL 5 s)
 *   sess:{sha256(token)}   session record (raw token never stored)
 *   rl:{bucket}:{key}      fixed-window rate-limit counters
 *   rlt:{bucket}:{key}     window-start timestamp (for retry_after_s)
 *   p:{device}             signaling presence (READ-ONLY here, owned by
 *                           lib/service.ts — a code is online iff it exists)
 */
import {
  createHash,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
  type ScryptOptions,
} from 'node:crypto';
import { promisify } from 'node:util';
import type { SignalingConfig } from './config.ts';
import type { Store } from './store.ts';
import {
  ACCOUNT_ERROR_CODES,
  USERNAME_RE,
  type AccountErrorCode,
  type AccountRequest,
  type AccountResponseAction,
} from './account-schema.ts';
import { log } from './log.ts';

// promisify() picks scrypt's 3-arg overload; pin the 4-arg (with options) one.
const scrypt = promisify(scryptCallback) as unknown as (
  password: string,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
) => Promise<Buffer>;

/** scrypt cost parameters (exported for tests). Deliberately conservative. */
export const SCRYPT_COST = { N: 16_384, r: 8, p: 1 } as const;
/** Verifier length in bytes (scrypt output == auth_key length). */
export const SCRYPT_KEYLEN_BYTES = 32;

/** Raw-token shape (64 lowercase hex) — checked before any store lookup. */
const SESSION_TOKEN_RE = /^[0-9a-f]{64}$/;

/** Fixed salt + verifier used to equalize unknown-username login latency. */
const DUMMY_SERVER_SALT = createHash('sha256').update('account-dummy-salt', 'utf8').digest().subarray(0, 16);
const DUMMY_VERIFIER = Buffer.alloc(SCRYPT_KEYLEN_BYTES);

/** rosterlock TTL: bounded so a crashed writer self-heals. */
export const ROSTER_LOCK_TTL_SEC = 5;

interface AccountRecord {
  v: 1;
  username: string;
  verifier_hex: string;
  server_salt_hex: string;
  auth_salt_hex: string;
  wrap_salt_hex: string;
  wrapped_dek_hex: string;
  dek_nonce_hex: string;
  created_ms: number;
}

interface RosterRecord {
  v: 1;
  ciphertext_hex: string;
  nonce_hex: string;
  version: number;
}

interface SessionRecord {
  v: 1;
  username: string;
  expires_ms: number;
}

/** One request's full outcome (the HTTP layer maps this to status + JSON). */
export type AccountCallResult =
  | { ok: true; body: AccountResponseAction }
  | {
      ok: false;
      error: AccountErrorCode;
      detail?: string;
      retry_after_s?: number;
      current_version?: number;
    };

export interface AccountCallContext {
  /** Client IP (last x-forwarded-for entry, else socket address). */
  ip: string;
  /** Bearer token from the Authorization header (null when absent). */
  token: string | null;
}

function sha256hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

/**
 * Deterministic decoy salt for an unknown username: first 16 bytes of
 * sha256("account-decoy|{username}|{kind}") — hex(32), byte-identical in
 * shape to a real salt, stable across instances (no per-process randomness,
 * so retries and multi-region answers agree).
 */
export function decoySaltHex(username: string, kind: 'auth' | 'wrap'): string {
  return createHash('sha256')
    .update(`account-decoy|${username}|${kind}`, 'utf8')
    .digest()
    .subarray(0, 16)
    .toString('hex');
}

export class AccountService {
  constructor(
    private readonly store: Store,
    private readonly cfg: SignalingConfig,
  ) {}

  private k(kind: string, id: string): string {
    return `${this.cfg.prefix}${kind}:${id}`;
  }

  // -------------------------------------------------------------------------
  // Entry point (one call = one logged outcome, never any key material)
  // -------------------------------------------------------------------------

  async call(req: AccountRequest, ctx: AccountCallContext): Promise<AccountCallResult> {
    // Bearer actions log the AUTHENTICATED username (the session's owner);
    // anonymous actions log the username they carry.
    let user = 'username' in req ? req.username : '-';
    const result = await this.dispatch(req, ctx, (authed: string) => {
      user = authed;
    });
    log.info(
      'account_call',
      { action: req.action, user, outcome: result.ok ? 'ok' : result.error },
      'account',
    );
    return result;
  }

  private async dispatch(
    req: AccountRequest,
    ctx: AccountCallContext,
    onAuth: (username: string) => void,
  ): Promise<AccountCallResult> {
    switch (req.action) {
      case 'register':
        return this.register(req, ctx.ip);
      case 'login_pre':
        return this.loginPre(req, ctx.ip);
      case 'login':
        return this.login(req, ctx.ip);
      case 'logout':
      case 'roster_get':
      case 'roster_put':
      case 'presence': {
        if (ctx.token === null) {
          return { ok: false, error: ACCOUNT_ERROR_CODES.UNAUTHORIZED };
        }
        const username = await this.authenticate(ctx.token);
        if (username === null) {
          return { ok: false, error: ACCOUNT_ERROR_CODES.UNAUTHORIZED };
        }
        onAuth(username);
        switch (req.action) {
          case 'logout':
            return this.logout(ctx.token);
          case 'roster_get':
            return this.rosterGet(username);
          case 'roster_put':
            return this.rosterPut(username, req);
          case 'presence':
            return this.presence(username, req);
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // Rate limiting (fixed window: INCR + EXPIRE-on-first + start timestamp)
  // -------------------------------------------------------------------------

  /**
   * Fixed-window limiter. Returns null when allowed, else `retry_after_s`
   * (computed from the window-start companion key `rlt:`; falls back to the
   * full window when that key is unavailable). Counters are only incremented
   * for requests that passed schema validation — malformed traffic is
   * rejected upstream and never consumes a user's quota. Key shape:
   * `{prefix}rl:{bucket}:{key}` where `bucket` names the limit
   * (e.g. `login-user`) and `key` is the username or IP.
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
        // Self-heal (security review P2-3): the counter outlived its window
        // metadata (instance died between INCR and EXPIRE, or the start key
        // was lost). Re-arm the TTL so the bucket cannot 429 forever —
        // without this, one failed EXPIRE locks a username in permanently.
        await this.store.expireAfterIncr(countKey, windowSec);
        await this.store.setNxEx(startKey, String(Date.now()), windowSec);
      }
      const clamped = Math.min(retryAfterS, windowSec);
      log.warn('account_rate_limited', { bucket: bucketAndKey.split(':')[0] ?? '-', retry_after_s: clamped }, 'account');
      return clamped;
    }
    return null;
  }

  // -------------------------------------------------------------------------
  // Register / login
  // -------------------------------------------------------------------------

  private async scryptHex(authKey: string, salt: Buffer): Promise<string> {
    const out = (await scrypt(authKey, salt, SCRYPT_KEYLEN_BYTES, { ...SCRYPT_COST })) as Buffer;
    return out.toString('hex');
  }

  private async mintSession(username: string): Promise<{ session_token: string; expires_ms: number }> {
    const token = randomBytes(32).toString('hex');
    const expires_ms = Date.now() + this.cfg.ttlAccountSessionSec * 1000;
    const rec: SessionRecord = { v: 1, username, expires_ms };
    // Store ONLY the sha256 of the token; the raw token exists in this
    // process frame and the client's hands, nowhere else.
    await this.store.setEx(this.k('sess', sha256hex(token)), JSON.stringify(rec), this.cfg.ttlAccountSessionSec);
    return { session_token: token, expires_ms };
  }

  private async register(
    req: Extract<AccountRequest, { action: 'register' }>,
    ip: string,
  ): Promise<AccountCallResult> {
    const limited = await this.rateLimit(`reg-ip:${ip}`, this.cfg.rlRegisterPerHour, 3_600);
    if (limited !== null) {
      return { ok: false, error: ACCOUNT_ERROR_CODES.RATE_LIMITED, retry_after_s: limited };
    }
    // Global ceiling (security review P2-5): per-IP limits are defeated by
    // rotating addresses; this bounds total 10-year account-record minting
    // (store cost) regardless of source.
    const limitedGlobal = await this.rateLimit('reg-global:all', this.cfg.rlRegisterGlobalPerDay, 86_400);
    if (limitedGlobal !== null) {
      return { ok: false, error: ACCOUNT_ERROR_CODES.RATE_LIMITED, retry_after_s: limitedGlobal };
    }
    const serverSalt = randomBytes(16);
    const verifierHex = await this.scryptHex(req.auth_key, serverSalt);
    const rec: AccountRecord = {
      v: 1,
      username: req.username,
      verifier_hex: verifierHex,
      server_salt_hex: serverSalt.toString('hex'),
      auth_salt_hex: req.auth_salt_hex,
      wrap_salt_hex: req.wrap_salt_hex,
      wrapped_dek_hex: req.wrapped_dek_hex,
      dek_nonce_hex: req.dek_nonce_hex,
      created_ms: Date.now(),
    };
    // Atomic claim: SETNX makes concurrent registers for one username a race
    // with exactly one winner — no read-then-write `username_taken` window.
    const claimed = await this.store.setNxEx(
      this.k('acct', req.username),
      JSON.stringify(rec),
      this.cfg.ttlAccountSec,
    );
    if (!claimed) {
      return { ok: false, error: ACCOUNT_ERROR_CODES.USERNAME_TAKEN };
    }
    const session = await this.mintSession(req.username);
    return { ok: true, body: { action: 'register', ...session } };
  }

  private parseAccount(raw: string | null): AccountRecord | null {
    if (raw === null) return null;
    try {
      const rec = JSON.parse(raw) as AccountRecord;
      if (
        rec &&
        rec.v === 1 &&
        typeof rec.username === 'string' &&
        USERNAME_RE.test(rec.username) &&
        typeof rec.verifier_hex === 'string' &&
        typeof rec.server_salt_hex === 'string' &&
        typeof rec.auth_salt_hex === 'string' &&
        typeof rec.wrap_salt_hex === 'string' &&
        typeof rec.wrapped_dek_hex === 'string' &&
        typeof rec.dek_nonce_hex === 'string'
      ) {
        return rec;
      }
      return null;
    } catch {
      return null;
    }
  }

  private async loginPre(
    req: Extract<AccountRequest, { action: 'login_pre' }>,
    ip: string,
  ): Promise<AccountCallResult> {
    const limited = await this.rateLimit(`pre-ip:${ip}`, this.cfg.rlLoginPrePerMin, 60);
    if (limited !== null) {
      return { ok: false, error: ACCOUNT_ERROR_CODES.RATE_LIMITED, retry_after_s: limited };
    }
    const rec = this.parseAccount(await this.store.get(this.k('acct', req.username)));
    if (rec !== null) {
      return {
        ok: true,
        body: { action: 'login_pre', auth_salt_hex: rec.auth_salt_hex, wrap_salt_hex: rec.wrap_salt_hex },
      };
    }
    // Unknown (or corrupt) username: deterministic decoys, byte-identical
    // response shape — existence is not disclosed.
    return {
      ok: true,
      body: {
        action: 'login_pre',
        auth_salt_hex: decoySaltHex(req.username, 'auth'),
        wrap_salt_hex: decoySaltHex(req.username, 'wrap'),
      },
    };
  }

  private async login(
    req: Extract<AccountRequest, { action: 'login' }>,
    ip: string,
  ): Promise<AccountCallResult> {
    // Both buckets up front: per-username stops credential stuffing on one
    // account, per-IP stops spraying many accounts from one host. Neither
    // answer runs scrypt before passing.
    const limitedUser = await this.rateLimit(`login-user:${req.username}`, this.cfg.rlLoginPerUserPer15m, 900);
    if (limitedUser !== null) {
      return { ok: false, error: ACCOUNT_ERROR_CODES.RATE_LIMITED, retry_after_s: limitedUser };
    }
    const limitedIp = await this.rateLimit(`login-ip:${ip}`, this.cfg.rlLoginPerIpPer15m, 900);
    if (limitedIp !== null) {
      return { ok: false, error: ACCOUNT_ERROR_CODES.RATE_LIMITED, retry_after_s: limitedIp };
    }
    const rec = this.parseAccount(await this.store.get(this.k('acct', req.username)));
    if (rec === null) {
      // Dummy scrypt against module-constant salt/verifier: same work, same
      // error, same rough latency as the real path — the response must not
      // distinguish "no such user" from "wrong password".
      const dummy = Buffer.from(await this.scryptHex(req.auth_key, DUMMY_SERVER_SALT), 'hex');
      void timingSafeEqual(dummy, DUMMY_VERIFIER); // always false; latency parity only
      return { ok: false, error: ACCOUNT_ERROR_CODES.INVALID_CREDENTIALS };
    }
    const computed = Buffer.from(await this.scryptHex(req.auth_key, Buffer.from(rec.server_salt_hex, 'hex')), 'hex');
    const stored = Buffer.from(rec.verifier_hex, 'hex');
    if (computed.length !== stored.length || !timingSafeEqual(computed, stored)) {
      return { ok: false, error: ACCOUNT_ERROR_CODES.INVALID_CREDENTIALS };
    }
    const session = await this.mintSession(rec.username);
    return {
      ok: true,
      body: {
        action: 'login',
        ...session,
        // Echoed so a new machine can unwrap its roster without re-sending
        // key material (see protocol::account docs).
        wrapped_dek_hex: rec.wrapped_dek_hex,
        dek_nonce_hex: rec.dek_nonce_hex,
      },
    };
  }

  // -------------------------------------------------------------------------
  // Sessions (bearer auth)
  // -------------------------------------------------------------------------

  /** Resolve a bearer token to its username; null when absent/expired/malformed. */
  async authenticate(token: string): Promise<string | null> {
    if (!SESSION_TOKEN_RE.test(token)) {
      // Shape check first: a bogus token costs zero store round trips.
      return null;
    }
    const key = this.k('sess', sha256hex(token));
    const raw = await this.store.get(key);
    if (raw === null) return null;
    try {
      const rec = JSON.parse(raw) as SessionRecord;
      if (
        rec &&
        rec.v === 1 &&
        typeof rec.username === 'string' &&
        USERNAME_RE.test(rec.username) &&
        typeof rec.expires_ms === 'number'
      ) {
        if (rec.expires_ms > Date.now()) {
          return rec.username;
        }
        // Expired but not yet swept: drop it now (the key TTL is the outer bound).
        await this.store.del(key);
        return null;
      }
      return null;
    } catch {
      return null;
    }
  }

  /** Invalidate exactly the presented token (the caller is authenticated). */
  private async logout(token: string): Promise<AccountCallResult> {
    await this.store.del(this.k('sess', sha256hex(token)));
    return { ok: true, body: { action: 'logout' } };
  }

  // -------------------------------------------------------------------------
  // Roster (encrypted blob + optimistic concurrency)
  // -------------------------------------------------------------------------

  private parseRoster(raw: string | null): RosterRecord | null {
    if (raw === null) return null;
    try {
      const rec = JSON.parse(raw) as RosterRecord;
      if (
        rec &&
        rec.v === 1 &&
        typeof rec.ciphertext_hex === 'string' &&
        typeof rec.nonce_hex === 'string' &&
        typeof rec.version === 'number' &&
        Number.isInteger(rec.version) &&
        rec.version >= 0
      ) {
        return rec;
      }
      return null;
    } catch {
      return null;
    }
  }

  private async rosterVersion(username: string): Promise<number> {
    const rec = this.parseRoster(await this.store.get(this.k('roster', username)));
    return rec === null ? 0 : rec.version;
  }

  private async rosterGet(username: string): Promise<AccountCallResult> {
    const rec = this.parseRoster(await this.store.get(this.k('roster', username)));
    if (rec === null) {
      return { ok: true, body: { action: 'roster_get', ciphertext_hex: '', nonce_hex: '', version: 0 } };
    }
    return {
      ok: true,
      body: {
        action: 'roster_get',
        ciphertext_hex: rec.ciphertext_hex,
        nonce_hex: rec.nonce_hex,
        version: rec.version,
      },
    };
  }

  private async rosterPut(
    username: string,
    req: Extract<AccountRequest, { action: 'roster_put' }>,
  ): Promise<AccountCallResult> {
    // Size cap BEFORE any store access (well-formed but oversize ciphertext
    // is its own typed 413, not `malformed` — the schema pins shape only).
    const decodedBytes = req.ciphertext_hex.length / 2;
    if (decodedBytes > this.cfg.rosterMaxCiphertextBytes) {
      return {
        ok: false,
        error: ACCOUNT_ERROR_CODES.ROSTER_TOO_LARGE,
        detail: `ciphertext is ${decodedBytes} bytes; cap is ${this.cfg.rosterMaxCiphertextBytes}`,
      };
    }
    const limited = await this.rateLimit(`roster-user:${username}`, this.cfg.rlRosterPutPerMin, 60);
    if (limited !== null) {
      return { ok: false, error: ACCOUNT_ERROR_CODES.RATE_LIMITED, retry_after_s: limited };
    }
    // Optimistic concurrency without CAS: a short-lived SETNX lock serializes
    // the read-version/write critical section (store calls only). Busy
    // (another writer holds the lock) and stale `base_version` both answer
    // `roster_conflict` with the CURRENT version so the client can rebase.
    const lockKey = this.k('rosterlock', username);
    const acquired = await this.store.setNxEx(lockKey, '1', ROSTER_LOCK_TTL_SEC);
    if (!acquired) {
      return {
        ok: false,
        error: ACCOUNT_ERROR_CODES.ROSTER_CONFLICT,
        current_version: await this.rosterVersion(username),
      };
    }
    try {
      const current = await this.rosterVersion(username);
      if (current !== req.base_version) {
        return {
          ok: false,
          error: ACCOUNT_ERROR_CODES.ROSTER_CONFLICT,
          current_version: current,
        };
      }
      const version = current + 1;
      const rec: RosterRecord = {
        v: 1,
        ciphertext_hex: req.ciphertext_hex,
        nonce_hex: req.nonce_hex,
        version,
      };
      await this.store.setEx(this.k('roster', username), JSON.stringify(rec), this.cfg.ttlAccountSec);
      return { ok: true, body: { action: 'roster_put', version } };
    } finally {
      // Always release — including the conflict returns above. A crashed
      // writer is healed by the lock TTL instead of deadlocking the username.
      await this.store.del(lockKey);
    }
  }

  // -------------------------------------------------------------------------
  // Presence (read-only over the signaling surface)
  // -------------------------------------------------------------------------

  private async presence(
    username: string,
    req: Extract<AccountRequest, { action: 'presence' }>,
  ): Promise<AccountCallResult> {
    const limited = await this.rateLimit(`pres-user:${username}`, this.cfg.rlPresencePerMin, 60);
    if (limited !== null) {
      return { ok: false, error: ACCOUNT_ERROR_CODES.RATE_LIMITED, retry_after_s: limited };
    }
    // A code is online iff the signaling presence key exists. Presence never
    // authenticates the QUERIED devices — only the caller's session is proven.
    const online: string[] = [];
    for (const code of req.codes) {
      const present = await this.store.get(this.k('p', code));
      if (present !== null) online.push(code);
    }
    return { ok: true, body: { action: 'presence', online } };
  }
}
