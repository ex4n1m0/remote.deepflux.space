/**
 * Environment-tunable configuration (defaults per source plan RD-009/010;
 * account/roster knobs per the post-MVP accounts patch, 2026-10-01).
 *
 * Every value has an expiry or bound; nothing lives forever and nothing is
 * unbounded (AGENTS.md invariant 3 applied to the control plane). The
 * account-TTL exception is deliberate: account/roster records are the one
 * DURABLE thing this control plane stores (10-year default TTL so records do
 * not silently expire underneath users) — everything else stays ephemeral.
 */

function intEnv(name: string, def: number, min: number, max: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') {
    return def;
  }
  const n = Number(raw);
  if (!Number.isFinite(n)) {
    return def;
  }
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

export interface SignalingConfig {
  /** Presence TTL refreshed by Register/Heartbeat (source plan: 30-60 s). */
  readonly ttlDeviceSec: number;
  /** Mailbox TTL: outer bound for undelivered envelopes (2-5 min). */
  readonly ttlMailboxSec: number;
  /** Session record TTL (5-10 min). */
  readonly ttlSessionSec: number;
  /** message_id dedupe window. */
  readonly ttlDedupeSec: number;
  /** Max entries retained per device mailbox. */
  readonly mailboxMax: number;
  /** Max entries returned per drain/poll. */
  readonly mailboxBatch: number;
  /** Max accepted envelope JSON size in bytes. */
  readonly envelopeMaxBytes: number;
  /** Mailbox drain interval per live WS connection. */
  readonly wsPollMs: number;
  /** Send `bye` and close a WS connection after this long (resume follows). */
  readonly maxConnectionSec: number;
  /** Redis key namespace. */
  readonly prefix: string;
  // --- account & roster API (POST /api/account) -----------------------------
  /** Account session-token TTL (default 30 days). */
  readonly ttlAccountSessionSec: number;
  /** Account + roster record TTL (default ~10 years; Upstash accepts it). */
  readonly ttlAccountSec: number;
  /** Decoded-byte cap for roster ciphertext (oversize answers 413). */
  readonly rosterMaxCiphertextBytes: number;
  /** Rate limits (fixed windows; see lib/account-service.ts key shapes). */
  readonly rlRegisterPerHour: number;
  /** Global register ceiling (all IPs combined) — bounds 10-year KV minting. */
  readonly rlRegisterGlobalPerDay: number;
  readonly rlLoginPrePerMin: number;
  readonly rlLoginPerUserPer15m: number;
  readonly rlLoginPerIpPer15m: number;
  readonly rlRosterPutPerMin: number;
  readonly rlPresencePerMin: number;
}

export function loadConfig(): SignalingConfig {
  return {
    ttlDeviceSec: intEnv('SIGNALING_TTL_DEVICE_SECONDS', 45, 1, 86_400),
    ttlMailboxSec: intEnv('SIGNALING_TTL_MAILBOX_SECONDS', 180, 1, 86_400),
    ttlSessionSec: intEnv('SIGNALING_TTL_SESSION_SECONDS', 480, 1, 86_400),
    ttlDedupeSec: intEnv('SIGNALING_TTL_DEDUPE_SECONDS', 120, 1, 86_400),
    mailboxMax: intEnv('SIGNALING_MAILBOX_MAX', 256, 1, 10_000),
    mailboxBatch: intEnv('SIGNALING_MAILBOX_BATCH', 64, 1, 1_000),
    envelopeMaxBytes: intEnv('SIGNALING_ENVELOPE_MAX_BYTES', 32_768, 512, 1 << 20),
    wsPollMs: intEnv('SIGNALING_WS_POLL_MS', 250, 50, 10_000),
    maxConnectionSec: intEnv('SIGNALING_MAX_CONNECTION_SECONDS', 290, 1, 3_600),
    prefix: process.env['SIGNALING_STORE_PREFIX'] ?? 'sg1:',
    ttlAccountSessionSec: intEnv('SIGNALING_TTL_ACCOUNT_SESSION_SECONDS', 2_592_000, 60, 315_532_800),
    ttlAccountSec: intEnv('SIGNALING_TTL_ACCOUNT_SECONDS', 315_532_800, 3_600, 2_000_000_000),
    rosterMaxCiphertextBytes: intEnv('SIGNALING_ROSTER_MAX_CIPHERTEXT_BYTES', 65_536, 1_024, 1 << 20),
    rlRegisterPerHour: intEnv('SIGNALING_RL_REGISTER_PER_HOUR', 10, 1, 100_000),
    rlRegisterGlobalPerDay: intEnv('SIGNALING_RL_REGISTER_GLOBAL_PER_DAY', 500, 1, 1_000_000),
    rlLoginPrePerMin: intEnv('SIGNALING_RL_LOGIN_PRE_PER_MIN', 120, 1, 100_000),
    rlLoginPerUserPer15m: intEnv('SIGNALING_RL_LOGIN_PER_USER_15M', 20, 1, 100_000),
    rlLoginPerIpPer15m: intEnv('SIGNALING_RL_LOGIN_PER_IP_15M', 60, 1, 100_000),
    rlRosterPutPerMin: intEnv('SIGNALING_RL_ROSTER_PUT_PER_MIN', 60, 1, 100_000),
    rlPresencePerMin: intEnv('SIGNALING_RL_PRESENCE_PER_MIN', 60, 1, 100_000),
  };
}
