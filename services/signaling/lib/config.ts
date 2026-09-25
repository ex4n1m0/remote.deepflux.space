/**
 * Environment-tunable configuration (defaults per source plan RD-009/010).
 *
 * Every value has an expiry or bound; nothing lives forever and nothing is
 * unbounded (AGENTS.md invariant 3 applied to the control plane).
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
  };
}
