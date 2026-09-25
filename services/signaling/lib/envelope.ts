/**
 * THE wire contract mirror: `crates/protocol/src/signaling.rs`.
 *
 * These zod schemas are the TypeScript side of the signaling envelope
 * contract (delta D7). Field names are stable snake_case; the flat `type`
 * discriminant; `protocol_version` is 1. They are pinned byte-for-byte by
 * the golden fixtures exported from the Rust crate
 * (`crates/node-runtime/tests/signaling_fixtures.rs` writes
 * `fixtures/golden/*.json`; `scripts/validate-wires.mjs` validates them
 * against these schemas) — a rename on either side fails validation.
 *
 * serde policy mirrored here:
 *  - unknown ADDITIVE fields are tolerated (zod strips them),
 *  - `session_id` is always present on the wire (`null` when absent),
 *  - `protocol_version` is checked on the raw value BEFORE body parsing so
 *    a v0 payload cannot be mistaken for a validation error.
 */
import { z } from 'zod';

export const SIGNALING_PROTOCOL_VERSION = 1 as const;
export const SIGNALING_SERVICE_ID = 'signaling';

/** Error envelope codes minted by this service (machine-readable). */
export const ERROR_CODES = {
  BAD_VERSION: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN_FROM: 403,
  UNKNOWN_TARGET: 404,
  MALFORMED: 422,
  TOO_LARGE: 413,
  INTERNAL: 500,
} as const;

// ---------------------------------------------------------------------------
// Capabilities (mirror of protocol::capabilities)
// ---------------------------------------------------------------------------

export const codecSchema = z.literal('H264');
export const encoderKindSchema = z.union([z.literal('Hardware'), z.literal('Software')]);

export const encoderCapabilitiesSchema = z.object({
  kind: encoderKindSchema,
  codec: codecSchema,
  max_width_px: z.number().int().nonnegative(),
  max_height_px: z.number().int().nonnegative(),
  max_fps: z.number().int().nonnegative(),
});

export const monitorInfoSchema = z.object({
  monitor_id: z.string().min(1),
  width_px: z.number().int().nonnegative(),
  height_px: z.number().int().nonnegative(),
  is_primary: z.boolean(),
});

export const capabilitiesSchema = z.object({
  encoders: z.array(encoderCapabilitiesSchema),
  monitors: z.array(monitorInfoSchema),
  max_bitrate_kbps: z.number().int().nonnegative(),
  features: z.number().int().nonnegative(),
});

// ---------------------------------------------------------------------------
// Envelope (mirror of protocol::signaling)
// ---------------------------------------------------------------------------

export const envelopeBaseSchema = z.object({
  protocol_version: z.number().int().nonnegative(),
  message_id: z.string().min(1).max(128),
  session_id: z.string().min(1).nullable(),
  from_device_id: z.string().min(1).max(64),
  to_device_id: z.string().min(1).max(64),
  timestamp_ms: z.number().int().nonnegative(),
});

export const signalingBodySchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('register'), capabilities: capabilitiesSchema }),
  z.object({ type: z.literal('heartbeat') }),
  z.object({ type: z.literal('connect_request'), capabilities: capabilitiesSchema }),
  z.object({ type: z.literal('accept'), session_secret: z.string().min(1) }),
  z.object({ type: z.literal('reject'), reason: z.enum(['busy', 'declined', 'timeout', 'unavailable']) }),
  z.object({ type: z.literal('offer'), sdp: z.string().min(1) }),
  z.object({ type: z.literal('answer'), sdp: z.string().min(1) }),
  z.object({
    type: z.literal('ice_candidate'),
    candidate: z.string(),
    sdp_mid: z.string().nullable(),
    sdp_mline_index: z.number().int().nonnegative().max(65535).nullable(),
  }),
  z.object({ type: z.literal('ice_complete') }),
  z.object({ type: z.literal('cancel'), reason: z.enum(['user', 'collision']) }),
  z.object({ type: z.literal('disconnect'), reason: z.enum(['user', 'timeout', 'transport_error']) }),
  z.object({ type: z.literal('error'), code: z.number().int().nonnegative(), detail: z.string() }),
]);

/** The full flattened envelope (body fields merged to the top level). */
export const signalingEnvelopeSchema = envelopeBaseSchema.and(signalingBodySchema);

export type Capabilities = z.infer<typeof capabilitiesSchema>;
export type SignalingEnvelope = z.infer<typeof signalingEnvelopeSchema>;
export type SignalingBody = z.infer<typeof signalingBodySchema>;

/** Body types that carry (or may carry) a session. */
const SESSION_SCOPED = new Set([
  'connect_request',
  'accept',
  'reject',
  'offer',
  'answer',
  'ice_candidate',
  'ice_complete',
  'cancel',
  'disconnect',
  'error',
]);

export function isSessionScoped(type: string): boolean {
  return SESSION_SCOPED.has(type);
}

export function isServiceDirected(env: SignalingEnvelope): boolean {
  return env.to_device_id === SIGNALING_SERVICE_ID;
}

/** A fresh message_id minted by the service for its own error envelopes. */
export function serviceMessageId(detail: string): string {
  // Deterministic-ish, unique per call: time + random suffix. The Rust side
  // dedupes by message_id; service-minted ids never collide with device ids
  // ("signaling-" prefix, QA F1 namespace rule).
  return `signaling-${detail}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

export interface MintedError {
  protocol_version: typeof SIGNALING_PROTOCOL_VERSION;
  message_id: string;
  session_id: string | null;
  from_device_id: string;
  to_device_id: string;
  timestamp_ms: number;
  type: 'error';
  code: number;
  detail: string;
}

/**
 * Mint a typed `Error` envelope addressed to `toDevice`. This is the only
 * envelope shape the service creates; everything else is forwarded verbatim.
 */
export function mintErrorEnvelope(
  toDevice: string,
  code: number,
  detail: string,
  sessionId: string | null = null,
): MintedError {
  return {
    protocol_version: SIGNALING_PROTOCOL_VERSION,
    message_id: serviceMessageId('err'),
    session_id: sessionId,
    from_device_id: SIGNALING_SERVICE_ID,
    to_device_id: toDevice,
    timestamp_ms: Date.now(),
    type: 'error',
    code,
    detail,
  };
}
