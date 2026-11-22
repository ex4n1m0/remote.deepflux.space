/**
 * Machine-chat inbox wire contract (ADR-005 RD-022, protocol version 1).
 *
 * The endpoint carries SEALED envelopes only — AES-256-GCM ciphertext the
 * clients sealed under their pairing secret. The service can neither read
 * nor forge messages (invariant 2: control plane carries envelopes, never
 * plaintext user data).
 *
 *   PUT /api/chat            { to, envelope }        → { ok }
 *   GET /api/chat?device=…   (drain, Bearer token)  → { ok, envelopes: [] }
 *
 * Envelope fields (all snake_case, hex lowercase — binary fields are
 * `*_hex` per the account-surface convention):
 *   v         1
 *   from      sender device id (16 hex)
 *   nonce_hex 12 bytes (24 hex)
 *   ct_hex    ciphertext (variable; ≤ CHAT_MAX_CT_HEX hex chars)
 *   ts_ms     sender wall clock (display + TTL hint)
 *
 * ADR-013 P3 fleet slice 2 (additive-optional; version stays 1):
 *   agent         optional bool (default false) — routing HINT only
 *   fleet_call_id optional string (≤ 128 chars) — fleet correlation HINT
 *
 * Both hints ride OUTSIDE the seal, so the service stores and returns
 * them opaquely and must never act on them: the AUTHORITATIVE agent bit
 * and fleet id live INSIDE ct_hex (a v2 sealed JSON payload —
 * `{v:2, body, agent, fleet_call_id?}` — under the pairing secret; v1
 * payloads are plain text). A v1 client ignores the hints (unknown keys)
 * and a v1 server strips them (zod) — either way the sealed payload is
 * untouched, so degradation is safe: no hint ever causes a wake.
 */

import { z } from 'zod';

export const CHAT_PROTOCOL_VERSION = 1;

/** Ciphertext cap (hex chars) ≈ 16 KB of plaintext headroom for chat. */
export const CHAT_MAX_CT_HEX = 40_000;

export const DEVICE_ID_RE = /^[0-9a-f]{16}$/;
export const NONCE_HEX_RE = /^[0-9a-f]{24}$/;
export const HEX_RE = /^[0-9a-f]+$/;

/** Fleet correlation id cap (outside-seal hint; bounded storage). */
export const CHAT_MAX_FLEET_CALL_ID_LEN = 128;

export const chatEnvelopeSchema = z.object({
  v: z.literal(CHAT_PROTOCOL_VERSION),
  from: z.string().regex(DEVICE_ID_RE),
  nonce_hex: z.string().regex(NONCE_HEX_RE),
  ct_hex: z.string().regex(HEX_RE).max(CHAT_MAX_CT_HEX),
  ts_ms: z.number().int().nonnegative(),
  // ADR-013 P3 slice 2: additive-optional routing hints, passed through
  // opaquely (the service never interprets them — see the header note).
  agent: z.boolean().optional().default(false),
  fleet_call_id: z.string().max(CHAT_MAX_FLEET_CALL_ID_LEN).optional(),
});

export const chatPutRequestSchema = z.object({
  to: z.string().regex(DEVICE_ID_RE),
  envelope: chatEnvelopeSchema,
});

export const chatGetResponseSchema = z.object({
  ok: z.literal(true),
  envelopes: z.array(chatEnvelopeSchema),
});

export type ChatEnvelope = z.infer<typeof chatEnvelopeSchema>;
export type ChatPutRequest = z.infer<typeof chatPutRequestSchema>;
