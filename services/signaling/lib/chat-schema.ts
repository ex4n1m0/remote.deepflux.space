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
 */

import { z } from 'zod';

export const CHAT_PROTOCOL_VERSION = 1;

/** Ciphertext cap (hex chars) ≈ 16 KB of plaintext headroom for chat. */
export const CHAT_MAX_CT_HEX = 40_000;

export const DEVICE_ID_RE = /^[0-9a-f]{16}$/;
export const NONCE_HEX_RE = /^[0-9a-f]{24}$/;
export const HEX_RE = /^[0-9a-f]+$/;

export const chatEnvelopeSchema = z.object({
  v: z.literal(CHAT_PROTOCOL_VERSION),
  from: z.string().regex(DEVICE_ID_RE),
  nonce_hex: z.string().regex(NONCE_HEX_RE),
  ct_hex: z.string().regex(HEX_RE).max(CHAT_MAX_CT_HEX),
  ts_ms: z.number().int().nonnegative(),
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
