/**
 * THE circle-directory wire-contract mirror: `crates/protocol/src/directory.rs`
 * (ADR-006). Fourth JSON surface owned by the Rust crate; same wire policy as
 * `lib/account-schema.ts`: stable snake_case keys, flat `action` discriminant,
 * `protocol_version` 1, additive-optional tolerance within a version. Pinned
 * byte-for-byte by the golden fixtures exported from the Rust crate
 * (`crates/node-runtime/tests/directory_fixtures.rs` writes
 * `fixtures/directory/{request,response,reject}/*.json`;
 * `scripts/validate-wires.mjs` validates them against these schemas).
 *
 * The service stores SEALED entries only: `ciphertext_hex`/`nonce_hex` are
 * AES-256-GCM under the client-held circle key (the server sees device ids,
 * ciphertext, server-minted timestamps, and online flags — never nicknames).
 *
 * Size caps that have their own typed error (`entry_too_large`, HTTP 413) are
 * deliberately NOT in the schema — shape vs size, same split as the roster.
 */
import { z } from 'zod';

export const DIRECTORY_PROTOCOL_VERSION = 1 as const;

/** circle_id is sha256 output: 32 bytes -> 64 hex chars. */
export const CIRCLE_ID_HEX_LEN = 64;
/** AES-GCM nonces: 12 bytes -> 24 hex chars. */
export const NONCE_HEX_LEN = 24;
/** Device ids: the 16-hex signaling connection codes (chat parity). */
export const DEVICE_CODE_RE = /^[0-9a-f]{16}$/;

export const DIRECTORY_MAX_MEMBERS = 128;
/** Sealed-entry ciphertext cap BEFORE hex encoding (service answers 413). */
export const DIRECTORY_ENTRY_MAX_BYTES = 2_048;

const LOWER_HEX_RE = /^[0-9a-f]+$/;

const hexBytes = (bytes: number) =>
  z.string().regex(LOWER_HEX_RE, `expected ${bytes * 2} lowercase hex chars`).length(bytes * 2);

/** Even-length lowercase hex of any size (ciphertext; size gated in the service). */
const evenHexSchema = z.string().regex(/^(?:[0-9a-f]{2})+$/, 'expected even-length lowercase hex');

export const circleIdSchema = hexBytes(CIRCLE_ID_HEX_LEN / 2);
export const nonceSchema = hexBytes(NONCE_HEX_LEN / 2);
export const deviceSchema = z
  .string()
  .regex(DEVICE_CODE_RE, 'expected a 16-hex device id (lowercase)');

const directoryActionSchema = z.discriminatedUnion('action', [
  z.object({
    action: z.literal('put'),
    device: deviceSchema,
    circle_id: circleIdSchema,
    ciphertext_hex: evenHexSchema,
    nonce_hex: nonceSchema,
  }),
  z.object({
    action: z.literal('list'),
    device: deviceSchema,
    circle_id: circleIdSchema,
  }),
  z.object({
    action: z.literal('remove'),
    device: deviceSchema,
    circle_id: circleIdSchema,
  }),
]);

/** `protocol_version: 1` is required — a camelCase probe fails as malformed
 *  (missing version), exactly like the account mirror. */
const versionedSchema = z.object({ protocol_version: z.literal(DIRECTORY_PROTOCOL_VERSION) });

export const directoryRequestSchema = versionedSchema.and(directoryActionSchema);

export type DirectoryRequest = { protocol_version: typeof DIRECTORY_PROTOCOL_VERSION } &
  z.infer<typeof directoryActionSchema>;

export const KNOWN_DIRECTORY_ACTIONS = ['put', 'list', 'remove'] as const;

/** Machine-readable service error codes (mirror of protocol::directory::error_code). */
export const DIRECTORY_ERROR_CODES = {
  UNSUPPORTED_VERSION: 'unsupported_version',
  MALFORMED: 'malformed',
  UNKNOWN_ACTION: 'unknown_action',
  UNAUTHORIZED: 'unauthorized',
  CIRCLE_FULL: 'circle_full',
  ENTRY_TOO_LARGE: 'entry_too_large',
  TOO_LARGE: 'too_large',
  RATE_LIMITED: 'rate_limited',
  STORE_UNAVAILABLE: 'store_unavailable',
  INTERNAL: 'internal',
} as const;

/** HTTP status per error code (mirrors accountStatusFor's mapping style). */
export function directoryStatusFor(error: string): number {
  switch (error) {
    case DIRECTORY_ERROR_CODES.MALFORMED:
    case DIRECTORY_ERROR_CODES.UNSUPPORTED_VERSION:
    case DIRECTORY_ERROR_CODES.UNKNOWN_ACTION:
      return 400;
    case DIRECTORY_ERROR_CODES.UNAUTHORIZED:
      return 401;
    case DIRECTORY_ERROR_CODES.CIRCLE_FULL:
      return 409;
    case DIRECTORY_ERROR_CODES.ENTRY_TOO_LARGE:
    case DIRECTORY_ERROR_CODES.TOO_LARGE:
      return 413;
    case DIRECTORY_ERROR_CODES.RATE_LIMITED:
      return 429;
    case DIRECTORY_ERROR_CODES.STORE_UNAVAILABLE:
      return 503;
    default:
      return 500;
  }
}
