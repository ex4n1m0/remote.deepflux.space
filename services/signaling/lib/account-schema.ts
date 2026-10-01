/**
 * THE account/roster wire-contract mirror: `crates/protocol/src/account.rs`.
 *
 * The account API is the second JSON surface owned by `crates/protocol`
 * (post-MVP accounts phase). Same wire policy as `lib/envelope.ts`: stable
 * snake_case keys, flat `action` discriminant (no `type`, no nested body),
 * `protocol_version` 1, additive-optional tolerance within a version. Pinned
 * byte-for-byte by the golden fixtures exported from the Rust crate
 * (`crates/node-runtime/tests/account_fixtures.rs` writes
 * `fixtures/account/{request,response,reject}/*.json`; `scripts/validate-wires.mjs`
 * validates them against these schemas).
 *
 * serde policy mirrored here:
 *  - unknown ADDITIVE fields are tolerated (zod strips them); camelCase keys
 *    are NOT translated — a `protocolVersion`-only body fails as `malformed`,
 *  - `protocol_version` is checked on the RAW value before body parsing at
 *    the service (a PRESENT numeric version != 1 answers
 *    `unsupported_version`; a missing one falls through to the schema and
 *    fails as `malformed` — this is what the camelcase reject fixture pins).
 *
 * Binary values travel as lowercase hex (`*_hex`). Size caps that have their
 * own typed error (`roster_too_large`, HTTP 413) are deliberately NOT in the
 * schema — the schema pins SHAPE, the service pins SIZE, so a shape violation
 * is `malformed` (400) while an oversize-but-well-formed ciphertext is
 * `roster_too_large` (413).
 */
import { z } from 'zod';

export const ACCOUNT_PROTOCOL_VERSION = 1 as const;

// --- field-shape constants (mirror of protocol::account) ---------------------

export const USERNAME_MIN_CHARS = 3;
export const USERNAME_MAX_CHARS = 32;
/** scrypt output: 32 bytes -> 64 hex chars. */
export const AUTH_KEY_HEX_LEN = 64;
/** Salts: 16 bytes -> 32 hex chars. */
export const SALT_HEX_LEN = 32;
/** AES-GCM nonces: 12 bytes -> 24 hex chars. */
export const NONCE_HEX_LEN = 24;
/** Session tokens: 32 bytes -> 64 hex chars. */
export const SESSION_TOKEN_HEX_LEN = 64;

export const ROSTER_MAX_COMPUTERS = 128;
/** Ciphertext byte cap BEFORE hex encoding (service returns 413 above it). */
export const ROSTER_MAX_CIPHERTEXT_BYTES = 64 * 1024;
/** Maximum codes per `presence` query. */
export const PRESENCE_MAX_CODES = 50;

/**
 * Username rules: 3-32 chars of [a-z0-9._-], starting with a letter or digit.
 * Clients normalize to lowercase before sending; the service does not.
 */
export const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,31}$/;

/** Lowercase hex only — uppercase is rejected (normalize client-side). */
export const LOWER_HEX_RE = /^[0-9a-f]+$/;

/**
 * Device codes in `presence` queries are device ids exactly as used in
 * signaling envelopes (the `DEVICE_ID_RE` shape from `lib/server.ts`).
 */
export const DEVICE_CODE_RE = /^[A-Za-z0-9._-]{1,64}$/;

/** Lowercase hex of exactly `bytes` bytes. */
export function hexBytes(bytes: number): z.ZodString {
  return z.string().regex(LOWER_HEX_RE, `expected ${bytes * 2} lowercase hex chars`).length(bytes * 2);
}

/** Even-length lowercase hex (whole bytes), any size. */
export const evenHexSchema = z.string().regex(/^(?:[0-9a-f]{2})+$/, 'expected even-length lowercase hex');

/** Even-length lowercase hex within a decoded byte range [minBytes, maxBytes]. */
export function boundedHexSchema(minBytes: number, maxBytes: number): z.ZodEffects<z.ZodString> {
  return evenHexSchema.refine(
    (v) => {
      const n = v.length / 2;
      return n >= minBytes && n <= maxBytes;
    },
    { message: `decoded length must be ${minBytes}..${maxBytes} bytes` },
  );
}

export const usernameSchema = z.string().regex(USERNAME_RE, 'expected 3-32 chars of [a-z0-9._-], starting alphanumeric');
export const authKeySchema = hexBytes(AUTH_KEY_HEX_LEN / 2);
export const saltSchema = hexBytes(SALT_HEX_LEN / 2);
export const nonceSchema = hexBytes(NONCE_HEX_LEN / 2);
export const sessionTokenSchema = hexBytes(SESSION_TOKEN_HEX_LEN / 2);
export const versionSchema = z.number().int().nonnegative().max(0xffffffff);

/**
 * wrapped_dek_hex: AES-256-GCM wrap of the 32-byte DEK (48 bytes = 96 hex
 * with the 16-byte tag). Bounded rather than pinned so a future KDF/tag-size
 * change stays additive within the version (wire bumps remain explicit).
 */
export const wrappedDekSchema = boundedHexSchema(16, 128);

/** Device codes as used in signaling (see DEVICE_CODE_RE). */
export const deviceCodeSchema = z.string().regex(DEVICE_CODE_RE, 'expected a device id ([A-Za-z0-9._-]{1,64})');

// --- request (mirror of protocol::account::AccountRequest) --------------------

export const accountActionSchema = z.discriminatedUnion('action', [
  z.object({
    action: z.literal('register'),
    username: usernameSchema,
    auth_key: authKeySchema,
    auth_salt_hex: saltSchema,
    wrap_salt_hex: saltSchema,
    wrapped_dek_hex: wrappedDekSchema,
    dek_nonce_hex: nonceSchema,
  }),
  z.object({
    action: z.literal('login_pre'),
    username: usernameSchema,
  }),
  z.object({
    action: z.literal('login'),
    username: usernameSchema,
    auth_key: authKeySchema,
  }),
  z.object({ action: z.literal('logout') }),
  z.object({ action: z.literal('roster_get') }),
  z.object({
    action: z.literal('roster_put'),
    ciphertext_hex: evenHexSchema,
    nonce_hex: nonceSchema,
    base_version: versionSchema,
  }),
  z.object({
    action: z.literal('presence'),
    codes: z.array(deviceCodeSchema).min(1).max(PRESENCE_MAX_CODES),
  }),
]);

export const KNOWN_ACCOUNT_ACTIONS = [
  'register',
  'login_pre',
  'login',
  'logout',
  'roster_get',
  'roster_put',
  'presence',
] as const;

/** The full request body: action union intersected with the version literal. */
export const accountRequestSchema = z.intersection(
  z.object({ protocol_version: z.literal(ACCOUNT_PROTOCOL_VERSION) }),
  accountActionSchema,
);

export type AccountAction = (typeof KNOWN_ACCOUNT_ACTIONS)[number];
export type AccountRequest = { protocol_version: typeof ACCOUNT_PROTOCOL_VERSION } & z.infer<typeof accountActionSchema>;

// --- response (mirror of protocol::account::AccountResponse) ------------------
// On the wire every variant additionally carries `ok: true` and
// `protocol_version: 1` (the service adds them; the Rust decoder ignores
// unknown keys, the mirror pins them).

const hexOrEmpty = (bytes: number): z.ZodUnion<[z.ZodLiteral<''>, z.ZodString]> =>
  z.union([z.literal(''), hexBytes(bytes)]);

const cipherOrEmpty = z.union([z.literal(''), evenHexSchema]);

export const accountResponseActionSchema = z.discriminatedUnion('action', [
  z.object({
    action: z.literal('register'),
    session_token: sessionTokenSchema,
    expires_ms: z.number().int().nonnegative(),
  }),
  z.object({
    action: z.literal('login_pre'),
    auth_salt_hex: saltSchema,
    wrap_salt_hex: saltSchema,
  }),
  z.object({
    action: z.literal('login'),
    session_token: sessionTokenSchema,
    expires_ms: z.number().int().nonnegative(),
    wrapped_dek_hex: wrappedDekSchema,
    dek_nonce_hex: nonceSchema,
  }),
  z.object({ action: z.literal('logout') }),
  z.object({
    action: z.literal('roster_get'),
    /** Empty string iff version == 0 (no roster stored yet). */
    ciphertext_hex: cipherOrEmpty,
    nonce_hex: hexOrEmpty(NONCE_HEX_LEN / 2),
    version: versionSchema,
  }),
  z.object({
    action: z.literal('roster_put'),
    version: versionSchema,
  }),
  z.object({
    action: z.literal('presence'),
    online: z.array(deviceCodeSchema),
  }),
]);

/**
 * The full response: `ok: true` + version literal + the action union, plus
 * the roster_get empty/nonempty coupling (kept OUTSIDE the union — zod's
 * discriminatedUnion only takes plain objects).
 */
export const accountResponseSchema = z
  .intersection(
    z.object({ ok: z.literal(true), protocol_version: z.literal(ACCOUNT_PROTOCOL_VERSION) }),
    accountResponseActionSchema,
  )
  .superRefine((value, ctx) => {
    if (value.action === 'roster_get') {
      const empty = value.version === 0;
      if (empty !== (value.ciphertext_hex === '') || empty !== (value.nonce_hex === '')) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['version'],
          message: 'version 0 <=> empty ciphertext/nonce; version > 0 <=> non-empty',
        });
      }
    }
  });

export type AccountResponseAction = z.infer<typeof accountResponseActionSchema>;

/** Machine-readable error codes (mirror of protocol::account::error_code). */
export const ACCOUNT_ERROR_CODES = {
  UNSUPPORTED_VERSION: 'unsupported_version',
  MALFORMED: 'malformed',
  USERNAME_TAKEN: 'username_taken',
  INVALID_CREDENTIALS: 'invalid_credentials',
  UNAUTHORIZED: 'unauthorized',
  RATE_LIMITED: 'rate_limited',
  ROSTER_CONFLICT: 'roster_conflict',
  ROSTER_TOO_LARGE: 'roster_too_large',
  TOO_LARGE: 'too_large',
  INTERNAL: 'internal',
} as const;

export type AccountErrorCode = (typeof ACCOUNT_ERROR_CODES)[keyof typeof ACCOUNT_ERROR_CODES];

/** HTTP status for each error code (single mapping, used by the server). */
export function accountStatusFor(error: AccountErrorCode): number {
  switch (error) {
    case 'unsupported_version':
    case 'malformed':
      return 400;
    case 'invalid_credentials':
    case 'unauthorized':
      return 401;
    case 'username_taken':
    case 'roster_conflict':
      return 409;
    case 'rate_limited':
      return 429;
    case 'roster_too_large':
    case 'too_large':
      return 413;
    default:
      return 500;
  }
}
