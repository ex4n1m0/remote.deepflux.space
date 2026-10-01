/**
 * Unit tests for the account wire mirror + decoy helpers (no servers — the
 * golden fixtures + the account contract suite cover the rest).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ACCOUNT_PROTOCOL_VERSION,
  PRESENCE_MAX_CODES,
  accountRequestSchema,
  accountResponseSchema,
} from '../../lib/account-schema.ts';
import { decoySaltHex, SCRYPT_COST, SCRYPT_KEYLEN_BYTES } from '../../lib/account-service.ts';

const REGISTER = {
  protocol_version: ACCOUNT_PROTOCOL_VERSION,
  action: 'register',
  username: 'alice',
  auth_key: '0a'.repeat(32),
  auth_salt_hex: '1b'.repeat(16),
  wrap_salt_hex: '2c'.repeat(16),
  wrapped_dek_hex: '3d'.repeat(48),
  dek_nonce_hex: '4e'.repeat(12),
};

test('request mirror: all seven actions parse; unknown/camelCase/v0 rejected', () => {
  const bodies = [
    REGISTER,
    { protocol_version: 1, action: 'login_pre', username: 'alice' },
    { protocol_version: 1, action: 'login', username: 'alice', auth_key: '0a'.repeat(32) },
    { protocol_version: 1, action: 'logout' },
    { protocol_version: 1, action: 'roster_get' },
    {
      protocol_version: 1,
      action: 'roster_put',
      ciphertext_hex: 'ab'.repeat(8),
      nonce_hex: '00'.repeat(12),
      base_version: 3,
    },
    { protocol_version: 1, action: 'presence', codes: ['0123456789abcdef'] },
  ];
  for (const body of bodies) {
    assert.equal(accountRequestSchema.safeParse(body).success, true, JSON.stringify(body));
  }
  assert.equal(
    accountRequestSchema.safeParse({ ...REGISTER, action: 'delete_everything' }).success,
    false,
    'unknown action',
  );
  assert.equal(
    accountRequestSchema.safeParse({ action: 'login_pre', protocolVersion: 1, username: 'alice' }).success,
    false,
    'camelCase must fail (no field renaming)',
  );
  assert.equal(accountRequestSchema.safeParse({ ...REGISTER, protocol_version: 0 }).success, false, 'v0');
  // Additive-optional tolerance (serde policy mirror).
  assert.equal(
    accountRequestSchema.safeParse({ ...REGISTER, future_additive_field: 42 }).success,
    true,
    'unknown additive fields are tolerated',
  );
});

test('field shapes: username, hex lengths, uppercase hex, presence caps', () => {
  for (const bad of ['Alice', 'ab', '-alice', 'alice!', ' alice', 'x'.repeat(33), '']) {
    assert.equal(
      accountRequestSchema.safeParse({ ...REGISTER, username: bad }).success,
      false,
      `username ${JSON.stringify(bad)} must fail`,
    );
  }
  assert.equal(accountRequestSchema.safeParse({ ...REGISTER, auth_key: '0A'.repeat(32) }).success, false, 'uppercase hex');
  assert.equal(accountRequestSchema.safeParse({ ...REGISTER, auth_key: '0a'.repeat(31) }).success, false, 'short auth_key');
  assert.equal(
    accountRequestSchema.safeParse({ ...REGISTER, wrapped_dek_hex: '0a'.repeat(9) }).success,
    false,
    'odd-length hex',
  );
  assert.equal(
    accountRequestSchema.safeParse({
      protocol_version: 1,
      action: 'presence',
      codes: Array.from({ length: PRESENCE_MAX_CODES + 1 }, () => '0123456789abcdef'),
    }).success,
    false,
    'more than PRESENCE_MAX_CODES codes',
  );
  assert.equal(
    accountRequestSchema.safeParse({ protocol_version: 1, action: 'presence', codes: ['bad code'] }).success,
    false,
    'invalid device code',
  );
});

test('response mirror: roster_get empty/nonempty coupling; ok:true + version pinned', () => {
  const empty = {
    ok: true,
    protocol_version: 1,
    action: 'roster_get',
    ciphertext_hex: '',
    nonce_hex: '',
    version: 0,
  };
  assert.equal(accountResponseSchema.safeParse(empty).success, true);
  const full = {
    ok: true,
    protocol_version: 1,
    action: 'roster_get',
    ciphertext_hex: '7c'.repeat(32),
    nonce_hex: '8d'.repeat(12),
    version: 4,
  };
  assert.equal(accountResponseSchema.safeParse(full).success, true);
  assert.equal(
    accountResponseSchema.safeParse({ ...full, version: 0 }).success,
    false,
    'version 0 with non-empty ciphertext violates the coupling',
  );
  assert.equal(
    accountResponseSchema.safeParse({ ...full, ok: false }).success,
    false,
    'ok must be literal true',
  );
  const login = {
    ok: true,
    protocol_version: 1,
    action: 'login',
    session_token: '9b'.repeat(32),
    expires_ms: 1_760_000_000_000,
    wrapped_dek_hex: '3d'.repeat(48),
    dek_nonce_hex: '4e'.repeat(12),
    future_additive_field: 1,
  };
  assert.equal(accountResponseSchema.safeParse(login).success, true, 'additive tolerance');
});

test('decoy salts: deterministic, username/kind-separated, right shape', () => {
  const a = decoySaltHex('alice', 'auth');
  const w = decoySaltHex('alice', 'wrap');
  assert.match(a, /^[0-9a-f]{32}$/);
  assert.match(w, /^[0-9a-f]{32}$/);
  assert.equal(a, decoySaltHex('alice', 'auth'));
  assert.notEqual(a, w);
  assert.notEqual(a, decoySaltHex('bob', 'auth'));
});

test('scrypt cost constants are the pinned conservative set', () => {
  assert.deepEqual(SCRYPT_COST, { N: 16_384, r: 8, p: 1 });
  assert.equal(SCRYPT_KEYLEN_BYTES, 32);
});
