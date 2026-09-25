/**
 * Unit tests for the TS envelope mirror (no servers spawned — the wire
 * fixtures + contract matrix cover the rest).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SIGNALING_PROTOCOL_VERSION,
  SIGNALING_SERVICE_ID,
  isServiceDirected,
  isSessionScoped,
  mintErrorEnvelope,
  signalingEnvelopeSchema,
} from '../../lib/envelope.ts';

const base = {
  protocol_version: SIGNALING_PROTOCOL_VERSION,
  message_id: 'unit-1',
  session_id: null as string | null,
  from_device_id: 'unit-a',
  to_device_id: SIGNALING_SERVICE_ID,
  timestamp_ms: 1,
};

test('register and heartbeat parse and classify as service-directed', () => {
  const reg = signalingEnvelopeSchema.parse({
    ...base,
    type: 'register',
    capabilities: { encoders: [], monitors: [], max_bitrate_kbps: 1, features: 0 },
  });
  assert.equal(isServiceDirected(reg), true);
  assert.equal(isSessionScoped(reg.type), false);
  const hb = signalingEnvelopeSchema.parse({ ...base, type: 'heartbeat' });
  assert.equal(isServiceDirected(hb), true);
});

test('every session-scoped type is classified', () => {
  for (const type of [
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
  ]) {
    assert.equal(isSessionScoped(type), true, type);
  }
  assert.equal(isSessionScoped('register'), false);
  assert.equal(isSessionScoped('heartbeat'), false);
});

test('minted error envelopes are valid v1 envelopes from the service', () => {
  const minted = mintErrorEnvelope('unit-a', 404, 'unknown target x', 'sess-1');
  const parsed = signalingEnvelopeSchema.parse(minted);
  assert.equal(parsed.type, 'error');
  assert.equal(parsed.from_device_id, SIGNALING_SERVICE_ID);
  assert.equal(parsed.to_device_id, 'unit-a');
  assert.equal(parsed.session_id, 'sess-1');
  assert.ok(parsed.message_id.startsWith('signaling-err-'));
});

test('v1 rejects the v0 numeric sdp_mid shape loudly', () => {
  const v0Shape = {
    ...base,
    to_device_id: 'unit-b',
    type: 'ice_candidate',
    candidate: 'x',
    sdp_mid: 0,
    sdp_mline_index: 0,
  };
  assert.equal(signalingEnvelopeSchema.safeParse(v0Shape).success, false);
  const v1Shape = { ...v0Shape, sdp_mid: '0' };
  assert.equal(signalingEnvelopeSchema.safeParse(v1Shape).success, true);
});
