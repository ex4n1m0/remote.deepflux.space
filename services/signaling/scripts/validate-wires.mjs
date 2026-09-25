#!/usr/bin/env node
/**
 * Wire-contract validation (delta D7): the TypeScript zod mirror in
 * lib/envelope.ts must accept exactly what `crates/protocol` emits.
 *
 * Fixtures are GOLDEN — exported deterministically from the Rust types by
 * `crates/node-runtime/tests/signaling_fixtures.rs`
 * (`UPDATE_SIGNALING_FIXTURES=1 cargo test -p node-runtime --test
 * signaling_fixtures` regenerates). This script validates:
 *
 *   fixtures/golden/**   -> every fixture parses with the TS schema,
 *                          is protocol_version 1, flat (no `payload` key)
 *   fixtures/reject/**   -> each must fail exactly the documented way
 *                          (schema-invalid, or version-gated for v0)
 *
 * Any mismatch on either side is a wire-contract change requiring a
 * conscious regeneration (AGENTS.md invariant 5).
 *
 * Run: node --import tsx scripts/validate-wires.mjs   (or `pnpm validate:wires`)
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { signalingEnvelopeSchema, SIGNALING_PROTOCOL_VERSION } from '../lib/envelope.ts';

const root = new URL('../fixtures/', import.meta.url).pathname
  // Windows: file URL -> plain path
  .replace(/^\/([A-Za-z]:)/, '$1');

let pass = 0;
let fail = 0;

function listJson(dir) {
  try {
    return readdirSync(dir).filter((f) => f.endsWith('.json'));
  } catch {
    return [];
  }
}

// --- golden: must parse, be v1, and be flat -------------------------------
for (const direction of ['golden/client_to_service', 'golden/service_to_client']) {
  const dir = join(root, direction);
  const files = listJson(dir);
  if (files.length === 0) {
    console.error(`FAIL ${direction}: no fixtures (regenerate from Rust)`);
    fail += 1;
    continue;
  }
  for (const file of files) {
    const text = readFileSync(join(dir, file), 'utf8');
    const value = JSON.parse(text);
    const parsed = signalingEnvelopeSchema.safeParse(value);
    if (!parsed.success) {
      console.error(`FAIL ${direction}/${file}: schema rejected: ${parsed.error.issues[0]?.path}`);
      fail += 1;
      continue;
    }
    if (parsed.data.protocol_version !== SIGNALING_PROTOCOL_VERSION) {
      console.error(`FAIL ${direction}/${file}: wrong protocol_version`);
      fail += 1;
      continue;
    }
    if ('payload' in value) {
      console.error(`FAIL ${direction}/${file}: envelope is not flat (payload key)`);
      fail += 1;
      continue;
    }
    // Unknown additive fields must be tolerated (serde policy mirror).
    const withFuture = { ...value, future_additive_field: 42 };
    if (!signalingEnvelopeSchema.safeParse(withFuture).success) {
      console.error(`FAIL ${direction}/${file}: additive optional field rejected`);
      fail += 1;
      continue;
    }
    pass += 1;
    console.log(`ok   ${direction}/${file} (type=${parsed.data.type})`);
  }
}

// --- reject: each must fail its documented way ------------------------------
const expectations = {
  // v0 is schema-shaped but must be version-gated by the service.
  'v0_heartbeat.json': (v) => v.protocol_version === 0 && 'version-gated',
  // v0 numeric mid under a v1 envelope: schema must reject loudly.
  'v1_ice_numeric_mid.json': () => 'schema-invalid',
  'unknown_type.json': () => 'schema-invalid',
  'camelcase_probe.json': () => 'schema-invalid',
};

for (const [file, expect] of Object.entries(expectations)) {
  const text = readFileSync(join(root, 'reject', file), 'utf8');
  const value = JSON.parse(text);
  const outcome = expect(value);
  const parsed = signalingEnvelopeSchema.safeParse(value);
  if (outcome === 'version-gated') {
    // The schema may or may not parse it; the SERVICE's raw version gate is
    // the rejection point (protocol_version checked before body parsing).
    if (parsed.success && value.protocol_version !== SIGNALING_PROTOCOL_VERSION) {
      // schema lenient on version by design: the gate is explicit.
      pass += 1;
      console.log(`ok   reject/${file} (version-gated at the service, saw v${value.protocol_version})`);
    } else if (!parsed.success) {
      pass += 1;
      console.log(`ok   reject/${file} (schema-invalid, also version-gated)`);
    } else {
      console.error(`FAIL reject/${file}: v0 parsed as v1-compatible`);
      fail += 1;
    }
    continue;
  }
  if (parsed.success) {
    console.error(`FAIL reject/${file}: schema accepted an invalid envelope`);
    fail += 1;
  } else {
    pass += 1;
    console.log(`ok   reject/${file} (schema-invalid)`);
  }
}

console.log(`\nvalidate-wires: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
