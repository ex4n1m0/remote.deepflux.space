//! Deterministic golden-vector generator for the ADR-032 VerifyDrafts
//! family and the cooperative negotiation shapes (implementation plan
//! `docs/implementation/adr-032-verifydrafts-plan.md` §2, step 2; the
//! fixture set is the ADR-032 §7 fixture-set table).
//!
//! Run from the repo root:
//!
//! ```text
//! cargo run -p modelswarm-session --example gen-verifydrafts-vectors
//! ```
//!
//! Determinism contract (plan §2.2): no arguments, no clock, no RNG. The
//! fixture-only Ed25519 seeds are recorded in every generated file
//! (coordinator `[0x11; 32]`, verifier `[0x22; 32]` — the `[9u8; 32]` /
//! `0x07` fixture-key style of ADR-020 / `lease-hubkey-1.json`; never
//! production; plan flag F-7: installation ids derive from the recorded
//! public keys, so these identities can never collide with a real one).
//! Every token id, session id, nonce, and deadline below is a fixed
//! constant; the ONLY time value is the recorded `verify_at`
//! (`2026-10-12T00:00:00Z`), which anchors every deadline check (case
//! pre-state times in `verifydrafts-malformed.json` are recorded context,
//! not fixture clocks). Output is `serde_json::to_string_pretty` + a
//! trailing newline, byte-identical on every rerun (idempotency asserted
//! at handoff via `git diff`, and permanently by the golden test
//! `tests/verifydrafts_vectors.rs`).
//!
//! Per signed message (plan §2.2 algorithm): build the session-1 struct →
//! serialize → remove `signature` → canonical JSON via
//! `modelswarm_types::canonical_json` (must succeed — floats are
//! forbidden in signed payloads) → sign the preimage bytes with
//! `SigningKey::from_bytes(&seed)` → base64 STANDARD → record `fields` +
//! `canonical_json` + `signature` + `canonical_json_sha256`. Every
//! `new_prefix_hash` is computed with the shipped `compute_prefix_hash`
//! (ADR-032 §1 rule 2: `hex(sha256(raw32(parent_hex) ‖ token ids as LE
//! u32))` over `(parent ‖ accepted prefix ‖ [correction])` — on FULL
//! acceptance the preimage therefore covers the whole accepted window
//! plus the bonus token) AND its construction inputs are recorded so any
//! second implementation can rebuild it independently of our function.
//!
//! Negotiation messages carry no signature (msp-cooperative-v1 §1: they
//! ride the handshake-authenticated session), so `session-offer-*.json`,
//! `session-accept-*.json`, and `session-reject-1.json` pin canonical
//! bytes + sha256 only.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use modelswarm_identity::InstallationIdentity;
use modelswarm_runtime::SamplingParams;
use modelswarm_session::negotiation::{
    Backend, EngineDisclosure, Preset, SessionAccept, SessionBudget, SessionOffer, SessionReject,
    SessionRejectReason,
};
use modelswarm_session::verifydrafts::{
    batch_generation_params_hash, sign_verify_drafts, sign_verify_drafts_result, signing_preimage,
    VerifyDrafts, VerifyDraftsResult, WINDOW_CAP,
};
use modelswarm_session::{compute_prefix_hash, GENESIS_PREFIX_HASH};
use modelswarm_types::canonical_json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use modelswarm_transport::ed25519_dalek::{Signer, SigningKey};

// ---------------------------------------------------------------------------
// Fixed fixture material (recorded in every file; never production)
// ---------------------------------------------------------------------------

/// Fixture-only coordinator seed (ADR-032 §7 fixture-set preamble; F-7).
const COORDINATOR_SEED: [u8; 32] = [0x11; 32];
/// Fixture-only verifier seed (ADR-032 §7 fixture-set preamble; F-7).
const VERIFIER_SEED: [u8; 32] = [0x22; 32];

/// The single time anchor of the whole fixture set (plan §2.2): every
/// deadline check is evaluated at this instant.
const VERIFY_AT: &str = "2026-10-12T00:00:00Z";
/// `VERIFY_AT` in unix milliseconds (cross-checked against the RFC 3339
/// string in `main`; verified against independent `date -u` output).
const VERIFY_AT_UNIX_MS: i64 = 1_791_763_200_000;
/// Deadline-past case pre-state: the frame arrived one minute before the
/// admission clock with a 1000 ms deadline (queue wait exhausted it).
const REQUEST_ARRIVAL: &str = "2026-10-11T23:59:00Z";
const REQUEST_ARRIVAL_UNIX_MS: i64 = 1_791_763_140_000;
/// Lease-expired case pre-state (an hour before the admission clock).
const LEASE_EXPIRY: &str = "2026-10-11T23:00:00Z";
const LEASE_EXPIRY_UNIX_MS: i64 = 1_791_759_600_000;

/// The session profile pinned by every family fixture
/// (`"msp1:" + "ab".repeat(32)`).
const PROFILE_ID: &str = "msp1:abababababababababababababababababababababababababababababababab";
/// The profile used by the wrong-`profile_id` malformed case.
const WRONG_PROFILE_ID: &str =
    "msp1:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

/// The chain-hash rule recorded beside every construction block
/// (ADR-032 §1 rule 2; the shipped `compute_prefix_hash`).
const PREFIX_HASH_RULE: &str =
    "hex(sha256(raw32(parent_hex) || token ids as little-endian u32 each))";

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Days-from-civil (Howard Hinnant's algorithm) — converts the fixed
/// `YYYY-MM-DDTHH:MM:SSZ` fixture timestamps to unix milliseconds without
/// pulling a datetime dependency into the crate. Only the three anchor
/// constants above ever pass through here, and each is cross-checked
/// against an independently computed epoch value in `main`.
fn unix_ms(rfc3339_utc: &str) -> i64 {
    let bytes = rfc3339_utc.as_bytes();
    let expect_digit = |slice: &str| -> i64 { slice.parse().expect("fixture timestamp digit") };
    let year = expect_digit(&rfc3339_utc[0..4]);
    let month = expect_digit(&rfc3339_utc[5..7]);
    let day = expect_digit(&rfc3339_utc[8..10]);
    let hour = expect_digit(&rfc3339_utc[11..13]);
    let minute = expect_digit(&rfc3339_utc[14..16]);
    let second = expect_digit(&rfc3339_utc[17..19]);
    assert_eq!(bytes[4], b'-', "fixture timestamps are calendar dates");
    assert_eq!(bytes[7], b'-', "fixture timestamps are calendar dates");
    assert_eq!(bytes[10], b'T', "fixture timestamps are RFC 3339 with T");
    assert!(rfc3339_utc.ends_with('Z'), "fixture timestamps are UTC Z");

    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if month > 2 { month - 3 } else { month + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    (((days * 24 + hour) * 60 + minute) * 60 + second) * 1000
}

struct Actor {
    identity: InstallationIdentity,
}

impl Actor {
    fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            identity: InstallationIdentity::from_bytes(&seed),
        }
    }

    /// The four recorded provenance fields for one actor, keyed
    /// `<prefix>_seed_hex` / `_public_key_hex` / `_installation_id` /
    /// `_peer_id` (plan §2.2 key block; `peer_id` is recorded because the
    /// request `proposer_id` references the coordinator's wire identity).
    fn block(&self, prefix: &str) -> Value {
        let mut map = Map::new();
        map.insert(
            format!("{prefix}_seed_hex"),
            json!(hex::encode(self.identity.to_bytes())),
        );
        map.insert(
            format!("{prefix}_public_key_hex"),
            json!(hex::encode(self.identity.public_key_bytes())),
        );
        map.insert(
            format!("{prefix}_installation_id"),
            json!(self.identity.installation_id()),
        );
        map.insert(format!("{prefix}_peer_id"), json!(self.identity.peer_id()));
        Value::Object(map)
    }
}

fn insert(dst: &mut Value, src: Value) {
    let dst_map = dst.as_object_mut().expect("fixture is an object");
    let src_map = src.as_object().expect("actor block is an object");
    for (key, value) in src_map {
        dst_map.insert(key.clone(), value.clone());
    }
}

/// sha256 over the canonical JSON of the pinned sampling-parameter object
/// (ADR-032 §1 rule 3 / plan flag F-1): integral values render as bare
/// integers. The generator asserts the runtime default renders exactly
/// this object, byte-pinning the preimage.
fn generation_params_block() -> (Value, String) {
    let params = SamplingParams::default();
    let object = json!({
        "seed": params.seed,
        "temperature": 1,
        "top_k": params.top_k,
        "top_p": 1,
    });
    let canonical = canonical_json(&object).expect("params preimage has no floats");
    let digest = sha256_hex(canonical.as_bytes());
    // Structural pin: the family hash over the runtime default MUST equal
    // the sha256 of the literal object above (F-1 byte-pin). If the
    // runtime default ever changes, generation fails loudly here.
    assert_eq!(
        batch_generation_params_hash(&params).expect("default params are integral"),
        digest,
        "SamplingParams::default() no longer renders the pinned preimage"
    );
    let block = json!({
        "seed": params.seed,
        "temperature": 1,
        "top_k": params.top_k,
        "top_p": 1,
        "canonical_json": canonical,
        "sha256_hex": digest,
    });
    (block, digest)
}

// ---------------------------------------------------------------------------
// Message builders (fixed values; the signer assigns sender + signature)
// ---------------------------------------------------------------------------

struct RequestSpec {
    session_id: &'static str,
    seq: u64,
    round: u64,
    window: Vec<u32>,
    nonce: &'static str,
    deadline_ms: u32,
    profile_id: &'static str,
}

impl RequestSpec {
    fn build(&self, params_hash: &str, proposer_id: &str, sender: &str) -> VerifyDrafts {
        VerifyDrafts {
            session_id: self.session_id.to_string(),
            protocol_version: "msp-cooperative-v1".to_string(),
            seq: self.seq,
            round: self.round,
            profile_id: self.profile_id.to_string(),
            parent_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
            generation_params_hash: params_hash.to_string(),
            window_tokens: self.window.clone(),
            proposer_id: proposer_id.to_string(),
            nonce: self.nonce.to_string(),
            deadline_ms: self.deadline_ms,
            sender: sender.to_string(),
            signature: String::new(),
        }
    }
}

struct ResultSpec {
    session_id: &'static str,
    seq: u64,
    round: u64,
    accepted_prefix_len: u32,
    divergence_point: Option<u32>,
    correction: Option<u32>,
    verify_pass_ms: u32,
    nonce_echo: &'static str,
}

impl ResultSpec {
    fn build(&self, sender: &str, new_prefix_hash: String) -> VerifyDraftsResult {
        VerifyDraftsResult {
            session_id: self.session_id.to_string(),
            protocol_version: "msp-cooperative-v1".to_string(),
            seq: self.seq,
            round: self.round,
            accepted_prefix_len: self.accepted_prefix_len,
            divergence_point: self.divergence_point,
            correction: self.correction,
            new_prefix_hash,
            verify_pass_ms: self.verify_pass_ms,
            nonce_echo: self.nonce_echo.to_string(),
            sender: sender.to_string(),
            signature: String::new(),
        }
    }
}

/// Signs `msg` (over the signature-omitted canonical preimage, base64
/// STANDARD) and returns the message with the signature assigned.
fn finalize_request(msg: &VerifyDrafts, signer: &InstallationIdentity) -> VerifyDrafts {
    let mut signed = msg.clone();
    signed.signature = sign_verify_drafts(msg, signer).expect("request signs");
    signed
}

fn finalize_result(msg: &VerifyDraftsResult, signer: &InstallationIdentity) -> VerifyDraftsResult {
    let mut signed = msg.clone();
    signed.signature = sign_verify_drafts_result(msg, signer).expect("result signs");
    signed
}

/// The plan-§2.2 recording block for one signed message: `fields` (the
/// full message including signature), `canonical_json` (the
/// signature-OMITTED canonical form — §1 rule 4), `signature`, and
/// `canonical_json_sha256`.
fn signed_block(fields: &Value, canonical: &str, signature: &str) -> Value {
    json!({
        "fields": fields,
        "canonical_json": canonical,
        "signature": signature,
        "canonical_json_sha256": sha256_hex(canonical.as_bytes()),
    })
}

fn request_block(msg: &VerifyDrafts) -> Value {
    let canonical = signing_preimage(msg).expect("request preimage has no floats");
    let fields = serde_json::to_value(msg).expect("request serializes");
    signed_block(&fields, &canonical, &msg.signature)
}

fn result_block(msg: &VerifyDraftsResult) -> Value {
    let canonical = signing_preimage(msg).expect("result preimage has no floats");
    let fields = serde_json::to_value(msg).expect("result serializes");
    signed_block(&fields, &canonical, &msg.signature)
}

/// The `expected` block: outcome + result-shape pins + the
/// `new_prefix_hash` VALUE and its recorded construction inputs (the
/// committed token ids the chain hash covers — ADR-032 §1 rule 2:
/// `(parent ‖ accepted prefix ‖ [correction])`).
fn expected_block(
    outcome: &str,
    accepted_prefix_len: u32,
    divergence_point: Option<u32>,
    correction: Option<u32>,
    committed: &[u32],
    new_prefix_hash: &str,
    eog: bool,
) -> Value {
    let mut expected = json!({
        "outcome": outcome,
        "accepted_prefix_len": accepted_prefix_len,
        "divergence_point": divergence_point,
        "correction": correction,
        "committed": committed,
        "new_prefix_hash": new_prefix_hash,
        "new_prefix_hash_construction": {
            "rule": PREFIX_HASH_RULE,
            "parent_prefix_hash": GENESIS_PREFIX_HASH,
            "committed_token_ids": committed,
        },
    });
    if eog {
        expected
            .as_object_mut()
            .expect("expected is an object")
            .insert("eog".to_string(), json!(true));
    }
    expected
}

/// Common family-fixture header: name, description, both actors' recorded
/// keys, the time anchor, and the pinned generation params.
fn family_header(name: &str, description: &str, coordinator: &Actor, verifier: &Actor) -> Value {
    let (params_block, _) = generation_params_block();
    let mut doc = json!({
        "name": name,
        "description": description,
        "verify_at": VERIFY_AT,
        "generation_params": params_block,
    });
    insert(&mut doc, coordinator.block("coordinator"));
    insert(&mut doc, verifier.block("verifier"));
    doc
}

fn engine_block(batch_window_max: u32) -> Value {
    json!({
        "backend": "cpu",
        "batch_verify": true,
        "batch_window_max": batch_window_max,
    })
}

// ---------------------------------------------------------------------------
// The four wire fixtures (ADR-032 §7 fixture-set table rows 1-4)
// ---------------------------------------------------------------------------

fn fixture_accept(coordinator: &Actor, verifier: &Actor, params_hash: &str) -> Value {
    // w=8 full acceptance: divergence_point null PRESENT-AS-NULL,
    // correction = bonus (lookahead) token, committed = whole accepted
    // window ++ [bonus] (§1 rule 2); seq pair (request 12, result 4) is
    // the §1/RC-7 illustration made normative bytes. Round 3 with the
    // genesis parent documents RC-5(c) gap tolerance (rounds 1-2
    // abandoned without commits; the committed hash never advanced).
    let window = vec![101, 102, 103, 104, 105, 106, 107, 108];
    let bonus = 999;
    let correction = Some(bonus);
    let mut committed = window.clone();
    committed.push(bonus);
    let new_prefix_hash = compute_prefix_hash(GENESIS_PREFIX_HASH, &committed)
        .expect("genesis parent is valid bare hex");

    let request = RequestSpec {
        session_id: "sess-vd-accept-0001",
        seq: 12,
        round: 3,
        window,
        nonce: "0a1b2c3d4e5f6071",
        deadline_ms: 2_500,
        profile_id: PROFILE_ID,
    }
    .build(
        params_hash,
        &coordinator.identity.peer_id(),
        &coordinator.identity.installation_id(),
    );
    let result = ResultSpec {
        session_id: "sess-vd-accept-0001",
        seq: 4,
        round: 3,
        accepted_prefix_len: 8,
        divergence_point: None,
        correction,
        verify_pass_ms: 35,
        nonce_echo: "0a1b2c3d4e5f6071",
    }
    .build(
        &verifier.identity.installation_id(),
        new_prefix_hash.clone(),
    );

    let mut doc = family_header(
        "verifydrafts-1-accept",
        "ADR-032 §7 fixture row 1 (plan §2.2): full acceptance, w=8. Pins the VerifyDrafts canonical-JSON bytes + sha256 (signature-omitted preimage, §1 rule 4), the signature, the VerifyDraftsResult canonical bytes + signature + sha256, accepted_prefix_len == len(window_tokens) == 8, divergence_point null PRESENT-AS-NULL, correction = bonus token, committed = window[..8] ++ [correction], the new_prefix_hash VALUE plus its byte-exact §1-rule-2 construction inputs, and the nonce_echo. Request seq 12 / result seq 4 are the VERIFIER-own-counter illustration of §2 RC-7 made normative bytes.",
        coordinator,
        verifier,
    );
    let doc_map = doc.as_object_mut().expect("header is an object");
    doc_map.insert("engine".to_string(), engine_block(WINDOW_CAP));
    doc_map.insert(
        "request".to_string(),
        request_block(&finalize_request(&request, &coordinator.identity)),
    );
    doc_map.insert(
        "result".to_string(),
        result_block(&finalize_result(&result, &verifier.identity)),
    );
    doc_map.insert(
        "expected".to_string(),
        expected_block(
            "accepted",
            8,
            None,
            correction,
            &committed,
            &new_prefix_hash,
            false,
        ),
    );
    doc
}

fn fixture_reject(coordinator: &Actor, verifier: &Actor, params_hash: &str) -> Value {
    // Mid-window rejection at k=3 < len 8: divergence_point ==
    // accepted_prefix_len == 3 (the §1 invariant), correction = the
    // replacement token, committed = window[..3] ++ [replacement], chain
    // hash recomputed over exactly that.
    let window = vec![201, 202, 203, 204, 205, 206, 207, 208];
    let k = 3;
    let replacement = 777;
    let correction = Some(replacement);
    let mut committed = window[..k].to_vec();
    committed.push(replacement);
    let new_prefix_hash =
        compute_prefix_hash(GENESIS_PREFIX_HASH, &committed).expect("genesis parent is valid");

    let request = RequestSpec {
        session_id: "sess-vd-reject-0001",
        seq: 12,
        round: 1,
        window,
        nonce: "1a2b3c4d5e6f7081",
        deadline_ms: 2_500,
        profile_id: PROFILE_ID,
    }
    .build(
        params_hash,
        &coordinator.identity.peer_id(),
        &coordinator.identity.installation_id(),
    );
    let result = ResultSpec {
        session_id: "sess-vd-reject-0001",
        seq: 4,
        round: 1,
        accepted_prefix_len: k as u32,
        divergence_point: Some(k as u32),
        correction,
        verify_pass_ms: 35,
        nonce_echo: "1a2b3c4d5e6f7081",
    }
    .build(
        &verifier.identity.installation_id(),
        new_prefix_hash.clone(),
    );

    let mut doc = family_header(
        "verifydrafts-2-reject",
        "ADR-032 §7 fixture row 2 (plan §2.2): mid-window rejection. accepted_prefix_len = 3 < len(window_tokens) = 8, divergence_point == accepted_prefix_len == 3 (§1 invariant), correction = replacement token, committed = window[..3] ++ [correction], new_prefix_hash recomputed over the committed ids (§1 rule 2).",
        coordinator,
        verifier,
    );
    let doc_map = doc.as_object_mut().expect("header is an object");
    doc_map.insert("engine".to_string(), engine_block(WINDOW_CAP));
    doc_map.insert(
        "request".to_string(),
        request_block(&finalize_request(&request, &coordinator.identity)),
    );
    doc_map.insert(
        "result".to_string(),
        result_block(&finalize_result(&result, &verifier.identity)),
    );
    doc_map.insert(
        "expected".to_string(),
        expected_block(
            "rejected",
            k as u32,
            Some(k as u32),
            correction,
            &committed,
            &new_prefix_hash,
            false,
        ),
    );
    doc
}

fn fixture_boundary(coordinator: &Actor, verifier: &Actor, params_hash: &str) -> Value {
    // Cap edge: len 32 == min(WINDOW_CAP, batch_window_max = 32) accepted;
    // len 33 > min(...) is payload_too_large BEFORE any engine work (the
    // admission input rides this same file per plan §2.2).
    let window: Vec<u32> = (300..=331).collect();
    assert_eq!(window.len(), WINDOW_CAP as usize);
    let bonus = 4242;
    let correction = Some(bonus);
    let mut committed = window.clone();
    committed.push(bonus);
    let new_prefix_hash = compute_prefix_hash(GENESIS_PREFIX_HASH, &committed)
        .expect("genesis parent is valid bare hex");

    let request = RequestSpec {
        session_id: "sess-vd-boundary-0001",
        seq: 12,
        round: 1,
        window,
        nonce: "2a3b4c5d6e7f8091",
        deadline_ms: 2_500,
        profile_id: PROFILE_ID,
    }
    .build(
        params_hash,
        &coordinator.identity.peer_id(),
        &coordinator.identity.installation_id(),
    );
    let result = ResultSpec {
        session_id: "sess-vd-boundary-0001",
        seq: 4,
        round: 1,
        accepted_prefix_len: WINDOW_CAP,
        divergence_point: None,
        correction,
        verify_pass_ms: 35,
        nonce_echo: "2a3b4c5d6e7f8091",
    }
    .build(
        &verifier.identity.installation_id(),
        new_prefix_hash.clone(),
    );

    // The len-33 admission input: schema- and signature-VALID (it must
    // pass every earlier admission stage so the reject fires at the cap
    // stage itself), expected payload_too_large with ZERO engine work.
    let over_window: Vec<u32> = (500..=532).collect();
    assert_eq!(over_window.len(), WINDOW_CAP as usize + 1);
    let over_request = RequestSpec {
        session_id: "sess-vd-boundary-0001",
        seq: 13,
        round: 2,
        window: over_window,
        nonce: "3a4b5c6d7e8f90a1",
        deadline_ms: 2_500,
        profile_id: PROFILE_ID,
    }
    .build(
        params_hash,
        &coordinator.identity.peer_id(),
        &coordinator.identity.installation_id(),
    );

    let mut doc = family_header(
        "verifydrafts-3-boundary",
        "ADR-032 §7 fixture row 3 (plan §2.2): cap edge. Main case: len 32 accepted when batch_window_max >= 32 (full-acceptance result at the cap). over_cap_case: the len-33 admission input, schema-valid and signature-valid, rejected payload_too_large before any engine work (pairs with the deadline-DoS shape).",
        coordinator,
        verifier,
    );
    let doc_map = doc.as_object_mut().expect("header is an object");
    doc_map.insert("engine".to_string(), engine_block(WINDOW_CAP));
    doc_map.insert("window_cap".to_string(), json!(WINDOW_CAP));
    doc_map.insert(
        "request".to_string(),
        request_block(&finalize_request(&request, &coordinator.identity)),
    );
    doc_map.insert(
        "result".to_string(),
        result_block(&finalize_result(&result, &verifier.identity)),
    );
    doc_map.insert(
        "expected".to_string(),
        expected_block(
            "accepted",
            WINDOW_CAP,
            None,
            correction,
            &committed,
            &new_prefix_hash,
            false,
        ),
    );
    doc_map.insert(
        "over_cap_case".to_string(),
        json!({
            "name": "len-33-window-over-cap",
            "description": "ADR-032 §7 fixture row 3 (plan §2.2): len(window_tokens) = 33 > min(WINDOW_CAP = 32, batch_window_max = 32) — payload_too_large BEFORE any engine work (schema-valid and signature-valid, so the reject fires at the cap stage itself; pairs with the deadline-DoS shape).",
            "wire": request_block(&finalize_request(&over_request, &coordinator.identity)),
            "context": {
                "batch_window_max": WINDOW_CAP,
                "window_cap": WINDOW_CAP,
                "window_len": 33,
                "effective_cap": WINDOW_CAP,
                "engine_passes_before_reject": 0,
            },
            "expected_reject": "payload_too_large",
        }),
    );
    doc
}

fn fixture_eos(coordinator: &Actor, verifier: &Actor, params_hash: &str) -> Value {
    // EOG inside the accepted path (plan flag F-2): the correction FIELD
    // is PRESENT as null (never omitted), the commit covers the accepted
    // prefix only — committed = window[..3] with NO correction token —
    // and the chain hash is computed over exactly those ids.
    let window = vec![601, 602, 603];
    let k = 3;
    let committed = window[..k].to_vec();
    let new_prefix_hash = compute_prefix_hash(GENESIS_PREFIX_HASH, &committed)
        .expect("genesis parent is valid bare hex");

    let request = RequestSpec {
        session_id: "sess-vd-eos-0001",
        seq: 12,
        round: 1,
        window,
        nonce: "4a5b6c7d8e9f01b2",
        deadline_ms: 2_500,
        profile_id: PROFILE_ID,
    }
    .build(
        params_hash,
        &coordinator.identity.peer_id(),
        &coordinator.identity.installation_id(),
    );
    let result = ResultSpec {
        session_id: "sess-vd-eos-0001",
        seq: 4,
        round: 1,
        accepted_prefix_len: k as u32,
        divergence_point: None,
        correction: None,
        verify_pass_ms: 35,
        nonce_echo: "4a5b6c7d8e9f01b2",
    }
    .build(
        &verifier.identity.installation_id(),
        new_prefix_hash.clone(),
    );

    let mut doc = family_header(
        "verifydrafts-4-eos",
        "ADR-032 §7 fixture row 4 (plan §2.2, flag F-2): end-of-generation inside the accepted path. divergence_point null (full acceptance) and correction null PRESENT-AS-NULL — the FIELD is always present, its VALUE is null exactly at EOG; the commit covers the accepted prefix only (committed = window[..3], no correction token) and new_prefix_hash chains over exactly those ids. Prevents second-implementation drift on EOS serialization.",
        coordinator,
        verifier,
    );
    let doc_map = doc.as_object_mut().expect("header is an object");
    doc_map.insert("engine".to_string(), engine_block(WINDOW_CAP));
    doc_map.insert(
        "request".to_string(),
        request_block(&finalize_request(&request, &coordinator.identity)),
    );
    doc_map.insert(
        "result".to_string(),
        result_block(&finalize_result(&result, &verifier.identity)),
    );
    doc_map.insert(
        "expected".to_string(),
        expected_block(
            "accepted",
            k as u32,
            None,
            None,
            &committed,
            &new_prefix_hash,
            true,
        ),
    );
    doc
}

// ---------------------------------------------------------------------------
// The malformed admission-rejection array (ADR-032 §7 fixture row 5)
// ---------------------------------------------------------------------------

/// Shared pre-state of the malformed-file session (recorded in every
/// case entry so each is self-contained). A prior round-1 request from
/// the coordinator (seq 12, nonce 5a6b…) was admitted and committed 16
/// output tokens — the budget ceiling — under a batch_window_max = 8
/// engine. The `committed_output_tokens: 16 == max_output_tokens: 16`
/// template is the injected condition of the `budget-exhausted` case;
/// the `deadline-past` case OVERRIDES it with a fresh ledger (see its
/// `context_extra`) so the ADR-032 §2 first-failure-wins stage order —
/// budget (stage 11) precedes deadline (stage 12) — lets its own
/// condition decide (fixture repair, session 4; the session-3 handoff
/// §5.1 finding, ruled on per the plan's ADR-wins rule: the ADR's stage
/// order wins, the fixture was over-constrained).
fn malformed_session_context() -> Value {
    json!({
        "admitted_session_id": "sess-vd-malformed-0001",
        "pinned_profile_id": PROFILE_ID,
        "session_state": "open",
        "engine": engine_block(8),
        "window_cap": WINDOW_CAP,
        "last_seq_from_coordinator": 12,
        "consumed_nonces": ["5a6b7c8d9e0f1c3d"],
        "last_handled_round": 1,
        "committed_prefix_hash": GENESIS_PREFIX_HASH,
        "budget": {
            "max_endpoints": 1,
            "max_endpoint_seconds": 120,
            "max_output_tokens": 16,
        },
        "committed_output_tokens": 16,
        "lease_expires_at": "2026-10-12T00:30:00Z",
        "admission_clock": VERIFY_AT,
        "admission_clock_unix_ms": VERIFY_AT_UNIX_MS,
    })
}

/// One malformed-file case entry: `{ name, description, verify_at, wire,
/// context, expected_reject }` plus the signature/canonical pins and the
/// recorded fixture keys (plan §2.2: seeds recorded in every file; each
/// entry is self-contained). The `wire` is recorded VERBATIM —
/// `msg.signature` is final (the bad-signature case carries the
/// wrong-key signature as-is).
fn malformed_case(
    name: &str,
    description: &str,
    msg: &VerifyDrafts,
    context_extra: Value,
    expected_reject: &str,
    keys: &Value,
) -> Value {
    assert!(
        !msg.signature.is_empty(),
        "case {name} must carry its final signature"
    );
    let canonical = signing_preimage(msg).expect("case preimage has no floats");
    let mut case = json!({
        "name": name,
        "description": description,
        "verify_at": VERIFY_AT,
        "wire": serde_json::to_value(msg).expect("case wire serializes"),
        "canonical_json": canonical,
        "signature": msg.signature,
        "canonical_json_sha256": sha256_hex(canonical.as_bytes()),
        "context": malformed_session_context(),
        "expected_reject": expected_reject,
    });
    insert(&mut case, keys.clone());
    if let (Some(case_map), Some(extra)) = (
        case.get_mut("context").and_then(|c| c.as_object_mut()),
        context_extra.as_object(),
    ) {
        for (key, value) in extra {
            case_map.insert(key.clone(), value.clone());
        }
    }
    case
}

fn fixture_malformed(coordinator: &Actor, verifier: &Actor, params_hash: &str) -> Value {
    let proposer = coordinator.identity.peer_id();
    let sender = coordinator.identity.installation_id();
    let mut keys = json!({});
    insert(&mut keys, coordinator.block("coordinator"));
    insert(&mut keys, verifier.block("verifier"));
    let valid = |seq: u64, nonce: &'static str| RequestSpec {
        session_id: "sess-vd-malformed-0001",
        seq,
        round: 2,
        window: vec![701, 702, 703, 704],
        nonce,
        deadline_ms: 2_500,
        profile_id: PROFILE_ID,
    };
    let signed = |spec: RequestSpec| {
        finalize_request(
            &spec.build(params_hash, &proposer, &sender),
            &coordinator.identity,
        )
    };

    let mut cases: Vec<Value> = Vec::new();

    // 1. Empty window: schema failure (strict parse rejects the empty
    //    window) -> bad_frame, before the signature stage.
    let mut empty_spec = valid(13, "bb0000000000000a");
    empty_spec.window = vec![];
    cases.push(malformed_case(
        "empty-window",
        "ADR-032 §2 admission table, schema row: window_tokens is empty — there is nothing to verify (§1: an empty window is malformed). The strict two-pass parse fails before the signature stage; expected code bad_frame.",
        &signed(empty_spec),
        json!({}),
        "bad_frame",
        &keys,
    ));

    // 2. Bad signature: a REAL Ed25519 signature by the verifier's key on
    //    the correct preimage, while `sender` names the coordinator —
    //    the sender-binding check fires first, and the signature fails
    //    under the expected coordinator key either way.
    //    Unauthenticated = malformed, fail-closed.
    let mut wrong_key = signed(valid(13, "bb0000000000000b"));
    let preimage = signing_preimage(&wrong_key).expect("preimage has no floats");
    let verifier_signature = BASE64.encode(
        SigningKey::from_bytes(&verifier.identity.to_bytes())
            .sign(preimage.as_bytes())
            .to_bytes(),
    );
    wrong_key.signature = verifier_signature;
    cases.push(malformed_case(
        "bad-signature",
        "ADR-032 §2 admission table, signature row: the signature is a genuine Ed25519 signature by the VERIFIER fixture key over the correct preimage, while sender names the coordinator — sender binding fails first (§1 rule 5) and the signature fails under the expected coordinator key; unauthenticated = malformed, fail-closed. Expected code bad_frame.",
        &wrong_key,
        json!({ "signed_by": "verifier fixture key (wrong signer)" }),
        "bad_frame",
        &keys,
    ));

    // 3. Wrong profile_id: profile_mismatch + session teardown (I7). The
    //    wire is signed WITH the wrong profile in it (schema-valid,
    //    signature-valid — the reject is semantic, not cryptographic).
    let mut cross_spec = valid(13, "bb00000000000001");
    cross_spec.profile_id = WRONG_PROFILE_ID;
    cases.push(malformed_case(
        "wrong-profile-id",
        "ADR-032 §2 admission table, profile row: profile_id differs from the session's pinned profile — profile_mismatch plus session teardown (invariant I7); later frames on this stream see cancelled_by_peer. The wire is schema-valid and signature-valid (signed with the wrong profile in the preimage).",
        &signed(cross_spec),
        json!({ "wire_profile_id": WRONG_PROFILE_ID }),
        "profile_mismatch",
        &keys,
    ));

    // 4. Duplicate nonce: replayed_request (I6) — the nonce is
    //    single-use per session at ANY seq (§2 RC-7).
    cases.push(malformed_case(
        "duplicate-nonce",
        "ADR-032 §2 admission table, nonce-reuse row: the nonce was already consumed by the admitted round-1 request (at any seq) — replayed_request, no state change (invariant I6).",
        &signed(valid(13, "5a6b7c8d9e0f1c3d")),
        json!({}),
        "replayed_request",
        &keys,
    ));

    // 5. Duplicate seq: seq == last seen from sender.
    cases.push(malformed_case(
        "duplicate-seq",
        "ADR-032 §2 admission table, duplicate-seq row: seq equals the last seen seq from this sender (12) with a fresh nonce — replayed_request before any other check (§2 RC-7).",
        &signed(valid(12, "bb00000000000002")),
        json!({}),
        "replayed_request",
        &keys,
    ));

    // 6. Non-monotone seq: a FRESH but decreased value.
    cases.push(malformed_case(
        "non-monotone-seq",
        "ADR-032 §2 admission table, decreased-seq row: a fresh but decreased seq (11 < last seen 12) — replayed_request (per-(session, sender) strict monotonicity, RC-7).",
        &signed(valid(11, "bb00000000000003")),
        json!({}),
        "replayed_request",
        &keys,
    ));

    // 7. Deadline past at admission: the frame arrived at 23:59:00Z with
    //    deadline_ms 1000 (the clamp minimum); the admission clock is
    //    verify_at (00:00:00Z) — 60 s of queue wait exhausted the
    //    deadline long before admission. Signed with deadline_ms 1000 in
    //    the preimage (schema- and signature-valid; the reject is
    //    temporal). Context carries a FRESH budget ledger (fixture
    //    repair, session 4): the template's at-ceiling 16/16 ledger is
    //    the budget-exhausted case's injected condition and would fire
    //    `overloaded` at stage 11 before the deadline stage could decide
    //    — here the round-1 request was admitted but ABANDONED before
    //    any commit (RC-5(c) gap semantics), so zero tokens are
    //    committed and the deadline stage classifies.
    let mut deadline_spec = valid(13, "bb00000000000004");
    deadline_spec.deadline_ms = 1_000;
    cases.push(malformed_case(
        "deadline-past",
        "ADR-032 §2 admission table, deadline-past-at-admission row: arrival 2026-10-11T23:59:00Z + deadline_ms 1000 (the DEADLINE_CLAMP_MIN_MS floor) = 23:59:01Z, one minute before the verify_at admission clock — deadline_exceeded at admission (stage 12; re-checked again before dispatch per A-2). The context's budget ledger is FRESH (0 tokens committed; the round-1 request was admitted but abandoned before commit, RC-5(c)), so the earlier budget stage passes and the deadline stage decides.",
        &signed(deadline_spec),
        json!({
            "request_arrival": REQUEST_ARRIVAL,
            "request_arrival_unix_ms": REQUEST_ARRIVAL_UNIX_MS,
            "deadline_ms_effective": 1_000,
            "deadline_expires_at_unix_ms": REQUEST_ARRIVAL_UNIX_MS + 1_000,
            "committed_output_tokens": 0,
            "budget_ledger": "fresh (0 tokens committed; round 1 was admitted but abandoned before commit, RC-5(c)) — stage 11 passes so stage 12 decides",
        }),
        "deadline_exceeded",
        &keys,
    ));

    // 8. Unknown session: session binding failure -> bad_frame. Signed
    //    with the unknown session id in the preimage.
    let mut unknown_spec = valid(13, "bb00000000000005");
    unknown_spec.session_id = "sess-vd-unknown-0009";
    cases.push(malformed_case(
        "unknown-session",
        "ADR-032 §2 admission table, session-binding row: session_id is unknown to (differs from) the stream's admitted session — bad_frame. The wire is schema-valid and signature-valid (the reject is a binding failure).",
        &signed(unknown_spec),
        json!({ "wire_session_id": "sess-vd-unknown-0009" }),
        "bad_frame",
        &keys,
    ));

    // 9. Torn-down session: cancelled_by_peer, stream closed.
    cases.push(malformed_case(
        "torn-down-session",
        "ADR-032 §2 admission table, torn-down row: the session was torn down after a profile_mismatch — cancelled_by_peer and the stream is closed.",
        &signed(valid(13, "bb00000000000006")),
        json!({
            "session_state": "torn_down",
            "teardown_reason": "profile_mismatch",
        }),
        "cancelled_by_peer",
        &keys,
    ));

    // 10. Lease expired mid-session: expired_token (ADR-026).
    cases.push(malformed_case(
        "lease-expired",
        "ADR-032 §2 admission table, lease row: the ADR-026 serving lease expired at 2026-10-11T23:00:00Z, an hour before the verify_at admission clock — expired_token.",
        &signed(valid(13, "bb00000000000007")),
        json!({
            "lease_expires_at": LEASE_EXPIRY,
            "lease_expires_at_unix_ms": LEASE_EXPIRY_UNIX_MS,
        }),
        "expired_token",
        &keys,
    ));

    // 11. Window over batch_window_max (not the global cap): len 9 >
    //     min(WINDOW_CAP = 32, batch_window_max = 8) = 8 ->
    //     payload_too_large before any engine work (RC-8).
    let mut over_bwm = valid(13, "bb00000000000008");
    over_bwm.window = (700..=708).collect();
    cases.push(malformed_case(
        "window-over-batch-window-max",
        "ADR-032 §2 admission table, batch-bound row: len(window_tokens) = 9 > min(WINDOW_CAP = 32, batch_window_max = 8) = 8 — payload_too_large BEFORE any engine work (RC-8); zero engine passes.",
        &signed(over_bwm),
        json!({
            "batch_window_max": 8,
            "effective_cap": 8,
            "window_len": 9,
            "engine_passes_before_reject": 0,
        }),
        "payload_too_large",
        &keys,
    ));

    // 12. Budget exhausted: overloaded (I8/§8e) — cumulative committed
    //     output tokens already sit at the session ceiling.
    cases.push(malformed_case(
        "budget-exhausted",
        "ADR-032 §2 admission table, budget row + §8 RC-5(e): cumulative committed output tokens (16) already equal budget.max_output_tokens (16) — this VerifyDrafts would exceed the session budget; overloaded (invariant I8).",
        &signed(valid(13, "bb00000000000009")),
        json!({}),
        "overloaded",
        &keys,
    ));

    Value::Array(cases)
}

// ---------------------------------------------------------------------------
// Negotiation vectors (ADR-032 §7 last row + the plan's base-form addition)
// ---------------------------------------------------------------------------

/// Unsigned canonical recording block: fields + canonical bytes + sha256.
fn canonical_block(fields: Value) -> Value {
    let canonical = canonical_json(&fields).expect("negotiation payload has no floats");
    json!({
        "fields": fields,
        "canonical_json": canonical,
        "canonical_json_sha256": sha256_hex(canonical.as_bytes()),
    })
}

const UNSIGNED_NOTE: &str = "none — negotiation messages carry no signature of their own \
    (msp-cooperative-v1 §1; msp-v1 §6.6 PeerId binding)";

fn negotiation_header(
    name: &str,
    description: &str,
    coordinator: &Actor,
    verifier: &Actor,
) -> Value {
    let mut doc = json!({
        "name": name,
        "description": description,
        "signed": UNSIGNED_NOTE,
    });
    insert(&mut doc, coordinator.block("coordinator"));
    insert(&mut doc, verifier.block("verifier"));
    doc
}

fn fixture_offer_1(coordinator: &Actor, verifier: &Actor) -> Value {
    let mut doc = negotiation_header(
        "session-offer-1",
        "Base ADR-029 SessionOffer canonical form (msp-cooperative-v1 §2) WITHOUT the ADR-032 §3 additive fields — pins the frozen base shape the additive verifier_backend extends. Unsigned: negotiation messages ride the handshake-authenticated session. The current Rust SessionOffer struct requires verifier_backend in the new canonical form (plan flag F-6 — no deployed fleet to be compatible with), so this base form is recorded as raw JSON and does NOT deserialize into the extended struct.",
        coordinator,
        verifier,
    );
    doc.as_object_mut().expect("doc").insert(
        "block".to_string(),
        canonical_block(json!({
            "session_id": "sess-coop-0001",
            "protocol_version": "msp-cooperative-v1",
            "preset": "fast",
            "budget": {
                "max_endpoints": 1,
                "max_endpoint_seconds": 120,
                "max_output_tokens": 2048,
            },
        })),
    );
    doc
}

fn fixture_offer_2(coordinator: &Actor, verifier: &Actor) -> Value {
    // Superseded SECOND form, preserved as DATA (ADR-032 revision 4
    // §3/G3): the v2 shape (base + verifier_backend) does NOT
    // deserialize into the v3 struct, exactly as session-offer-1 pins
    // the base form against the v2 struct. Recorded as raw JSON — the
    // live struct serializes the v3 form.
    let mut doc = negotiation_header(
        "session-offer-2",
        "SECOND SessionOffer canonical form (ADR-032 §3 / A-4, plan §2.2): the base ADR-029 shape plus the ADDITIVE verifier_backend (the requester's own backend). SUPERSEDED at ADR-032 revision 4 (§3/G3) by the THIRD form (session-offer-3.json, which adds the REQUIRED profile_id + generation_params_hash) and preserved as DATA that does NOT deserialize into the current extended struct — the F-6 discipline: no deployed fleet reads any earlier form, superseded forms fail schema. Unsigned (handshake-authenticated session).",
        coordinator,
        verifier,
    );
    doc.as_object_mut().expect("doc").insert(
        "block".to_string(),
        canonical_block(json!({
            "session_id": "sess-coop-0002",
            "protocol_version": "msp-cooperative-v1",
            "preset": "verified",
            "budget": {
                "max_endpoints": 1,
                "max_endpoint_seconds": 120,
                "max_output_tokens": 2048,
            },
            "verifier_backend": "cpu",
        })),
    );
    doc
}

/// The THIRD offer canonical form (ADR-032 revision 4 §3/G3): v2 plus the
/// REQUIRED `profile_id` (msp1:<64 hex>, §1 form) and
/// `generation_params_hash` (bare 64-hex, §1 rule-3 preimage) — the
/// coordinator's pinned exact profile and sampling parameters, both
/// compared against the serving side's own pinned config at negotiation
/// (honest `profile_mismatch` / `params_mismatch` rejects; discovery, not
/// trusted input — verifier-side pinning stays the enforcement
/// authority).
fn fixture_offer_3(
    coordinator: &Actor,
    verifier: &Actor,
    profile_id: &str,
    params_hash: &str,
) -> Value {
    let offer = SessionOffer {
        session_id: "sess-coop-0003".to_string(),
        protocol_version: "msp-cooperative-v1".to_string(),
        preset: Preset::Verified,
        budget: SessionBudget {
            max_endpoints: 1,
            max_endpoint_seconds: 120,
            max_output_tokens: 2048,
        },
        verifier_backend: Backend::Cpu,
        profile_id: profile_id.to_string(),
        generation_params_hash: params_hash.to_string(),
    };
    let mut doc = negotiation_header(
        "session-offer-3",
        "THIRD SessionOffer canonical form (ADR-032 revision 4 §3/G3, 2026-10-12): the v2 shape plus the REQUIRED binding fields profile_id (msp1:<64 hex> — the coordinator's pinned exact profile under the project rule) and generation_params_hash (bare 64-hex, the §1 rule-3 canonical preimage). Absence of EITHER fails schema; the base and v2 forms are preserved as data that fails deserialization (session-offer-1/2.json). The serving side compares both against its own pinned config and rejects profile_mismatch / params_mismatch — negotiation-time discovery; verifier-side pinning (stage 4 params, stage 7 profile, §8 commit-time equality) remains the enforcement authority. Unsigned (handshake-authenticated session).",
        coordinator,
        verifier,
    );
    doc.as_object_mut().expect("doc").insert(
        "block".to_string(),
        canonical_block(serde_json::to_value(&offer).expect("offer serializes")),
    );
    doc
}

fn fixture_accept_1(coordinator: &Actor, verifier: &Actor) -> Value {
    let mut doc = negotiation_header(
        "session-accept-1",
        "Base ADR-029 SessionAccept canonical form (msp-cooperative-v1 §3) WITHOUT the ADR-032 §3 additive engine disclosure — pins the frozen base shape the additive engine object extends. Unsigned (handshake-authenticated session); raw JSON form, not deserializable into the extended Rust struct (F-6 discipline).",
        coordinator,
        verifier,
    );
    doc.as_object_mut().expect("doc").insert(
        "block".to_string(),
        canonical_block(json!({
            "session_id": "sess-coop-0001",
            "protocol_version": "msp-cooperative-v1",
            "preset": "fast",
            "budget": {
                "max_endpoints": 1,
                "max_endpoint_seconds": 120,
                "max_output_tokens": 2048,
            },
        })),
    );
    doc
}

fn fixture_accept_2(coordinator: &Actor, verifier: &Actor) -> Value {
    let accept = SessionAccept {
        session_id: "sess-coop-0002".to_string(),
        protocol_version: "msp-cooperative-v1".to_string(),
        preset: Preset::Verified,
        budget: SessionBudget {
            max_endpoints: 1,
            max_endpoint_seconds: 60,
            max_output_tokens: 512,
        },
        engine: EngineDisclosure {
            backend: Backend::Cpu,
            batch_verify: true,
            batch_window_max: WINDOW_CAP,
        },
    };
    let mut doc = negotiation_header(
        "session-accept-2",
        "Extended SessionAccept canonical form (ADR-032 §3 / RC-8, plan §2.2): the base shape plus the ADDITIVE engine disclosure {backend, batch_verify, batch_window_max} — batch_verify: true requires an honest batch_window_max in 1..=WINDOW_CAP (invariant I4); the effective budget is clamped DOWN only (never up). Unsigned (handshake-authenticated session).",
        coordinator,
        verifier,
    );
    doc.as_object_mut().expect("doc").insert(
        "block".to_string(),
        canonical_block(serde_json::to_value(&accept).expect("accept serializes")),
    );
    doc
}

fn fixture_reject_1(coordinator: &Actor, verifier: &Actor) -> Value {
    // Six frozen reasons: the revision-2 four PLUS the two offer-form-v3
    // reasons (revision 4 §3/G3). The four existing canonicalizations
    // are UNCHANGED BYTES — the extended file only appends entries.
    let reasons = [
        SessionRejectReason::PresetUnavailable,
        SessionRejectReason::BackendMismatch,
        SessionRejectReason::BatchVerifyUnsupported,
        SessionRejectReason::BudgetInfeasible,
        SessionRejectReason::ProfileMismatch,
        SessionRejectReason::ParamsMismatch,
    ];
    let reason_list: Vec<Value> = reasons
        .iter()
        .map(|&reason| {
            let reject = SessionReject {
                session_id: "sess-coop-0003".to_string(),
                protocol_version: "msp-cooperative-v1".to_string(),
                reason,
            };
            let mut block =
                canonical_block(serde_json::to_value(&reject).expect("reject serializes"));
            block
                .as_object_mut()
                .expect("block")
                .insert("reason".to_string(), json!(reason.as_str()));
            block
        })
        .collect();
    let primary = reason_list
        .iter()
        .find(|b| b["reason"] == json!("backend_mismatch"))
        .expect("backend_mismatch is one of the frozen reasons")
        .clone();

    let mut doc = negotiation_header(
        "session-reject-1",
        "SessionReject canonical form (ADR-032 §3 / A-4, plan §2.2): the honest offer-reject wire shape {session_id, protocol_version, reason} with the frozen reason vocabulary preset_unavailable | backend_mismatch | batch_verify_unsupported | budget_infeasible plus the two offer-form-v3 reasons profile_mismatch | params_mismatch (ADR-032 revision 4 §3/G3 — negotiation-level vocabulary, the same class as preset_unavailable; the §6.5 registry is untouched). The primary case is backend_mismatch (the E0 backend-pairing reject); the reasons list records ALL SIX canonical serializations (the first four are unchanged bytes from the pre-revision-4 file). Unsigned (handshake-authenticated session).",
        coordinator,
        verifier,
    );
    let doc_map = doc.as_object_mut().expect("doc");
    doc_map.insert("primary".to_string(), primary);
    doc_map.insert("reasons".to_string(), Value::Array(reason_list));
    doc
}

// ---------------------------------------------------------------------------
// The commit-form carrier vector (ADR-032 §2/G2, revision 4: "a
// commit-form golden vector joins the §7 fixture set before any second
// consumer exists")
// ---------------------------------------------------------------------------

/// The family's `PrefixCommit` carrier as a golden vector: the BARE JSON
/// object with exactly the shipped `SpecMessage::PrefixCommit` field
/// names — NO externally-tagged envelope, NO signature — whose content
/// reproduces the `verifydrafts-1-accept` result (same session, round,
/// committed ids, chain hash), so the golden test can admit fixture 1's
/// request and apply THIS carrier through the real gate.
fn fixture_commit_carrier(
    coordinator: &Actor,
    verifier: &Actor,
    profile_id: &str,
    params_hash: &str,
) -> Value {
    // Exactly fixture_accept's committed set: window [101..108] ++ [999]
    // bonus, chaining from the genesis root.
    let mut committed: Vec<u32> = vec![101, 102, 103, 104, 105, 106, 107, 108];
    committed.push(999);
    let new_prefix_hash = compute_prefix_hash(GENESIS_PREFIX_HASH, &committed)
        .expect("genesis parent is valid bare hex");

    // The carrier, field-for-field (the shipped SpecMessage::PrefixCommit
    // names; `profile_id` for the state machine's `model_profile_id`).
    let carrier = json!({
        "session_id": "sess-vd-accept-0001",
        "round": 3,
        "previous_prefix_hash": GENESIS_PREFIX_HASH,
        "accepted_token_ids": committed,
        "new_prefix_hash": new_prefix_hash,
        "profile_id": profile_id,
        "generation_params_hash": params_hash,
        "sender": coordinator.identity.installation_id(),
    });
    let canonical = canonical_json(&carrier).expect("carrier has no floats");

    let mut doc = json!({
        "name": "verifydrafts-5-commit-carrier",
        "description": "ADR-032 §2/G2 (revision 4, 2026-10-12): the family's PrefixCommit carrier as a commit-form golden vector — the BARE JSON object carrying exactly the shipped SpecMessage::PrefixCommit field names (session_id, round, previous_prefix_hash, accepted_token_ids, new_prefix_hash, profile_id, generation_params_hash, sender) WITHOUT the old vocabulary's externally-tagged envelope and WITHOUT signature. Authentication is the cryptographically authenticated session channel plus RC-4 reproduction: the carrier's sender MUST equal the installation id pinned from that channel (mismatch is bad_frame), and the content must reproduce the verifier's own outstanding VerifyDraftsResult. Parsing is STRICT (unknown fields, wrong types, non-bare-hex hashes are bad_frame before any state is touched). The content reproduces verifydrafts-1-accept's result (same session/round/ids/hash), so the golden test replays fixture 1's request and applies this carrier through the real gate. The freeze ADR's binding migration (version, nonce, deadline, signature) remains deferred.",
        "field_names": [
            "session_id",
            "round",
            "previous_prefix_hash",
            "accepted_token_ids",
            "new_prefix_hash",
            "profile_id",
            "generation_params_hash",
            "sender",
        ],
        "carrier": {
            "fields": carrier,
            "canonical_json": canonical,
            "canonical_json_sha256": sha256_hex(canonical.as_bytes()),
        },
        "construction": {
            "rule": PREFIX_HASH_RULE,
            "parent_prefix_hash": GENESIS_PREFIX_HASH,
            "committed_token_ids": committed,
        },
        "binding": {
            "signed": "none — the carrier carries NO signature (§2/G2); it rides the authenticated session channel",
            "sender_rule": "sender MUST equal the installation id pinned from the authenticated channel (mismatch is bad_frame)",
            "sender": coordinator.identity.installation_id(),
        },
    });
    insert(&mut doc, coordinator.block("coordinator"));
    insert(&mut doc, verifier.block("verifier"));
    doc
}

// ---------------------------------------------------------------------------
// main: write everything (idempotent by construction)
// ---------------------------------------------------------------------------

fn main() {
    // Self-checks on the time anchors (values verified independently
    // against `date -u`): the recorded integers must equal the RFC 3339
    // strings they accompany, or the deadline contexts would lie.
    assert_eq!(unix_ms(VERIFY_AT), VERIFY_AT_UNIX_MS);
    assert_eq!(unix_ms(REQUEST_ARRIVAL), REQUEST_ARRIVAL_UNIX_MS);
    assert_eq!(unix_ms(LEASE_EXPIRY), LEASE_EXPIRY_UNIX_MS);

    let coordinator = Actor::from_seed(COORDINATOR_SEED);
    let verifier = Actor::from_seed(VERIFIER_SEED);
    let (_, params_hash) = generation_params_block();

    let vectors_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../protocol/vectors");

    let files: Vec<(&str, Value)> = vec![
        (
            "verifydrafts-1-accept.json",
            fixture_accept(&coordinator, &verifier, &params_hash),
        ),
        (
            "verifydrafts-2-reject.json",
            fixture_reject(&coordinator, &verifier, &params_hash),
        ),
        (
            "verifydrafts-3-boundary.json",
            fixture_boundary(&coordinator, &verifier, &params_hash),
        ),
        (
            "verifydrafts-4-eos.json",
            fixture_eos(&coordinator, &verifier, &params_hash),
        ),
        (
            "verifydrafts-malformed.json",
            fixture_malformed(&coordinator, &verifier, &params_hash),
        ),
        (
            "session-offer-1.json",
            fixture_offer_1(&coordinator, &verifier),
        ),
        (
            "session-offer-2.json",
            fixture_offer_2(&coordinator, &verifier),
        ),
        (
            "session-offer-3.json",
            fixture_offer_3(&coordinator, &verifier, PROFILE_ID, &params_hash),
        ),
        (
            "session-accept-1.json",
            fixture_accept_1(&coordinator, &verifier),
        ),
        (
            "session-accept-2.json",
            fixture_accept_2(&coordinator, &verifier),
        ),
        (
            "session-reject-1.json",
            fixture_reject_1(&coordinator, &verifier),
        ),
        (
            "verifydrafts-5-commit-carrier.json",
            fixture_commit_carrier(&coordinator, &verifier, PROFILE_ID, &params_hash),
        ),
    ];

    for (filename, doc) in &files {
        let path = vectors_dir.join(filename);
        let pretty = serde_json::to_string_pretty(doc).expect("fixture pretty-prints");
        std::fs::write(&path, format!("{pretty}\n")).expect("write fixture");
        println!("wrote {}", path.display());
    }
    println!(
        "verifydrafts fixture generation complete: {} files (idempotent — rerun leaves git diff empty)",
        files.len()
    );
}
