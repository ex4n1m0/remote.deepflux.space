//! Consumer-side golden-vector test for the ADR-032 VerifyDrafts family
//! and the cooperative negotiation shapes (implementation plan §2.3; the
//! fixtures are `protocol/vectors/*` produced by
//! `cargo run -p modelswarm-session --example gen-verifydrafts-vectors`).
//!
//! Venue: per-push, default features (ADR-032 §7 execution-venue matrix,
//! item 1). This test is the CI guard that the committed fixtures and
//! the implementation still reproduce each other byte-for-byte: any
//! future implementation in any language must reproduce identical
//! canonical bytes, signatures, and outcomes from the same files
//! (consumer-neutrality rule).
//!
//! Session 3 activation: every family fixture (1–4, the len-33 over-cap
//! case, and all 12 malformed admission-rejection cases) is REPLAYED
//! through the real §3 [`VerifyDraftsGate`] with a mock engine and the
//! clock fixed at the recorded `verify_at`, asserting the exact expected
//! codes / CancelRound reasons / state transitions (the session-2
//! `TODO(session 3)` hooks, now live).

use modelswarm_identity::{installation_id_for, peer_id_for, InstallationIdentity};
use modelswarm_runtime::SamplingParams;
use modelswarm_session::negotiation::FrameRejectReason;
use modelswarm_session::negotiation::{
    EngineDisclosure, SessionAccept, SessionBudget, SessionOffer, SessionReject,
    SessionRejectReason,
};
use modelswarm_session::verifydrafts::{
    batch_generation_params_hash, is_bare_hash, sign_verify_drafts_result, signing_preimage,
    verify_verify_drafts_result_signature, verify_verify_drafts_signature, AdmissionDecision,
    BatchVerifyEngine, CommitApplyOutcome, DispatchOutcome, FrameParseError, GatePreStateSeed,
    GateState, VerifyDrafts, VerifyDraftsGate, VerifyDraftsGateConfig, VerifyDraftsResult,
    COOPERATIVE_PROTOCOL_VERSION, WINDOW_CAP,
};
use modelswarm_session::{compute_prefix_hash, CommitPrefix, GENESIS_PREFIX_HASH};
use modelswarm_transport::ed25519_dalek::VerifyingKey;
use modelswarm_types::canonical_json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering};

const FIXTURE_ACCEPT: &str = include_str!("../../../protocol/vectors/verifydrafts-1-accept.json");
const FIXTURE_REJECT: &str = include_str!("../../../protocol/vectors/verifydrafts-2-reject.json");
const FIXTURE_BOUNDARY: &str =
    include_str!("../../../protocol/vectors/verifydrafts-3-boundary.json");
const FIXTURE_EOS: &str = include_str!("../../../protocol/vectors/verifydrafts-4-eos.json");
const FIXTURE_MALFORMED: &str =
    include_str!("../../../protocol/vectors/verifydrafts-malformed.json");
const SESSION_OFFER_1: &str = include_str!("../../../protocol/vectors/session-offer-1.json");
const SESSION_OFFER_2: &str = include_str!("../../../protocol/vectors/session-offer-2.json");
const SESSION_OFFER_3: &str = include_str!("../../../protocol/vectors/session-offer-3.json");
const SESSION_OFFER_4: &str =
    include_str!("../../../protocol/vectors/session-offer-4-unknown-preset.json");
const SESSION_ACCEPT_1: &str = include_str!("../../../protocol/vectors/session-accept-1.json");
const SESSION_ACCEPT_2: &str = include_str!("../../../protocol/vectors/session-accept-2.json");
const SESSION_REJECT_1: &str = include_str!("../../../protocol/vectors/session-reject-1.json");
const PIN_CARRIER_1: &str = include_str!("../../../protocol/vectors/pin-carrier-1-accept.json");
const PIN_CARRIER_2: &str = include_str!("../../../protocol/vectors/pin-carrier-2-mismatch.json");
const COMMIT_CARRIER: &str =
    include_str!("../../../protocol/vectors/verifydrafts-5-commit-carrier.json");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn doc(raw: &str) -> Value {
    serde_json::from_str(raw).expect("fixture json parses")
}

fn verifying_key(pubkey_hex: &str) -> VerifyingKey {
    let bytes = hex::decode(pubkey_hex).expect("recorded public key is hex");
    let bytes: [u8; 32] = bytes.try_into().expect("recorded public key is 32 bytes");
    VerifyingKey::from_bytes(&bytes).expect("recorded public key parses")
}

fn token_ids(value: &Value) -> Vec<u32> {
    value
        .as_array()
        .expect("token id list")
        .iter()
        .map(|v| v.as_u64().expect("token id is a u32") as u32)
        .collect()
}

// ---------------------------------------------------------------------------
// Session-3 replay helpers: injected clock + mock engine + the real gate
// ---------------------------------------------------------------------------

/// Days-from-civil (Howard Hinnant) — the generator's own conversion, so
/// the test derives the anchors independently of any stored unix-ms int.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parses the fixtures' `"YYYY-MM-DDTHH:MM:SSZ"` stamps into unix ms.
fn unix_ms(iso: &str) -> u64 {
    let (y, m, d) = (
        iso[0..4].parse::<i64>().expect("year"),
        iso[5..7].parse::<i64>().expect("month"),
        iso[8..10].parse::<i64>().expect("day"),
    );
    let (hh, mm, ss) = (
        iso[11..13].parse::<i64>().expect("hour"),
        iso[14..16].parse::<i64>().expect("minute"),
        iso[17..19].parse::<i64>().expect("second"),
    );
    (((days_from_civil(y, m, d) * 24 + hh) * 60 + mm) * 60 + ss) as u64 * 1000
}

#[test]
fn unix_ms_matches_the_recorded_fixture_anchors() {
    // Session 2 verified these against `date -u`; the test re-derives them.
    assert_eq!(unix_ms("2026-10-12T00:00:00Z"), 1_791_763_200_000);
    assert_eq!(unix_ms("2026-10-11T23:59:00Z"), 1_791_763_140_000);
    assert_eq!(unix_ms("2026-10-11T23:00:00Z"), 1_791_759_600_000);
}

/// The counting mock engine (plan §3.5: mock-fixed outcome; the recorded
/// fixture result IS the outcome).
struct MockVerifyEngine {
    disclosure: EngineDisclosure,
    outcome: (u32, Option<u32>),
    calls: AtomicUsize,
}

impl MockVerifyEngine {
    fn new(disclosure: EngineDisclosure, outcome: (u32, Option<u32>)) -> Self {
        Self {
            disclosure,
            outcome,
            calls: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl BatchVerifyEngine for MockVerifyEngine {
    async fn verify_window(
        &self,
        window: &[u32],
        _params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), modelswarm_runtime::RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok((self.outcome.0.min(window.len() as u32), self.outcome.1))
    }
    fn capabilities(&self) -> EngineDisclosure {
        self.disclosure.clone()
    }
}

/// Plan §2.3 check (1)+(2) for one recorded message block: recompute the
/// canonical bytes from `fields`, assert equality with the recorded
/// `canonical_json` AND `canonical_json_sha256`, verify the signature
/// under the recorded public key, and assert
/// `installation_id_for(pubkey) == sender` (§1 rule 5).
fn check_signed_request(block: &Value, pubkey_hex: &str) -> VerifyDrafts {
    let fields = block.get("fields").expect("block records fields").clone();
    let msg = VerifyDrafts::parse(&fields).expect("strict two-pass parse accepts the wire form");
    let canonical = signing_preimage(&msg).expect("request preimage canonicalizes");
    assert_eq!(
        canonical,
        block["canonical_json"].as_str().expect("canonical_json"),
        "recomputed canonical bytes must equal the recorded form"
    );
    assert_eq!(
        sha256_hex(canonical.as_bytes()),
        block["canonical_json_sha256"]
            .as_str()
            .expect("canonical_json_sha256"),
    );
    assert_eq!(
        msg.signature,
        block["signature"].as_str().expect("signature"),
        "recorded signature must equal the fields form"
    );
    let key = verifying_key(pubkey_hex);
    verify_verify_drafts_signature(&msg, &key)
        .expect("signature verifies under the recorded coordinator key");
    assert_eq!(
        installation_id_for(&key.to_bytes()),
        msg.sender,
        "sender must derive from the verifying key (§1 rule 5)"
    );
    // The full serde form of the parsed message equals the recorded fields.
    assert_eq!(serde_json::to_value(&msg).unwrap(), fields);
    msg
}

fn check_signed_result(block: &Value, pubkey_hex: &str) -> VerifyDraftsResult {
    let fields = block.get("fields").expect("block records fields").clone();
    let msg =
        VerifyDraftsResult::parse(&fields).expect("strict two-pass parse accepts the wire form");
    let canonical = signing_preimage(&msg).expect("result preimage canonicalizes");
    assert_eq!(
        canonical,
        block["canonical_json"].as_str().expect("canonical_json"),
        "recomputed canonical bytes must equal the recorded form"
    );
    assert_eq!(
        sha256_hex(canonical.as_bytes()),
        block["canonical_json_sha256"]
            .as_str()
            .expect("canonical_json_sha256"),
    );
    assert_eq!(
        msg.signature,
        block["signature"].as_str().expect("signature"),
    );
    let key = verifying_key(pubkey_hex);
    verify_verify_drafts_result_signature(&msg, &key)
        .expect("signature verifies under the recorded verifier key");
    assert_eq!(
        installation_id_for(&key.to_bytes()),
        msg.sender,
        "sender must derive from the verifying key (§1 rule 5)"
    );
    assert_eq!(serde_json::to_value(&msg).unwrap(), fields);
    msg
}

/// Shared invariants of every family fixture (fixtures 1-4): request +
/// result blocks verify, the result echoes the request binding, the
/// generation-params preimage is byte-pinned (F-1), the engine
/// disclosure is schema-valid, all hashes are bare hex, and the window
/// is inside the effective cap.
fn check_family_fixture(f: &Value) -> (VerifyDrafts, VerifyDraftsResult) {
    let req = check_signed_request(
        &f["request"],
        f["coordinator_public_key_hex"].as_str().unwrap(),
    );
    let res = check_signed_result(&f["result"], f["verifier_public_key_hex"].as_str().unwrap());

    // Recorded identities.
    assert_eq!(
        req.sender,
        f["coordinator_installation_id"].as_str().unwrap(),
        "request sender is the recorded coordinator installation id"
    );
    assert_eq!(
        res.sender,
        f["verifier_installation_id"].as_str().unwrap(),
        "result sender is the recorded verifier installation id"
    );
    assert_eq!(req.proposer_id, f["coordinator_peer_id"].as_str().unwrap());

    // Result echoes the request binding (RC-3 (b)/(c) inputs).
    assert_eq!(res.session_id, req.session_id);
    assert_eq!(res.round, req.round);
    assert_eq!(res.nonce_echo, req.nonce);
    assert_eq!(req.protocol_version, COOPERATIVE_PROTOCOL_VERSION);
    assert_eq!(res.protocol_version, COOPERATIVE_PROTOCOL_VERSION);

    // F-1 byte-pin: the recorded generation-params preimage canonical
    // bytes and sha256 equal the family hash over the runtime default.
    let params = &f["generation_params"];
    let params_object = json!({
        "seed": params["seed"],
        "temperature": params["temperature"],
        "top_k": params["top_k"],
        "top_p": params["top_p"],
    });
    assert_eq!(
        canonical_json(&params_object).unwrap(),
        params["canonical_json"].as_str().unwrap(),
    );
    let params_hash = batch_generation_params_hash(&SamplingParams::default())
        .expect("default sampling params are integral");
    assert_eq!(params_hash, req.generation_params_hash);
    assert_eq!(params_hash, params["sha256_hex"].as_str().unwrap());

    // Engine disclosure (RC-8): schema-valid, and the window fits the
    // effective cap min(WINDOW_CAP, batch_window_max).
    let engine: EngineDisclosure =
        serde_json::from_value(f["engine"].clone()).expect("engine disclosure parses");
    assert!(engine.is_valid_disclosure());
    let effective_cap = WINDOW_CAP.min(engine.batch_window_max);
    assert!(!req.window_tokens.is_empty());
    assert!(
        req.window_tokens.len() as u32 <= effective_cap,
        "fixture window must fit min(WINDOW_CAP, batch_window_max)"
    );

    // §1 rule 1: every hash is bare lowercase 64-hex (no "sha256:" prefix).
    assert!(is_bare_hash(&req.parent_prefix_hash));
    assert!(is_bare_hash(&req.generation_params_hash));
    assert!(is_bare_hash(&res.new_prefix_hash));

    // verify_pass_ms is an integer field >= 0 only (A4: never a measured
    // value assertion) — pinned simply by being a u32 here.
    let _ = res.verify_pass_ms;

    // Session-3 activation: replay through the real §3 admission gate.
    replay_family_fixture(f, &req, &res);
    (req, res)
}

/// Session-3 activation: replays one family fixture through the real gate
/// (mock engine, clock fixed at `verify_at`) — admission (no engine work),
/// exactly ONE engine pass at dispatch, the emitted result equalling the
/// recorded one on every signed field, re-signing the draft with the
/// recorded verifier key reproducing the recorded signature
/// byte-for-byte, and the RC-4 commit reproduction (advance + duplicate
/// no-op).
fn replay_family_fixture(f: &Value, req: &VerifyDrafts, res: &VerifyDraftsResult) {
    let anchor = unix_ms(f["verify_at"].as_str().unwrap());
    let engine_disclosure: EngineDisclosure =
        serde_json::from_value(f["engine"].clone()).expect("engine disclosure parses");
    let mut gate = VerifyDraftsGate::new(VerifyDraftsGateConfig {
        session_id: req.session_id.clone(),
        profile_id: req.profile_id.clone(),
        generation_params_hash: req.generation_params_hash.clone(),
        committed_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        coordinator_key: verifying_key(f["coordinator_public_key_hex"].as_str().unwrap()),
        verifier_installation_id: f["verifier_installation_id"].as_str().unwrap().to_string(),
        engine: engine_disclosure.clone(),
        budget: SessionBudget {
            max_endpoints: 1,
            max_endpoint_seconds: 3600,
            max_output_tokens: 1_000_000,
        },
        lease_expires_at_ms: anchor + 3_600_000,
        sampling_params: SamplingParams::default(),
        // The recorded result seq is the RC-7 verifier-own-counter
        // illustration made normative bytes (request 12 / result 4).
        verifier_next_seq: res.seq,
    })
    .expect("gate config is valid");
    let engine =
        MockVerifyEngine::new(engine_disclosure, (res.accepted_prefix_len, res.correction));

    let fields = f["request"]["fields"].clone();
    let coord_peer =
        peer_id_for(&verifying_key(f["coordinator_public_key_hex"].as_str().unwrap()).to_bytes());
    match gate.admit_verify_drafts(&fields, anchor, anchor, &coord_peer) {
        AdmissionDecision::Admitted { round, .. } => {
            assert_eq!(round, req.round, "admitted round");
        }
        other => panic!(
            "fixture {} must admit: {other:?}",
            f["name"].as_str().unwrap()
        ),
    }
    assert_eq!(
        engine.calls(),
        0,
        "no engine work at admission (stages 1-12)"
    );
    assert_eq!(gate.state(), GateState::Verify);

    // Dispatch: exactly ONE pass; the pass clock delta equals the
    // recorded verify_pass_ms so the emitted draft is byte-comparable.
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime");
    let outcome = rt.block_on(gate.dispatch_outstanding(
        &engine,
        anchor,
        anchor + u64::from(res.verify_pass_ms),
    ));
    let DispatchOutcome::Dispatched(draft) = outcome else {
        panic!(
            "fixture {} must dispatch: {outcome:?}",
            f["name"].as_str().unwrap()
        );
    };
    assert_eq!(
        engine.calls(),
        1,
        "exactly ONE engine pass per VerifyDrafts"
    );
    assert_eq!(gate.state(), GateState::WaitCommit);

    // The emitted draft equals the recorded result on every signed field;
    // the gate emits UNSIGNED drafts (the serve loop signs).
    assert_eq!(draft.session_id, res.session_id);
    assert_eq!(draft.protocol_version, res.protocol_version);
    assert_eq!(draft.seq, res.seq);
    assert_eq!(draft.round, res.round);
    assert_eq!(draft.accepted_prefix_len, res.accepted_prefix_len);
    assert_eq!(draft.divergence_point, res.divergence_point);
    assert_eq!(draft.correction, res.correction);
    assert_eq!(draft.new_prefix_hash, res.new_prefix_hash);
    assert_eq!(draft.verify_pass_ms, res.verify_pass_ms);
    assert_eq!(draft.nonce_echo, res.nonce_echo);
    assert_eq!(draft.sender, res.sender);
    assert_eq!(draft.signature, "");

    // Signing the draft with the recorded verifier fixture key
    // reproduces the recorded signature byte-for-byte.
    let seed: [u8; 32] = hex::decode(f["verifier_seed_hex"].as_str().unwrap())
        .expect("verifier seed decodes")
        .try_into()
        .expect("verifier seed is 32 bytes");
    let verifier = InstallationIdentity::from_bytes(&seed);
    assert_eq!(
        sign_verify_drafts_result(&draft, &verifier).unwrap(),
        res.signature
    );

    // RC-4: the reproducing commit over the recorded committed ids
    // advances the gate's own chain; a replay is a remembered no-op.
    let committed = token_ids(&f["expected"]["committed"]);
    let commit = CommitPrefix {
        session_id: req.session_id.clone(),
        round: req.round,
        previous_prefix_hash: req.parent_prefix_hash.clone(),
        accepted_token_ids: committed.clone(),
        new_prefix_hash: res.new_prefix_hash.clone(),
        model_profile_id: req.profile_id.clone(),
        generation_params_hash: req.generation_params_hash.clone(),
        sender: req.sender.clone(),
    };
    assert_eq!(
        gate.apply_prefix_commit(&commit),
        CommitApplyOutcome::Advanced { round: req.round }
    );
    assert_eq!(gate.committed_prefix_hash(), res.new_prefix_hash);
    assert_eq!(gate.last_committed_round(), req.round);
    assert_eq!(gate.state(), GateState::Committed);
    assert_eq!(gate.committed_output_tokens(), committed.len() as u64);
    assert_eq!(
        gate.apply_prefix_commit(&commit),
        CommitApplyOutcome::DuplicateRound
    );
}

/// Plan §2.3 check (4): the `expected` block is internally consistent
/// with the messages AND `new_prefix_hash` equals
/// `compute_prefix_hash(parent, committed)` recomputed from the recorded
/// construction inputs (ADR-032 §1 rule 2 over
/// `(parent ‖ accepted prefix ‖ [correction])`).
fn check_expected(f: &Value, req: &VerifyDrafts, res: &VerifyDraftsResult) {
    let expected = &f["expected"];
    let k = expected["accepted_prefix_len"].as_u64().unwrap() as usize;
    assert_eq!(k, res.accepted_prefix_len as usize);
    assert!(k <= req.window_tokens.len(), "accepted len <= window len");
    assert_eq!(
        expected["outcome"].as_str().unwrap(),
        if res.divergence_point.is_some() {
            "rejected"
        } else {
            "accepted"
        },
        "outcome label matches the divergence shape"
    );

    // divergence_point: null on full acceptance (and PRESENT in the wire
    // fields); == accepted_prefix_len on rejection (§1 invariant).
    let result_fields = f["result"]["fields"].as_object().unwrap();
    assert!(
        result_fields.contains_key("divergence_point"),
        "divergence_point is present-as-null, never omitted"
    );
    assert!(result_fields.contains_key("correction"));
    match res.divergence_point {
        None => {
            assert_eq!(
                k,
                req.window_tokens.len(),
                "full acceptance covers the window"
            );
            assert!(expected["divergence_point"].is_null());
        }
        Some(d) => {
            assert!(
                k < req.window_tokens.len(),
                "rejection stops inside the window"
            );
            assert_eq!(d as usize, k, "divergence_point == accepted_prefix_len");
            assert_eq!(expected["divergence_point"].as_u64().unwrap() as u32, d);
        }
    }

    // committed == window[..k] ++ [correction]; at EOG (F-2) correction
    // is null and the commit covers the accepted prefix ONLY.
    let committed = token_ids(&expected["committed"]);
    let mut rebuilt: Vec<u32> = req.window_tokens[..k].to_vec();
    if let Some(c) = res.correction {
        rebuilt.push(c);
        assert_eq!(expected["correction"].as_u64().unwrap() as u32, c);
    } else {
        assert!(
            expected["correction"].is_null(),
            "F-2: correction null at EOG"
        );
        assert_eq!(expected["eog"].as_bool(), Some(true), "EOG case is labeled");
    }
    assert_eq!(
        committed, rebuilt,
        "committed = window[..k] ++ [correction]"
    );

    // new_prefix_hash: the recorded VALUE equals the recomputation from
    // the recorded construction inputs, independent of our function.
    let construction = &expected["new_prefix_hash_construction"];
    let parent = construction["parent_prefix_hash"].as_str().unwrap();
    let construction_ids = token_ids(&construction["committed_token_ids"]);
    assert_eq!(construction_ids, committed);
    assert_eq!(parent, req.parent_prefix_hash);
    assert_eq!(
        parent, GENESIS_PREFIX_HASH,
        "every family fixture chains from the pinned genesis root"
    );
    assert_eq!(
        compute_prefix_hash(parent, &construction_ids).unwrap(),
        res.new_prefix_hash,
        "new_prefix_hash recomputes from the recorded construction inputs"
    );
    assert_eq!(
        res.new_prefix_hash,
        expected["new_prefix_hash"].as_str().unwrap()
    );
}

// ---------------------------------------------------------------------------
// Family fixtures 1-4 (ADR-032 §7 fixture-set table rows 1-4)
// ---------------------------------------------------------------------------

#[test]
fn golden_verifydrafts_1_accept_full_acceptance() {
    let f = doc(FIXTURE_ACCEPT);
    assert_eq!(f["name"].as_str().unwrap(), "verifydrafts-1-accept");
    let (req, res) = check_family_fixture(&f);
    check_expected(&f, &req, &res);
    // Row-1 specifics: w=8, seq pair (request 12, result 4 — §1/RC-7
    // illustration made normative bytes), correction = bonus token.
    assert_eq!(req.window_tokens.len(), 8);
    assert_eq!(req.seq, 12);
    assert_eq!(res.seq, 4, "the result carries the VERIFIER's own counter");
    assert_eq!(res.accepted_prefix_len, 8);
    assert_eq!(res.divergence_point, None);
    assert_eq!(
        res.correction,
        Some(999),
        "bonus (lookahead) token on full acceptance"
    );
    // Present-as-null on the wire fields.
    assert!(f["result"]["fields"]["divergence_point"].is_null());
    // (The gate replay itself — admission, ONE pass, byte-equal result,
    // RC-4 commit reproduction — runs inside check_family_fixture.)
}

#[test]
fn golden_verifydrafts_2_reject_mid_window() {
    let f = doc(FIXTURE_REJECT);
    assert_eq!(f["name"].as_str().unwrap(), "verifydrafts-2-reject");
    let (req, res) = check_family_fixture(&f);
    check_expected(&f, &req, &res);
    // Row-2 specifics: k < len, divergence == k, replacement correction.
    assert_eq!(req.window_tokens.len(), 8);
    assert_eq!(res.accepted_prefix_len, 3);
    assert_eq!(res.divergence_point, Some(3));
    assert_eq!(res.correction, Some(777), "replacement token on rejection");
    assert_eq!(
        token_ids(&f["expected"]["committed"]),
        vec![201, 202, 203, 777]
    );
    // (Gate replay with the mid-window rollback runs in
    // check_family_fixture: divergence == accepted_prefix_len == 3.)
}

#[test]
fn golden_verifydrafts_3_boundary_cap_edge() {
    let f = doc(FIXTURE_BOUNDARY);
    assert_eq!(f["name"].as_str().unwrap(), "verifydrafts-3-boundary");
    let (req, res) = check_family_fixture(&f);
    check_expected(&f, &req, &res);
    // Row-3 main case: len 32 == min(WINDOW_CAP, batch_window_max).
    assert_eq!(req.window_tokens.len(), WINDOW_CAP as usize);
    assert_eq!(res.accepted_prefix_len, WINDOW_CAP);
    assert_eq!(res.divergence_point, None);

    // Row-3 admission case: len 33 > min(WINDOW_CAP=32, bwm=32) is
    // payload_too_large BEFORE any engine work.
    let over = &f["over_cap_case"];
    assert_eq!(over["name"].as_str().unwrap(), "len-33-window-over-cap");
    assert_eq!(
        over["expected_reject"].as_str().unwrap(),
        "payload_too_large"
    );
    let over_req = check_signed_request(
        &over["wire"],
        f["coordinator_public_key_hex"].as_str().unwrap(),
    );
    assert_eq!(over_req.window_tokens.len(), 33);
    assert_eq!(
        over_req.window_tokens.len() as u32,
        over["context"]["window_len"].as_u64().unwrap() as u32,
    );
    let bwm = over["context"]["batch_window_max"].as_u64().unwrap() as u32;
    assert_eq!(bwm, 32);
    assert!(
        over_req.window_tokens.len() as u32 > WINDOW_CAP.min(bwm),
        "len 33 exceeds the effective cap min(WINDOW_CAP, batch_window_max)"
    );
    assert_eq!(
        over["context"]["engine_passes_before_reject"], 0,
        "the cap reject fires before any engine work (RC-8)"
    );

    // Session-3 activation: gate replay of the len-33 wire —
    // payload_too_large at stage 10 with ZERO verify_window calls.
    let anchor = unix_ms(f["verify_at"].as_str().unwrap());
    let engine_disclosure: EngineDisclosure = serde_json::from_value(f["engine"].clone()).unwrap();
    let mut gate = VerifyDraftsGate::new(VerifyDraftsGateConfig {
        session_id: over_req.session_id.clone(),
        profile_id: over_req.profile_id.clone(),
        generation_params_hash: over_req.generation_params_hash.clone(),
        committed_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        coordinator_key: verifying_key(f["coordinator_public_key_hex"].as_str().unwrap()),
        verifier_installation_id: f["verifier_installation_id"].as_str().unwrap().to_string(),
        engine: engine_disclosure.clone(),
        budget: SessionBudget {
            max_endpoints: 1,
            max_endpoint_seconds: 3600,
            max_output_tokens: 1_000_000,
        },
        lease_expires_at_ms: anchor + 3_600_000,
        sampling_params: SamplingParams::default(),
        verifier_next_seq: 4,
    })
    .unwrap();
    let engine = MockVerifyEngine::new(engine_disclosure, (32, None));
    let coord_peer =
        peer_id_for(&verifying_key(f["coordinator_public_key_hex"].as_str().unwrap()).to_bytes());
    match gate.admit_verify_drafts(&over["wire"]["fields"], anchor, anchor, &coord_peer) {
        AdmissionDecision::FrameRejected(reject) => {
            assert_eq!(reject.code, FrameRejectReason::PayloadTooLarge);
        }
        other => panic!("len-33 must be payload_too_large: {other:?}"),
    }
    assert_eq!(engine.calls(), 0, "ZERO verify_window calls (RC-8)");
}

#[test]
fn golden_verifydrafts_4_eos_correction_null() {
    let f = doc(FIXTURE_EOS);
    assert_eq!(f["name"].as_str().unwrap(), "verifydrafts-4-eos");
    let (req, res) = check_family_fixture(&f);
    check_expected(&f, &req, &res);
    // Row-4 / F-2 specifics: correction PRESENT as null at EOG; the
    // commit covers the accepted prefix only.
    assert_eq!(res.correction, None);
    assert!(f["result"]["fields"]
        .as_object()
        .unwrap()
        .contains_key("correction"));
    assert!(f["result"]["fields"]["correction"].is_null());
    assert_eq!(token_ids(&f["expected"]["committed"]), vec![601, 602, 603]);
    assert_eq!(
        f["expected"]["new_prefix_hash_construction"]["committed_token_ids"],
        f["expected"]["committed"],
        "no correction token is chained at EOG"
    );
    // (Gate replay with the EOG outcome — correction None, prefix-only
    // commit — runs in check_family_fixture.)
}

// ---------------------------------------------------------------------------
// The malformed admission-rejection array (ADR-032 §7 fixture row 5)
// ---------------------------------------------------------------------------

/// The exact 12-case mapping of the ADR-032 §2 admission table the
/// malformed file must record (name -> expected reject code). Doubles as
/// a pin that the file never drifts from the table.
const EXPECTED_MALFORMED: [(&str, &str); 12] = [
    ("empty-window", "bad_frame"),
    ("bad-signature", "bad_frame"),
    ("wrong-profile-id", "profile_mismatch"),
    ("duplicate-nonce", "replayed_request"),
    ("duplicate-seq", "replayed_request"),
    ("non-monotone-seq", "replayed_request"),
    ("deadline-past", "deadline_exceeded"),
    ("unknown-session", "bad_frame"),
    ("torn-down-session", "cancelled_by_peer"),
    ("lease-expired", "expired_token"),
    ("window-over-batch-window-max", "payload_too_large"),
    ("budget-exhausted", "overloaded"),
];

#[test]
fn golden_verifydrafts_malformed_admission_cases() {
    let cases: Vec<Value> =
        serde_json::from_str(FIXTURE_MALFORMED).expect("malformed file is an array");
    assert_eq!(cases.len(), EXPECTED_MALFORMED.len());
    let recorded: Vec<(String, String)> = cases
        .iter()
        .map(|c| {
            (
                c["name"].as_str().unwrap().to_string(),
                c["expected_reject"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    for (name, code) in &EXPECTED_MALFORMED {
        assert!(
            recorded.contains(&(name.to_string(), code.to_string())),
            "malformed file must record case {name} -> {code}"
        );
    }

    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let code = case["expected_reject"].as_str().unwrap();
        let wire = &case["wire"];
        let context = &case["context"];

        // Every expected code is a frozen effective-§6.5-registry string
        // (ADR-032 §2: no registry change, 1:1 mapping).
        serde_json::from_value::<FrameRejectReason>(json!(code))
            .unwrap_or_else(|e| panic!("case {name}: {code} is not a family reject code: {e}"));

        // Canonical pins hold for every case wire (recompute + sha256).
        let canonical = canonical_json(&{
            let mut v = wire.clone();
            v.as_object_mut().unwrap().remove("signature");
            v
        })
        .unwrap_or_else(|e| panic!("case {name}: preimage canonicalization failed: {e}"));
        assert_eq!(
            canonical,
            case["canonical_json"].as_str().unwrap(),
            "case {name}: canonical bytes"
        );
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            case["canonical_json_sha256"].as_str().unwrap(),
            "case {name}: canonical sha256"
        );

        // Per-case classification inputs (assertible BEFORE the §3 gate
        // exists); each carries its TODO(session 3) replay hook.
        match name {
            "empty-window" => {
                // Schema stage: the strict two-pass parse rejects the
                // empty window before the signature stage.
                assert_eq!(
                    VerifyDrafts::parse(wire).unwrap_err(),
                    FrameParseError::EmptyWindow
                );
            }
            "bad-signature" => {
                // Signature stage: a genuine signature by the WRONG key
                // (sender binding fails first, fail-closed).
                let msg: VerifyDrafts = serde_json::from_value(wire.clone()).unwrap();
                let key = verifying_key(case["coordinator_public_key_hex"].as_str().unwrap());
                assert!(
                    verify_verify_drafts_signature(&msg, &key).is_err(),
                    "wrong-key signature must fail under the coordinator key"
                );
            }
            "wrong-profile-id" => {
                let msg = VerifyDrafts::parse(wire).unwrap();
                let key = verifying_key(case["coordinator_public_key_hex"].as_str().unwrap());
                verify_verify_drafts_signature(&msg, &key).unwrap();
                assert_ne!(
                    msg.profile_id,
                    context["pinned_profile_id"].as_str().unwrap(),
                    "classification input: wire profile differs from the pinned profile"
                );
                assert_eq!(msg.profile_id, context["wire_profile_id"].as_str().unwrap());
            }
            "duplicate-nonce" => {
                let msg = VerifyDrafts::parse(wire).unwrap();
                assert!(
                    context["consumed_nonces"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|n| n.as_str() == Some(msg.nonce.as_str())),
                    "classification input: the nonce is in the consumed set"
                );
                assert!(msg.seq > context["last_seq_from_coordinator"].as_u64().unwrap());
            }
            "duplicate-seq" => {
                let msg = VerifyDrafts::parse(wire).unwrap();
                assert_eq!(
                    msg.seq,
                    context["last_seq_from_coordinator"].as_u64().unwrap(),
                    "classification input: seq equals the last seen seq"
                );
                assert!(
                    !context["consumed_nonces"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|n| n.as_str() == Some(msg.nonce.as_str())),
                    "the nonce itself is fresh — only the seq is stale"
                );
            }
            "non-monotone-seq" => {
                let msg = VerifyDrafts::parse(wire).unwrap();
                assert!(
                    msg.seq < context["last_seq_from_coordinator"].as_u64().unwrap(),
                    "classification input: fresh but decreased seq"
                );
            }
            "deadline-past" => {
                let msg = VerifyDrafts::parse(wire).unwrap();
                assert_eq!(msg.deadline_ms, 1_000);
                let arrival = context["request_arrival_unix_ms"].as_i64().unwrap();
                let deadline = context["deadline_ms_effective"].as_i64().unwrap();
                let clock = context["admission_clock_unix_ms"].as_i64().unwrap();
                assert_eq!(
                    context["deadline_expires_at_unix_ms"].as_i64().unwrap(),
                    arrival + deadline
                );
                assert!(
                    arrival + deadline < clock,
                    "classification input: the deadline expired before the admission clock"
                );
                assert_eq!(
                    context["admission_clock"].as_str().unwrap(),
                    "2026-10-12T00:00:00Z"
                );
                assert_eq!(
                    context["request_arrival"].as_str().unwrap(),
                    "2026-10-11T23:59:00Z"
                );
                // Fixture repair (session 4, session-3 handoff §5.1
                // finding): the context carries a FRESH budget ledger
                // (0 committed tokens), so the earlier budget stage
                // (stage 11) passes and the deadline stage (12) decides —
                // a literally-seeded gate replays deadline_exceeded.
                assert_eq!(
                    context["committed_output_tokens"].as_u64().unwrap(),
                    0,
                    "deadline-past context must carry a fresh budget ledger"
                );
                assert!(context["budget_ledger"].is_string());
            }
            "unknown-session" => {
                let msg = VerifyDrafts::parse(wire).unwrap();
                assert_ne!(
                    msg.session_id,
                    context["admitted_session_id"].as_str().unwrap(),
                    "classification input: session binding fails"
                );
                assert_eq!(msg.session_id, context["wire_session_id"].as_str().unwrap());
            }
            "torn-down-session" => {
                VerifyDrafts::parse(wire).unwrap();
                assert_eq!(context["session_state"].as_str().unwrap(), "torn_down");
                assert_eq!(
                    context["teardown_reason"].as_str().unwrap(),
                    "profile_mismatch"
                );
            }
            "lease-expired" => {
                VerifyDrafts::parse(wire).unwrap();
                let expiry = context["lease_expires_at_unix_ms"].as_i64().unwrap();
                let clock = context["admission_clock_unix_ms"].as_i64().unwrap();
                assert!(
                    expiry < clock,
                    "classification input: the lease expired first"
                );
                assert_eq!(
                    context["lease_expires_at"].as_str().unwrap(),
                    "2026-10-11T23:00:00Z"
                );
            }
            "window-over-batch-window-max" => {
                let msg = VerifyDrafts::parse(wire).unwrap();
                let bwm = context["batch_window_max"].as_u64().unwrap() as u32;
                let cap = context["window_cap"].as_u64().unwrap() as u32;
                assert_eq!(cap, WINDOW_CAP);
                assert_eq!(
                    context["effective_cap"].as_u64().unwrap() as u32,
                    WINDOW_CAP.min(bwm)
                );
                assert_eq!(
                    msg.window_tokens.len() as u64,
                    context["window_len"].as_u64().unwrap()
                );
                assert!(
                    msg.window_tokens.len() as u32 > WINDOW_CAP.min(bwm),
                    "classification input: window over batch_window_max (inside the global cap)"
                );
                assert!(
                    msg.window_tokens.len() as u32 <= WINDOW_CAP,
                    "distinguishes the bwm bound from the global cap"
                );
                assert_eq!(context["engine_passes_before_reject"], 0);
            }
            "budget-exhausted" => {
                VerifyDrafts::parse(wire).unwrap();
                assert_eq!(
                    context["committed_output_tokens"].as_u64().unwrap(),
                    context["budget"]["max_output_tokens"].as_u64().unwrap(),
                    "classification input: cumulative committed tokens already at the ceiling"
                );
            }
            other => panic!("unknown malformed case {other}"),
        }

        // Session-3 activation: replay each wire through the real §3
        // admission gate against the recorded context pre-state (clock
        // fixed at verify_at, mock engine) and assert the EXACT emitted
        // code equals `expected_reject`.
        let (gate, decision) = replay_malformed_case(case);
        let expected_code: FrameRejectReason =
            serde_json::from_value(json!(code)).expect("expected code is a family code");
        match decision {
            AdmissionDecision::FrameRejected(reject) => {
                assert_eq!(reject.code, expected_code, "case {name}: gate replay code");
                // Privacy (A-3): the reject frame carries codes/counts/
                // hashes only — serialized, no token id can appear.
                let serialized = serde_json::to_string(&reject).unwrap();
                assert!(!serialized.contains("701"), "case {name}: token id leak");
            }
            other => panic!("case {name}: expected reject {code}, got {other:?}"),
        }
        if name == "wrong-profile-id" {
            // The profile row tears the session down (I7).
            assert!(
                gate.is_torn_down(),
                "case {name}: profile mismatch must tear down"
            );
            assert_eq!(gate.teardown_reason(), Some("profile_mismatch"));
        }
    }
}

/// Builds the gate recorded in one malformed case's `context` pre-state
/// and replays the case's wire through it. Budget-ledger seeding is
/// LITERAL from the recorded context for every case: the shared
/// template's at-ceiling `committed_output_tokens: 16 ==
/// max_output_tokens: 16` is the injected condition of the
/// `budget-exhausted` case, while `deadline-past` records a FRESH
/// ledger (0 tokens committed; fixture repair, session 4 — the
/// session-3 handoff §5.1 finding, ruled per the plan's ADR-wins rule:
/// the ADR-032 §2 first-failure-wins stage order wins, the fixture was
/// over-constrained), so every case now replays directly to its
/// recorded `expected_reject` with no compensating seeding.
fn replay_malformed_case(case: &Value) -> (VerifyDraftsGate, AdmissionDecision) {
    let ctx = &case["context"];
    let anchor = unix_ms(case["verify_at"].as_str().unwrap());
    let arrival = ctx
        .get("request_arrival_unix_ms")
        .and_then(Value::as_u64)
        .unwrap_or(anchor);
    let budget: SessionBudget = serde_json::from_value(ctx["budget"].clone()).unwrap();
    let engine_disclosure: EngineDisclosure =
        serde_json::from_value(ctx["engine"].clone()).unwrap();

    let mut gate = VerifyDraftsGate::new(VerifyDraftsGateConfig {
        session_id: ctx["admitted_session_id"].as_str().unwrap().to_string(),
        profile_id: ctx["pinned_profile_id"].as_str().unwrap().to_string(),
        generation_params_hash: batch_generation_params_hash(&SamplingParams::default())
            .expect("default params are integral"),
        committed_prefix_hash: ctx["committed_prefix_hash"].as_str().unwrap().to_string(),
        coordinator_key: verifying_key(case["coordinator_public_key_hex"].as_str().unwrap()),
        verifier_installation_id: case["verifier_installation_id"]
            .as_str()
            .unwrap()
            .to_string(),
        engine: engine_disclosure.clone(),
        budget,
        lease_expires_at_ms: unix_ms(ctx["lease_expires_at"].as_str().unwrap()),
        sampling_params: SamplingParams::default(),
        verifier_next_seq: 4,
    })
    .expect("recorded context builds a valid gate");
    gate.seed_pre_state(GatePreStateSeed {
        torn_down: ctx["session_state"].as_str() == Some("torn_down"),
        last_seq: vec![(
            case["coordinator_installation_id"]
                .as_str()
                .unwrap()
                .to_string(),
            ctx["last_seq_from_coordinator"].as_u64().unwrap(),
        )],
        consumed_nonces: ctx["consumed_nonces"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|n| n.as_str().map(str::to_string))
            .collect(),
        committed_output_tokens: Some(ctx["committed_output_tokens"].as_u64().unwrap()),
        last_handled_round: Some(ctx["last_handled_round"].as_u64().unwrap()),
        served_ms: None,
        lease_expires_at_ms: None,
    });

    let coord_peer = peer_id_for(
        &verifying_key(case["coordinator_public_key_hex"].as_str().unwrap()).to_bytes(),
    );
    let decision = gate.admit_verify_drafts(&case["wire"], arrival, anchor, &coord_peer);
    (gate, decision)
}

// ---------------------------------------------------------------------------
// Negotiation vectors (ADR-032 §7 last row + the base-form addition)
// ---------------------------------------------------------------------------

fn check_canonical_block(block: &Value) -> Value {
    let fields = block["fields"].clone();
    let canonical = canonical_json(&fields).expect("negotiation payload canonicalizes");
    assert_eq!(
        canonical,
        block["canonical_json"].as_str().expect("canonical_json"),
    );
    assert_eq!(
        sha256_hex(canonical.as_bytes()),
        block["canonical_json_sha256"]
            .as_str()
            .expect("canonical_json_sha256"),
    );
    fields
}

#[test]
fn golden_session_offer_2_is_superseded_failing_data() {
    // ADR-032 revision 4 §3/G3: the SECOND form (base +
    // verifier_backend) is SUPERSEDED by the third — it is preserved as
    // DATA whose canonical bytes are pinned and which does NOT
    // deserialize into the v3 struct (missing profile_id +
    // generation_params_hash), exactly as session-offer-1 pins the base
    // form.
    let f = doc(SESSION_OFFER_2);
    assert_eq!(f["name"].as_str().unwrap(), "session-offer-2");
    let fields = check_canonical_block(&f["block"]);
    assert!(fields.as_object().unwrap().contains_key("verifier_backend"));
    assert_eq!(fields["verifier_backend"], json!("cpu"));
    assert!(
        !fields.as_object().unwrap().contains_key("profile_id"),
        "the v2 form predates the v3 binding fields"
    );
    assert!(
        serde_json::from_value::<SessionOffer>(fields).is_err(),
        "F-6/G3: the v2 offer form must fail the v3 schema"
    );
}

#[test]
fn golden_session_offer_3_third_canonical_form() {
    let f = doc(SESSION_OFFER_3);
    assert_eq!(f["name"].as_str().unwrap(), "session-offer-3");
    let fields = check_canonical_block(&f["block"]);
    // Deserializes into the extended struct and round-trips byte-equal.
    let offer: SessionOffer = serde_json::from_value(fields.clone()).unwrap();
    assert_eq!(serde_json::to_value(&offer).unwrap(), fields);
    // The v2 additive field is present and CPU-paired (E0 / ADR-032 §3).
    assert_eq!(fields["verifier_backend"], json!("cpu"));
    assert_eq!(fields["protocol_version"], COOPERATIVE_PROTOCOL_VERSION);
    // The G3 binding fields: the pinned exact profile (msp1:<64 hex>) and
    // this family's canonical generation-params hash (§1 rule-3 preimage
    // over the runtime default — cross-checked against the live hash).
    let profile_id = fields["profile_id"].as_str().unwrap();
    assert!(
        profile_id.starts_with("msp1:") && is_bare_hash(profile_id.strip_prefix("msp1:").unwrap()),
        "profile_id is the §1 msp1:<64 hex> form"
    );
    let params_hash = batch_generation_params_hash(&SamplingParams::default())
        .expect("default sampling params are integral");
    assert_eq!(fields["generation_params_hash"], json!(params_hash));
    assert!(is_bare_hash(
        fields["generation_params_hash"].as_str().unwrap()
    ));
}

#[test]
fn golden_session_accept_2_engine_disclosure() {
    let f = doc(SESSION_ACCEPT_2);
    assert_eq!(f["name"].as_str().unwrap(), "session-accept-2");
    let fields = check_canonical_block(&f["block"]);
    let accept: SessionAccept = serde_json::from_value(fields.clone()).unwrap();
    assert_eq!(serde_json::to_value(&accept).unwrap(), fields);
    // RC-8: batch_verify: true requires an honest in-range window max.
    assert!(accept.engine.is_valid_disclosure());
    assert!(accept.engine.batch_verify);
    assert_eq!(accept.engine.batch_window_max, WINDOW_CAP);
    // The effective budget is clamped DOWN only vs the offer-2 budget.
    let offer = doc(SESSION_OFFER_2);
    let offer_budget = &offer["block"]["fields"]["budget"];
    assert!(
        accept.budget.max_endpoint_seconds
            <= offer_budget["max_endpoint_seconds"].as_u64().unwrap()
    );
    assert!(
        u64::from(accept.budget.max_output_tokens)
            <= offer_budget["max_output_tokens"].as_u64().unwrap()
    );
    assert_eq!(accept.session_id, "sess-coop-0002");
}

#[test]
fn golden_session_reject_1_all_reasons() {
    let f = doc(SESSION_REJECT_1);
    assert_eq!(f["name"].as_str().unwrap(), "session-reject-1");
    let primary_fields = check_canonical_block(&f["primary"]);
    let primary: SessionReject = serde_json::from_value(primary_fields).unwrap();
    assert_eq!(primary.reason, SessionRejectReason::BackendMismatch);

    let reasons = f["reasons"].as_array().expect("reasons list");
    assert_eq!(
        reasons.len(),
        8,
        "the frozen ADR-032 six (four pre-revision-4 + the two v3 reasons) \
         plus the two ADR-036 carrier reasons"
    );
    let mut seen: Vec<&str> = Vec::new();
    for block in reasons {
        let fields = check_canonical_block(block);
        let reject: SessionReject = serde_json::from_value(fields).unwrap();
        assert_eq!(reject.session_id, primary.session_id);
        seen.push(reject.reason.as_str());
    }
    seen.sort_unstable();
    assert_eq!(
        seen,
        [
            "backend_mismatch",
            "batch_verify_unsupported",
            "budget_infeasible",
            "content_carriage_refused",
            "params_mismatch",
            "pin_mismatch",
            "preset_unavailable",
            "profile_mismatch"
        ],
        "the frozen vocabulary (ADR-032 §3 / A-4 + revision 4 §3/G3 + the \
         ADR-036 §3.2 carrier reasons)"
    );
}

/// The commit-form golden vector the §2 carrier obligates (ADR-032
/// revision 4 §2/G2: "a commit-form golden vector joins the §7 fixture
/// set before any second consumer exists"). Pins the BARE-object wire
/// form — exactly the shipped `SpecMessage::PrefixCommit` field names, no
/// envelope tag, no signature — its canonical bytes, the §1-rule-2
/// construction, the sender binding, and replays it through the real
/// gate against the `verifydrafts-1-accept` request/result it reproduces.
#[test]
fn golden_verifydrafts_5_commit_carrier_bare_object_form() {
    let f = doc(COMMIT_CARRIER);
    assert_eq!(f["name"].as_str().unwrap(), "verifydrafts-5-commit-carrier");

    // (1) The wire form: a BARE JSON object whose key set is EXACTLY the
    // eight shipped field names — no envelope tag, no signature, no
    // unknown fields (the §2 strict schema).
    let fields = f["carrier"]["fields"].clone();
    let object = fields.as_object().expect("carrier is a JSON object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    let mut expected: Vec<&str> = f["field_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    expected.sort_unstable();
    assert_eq!(
        keys, expected,
        "the carrier carries exactly the shipped PrefixCommit field names"
    );
    assert_eq!(
        expected.len(),
        8,
        "session_id, round, previous_prefix_hash, accepted_token_ids, new_prefix_hash, profile_id, generation_params_hash, sender"
    );
    assert!(
        !keys.contains(&"signature"),
        "the carrier is unsigned (§2/G2)"
    );
    assert!(
        !keys.contains(&"prefix_commit") && !keys.contains(&"PrefixCommit"),
        "no externally-tagged envelope"
    );

    // (2) Canonical bytes + sha256 (no signature to omit — the whole
    // object IS the preimage).
    let canonical = canonical_json(&fields).expect("carrier canonicalizes");
    assert_eq!(
        canonical,
        f["carrier"]["canonical_json"].as_str().unwrap(),
        "canonical bytes"
    );
    assert_eq!(
        sha256_hex(canonical.as_bytes()),
        f["carrier"]["canonical_json_sha256"].as_str().unwrap(),
        "canonical sha256"
    );

    // (3) The §1-rule-2 construction: new_prefix_hash recomputes from the
    // recorded construction inputs independent of our function.
    let construction = &f["construction"];
    let committed = token_ids(&construction["committed_token_ids"]);
    assert_eq!(
        token_ids(&fields["accepted_token_ids"]),
        committed,
        "the committed ids are the carrier's accepted_token_ids"
    );
    assert_eq!(
        compute_prefix_hash(
            construction["parent_prefix_hash"].as_str().unwrap(),
            &committed
        )
        .unwrap(),
        fields["new_prefix_hash"].as_str().unwrap(),
        "new_prefix_hash recomputes from the recorded construction inputs"
    );
    assert_eq!(
        construction["parent_prefix_hash"].as_str().unwrap(),
        fields["previous_prefix_hash"].as_str().unwrap()
    );

    // (4) The sender binding: sender == the coordinator installation id
    // recorded from the fixture keypair (§2: MUST equal the installation
    // id pinned from the authenticated channel; mismatch is bad_frame).
    assert_eq!(
        fields["sender"].as_str().unwrap(),
        f["coordinator_installation_id"].as_str().unwrap(),
        "the carrier's sender is the authenticated-channel-pinned id"
    );
    let coord_key = verifying_key(f["coordinator_public_key_hex"].as_str().unwrap());
    assert_eq!(
        installation_id_for(&coord_key.to_bytes()),
        fields["sender"].as_str().unwrap(),
        "sender derives from the recorded coordinator key (§1 rule 5)"
    );

    // (5) Gate replay: the carrier reproduces the verifydrafts-1-accept
    // result — admit fixture 1's request, dispatch ONE pass with the
    // recorded outcome, apply THIS carrier (mapped to the state
    // machine's CommitPrefix names), and the gate ADVANCES; the §2
    // carrier sender check passes because the gate pins the same
    // coordinator key.
    let accept_fixture = doc(FIXTURE_ACCEPT);
    let req = check_signed_request(
        &accept_fixture["request"],
        accept_fixture["coordinator_public_key_hex"]
            .as_str()
            .unwrap(),
    );
    let res = check_signed_result(
        &accept_fixture["result"],
        accept_fixture["verifier_public_key_hex"].as_str().unwrap(),
    );
    assert_eq!(fields["session_id"], json!(req.session_id));
    assert_eq!(fields["round"], json!(req.round));
    assert_eq!(fields["new_prefix_hash"], json!(res.new_prefix_hash));
    let engine_disclosure: EngineDisclosure =
        serde_json::from_value(accept_fixture["engine"].clone()).unwrap();
    let anchor = unix_ms(accept_fixture["verify_at"].as_str().unwrap());
    let mut gate = VerifyDraftsGate::new(VerifyDraftsGateConfig {
        session_id: req.session_id.clone(),
        profile_id: req.profile_id.clone(),
        generation_params_hash: req.generation_params_hash.clone(),
        committed_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        coordinator_key: coord_key,
        verifier_installation_id: f["verifier_installation_id"].as_str().unwrap().to_string(),
        engine: engine_disclosure.clone(),
        budget: SessionBudget {
            max_endpoints: 1,
            max_endpoint_seconds: 3600,
            max_output_tokens: 1_000_000,
        },
        lease_expires_at_ms: anchor + 3_600_000,
        sampling_params: SamplingParams::default(),
        verifier_next_seq: res.seq,
    })
    .unwrap();
    let coord_peer = peer_id_for(&coord_key.to_bytes());
    assert!(matches!(
        gate.admit_verify_drafts(
            &accept_fixture["request"]["fields"],
            anchor,
            anchor,
            &coord_peer
        ),
        AdmissionDecision::Admitted { .. }
    ));
    let engine =
        MockVerifyEngine::new(engine_disclosure, (res.accepted_prefix_len, res.correction));
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime");
    assert!(matches!(
        rt.block_on(gate.dispatch_outstanding(
            &engine,
            anchor,
            anchor + u64::from(res.verify_pass_ms)
        )),
        DispatchOutcome::Dispatched(_)
    ));
    let commit = CommitPrefix {
        session_id: fields["session_id"].as_str().unwrap().to_string(),
        round: fields["round"].as_u64().unwrap(),
        previous_prefix_hash: fields["previous_prefix_hash"].as_str().unwrap().to_string(),
        accepted_token_ids: committed.clone(),
        new_prefix_hash: fields["new_prefix_hash"].as_str().unwrap().to_string(),
        model_profile_id: fields["profile_id"].as_str().unwrap().to_string(),
        generation_params_hash: fields["generation_params_hash"]
            .as_str()
            .unwrap()
            .to_string(),
        sender: fields["sender"].as_str().unwrap().to_string(),
    };
    assert_eq!(
        gate.apply_prefix_commit(&commit),
        CommitApplyOutcome::Advanced {
            round: fields["round"].as_u64().unwrap()
        },
        "the bare carrier applies through the real gate (RC-4 reproduction)"
    );
    assert_eq!(gate.committed_prefix_hash(), res.new_prefix_hash);
}

#[test]
fn golden_session_offer_and_accept_1_base_forms_pin_f6() {
    // The base ADR-029 forms are recorded as raw JSON (the extended
    // structs cannot express them). Their canonical bytes are pinned,
    // and — plan flag F-6 — they do NOT deserialize into the extended
    // structs, whose new canonical forms REQUIRE the additive fields.
    let offer1 = doc(SESSION_OFFER_1);
    assert_eq!(offer1["name"].as_str().unwrap(), "session-offer-1");
    let offer_fields = check_canonical_block(&offer1["block"]);
    assert!(!offer_fields
        .as_object()
        .unwrap()
        .contains_key("verifier_backend"));
    assert!(
        serde_json::from_value::<SessionOffer>(offer_fields).is_err(),
        "F-6: the base form lacks the now-required verifier_backend"
    );

    let accept1 = doc(SESSION_ACCEPT_1);
    assert_eq!(accept1["name"].as_str().unwrap(), "session-accept-1");
    let accept_fields = check_canonical_block(&accept1["block"]);
    assert!(!accept_fields.as_object().unwrap().contains_key("engine"));
    assert!(
        serde_json::from_value::<SessionAccept>(accept_fields).is_err(),
        "F-6: the base form lacks the now-required engine disclosure"
    );
}

// ---------------------------------------------------------------------------
// Cross-file consistency (single time anchor, single fixture keypair)
// ---------------------------------------------------------------------------

#[test]
fn golden_fixture_set_shares_one_anchor_and_keypair() {
    let family_files = [
        doc(FIXTURE_ACCEPT),
        doc(FIXTURE_REJECT),
        doc(FIXTURE_BOUNDARY),
        doc(FIXTURE_EOS),
    ];
    for f in &family_files {
        assert_eq!(f["verify_at"].as_str().unwrap(), "2026-10-12T00:00:00Z");
        assert_eq!(
            f["coordinator_seed_hex"].as_str().unwrap(),
            "11".repeat(32),
            "coordinator fixture seed [0x11; 32] recorded in every file"
        );
        assert_eq!(
            f["verifier_seed_hex"].as_str().unwrap(),
            "22".repeat(32),
            "verifier fixture seed [0x22; 32] recorded in every file"
        );
    }
    // Every malformed case entry records the same keypair + anchor.
    let cases: Vec<Value> = serde_json::from_str(FIXTURE_MALFORMED).unwrap();
    for case in &cases {
        assert_eq!(case["verify_at"].as_str().unwrap(), "2026-10-12T00:00:00Z");
        assert_eq!(
            case["coordinator_seed_hex"].as_str().unwrap(),
            "11".repeat(32)
        );
        assert_eq!(case["verifier_seed_hex"].as_str().unwrap(), "22".repeat(32));
        assert_eq!(
            case["coordinator_public_key_hex"],
            family_files[0]["coordinator_public_key_hex"]
        );
    }
    // The recorded public keys derive from the recorded seeds (the
    // in-file provenance is internally consistent).
    for f in &family_files {
        let coord = verifying_key(f["coordinator_public_key_hex"].as_str().unwrap());
        let verif = verifying_key(f["verifier_public_key_hex"].as_str().unwrap());
        assert_eq!(
            installation_id_for(&coord.to_bytes()),
            f["coordinator_installation_id"].as_str().unwrap()
        );
        assert_eq!(
            installation_id_for(&verif.to_bytes()),
            f["verifier_installation_id"].as_str().unwrap()
        );
        assert_ne!(coord.to_bytes(), verif.to_bytes());
    }
}

/// The ADR-036 pin-carrier golden vectors: the ACCEPT case replays the
/// strict bare-object canonical form, the signature-omitted preimage,
/// the LE-u32 commitment, and the signature verification with the
/// fixture key; the MISMATCH case pins the pure-core failure behind the
/// `pin_mismatch` session reject.
#[test]
fn golden_pin_carrier_1_accept() {
    use modelswarm_session::negotiation::{pin_commitment_of, WirePinCarrier};
    use modelswarm_session::verifydrafts::{sign_pin_carrier, verify_pin_carrier_signature};
    use modelswarm_transport::ed25519_dalek::SigningKey;

    let f = doc(PIN_CARRIER_1);
    assert_eq!(f["name"].as_str().unwrap(), "pin-carrier-1-accept");
    let wire_fields = check_canonical_block(&f["wire"]);
    let preimage_fields = check_canonical_block(&f["preimage"]);

    // The preimage omits `signature` entirely; the wire carries it.
    assert!(preimage_fields.get("signature").is_none());
    assert!(wire_fields.get("signature").is_some());

    let carrier: WirePinCarrier = serde_json::from_value(wire_fields.clone()).unwrap();
    assert_eq!(carrier.round, 0, "the reserved session-open marker");
    assert_eq!(carrier.seq, 1, "the coordinator baseline");
    // The commitment is the rule-3 LE-u32 construction over the payload.
    assert_eq!(
        carrier.pin_commitment,
        pin_commitment_of(&carrier.prompt_tokens)
    );
    assert_eq!(carrier.validate(), Ok(()));

    // Fixture identity binding + signature verification (sender
    // binding FIRST, then Ed25519 over the pinned preimage).
    let seed: [u8; 32] = hex::decode(f["coordinator_seed_hex"].as_str().unwrap())
        .expect("fixture seed hex")
        .try_into()
        .expect("32-byte seed");
    let identity = InstallationIdentity::from_bytes(&seed);
    assert_eq!(
        carrier.sender,
        f["coordinator_installation_id"].as_str().unwrap()
    );
    let verifying = SigningKey::from_bytes(&seed).verifying_key();
    assert!(verify_pin_carrier_signature(&carrier, &verifying).is_ok());
    // Determinism: re-signing the pinned carrier reproduces the pinned
    // signature (canonical form + key discipline byte-stable).
    let mut resigned = carrier.clone();
    resigned.signature = sign_pin_carrier(&resigned, &identity).unwrap();
    assert_eq!(resigned.signature, carrier.signature);
}

#[test]
fn golden_pin_carrier_2_mismatch() {
    use modelswarm_session::negotiation::{PinCarrierError, WirePinCarrier};

    let f = doc(PIN_CARRIER_2);
    assert_eq!(f["name"].as_str().unwrap(), "pin-carrier-2-mismatch");
    let fields = check_canonical_block(&f);
    let carrier: WirePinCarrier = serde_json::from_value(fields).unwrap();
    // Well-formed 64-hex commitment that does NOT bind the payload: the
    // pure core behind the serving side's `pin_mismatch` reject.
    assert_eq!(carrier.validate(), Err(PinCarrierError::CommitmentMismatch));
    assert_eq!(f["expected_reject"].as_str().unwrap(), "pin_mismatch");
}

#[test]
fn golden_session_offer_4_unknown_preset_fails_closed() {
    // ADR-045 (S-1 supersession + the P2 receipt-population contract): a
    // preset OUTSIDE the frozen five-value enum fails the offer schema —
    // no session opens, no receipt is produced, and the value is never
    // coerced to a nearby tier (msp-cooperative-v1 §6 compatibility).
    let f = doc(SESSION_OFFER_4);
    assert_eq!(
        f["name"].as_str().unwrap(),
        "session-offer-4-unknown-preset"
    );
    assert_eq!(f["fails_deserialization"], json!(true));
    let fields = check_canonical_block(&f["block"]);
    assert_eq!(fields["preset"], json!("turbo"));
    assert!(
        serde_json::from_value::<SessionOffer>(fields).is_err(),
        "ADR-045: an unknown preset variant must fail deserialization (fail-closed)"
    );
}
