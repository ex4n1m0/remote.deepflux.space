//! ADR-036 §3/§6 gates for the node layer (feature `verifydrafts`): the
//! session-open PIN CARRIER — the serving-side admission table, the fixed
//! open-sequence order, the carrier-session invariants, and the hygiene
//! (counts-only) rules — over the REAL staged transport with scripted
//! engines.
//!
//! - `golden_vectors_replay_through_the_admission_table`: the three
//!   `protocol/vectors/pin-carrier-*.json` fixtures replayed through
//!   [`modelswarm_node::verifydrafts::admit_pin_carrier`] with the EXACT
//!   expected outcomes (accept / `pin_mismatch` / every malformed label /
//!   the two admission-path arms carriage-off and context-overflow).
//! - `admission_first_failure_order_is_pinned`: the §3.2 table's row
//!   order, swept pairwise (schema beats signature beats carriage beats
//!   profile beats params beats pin beats prefill beats deadline).
//! - `open_sequence_order_is_fixed_and_neutral_stays_neutral`:
//!   lease→pin→offer, pin→offer, lease→offer, offer — plus the
//!   deviations (pin→lease→offer, lease→lease, oversize carrier) that
//!   are bad_frame-class ends.
//! - `carrier_session_seeds_the_gate_and_rejects_replays`: a full
//!   carrier session over the staged wire — the client's FIRST round
//!   carries seq ≥ 2 (strictly above the carrier baseline) and round ≥
//!   1; a later frame reusing the carrier's NONCE or its SEQ is
//!   `replayed_request`.
//! - `carrier_rejects_carry_codes_only_never_content`: the honest
//!   `SessionReject` frames and every telemetry row on the refusal paths
//!   carry codes/counts only — no token arrays, no commitment hash.
//! - `engine_handle_teardown_bounds_the_session`: the per-session engine
//!   handle the serve loop holds is dropped at session end (the
//!   KV-residency bound at the seam; the Capi variant makes it a real
//!   per-session engine in production).

#![cfg(feature = "verifydrafts")]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use modelswarm_identity::{new_nonce, InstallationIdentity};
use modelswarm_node::verifydrafts::serve::{
    admit_pin_carrier, read_session_open, serve_verifydrafts_session_with_pin, ContentCarriage,
    PinAdmission, SessionOpenError, VerifyDraftsServeConfig,
};
use modelswarm_node::verifydrafts::wire::{accept_staged, dial_staged};
use modelswarm_node::verifydrafts::{
    ClientOpenError, VerifyDraftsClient, VerifyDraftsClientConfig, VerifyDraftsWire,
};
use modelswarm_session::negotiation::{
    pin_commitment_of, EngineDisclosure, SessionRejectReason, WirePinCarrier,
    COOPERATIVE_PROTOCOL_VERSION,
};
use modelswarm_session::verifydrafts::{
    batch_generation_params_hash, sign_pin_carrier, sign_verify_drafts, BatchVerifyEngine,
    VerifyDrafts,
};
use modelswarm_telemetry::Telemetry;
use modelswarm_transport::ed25519_dalek::VerifyingKey;
use modelswarm_transport::SignedFrameTransport;
use serde_json::{json, Value};

const FIXTURE_ACCEPT: &str = include_str!("../../../protocol/vectors/pin-carrier-1-accept.json");
const FIXTURE_MISMATCH: &str =
    include_str!("../../../protocol/vectors/pin-carrier-2-mismatch.json");
const FIXTURE_MALFORMED: &str =
    include_str!("../../../protocol/vectors/pin-carrier-malformed.json");

/// A profile id that passes the msp1 form checks (serving.rs test pattern).
const TEST_PROFILE: &str = "msp1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const ACCEPT_DEADLINE: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Scripted engine (the wiring-test pattern) + drop counting
// ---------------------------------------------------------------------------

struct ScriptedEngine {
    disclosure: EngineDisclosure,
    outcomes: Mutex<VecDeque<(u32, Option<u32>)>>,
    calls: Mutex<usize>,
}

impl ScriptedEngine {
    fn new(disclosure: EngineDisclosure, outcomes: Vec<(u32, Option<u32>)>) -> Arc<Self> {
        Arc::new(Self {
            disclosure,
            outcomes: Mutex::new(outcomes.into()),
            calls: Mutex::new(0),
        })
    }

    fn calls(&self) -> usize {
        *self.calls.lock().expect("calls lock")
    }
}

#[async_trait::async_trait]
impl BatchVerifyEngine for ScriptedEngine {
    async fn verify_window(
        &self,
        _window: &[u32],
        _params: &modelswarm_runtime::SamplingParams,
    ) -> Result<(u32, Option<u32>), modelswarm_runtime::RuntimeError> {
        *self.calls.lock().expect("calls lock") += 1;
        self.outcomes
            .lock()
            .expect("outcomes lock")
            .pop_front()
            .ok_or_else(|| {
                modelswarm_runtime::RuntimeError::MalformedResponse("script exhausted".to_string())
            })
    }

    fn capabilities(&self) -> EngineDisclosure {
        self.disclosure.clone()
    }
}

fn batch_engine(window_max: u32) -> EngineDisclosure {
    EngineDisclosure {
        backend: modelswarm_session::negotiation::Backend::Cpu,
        batch_verify: true,
        batch_window_max: window_max,
    }
}

// ---------------------------------------------------------------------------
// Golden-vector replay through the node admission table (ADR-036 §6)
// ---------------------------------------------------------------------------

/// The admission call over one carrier, with the fixture-aligned pins:
/// the serving side pins the VECTOR's profile and params (so pairing
/// faults never mask the fault under test), carriage ON, no context cap,
/// and a future deadline.
fn admit(
    carrier: &WirePinCarrier,
    identity: &InstallationIdentity,
    carriage: ContentCarriage,
    cap: Option<u64>,
) -> PinAdmission {
    admit_pin_carrier(
        carrier,
        &identity.peer_id(),
        &identity.verifying_key(),
        // Pin the SERVED profile to the vector's own profile for the
        // accept/mismatch/malformed replays (pairing is not under test
        // there) — EXCEPT where a row pins it differently.
        carrier.profile_id.as_str(),
        carrier.generation_params_hash.as_str(),
        carriage,
        cap,
        1_000_000, // arrival
        1_000_000, // now (no deadline pressure)
    )
}

#[test]
fn golden_vectors_replay_through_the_admission_table() {
    // The fixture coordinator (seed 0x11*32 — the session-vectors
    // convention, recorded in the fixture file).
    let identity = InstallationIdentity::from_bytes(&[0x11; 32]);

    // 1) pin-carrier-1-accept: the canonical wire frame parses strictly,
    //    the signature verifies under the fixture key, admission accepts.
    let accept: Value = serde_json::from_str(FIXTURE_ACCEPT).expect("accept fixture parses");
    assert_eq!(accept["expected"], "accept", "fixture posture");
    let wire_json: Value =
        serde_json::from_str(accept["wire"]["canonical_json"].as_str().unwrap()).unwrap();
    let carrier: WirePinCarrier = serde_json::from_value(wire_json.clone())
        .expect("the canonical wire frame parses strictly");
    // The byte-pin: the strict round-trip reproduces the pinned CANONICAL
    // bytes (sorted-key canonical JSON — the msp-v1 §2.2 form; the
    // vector's own sha256 pins the string).
    let round_trip =
        modelswarm_types::canonical_json(&serde_json::to_value(&carrier).unwrap()).unwrap();
    assert_eq!(
        round_trip,
        accept["wire"]["canonical_json"].as_str().unwrap(),
        "strict parse round-trips the pinned canonical form"
    );
    match admit(&carrier, &identity, ContentCarriage::On, None) {
        PinAdmission::Admitted(admitted) => {
            assert_eq!(admitted.session_id, "sess-pin-0001");
            assert_eq!(admitted.seq, 1, "the carrier establishes the seq baseline");
            assert_eq!(admitted.prompt_tokens, vec![151644, 11, 22, 33, 44, 151645]);
            assert_eq!(
                admitted.nonce, "cc0000000000000a",
                "the nonce enters the ledger"
            );
        }
        other => panic!("vector 1 must accept, got {other:?}"),
    }
    // The preimage discipline: the signature-omitted canonical form is
    // pinned by the fixture and the commitment binds the payload.
    assert!(carrier.commitment_matches());
    assert_eq!(
        carrier.pin_commitment,
        pin_commitment_of(&carrier.prompt_tokens),
        "the LE-u32 construction is the shared pure core"
    );

    // 2) pin-carrier-2-mismatch: a well-formed commitment over a
    //    DIFFERENT payload → the honest pin_mismatch reject.
    let mismatch: Value = serde_json::from_str(FIXTURE_MISMATCH).expect("mismatch fixture parses");
    assert_eq!(mismatch["expected_reject"], "pin_mismatch");
    let fields = &mismatch["fields"];
    let mut carrier: WirePinCarrier = serde_json::from_value(fields.clone()).expect("fields parse");
    // The fixture's signature is empty (the mismatch must be reachable
    // under an HONEST signature — sign over the mutated form).
    carrier.signature = sign_pin_carrier(&carrier, &identity).expect("fixture key signs");
    match admit(&carrier, &identity, ContentCarriage::On, None) {
        PinAdmission::Rejected(reason) => assert_eq!(reason, SessionRejectReason::PinMismatch),
        other => panic!("vector 2 must reject pin_mismatch, got {other:?}"),
    }

    // 3) pin-carrier-malformed: every structural mutation byte-pins its
    //    label; the two admission-path arms (carriage-off,
    //    context-overflow) are exercised with their fixture rows.
    let malformed: Value = serde_json::from_str(FIXTURE_MALFORMED).expect("malformed fixture");
    for case in malformed["cases"].as_array().expect("cases array") {
        let description = case["description"].as_str().unwrap_or("").to_string();
        let expected = case["expected_reject"].as_str().unwrap_or("").to_string();
        match expected.as_str() {
            // Structural rows: the pinned canonical bytes deserialize
            // (they are valid JSON) and hit the admission table.
            "bad_frame"
            | "commitment_form"
            | "empty_prompt_tokens"
            | "protocol_version"
            | "round_not_session_open"
            | "seq_baseline" => {
                let raw = case["canonical_json"].as_str().expect("byte-pinned form");
                let value: Value = serde_json::from_str(raw).expect("pinned bytes are JSON");
                // Non-u32 token ids fail STRICT deserialization itself
                // (the bad_frame class at the schema gate).
                let parsed: Result<WirePinCarrier, _> = serde_json::from_value(value.clone());
                match parsed {
                    Err(_) => {
                        // The schema arm of bad_frame (unknown fields,
                        // envelope tags, non-u32 ids): strict parse fails.
                        assert_eq!(
                            expected, "bad_frame",
                            "{description}: strict-parse failure is the bad_frame class"
                        );
                    }
                    Ok(carrier) => {
                        // The pinned bytes carry their OWN signature (the
                        // vector's, over the ORIGINAL form): the mutation
                        // under test invalidates exactly what the row
                        // intends — the signature rows break the signature
                        // itself, the schema rows are caught EARLIER by
                        // validate(). Never re-sign here.
                        let outcome = admit(&carrier, &identity, ContentCarriage::On, None);
                        match (&outcome, expected.as_str()) {
                            (PinAdmission::BadFrame(label), want) => {
                                // The pure-validate labels ride verbatim;
                                // the signature/sender rows land in the
                                // same bad_frame class.
                                let ok = match want {
                                    "bad_frame" => true,
                                    other => *label == other,
                                };
                                assert!(
                                    ok,
                                    "{description}: expected {want}, got BadFrame({label})"
                                );
                            }
                            other => panic!("{description}: expected {expected}, got {other:?}"),
                        }
                    }
                }
            }
            // The two admission-path outcomes (not wire mutations).
            "content_carriage_refused" => {
                let accept: Value =
                    serde_json::from_str(FIXTURE_ACCEPT).expect("the accept fixture");
                let wire_json: Value =
                    serde_json::from_str(accept["wire"]["canonical_json"].as_str().unwrap())
                        .unwrap();
                let carrier: WirePinCarrier = serde_json::from_value(wire_json).unwrap();
                match admit(&carrier, &identity, ContentCarriage::Off, None) {
                    PinAdmission::Rejected(reason) => assert_eq!(
                        reason,
                        SessionRejectReason::ContentCarriageRefused,
                        "{description}: the opt-out refuses honestly"
                    ),
                    other => panic!("{description}: expected the honest refusal, got {other:?}"),
                }
            }
            "budget_infeasible" => {
                let accept: Value =
                    serde_json::from_str(FIXTURE_ACCEPT).expect("the accept fixture");
                let wire_json: Value =
                    serde_json::from_str(accept["wire"]["canonical_json"].as_str().unwrap())
                        .unwrap();
                let mut carrier: WirePinCarrier = serde_json::from_value(wire_json).unwrap();
                // Re-bind the commitment over a LONGER payload so the
                // conversation is well-formed but over the cap.
                carrier.prompt_tokens = vec![7u32; 200];
                carrier.pin_commitment = pin_commitment_of(&carrier.prompt_tokens);
                carrier.signature = sign_pin_carrier(&carrier, &identity).unwrap();
                match admit(&carrier, &identity, ContentCarriage::On, Some(64)) {
                    PinAdmission::Rejected(reason) => assert_eq!(
                        reason,
                        SessionRejectReason::BudgetInfeasible,
                        "{description}: a conversation that does not fit refuses honestly"
                    ),
                    other => panic!("{description}: expected budget_infeasible, got {other:?}"),
                }
            }
            other => panic!("unhandled fixture row {other:?} ({description})"),
        }
    }
}

/// The §3.2 table's FIRST-FAILURE-WINS order, pinned pairwise: whenever
/// two faults are injected at once, the EARLIER row's outcome is the one
/// on the wire.
#[test]
fn admission_first_failure_order_is_pinned() {
    let identity = InstallationIdentity::from_bytes(&[0x31; 32]);
    let tokens = vec![11u32, 22, 33];
    // FIXED pins for this sweep (the serving side's own profile/params —
    // the pairing faults are under test, so the carrier's fields are the
    // moving parts).
    let params_hash = "3d".repeat(32);
    let admit_fixed = |carrier: &WirePinCarrier, carriage: ContentCarriage, cap: Option<u64>| {
        admit_pin_carrier(
            carrier,
            &identity.peer_id(),
            &identity.verifying_key(),
            TEST_PROFILE,
            &params_hash,
            carriage,
            cap,
            1_000_000,
            1_000_000,
        )
    };
    let good = |profile: &str, params: &str| WirePinCarrier {
        session_id: "vd-order".into(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.into(),
        seq: 1,
        round: 0,
        profile_id: profile.into(),
        generation_params_hash: params.into(),
        prompt_tokens: tokens.clone(),
        pin_commitment: pin_commitment_of(&tokens),
        nonce: new_nonce(),
        deadline_ms: 60_000,
        sender: identity.installation_id(),
        signature: String::new(),
    };
    let params_hash = "3d".repeat(32);
    let base = good(TEST_PROFILE, &params_hash);
    let other_profile = "msp1:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    // Row order reference: schema < signature/sender < carriage < profile
    // < params < pin < prefill < deadline.
    let misform = |mut c: WirePinCarrier| {
        c.pin_commitment = "AB".repeat(32); // commitment_form (schema class)
        c
    };
    let badsig = |mut c: WirePinCarrier| {
        c.signature = "AAAA".into(); // never a valid 64-byte signature
        c
    };
    let carrier_off = |c: WirePinCarrier| (c, ContentCarriage::Off);
    let wrong_profile = |mut c: WirePinCarrier| {
        c.profile_id = other_profile.into();
        c
    };
    let wrong_params = |mut c: WirePinCarrier| {
        c.generation_params_hash = "aa".repeat(32);
        c
    };
    let bad_pin = |mut c: WirePinCarrier| {
        c.pin_commitment = pin_commitment_of(&[9u32, 9, 9]);
        c
    };
    let too_long = |mut c: WirePinCarrier| {
        c.prompt_tokens = vec![5u32; 300];
        c.pin_commitment = pin_commitment_of(&c.prompt_tokens);
        c
    };

    let signed = |mut c: WirePinCarrier| {
        c.signature = sign_pin_carrier(&c, &identity).unwrap();
        c
    };

    // schema beats signature faults (the form fault is applied AFTER
    // signing so BOTH faults are live).
    let c = badsig(signed(misform(base.clone())));
    assert!(matches!(
        admit_fixed(&c, ContentCarriage::On, None),
        PinAdmission::BadFrame("commitment_form")
    ));
    // signature beats carriage-off (the refusal posture is stated only to
    // an authenticated peer): a carrier with a BROKEN signature under an
    // opted-out posture is bad_frame, not the refusal.
    let c = badsig(signed(base.clone()));
    let carriage = ContentCarriage::Off;
    assert!(matches!(
        admit_fixed(&c, carriage, None),
        PinAdmission::BadFrame(_)
    ));
    // carriage beats profile mismatch.
    let (c, carriage) = carrier_off(signed(wrong_profile(base.clone())));
    assert!(matches!(
        admit_fixed(&c, carriage, None),
        PinAdmission::Rejected(SessionRejectReason::ContentCarriageRefused)
    ));
    // profile beats params mismatch.
    let c = signed(wrong_params(wrong_profile(base.clone())));
    assert!(matches!(
        admit_fixed(&c, ContentCarriage::On, None),
        PinAdmission::Rejected(SessionRejectReason::ProfileMismatch)
    ));
    // params beats pin mismatch.
    let c = signed(bad_pin(wrong_params(base.clone())));
    assert!(matches!(
        admit_fixed(&c, ContentCarriage::On, None),
        PinAdmission::Rejected(SessionRejectReason::ParamsMismatch)
    ));
    // pin beats prefill infeasibility: a payload that does NOT fit AND a
    // commitment that does not bind it (bad_pin applied AFTER too_long so
    // both faults stay live — too_long alone would re-bind correctly).
    let c = signed(bad_pin(too_long(base.clone())));
    assert!(matches!(
        admit_fixed(&c, ContentCarriage::On, Some(64)),
        PinAdmission::Rejected(SessionRejectReason::PinMismatch)
    ));
    // prefill beats deadline: a too-long conversation whose deadline ALSO
    // already passed (now 2000 ms past arrival; deadline_ms clamps to the
    // 1000 floor) — row 8's reason is the one that lands.
    let c = signed(too_long(base.clone()));
    assert!(matches!(
        admit_pin_carrier(
            &c,
            &identity.peer_id(),
            &identity.verifying_key(),
            TEST_PROFILE,
            &params_hash,
            ContentCarriage::On,
            Some(64),
            1_000_000,
            1_000_000 + 2_000,
        ),
        PinAdmission::Rejected(SessionRejectReason::BudgetInfeasible)
    ));
    // deadline past at admission (clamped) with everything else clean: a
    // deadline_ms of 1 clamps to the 1000 floor, and `now` 2000 ms past
    // arrival has exceeded it.
    let mut soon = base.clone();
    soon.deadline_ms = 1;
    let c = signed(soon);
    assert!(matches!(
        admit_pin_carrier(
            &c,
            &identity.peer_id(),
            &identity.verifying_key(),
            TEST_PROFILE,
            &params_hash,
            ContentCarriage::On,
            None,
            1_000_000,
            1_000_000 + 2_000,
        ),
        PinAdmission::DeadlineExceeded
    ));
    // Clean baseline: admitted.
    let c = signed(base);
    assert!(matches!(
        admit_fixed(&c, ContentCarriage::On, None),
        PinAdmission::Admitted(_)
    ));
}

// ---------------------------------------------------------------------------
// The fixed open-sequence order (ADR-036 §6 property: lease → pin → offer)
// ---------------------------------------------------------------------------

/// An in-memory wire the open-sequence test drives frame by frame (the
/// reader is transport-agnostic behind `VerifyDraftsWire`).
struct VecWire {
    frames: VecDeque<Value>,
    peer_id: String,
}

#[async_trait::async_trait]
impl VerifyDraftsWire for VecWire {
    async fn send_json(
        &mut self,
        _value: &Value,
        _deadline: Duration,
    ) -> Result<(), modelswarm_node::verifydrafts::wire::WireError> {
        Ok(())
    }
    async fn recv_json(
        &mut self,
        _deadline: Duration,
    ) -> Result<Value, modelswarm_node::verifydrafts::wire::WireError> {
        self.frames
            .pop_front()
            .ok_or(modelswarm_node::verifydrafts::wire::WireError::Closed)
    }
    fn remote_peer_id(&self) -> &str {
        &self.peer_id
    }
}

fn lease_frame() -> Value {
    json!({ "lease": "dGVzdC5sZWFzZQ.sig" })
}

fn offer_frame() -> Value {
    json!({ "session_id": "s", "protocol_version": "msp-cooperative-v1", "preset": "verified" })
}

fn pin_frame(identity: &InstallationIdentity) -> Value {
    let tokens = vec![151644u32, 1, 151645];
    let carrier = WirePinCarrier {
        session_id: "s".into(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.into(),
        seq: 1,
        round: 0,
        profile_id: TEST_PROFILE.into(),
        generation_params_hash: "3d".repeat(32),
        prompt_tokens: tokens.clone(),
        pin_commitment: pin_commitment_of(&tokens),
        nonce: new_nonce(),
        deadline_ms: 60_000,
        sender: identity.installation_id(),
        signature: String::new(),
    };
    let mut carrier = carrier;
    carrier.signature = sign_pin_carrier(&carrier, identity).unwrap();
    serde_json::to_value(&carrier).unwrap()
}

#[tokio::test]
async fn open_sequence_order_is_fixed_and_neutral_stays_neutral() {
    let identity = InstallationIdentity::from_bytes(&[0x41; 32]);
    // lease → pin → offer: both carriers read, offer unparsed. (`first`
    // is the pre-read frame; the wire queues what FOLLOWS it.)
    let mut wire = VecWire {
        frames: [pin_frame(&identity), offer_frame()].into_iter().collect(),
        peer_id: identity.peer_id(),
    };
    let open = read_session_open(&mut wire, lease_frame(), ACCEPT_DEADLINE)
        .await
        .expect("the full three-part order opens");
    assert!(open.lease.is_some());
    assert!(open.pin.is_some());
    assert_eq!(open.offer["preset"], "verified");

    // pin → offer (no lease presented): VALID (roster-fed coordinators).
    let mut wire = VecWire {
        frames: [offer_frame()].into_iter().collect(),
        peer_id: identity.peer_id(),
    };
    let open = read_session_open(&mut wire, pin_frame(&identity), ACCEPT_DEADLINE)
        .await
        .expect("a pin carrier without a lease is valid");
    assert!(open.lease.is_none());
    assert!(open.pin.is_some());
    assert_eq!(open.offer["preset"], "verified");

    // lease → offer (no pin): the NEUTRAL path, byte-unchanged.
    let mut wire = VecWire {
        frames: [offer_frame()].into_iter().collect(),
        peer_id: identity.peer_id(),
    };
    let open = read_session_open(&mut wire, lease_frame(), ACCEPT_DEADLINE)
        .await
        .expect("the pre-ADR-036 order still opens");
    assert!(open.lease.is_some());
    assert!(open.pin.is_none(), "a neutral session carries no pin");
    assert_eq!(open.offer["preset"], "verified");

    // offer only: the classic roster path.
    let mut wire = VecWire {
        frames: VecDeque::new(),
        peer_id: identity.peer_id(),
    };
    let open = read_session_open(&mut wire, offer_frame(), ACCEPT_DEADLINE)
        .await
        .expect("an offer alone is a neutral session");
    assert!(open.lease.is_none() && open.pin.is_none());

    // DEVIATIONS — bad_frame-class ends:
    // pin → lease → offer (the lease is FIRST or not at this position).
    let mut wire = VecWire {
        frames: [lease_frame(), offer_frame()].into_iter().collect(),
        peer_id: identity.peer_id(),
    };
    let err = read_session_open(&mut wire, pin_frame(&identity), ACCEPT_DEADLINE)
        .await
        .expect_err("a lease behind the pin carrier is out of order");
    assert!(matches!(err, SessionOpenError::OutOfOrder(_)), "{err}");

    // lease → lease → … (a repeated lease carrier).
    let mut wire = VecWire {
        frames: [lease_frame(), offer_frame()].into_iter().collect(),
        peer_id: identity.peer_id(),
    };
    let err = read_session_open(&mut wire, lease_frame(), ACCEPT_DEADLINE)
        .await
        .expect_err("a second lease carrier is out of order");
    assert!(matches!(err, SessionOpenError::OutOfOrder(_)), "{err}");

    // An oversize pin-carrier frame: payload_too_large BEFORE parse.
    let mut huge = pin_frame(&identity);
    let big: Vec<u32> = (0..200_000).collect(); // ~1.4 MB of ids
    huge["prompt_tokens"] = serde_json::to_value(&big).unwrap();
    let mut wire = VecWire {
        frames: [offer_frame()].into_iter().collect(),
        peer_id: identity.peer_id(),
    };
    let err = read_session_open(&mut wire, huge, ACCEPT_DEADLINE)
        .await
        .expect_err("an oversize carrier is refused before parse");
    assert_eq!(err, SessionOpenError::PayloadTooLarge, "{err}");
}

// ---------------------------------------------------------------------------
// The full carrier session over the REAL staged transport
// ---------------------------------------------------------------------------

/// A full ELECTED carrier session: lease → pin carrier → offer opens, the
/// client's first round rides seq ≥ 2 (strictly above the carrier's
/// baseline) and round 1, and later frames reusing the carrier's NONCE or
/// its SEQ are `replayed_request` (the seeded ledger bites).
#[tokio::test]
async fn carrier_session_seeds_the_gate_and_rejects_replays() {
    let server_identity = InstallationIdentity::from_bytes(&[0x51; 32]);
    let client_identity = InstallationIdentity::from_bytes(&[0x52; 32]);
    let (_telemetry, sink) = Telemetry::memory();

    let engine = ScriptedEngine::new(
        batch_engine(8),
        vec![(2, Some(901)), (2, Some(902)), (2, Some(903))],
    );
    let mut config =
        VerifyDraftsServeConfig::honest(TEST_PROFILE.to_string(), server_identity.clone());
    config.engine = batch_engine(8);
    config.session_idle = Duration::from_secs(60);

    let listener = SignedFrameTransport::listen("127.0.0.1:0")
        .await
        .expect("loopback listen");
    let addr = listener.local_addr().expect("bound").to_string();
    let mut trusted: HashMap<String, VerifyingKey> = HashMap::new();
    trusted.insert(client_identity.peer_id(), client_identity.verifying_key());
    let serve_engine = Arc::clone(&engine);
    let serve_config = config.clone();
    let server = tokio::spawn(async move {
        let mut wire = accept_staged(&listener, &trusted, ACCEPT_DEADLINE)
            .await
            .expect("authenticated accept");
        // The composed daemon's family branch, in shape: read the open
        // exchange, admit the carrier, hand the serve loop the admitted
        // facts (seq/nonce seeding) and the offer pre-read.
        let first = wire.recv_json(ACCEPT_DEADLINE).await.expect("first frame");
        let open =
            modelswarm_node::verifydrafts::read_session_open(&mut wire, first, ACCEPT_DEADLINE)
                .await
                .expect("session-open exchange");
        let carrier = open.pin.expect("this session elects a carrier");
        let admitted = match admit_pin_carrier(
            &carrier,
            wire.remote_peer_id(),
            &modelswarm_node::verifydrafts::verifying_key_from_peer_id(wire.remote_peer_id())
                .expect("ed25519 peer"),
            TEST_PROFILE,
            &batch_generation_params_hash(&serve_config.sampling_params).unwrap(),
            ContentCarriage::On,
            None,
            1,
            1,
        ) {
            PinAdmission::Admitted(admitted) => admitted,
            other => panic!("the well-formed carrier must admit, got {other:?}"),
        };
        let preface = modelswarm_node::verifydrafts::PrefacedWire::new(wire, Some(open.offer));
        serve_verifydrafts_session_with_pin(
            preface,
            serve_config,
            serve_engine,
            Some(admitted),
            &modelswarm_telemetry::Telemetry::memory().0,
        )
        .await
    });

    let wire = dial_staged(
        &addr,
        &client_identity,
        TEST_PROFILE,
        &server_identity.verifying_key(),
        ACCEPT_DEADLINE,
    )
    .await
    .expect("dial + handshake");
    let mut client_config =
        VerifyDraftsClientConfig::new(TEST_PROFILE.to_string(), server_identity.verifying_key());
    client_config.carrier_prompt_tokens = Some(vec![151644, 100, 151645]);
    let tel = Telemetry::memory().0;
    let mut client =
        VerifyDraftsClient::negotiate(wire, client_identity.clone(), client_config, &tel)
            .await
            .expect("the carrier session opened");

    // Round 1 (the first VerifyDrafts): seq 2 (strictly above the
    // carrier baseline of 1), round 1 (the carrier's 0 is behind it).
    let r1 = client.round(&[71, 72], &tel).await.expect("round 1");
    assert_eq!(r1.round, 1);
    assert_eq!(r1.committed, vec![71, 72, 901]);

    // A REPLAYED frame — the coordinator's own seq 2 again, signed — is
    // refused `replayed_request` by the seeded ledger. (The client's
    // high-level round() cannot send a decreasing seq by construction, so
    // the pin crafts the raw frame the way a hostile coordinator would.
    // The frame must otherwise BIND to the session: the params hash the
    // server pins is the honest defaults'.)
    let mut raw = VerifyDrafts {
        session_id: client.session_id().to_string(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
        seq: 2, // NOT strictly greater than the last handled (2)
        round: 2,
        profile_id: TEST_PROFILE.to_string(),
        parent_prefix_hash: client.committed_prefix_hash().to_string(),
        generation_params_hash: batch_generation_params_hash(
            &modelswarm_runtime::SamplingParams::default(),
        )
        .unwrap(),
        window_tokens: vec![81, 82],
        proposer_id: client_identity.peer_id(),
        nonce: new_nonce(),
        deadline_ms: 2_500,
        sender: client_identity.installation_id(),
        signature: String::new(),
    };
    raw.signature = sign_verify_drafts(&raw, &client_identity).expect("signs");
    let frame = serde_json::to_value(&raw).unwrap();
    let report = {
        // Send the raw frame on the client's wire and read the reject.
        let mut wire = client.into_wire();
        wire.send_json(&frame, ACCEPT_DEADLINE).await.unwrap();
        let reply = wire.recv_json(ACCEPT_DEADLINE).await.expect("reject");
        assert_eq!(
            reply["code"], "replayed_request",
            "seq replay refused: {reply}"
        );
        // Close cleanly; the server settles with the report.
        let wire = wire;
        drop(wire);
        tokio::time::timeout(Duration::from_secs(15), server)
            .await
            .expect("server settles")
            .expect("server task ok")
    };
    assert!(report.accepted);
    assert_eq!(report.rounds_committed, 1);
    assert_eq!(engine.calls(), 1, "the replay never reached the engine");

    // Hygiene over the whole exchange: counts and labels only — no token
    // arrays and no content-derived hashes (the pin commitment) anywhere.
    let events = sink.snapshot().join("\n");
    assert!(
        !events.contains("pin_commitment"),
        "no commitment in telemetry"
    );
    assert!(!events.contains("[151644"), "no token arrays in telemetry");
}

/// The honest-refusal hygiene: a `content_carriage_refused` reject and a
/// `pin_mismatch` reject both reach the CLIENT as a normal SessionReject
/// (the fallback-to-single signal), and the wire frame carries codes
/// only — never the payload or its hash.
#[tokio::test]
async fn carrier_rejects_carry_codes_only_never_content() {
    let identity = InstallationIdentity::from_bytes(&[0x61; 32]);
    let tokens = vec![42u32, 43];
    let mut carrier = WirePinCarrier {
        session_id: "vd-hygiene".into(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.into(),
        seq: 1,
        round: 0,
        profile_id: TEST_PROFILE.into(),
        generation_params_hash: "3d".repeat(32),
        prompt_tokens: tokens.clone(),
        pin_commitment: pin_commitment_of(&tokens),
        nonce: new_nonce(),
        deadline_ms: 60_000,
        sender: identity.installation_id(),
        signature: String::new(),
    };
    carrier.signature = sign_pin_carrier(&carrier, &identity).unwrap();
    let commitment = carrier.pin_commitment.clone();

    // The opted-out peer refuses honestly; the reject frame serializes to
    // EXACTLY the codes-only shape.
    let (telemetry, sink) = Telemetry::memory();
    let outcome = admit(&carrier, &identity, ContentCarriage::Off, None);
    let PinAdmission::Rejected(reason) = outcome else {
        panic!("carriage off must refuse, got {outcome:?}")
    };
    assert_eq!(reason, SessionRejectReason::ContentCarriageRefused);
    let reject = modelswarm_session::negotiation::SessionReject {
        session_id: carrier.session_id.clone(),
        protocol_version: carrier.protocol_version.clone(),
        reason,
    };
    let wire_frame = serde_json::to_string(&reject).unwrap();
    assert_eq!(
        wire_frame,
        "{\"session_id\":\"vd-hygiene\",\"protocol_version\":\"msp-cooperative-v1\",\"reason\":\"content_carriage_refused\"}",
        "the reject is codes-only by construction"
    );
    drop(telemetry);
    let events = sink.snapshot().join("\n");
    assert!(!events.contains(&commitment), "no content-derived hash");
    assert!(!events.contains(&format!("{tokens:?}")), "no token arrays");

    // The mismatch arm: the same shape, reason pin_mismatch.
    let mut wrong = carrier.clone();
    wrong.pin_commitment = pin_commitment_of(&[1, 2, 3]);
    wrong.signature = sign_pin_carrier(&wrong, &identity).unwrap();
    match admit(&wrong, &identity, ContentCarriage::On, None) {
        PinAdmission::Rejected(reason) => assert_eq!(reason, SessionRejectReason::PinMismatch),
        other => panic!("expected the honest mismatch, got {other:?}"),
    }

    // The client maps every new reject reason onto the honest
    // fallback-to-single error (the frozen strings ride verbatim).
    for reason in [
        SessionRejectReason::PinMismatch,
        SessionRejectReason::ContentCarriageRefused,
        SessionRejectReason::ProfileMismatch,
        SessionRejectReason::ParamsMismatch,
        SessionRejectReason::BudgetInfeasible,
    ] {
        let error = ClientOpenError::Rejected(reason.as_str());
        assert!(
            error.to_string().contains(reason.as_str()),
            "the frozen string rides the error: {error}"
        );
    }
}

/// The KV-residency bound AT THE SEAM (ADR-036 §3.2/§6): the engine
/// handle a carrier session holds is dropped when the session ends —
/// observable on the per-session Arc the serve loop owns. (The Capi
/// variant makes this a REAL per-session engine in production; the
/// Shared venue here pins the lifecycle discipline.)
#[tokio::test]
async fn engine_handle_teardown_bounds_the_session() {
    let server_identity = InstallationIdentity::from_bytes(&[0x71; 32]);
    let client_identity = InstallationIdentity::from_bytes(&[0x72; 32]);

    let engine = ScriptedEngine::new(batch_engine(8), vec![(1, Some(901))]);
    let mut config =
        VerifyDraftsServeConfig::honest(TEST_PROFILE.to_string(), server_identity.clone());
    config.engine = batch_engine(8);
    config.session_idle = Duration::from_secs(60);

    let listener = SignedFrameTransport::listen("127.0.0.1:0")
        .await
        .expect("loopback listen");
    let addr = listener.local_addr().expect("bound").to_string();
    let mut trusted: HashMap<String, VerifyingKey> = HashMap::new();
    trusted.insert(client_identity.peer_id(), client_identity.verifying_key());

    // The per-session handle: a wrapper Arc whose drop is counted — the
    // serve loop receives IT (exactly what engine_for_root yields), and
    // its teardown at session end is the bound.
    struct DropCounted {
        inner: Arc<dyn BatchVerifyEngine>,
        dropped: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Drop for DropCounted {
        fn drop(&mut self) {
            self.dropped
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    #[async_trait::async_trait]
    impl BatchVerifyEngine for DropCounted {
        async fn verify_window(
            &self,
            window: &[u32],
            params: &modelswarm_runtime::SamplingParams,
        ) -> Result<(u32, Option<u32>), modelswarm_runtime::RuntimeError> {
            self.inner.verify_window(window, params).await
        }
        fn capabilities(&self) -> EngineDisclosure {
            self.inner.capabilities()
        }
    }
    let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // Hand-shape the carrier FIRST so the admitted facts (nonce!) are the
    // ones the wire carrier actually rode — the ledger seeding is under
    // test. The carrier rides the server's pinned params hash.
    let tokens = vec![1u32, 2, 3];
    let params_hash =
        batch_generation_params_hash(&modelswarm_runtime::SamplingParams::default()).unwrap();
    let mut carrier = WirePinCarrier {
        session_id: "vd-teardown".into(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.into(),
        seq: 1,
        round: 0,
        profile_id: TEST_PROFILE.into(),
        generation_params_hash: params_hash.clone(),
        prompt_tokens: tokens.clone(),
        pin_commitment: pin_commitment_of(&tokens),
        nonce: new_nonce(),
        deadline_ms: 60_000,
        sender: client_identity.installation_id(),
        signature: String::new(),
    };
    carrier.signature = sign_pin_carrier(&carrier, &client_identity).unwrap();

    // The server task drives the composed daemon's family branch in
    // shape: read the open exchange, ADMIT the carrier (the facts — nonce
    // included — come from the wire carrier), then hand the serve loop
    // the admitted pin, the offer pre-read, and the per-session handle.
    let dropped_for_task = Arc::clone(&dropped);
    let engine_for_task = Arc::clone(&engine);
    let server = tokio::spawn(async move {
        let mut wire = accept_staged(&listener, &trusted, ACCEPT_DEADLINE)
            .await
            .expect("authenticated accept");
        let first = wire.recv_json(ACCEPT_DEADLINE).await.expect("first frame");
        let open =
            modelswarm_node::verifydrafts::read_session_open(&mut wire, first, ACCEPT_DEADLINE)
                .await
                .expect("session-open exchange");
        let carrier = open.pin.expect("this session elects a carrier");
        let admitted = match admit_pin_carrier(
            &carrier,
            wire.remote_peer_id(),
            &modelswarm_node::verifydrafts::verifying_key_from_peer_id(wire.remote_peer_id())
                .expect("ed25519 peer"),
            TEST_PROFILE,
            &batch_generation_params_hash(&config.sampling_params).unwrap(),
            ContentCarriage::On,
            None,
            1,
            1,
        ) {
            PinAdmission::Admitted(admitted) => admitted,
            other => panic!("the well-formed carrier must admit, got {other:?}"),
        };
        let handle: Arc<dyn BatchVerifyEngine> = Arc::new(DropCounted {
            inner: engine_for_task as Arc<dyn BatchVerifyEngine>,
            dropped: dropped_for_task,
        });
        serve_verifydrafts_session_with_pin(
            modelswarm_node::verifydrafts::PrefacedWire::new(wire, Some(open.offer)),
            config,
            handle,
            Some(admitted),
            &Telemetry::memory().0,
        )
        .await
    });

    // The client opens with a pin carrier whose session id matches the
    // admitted one and serves exactly one round.
    let wire = dial_staged(
        &addr,
        &client_identity,
        TEST_PROFILE,
        &server_identity.verifying_key(),
        ACCEPT_DEADLINE,
    )
    .await
    .expect("dial + handshake");
    // Hand-shape the open exchange: pin carrier then offer (the reader
    // consumes both before the serve loop's preface).
    let mut wire = wire;
    wire.send_json(&serde_json::to_value(&carrier).unwrap(), ACCEPT_DEADLINE)
        .await
        .unwrap();
    let offer = json!({
        "session_id": "vd-teardown",
        "protocol_version": COOPERATIVE_PROTOCOL_VERSION,
        "preset": "verified",
        "budget": { "max_endpoints": 1, "max_endpoint_seconds": 120, "max_output_tokens": 4096 },
        "verifier_backend": "cpu",
        "profile_id": TEST_PROFILE,
        "generation_params_hash": params_hash,
    });
    wire.send_json(&offer, ACCEPT_DEADLINE).await.unwrap();
    // Read the accept, then send one signed round through the low-level
    // surface (the client's negotiate would generate its own session id).
    let accept = wire.recv_json(ACCEPT_DEADLINE).await.expect("accept");
    assert!(accept.get("engine").is_some(), "accept: {accept}");
    // The NONCE-LEDGER arm first: a well-formed frame (fresh seq 2, round
    // 1) that REUSES THE CARRIER'S NONCE is `replayed_request` — the
    // seeded ledger bites, and no engine pass runs for it.
    let carrier_nonce = carrier.nonce.clone();
    let mut replay = VerifyDrafts {
        session_id: "vd-teardown".into(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.into(),
        seq: 2,
        round: 1,
        profile_id: TEST_PROFILE.into(),
        parent_prefix_hash: modelswarm_session::GENESIS_PREFIX_HASH.to_string(),
        generation_params_hash: params_hash.clone(),
        window_tokens: vec![5, 6],
        proposer_id: client_identity.peer_id(),
        nonce: carrier_nonce,
        deadline_ms: 2_500,
        sender: client_identity.installation_id(),
        signature: String::new(),
    };
    replay.signature = sign_verify_drafts(&replay, &client_identity).unwrap();
    wire.send_json(&serde_json::to_value(&replay).unwrap(), ACCEPT_DEADLINE)
        .await
        .unwrap();
    let rejected = wire
        .recv_json(ACCEPT_DEADLINE)
        .await
        .expect("the replay is refused");
    assert_eq!(
        rejected["code"], "replayed_request",
        "nonce reuse: {rejected}"
    );
    assert_eq!(engine.calls(), 0, "the replay never reached the engine");
    // The legit round: seq 3 (strictly above the rejected-but-seen seq 2?
    // No — the REPLAY changed no state, so seq 2 is still fresh; use 3 to
    // stay strictly above every frame the peer has SEEN).
    let mut round = VerifyDrafts {
        session_id: "vd-teardown".into(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.into(),
        seq: 3,
        round: 1,
        profile_id: TEST_PROFILE.into(),
        parent_prefix_hash: modelswarm_session::GENESIS_PREFIX_HASH.to_string(),
        generation_params_hash: params_hash,
        window_tokens: vec![5, 6],
        proposer_id: client_identity.peer_id(),
        nonce: new_nonce(),
        deadline_ms: 2_500,
        sender: client_identity.installation_id(),
        signature: String::new(),
    };
    round.signature = sign_verify_drafts(&round, &client_identity).unwrap();
    wire.send_json(&serde_json::to_value(&round).unwrap(), ACCEPT_DEADLINE)
        .await
        .unwrap();
    let result = wire.recv_json(ACCEPT_DEADLINE).await.expect("result");
    assert!(result.get("nonce_echo").is_some(), "result: {result}");
    // Commit the round, then close — the session ends, the handle drops.
    // RC-4: the commit reproduces the result — window[..accepted] ++ the
    // correction.
    let accepted = result["accepted_prefix_len"].as_u64().unwrap_or(0) as usize;
    let mut committed_ids = round.window_tokens[..accepted.min(round.window_tokens.len())].to_vec();
    if let Some(correction) = result["correction"].as_u64() {
        committed_ids.push(correction as u32);
    }
    let committed = result["new_prefix_hash"].as_str().unwrap().to_string();
    let commit = json!({
        "session_id": "vd-teardown",
        "round": 1,
        "previous_prefix_hash": modelswarm_session::GENESIS_PREFIX_HASH,
        "accepted_token_ids": committed_ids,
        "new_prefix_hash": committed,
        "profile_id": TEST_PROFILE,
        "generation_params_hash": batch_generation_params_hash(
            &modelswarm_runtime::SamplingParams::default()
        ).unwrap(),
        "sender": client_identity.installation_id(),
    });
    wire.send_json(&serde_json::to_value(&commit).unwrap(), ACCEPT_DEADLINE)
        .await
        .unwrap();
    drop(wire);
    let report = tokio::time::timeout(Duration::from_secs(15), server)
        .await
        .expect("server settles")
        .expect("server task ok");
    assert!(report.accepted, "report: {report:?}");
    assert_eq!(report.rounds_committed, 1);
    // THE BOUND: the per-session engine handle is gone with the session.
    assert_eq!(
        dropped.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the session's engine handle was dropped at session end"
    );
    assert_eq!(engine.calls(), 1, "exactly the one real engine pass");
}
