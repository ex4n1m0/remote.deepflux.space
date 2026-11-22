//! ADR-036 §6 Security-seat adversarial additions (feature `verifydrafts`)
//! — the two open-exchange bindings the implementation gate found
//! untested, pinned here so no later change silently drops them:
//!
//! - `offer_session_id_must_equal_the_carriers`: ADR-036 §3.2 binds the
//!   carrier's `session_id` to the subsequent `SessionOffer`'s (mismatch
//!   is `bad_frame`, enforced before any accept) — a carrier admitted for
//!   session A must never serve an offer for session B on the same
//!   stream.
//! - `partial_carrier_keys_in_the_offer_position_stay_neutral`: ADR-036
//!   §4.3 names BOTH `pin_commitment` and `prompt_tokens` as the
//!   carrier's discriminant keys; a frame carrying only ONE of them in
//!   the offer position is NOT a carrier — the reader hands it to the
//!   serve loop as the offer, and its content-bearing key is dropped
//!   unprocessed (never prefilled, never admitted). The pin documents
//!   the classification so a future "classify on either key" change
//!   (stricter, bad_frame-class) is a deliberate decision, not drift.

#![cfg(feature = "verifydrafts")]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use modelswarm_identity::InstallationIdentity;
use modelswarm_node::verifydrafts::serve::{
    read_session_open, serve_verifydrafts_session_with_pin, AdmittedPinCarrier,
    VerifyDraftsServeConfig,
};
use modelswarm_node::verifydrafts::wire::{PrefacedWire, VerifyDraftsWire, WireError};
use modelswarm_node::verifydrafts::WirePinCarrier;
use modelswarm_runtime::SamplingParams;
use modelswarm_session::negotiation::{Backend, EngineDisclosure, SessionOffer};
use modelswarm_session::verifydrafts::BatchVerifyEngine;
use modelswarm_telemetry::Telemetry;
use serde_json::{json, Value};

const TEST_PROFILE: &str = "msp1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ACCEPT_DEADLINE: Duration = Duration::from_secs(10);

/// An in-memory wire the tests drive frame by frame (the reader and the
/// serve loop are transport-agnostic behind `VerifyDraftsWire`). The
/// sent-frame log is shared so a test can inspect what left the loop
/// after the wire itself is consumed.
struct VecWire {
    frames: VecDeque<Value>,
    sent: Arc<Mutex<Vec<String>>>,
    peer_id: String,
}

impl VecWire {
    fn empty(peer_id: String) -> (Self, Arc<Mutex<Vec<String>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                frames: VecDeque::new(),
                sent: Arc::clone(&sent),
                peer_id,
            },
            sent,
        )
    }
}

#[async_trait::async_trait]
impl VerifyDraftsWire for VecWire {
    async fn send_json(&mut self, value: &Value, _deadline: Duration) -> Result<(), WireError> {
        self.sent.lock().expect("sent lock").push(value.to_string());
        Ok(())
    }
    async fn recv_json(&mut self, _deadline: Duration) -> Result<Value, WireError> {
        self.frames.pop_front().ok_or(WireError::Closed)
    }
    fn remote_peer_id(&self) -> &str {
        &self.peer_id
    }
}

/// A counting engine: every `verify_window` pass is recorded in a shared
/// counter — the session-id-binding pin asserts the engine is NEVER
/// touched while keeping the engine itself movable into the serve loop.
struct CountingEngine {
    calls: Arc<Mutex<usize>>,
}

impl CountingEngine {
    fn new() -> (Arc<Self>, Arc<Mutex<usize>>) {
        let calls = Arc::new(Mutex::new(0));
        (
            Arc::new(Self {
                calls: Arc::clone(&calls),
            }),
            calls,
        )
    }
}

#[async_trait::async_trait]
impl BatchVerifyEngine for CountingEngine {
    async fn verify_window(
        &self,
        _window: &[u32],
        _params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), modelswarm_runtime::RuntimeError> {
        *self.calls.lock().expect("calls lock") += 1;
        Ok((0, None))
    }
    fn capabilities(&self) -> EngineDisclosure {
        EngineDisclosure {
            backend: Backend::Cpu,
            batch_verify: false,
            batch_window_max: 8,
        }
    }
}

/// A full, schema-valid offer for `session_id` (every v3 field present).
fn full_offer(session_id: &str) -> Value {
    json!({
        "session_id": session_id,
        "protocol_version": "msp-cooperative-v1",
        "preset": "verified",
        "budget": {
            "max_endpoints": 1,
            "max_endpoint_seconds": 60,
            "max_output_tokens": 256
        },
        "verifier_backend": "cpu",
        "profile_id": TEST_PROFILE,
        "generation_params_hash": "0".repeat(64),
    })
}

/// The serve loop must refuse an offer whose `session_id` differs from
/// the ADMITTED carrier's (ADR-036 §3.2: mismatch is `bad_frame`,
/// enforced before any accept, before any reject is sent, and before any
/// engine work) — a carrier admitted for session A can never serve an
/// offer for session B on the same authenticated stream.
#[tokio::test]
async fn offer_session_id_must_equal_the_carriers() {
    let server_identity = InstallationIdentity::from_bytes(&[0x81; 32]);
    let (engine, calls) = CountingEngine::new();
    let mut config =
        VerifyDraftsServeConfig::honest(TEST_PROFILE.to_string(), server_identity.clone());
    // The offer's params hash will mismatch nothing: the binding under
    // test fires FIRST, so the pinned defaults' hash is never compared.
    config.session_idle = Duration::from_secs(60);

    let admitted = AdmittedPinCarrier {
        session_id: "vd-carrier-session".to_string(),
        prompt_tokens: vec![151644, 100, 151645],
        seq: 1,
        nonce: "n".repeat(16),
        sender: "sender".to_string(),
        deadline_expires_at_ms: u64::MAX,
    };

    let sent: Arc<Mutex<Vec<String>>>;
    let wire = {
        let (inner, sent_log) = VecWire::empty(server_identity.peer_id());
        sent = sent_log;
        PrefacedWire::new(inner, Some(full_offer("vd-DIFFERENT-session")))
    };
    let telemetry = Telemetry::memory().0;
    let report =
        serve_verifydrafts_session_with_pin(wire, config, engine, Some(admitted), &telemetry).await;

    assert!(
        !report.accepted,
        "a session-id-mismatched offer must never be accepted: {report:?}"
    );
    assert!(
        matches!(
            report.ended_by,
            modelswarm_node::verifydrafts::serve::ServeEndReason::BadOffer(
                "carrier session id mismatch"
            )
        ),
        "the binding's honest label: {report:?}"
    );
    // No engine pass ran: the binding fires before any engine work.
    assert_eq!(
        *calls.lock().expect("calls lock"),
        0,
        "the engine is never touched"
    );
    // No reject vocabulary exists for a bad_frame-class session end — the
    // honest answer is the session end itself; nothing was sent.
    assert!(
        sent.lock().expect("sent lock").is_empty(),
        "bad_frame-class ends send nothing"
    );
}

/// The §4.3 both-keys discriminant rule, pinned at the reader: a frame
/// carrying exactly ONE carrier key in the offer position is NOT a pin
/// carrier — the session opens NEUTRAL and the stray content-bearing key
/// is dropped unprocessed (never parsed as a carrier, never prefilled).
/// Both halves are pinned: `prompt_tokens` alone and `pin_commitment`
/// alone.
#[tokio::test]
async fn partial_carrier_keys_in_the_offer_position_stay_neutral() {
    let identity = InstallationIdentity::from_bytes(&[0x82; 32]);

    // `prompt_tokens` riding an otherwise-valid offer frame.
    let mut offer_with_tokens = full_offer("vd-neutral-1");
    offer_with_tokens["prompt_tokens"] = json!([151644, 100, 151645]);
    let (mut wire, _sent) = VecWire::empty(identity.peer_id());
    let open = read_session_open(&mut wire, offer_with_tokens, ACCEPT_DEADLINE)
        .await
        .expect("the reader hands the frame to the serve loop");
    assert!(
        open.pin.is_none() && open.lease.is_none(),
        "a single-key frame is not a carrier"
    );
    // The serve loop's strict offer parse accepts it as a NEUTRAL offer:
    // `SessionOffer` is not `deny_unknown_fields` (an ADR-032 shape), so
    // the stray key is ignored — the content is dropped unprocessed, and
    // the session that would open is the neutral one (its rounds would
    // honestly diverge against a conversation-rooted coordinator).
    assert!(
        serde_json::from_value::<SessionOffer>(open.offer).is_ok(),
        "the degraded frame still parses as the neutral offer"
    );

    // `pin_commitment` riding an otherwise-valid offer frame: same class.
    let mut offer_with_commitment = full_offer("vd-neutral-2");
    offer_with_commitment["pin_commitment"] = json!("ab".repeat(32));
    let (mut wire, _sent) = VecWire::empty(identity.peer_id());
    let open = read_session_open(&mut wire, offer_with_commitment, ACCEPT_DEADLINE)
        .await
        .expect("the reader hands the frame to the serve loop");
    assert!(
        open.pin.is_none() && open.lease.is_none(),
        "a single-key frame is not a carrier"
    );
    assert!(serde_json::from_value::<SessionOffer>(open.offer).is_ok());

    // For contrast, BOTH keys together ARE the carrier — even over an
    // otherwise-valid offer body (the strict carrier parse then fails on
    // the offer fields as unknown fields → `bad_frame`-class, never a
    // neutral session).
    let mut both_keys = full_offer("vd-neutral-3");
    both_keys["prompt_tokens"] = json!([1, 2, 3]);
    both_keys["pin_commitment"] = json!("cd".repeat(32));
    let (mut wire, _sent) = VecWire::empty(identity.peer_id());
    let err = read_session_open(&mut wire, both_keys, ACCEPT_DEADLINE)
        .await
        .expect_err("both keys = the carrier discriminant");
    assert!(
        matches!(
            err,
            modelswarm_node::verifydrafts::serve::SessionOpenError::BadPinCarrier(_)
        ),
        "the strict carrier schema refuses the offer-shaped body: {err}"
    );
}

/// The commitment is SELF-CONSISTENCY only (ADR-036 §6 pre-analysis):
/// `pin_commitment_of` recomputes over the payload the serving peer
/// already holds — no third party can probe the check, and the mismatch
/// reject (`pin_mismatch`) discloses nothing beyond "these bytes do not
/// hash to this value". Pinned so a future change cannot turn the check
/// into an oracle (e.g. by echoing derived values in any frame or log).
#[test]
fn commitment_check_is_pure_self_consistency() {
    let tokens = vec![7u32, 11, 13];
    let mut carrier = WirePinCarrier {
        session_id: "vd-oracle".into(),
        protocol_version: "msp-cooperative-v1".into(),
        seq: 1,
        round: 0,
        profile_id: TEST_PROFILE.into(),
        generation_params_hash: "3d".repeat(32),
        prompt_tokens: tokens.clone(),
        pin_commitment: modelswarm_session::negotiation::pin_commitment_of(&tokens),
        nonce: "n".repeat(16),
        deadline_ms: 60_000,
        sender: "s".into(),
        signature: String::new(),
    };
    assert!(carrier.commitment_matches());
    // A one-token perturbation flips the commitment: the construction is
    // a plain SHA-256 over LE-u32s with no parent, no salt, no secret —
    // and no output beyond the boolean ever leaves the check.
    carrier.prompt_tokens.push(1);
    assert!(!carrier.commitment_matches());
    // The only wire surface for a mismatch is the frozen reason string.
    assert_eq!(
        modelswarm_session::negotiation::SessionRejectReason::PinMismatch.as_str(),
        "pin_mismatch"
    );
}
