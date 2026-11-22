//! The composed-daemon demux (feature `verifydrafts` + `libp2p-backend`):
//! ONE QUIC listener serving BOTH session vocabularies behind ONE
//! admission gate and ONE ADR-026 lease discipline
//! (`serve_sessions_composed`).
//!
//! - `one_listener_serves_both_vocabularies`: a SpecMessage (msp-v1)
//!   session and a VerifyDrafts family session coexist on one listener —
//!   the required demux pin — with the family's lease PRESENTED by the
//!   coordinator in the session-open carrier (ADR-032 §2 admission
//!   order) and admitted through the PRODUCTION source with an EMPTY
//!   roster (the two-fresh-installations pairing: nothing feeds the
//!   roster, the hub-signed presented token is the whole claim), and the
//!   family's engine disclosure coming from the INJECTED engine through
//!   the seam (real geometry, never the hand-set config field), while
//!   the msp-v1 path streams through its executor unchanged.
//! - `family_session_refused_without_lease`: the fail-closed lease seam —
//!   no lease derivation for the authenticated coordinator PeerId means
//!   no family session (the honest fallback-to-single signal on the
//!   client), telemetered with a stable label.
//! - `family_session_refused_on_wrong_profile_lease` (RC-L1): a
//!   coordinator PRESENTING a lease signed for ANOTHER profile is
//!   refused before any engine work — the profile binding the security
//!   disposition made a condition of light-up.

#![cfg(all(feature = "verifydrafts", feature = "libp2p-backend"))]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::stream;
use modelswarm_eligibility::{CapacityClass, EligibilityLease};
use modelswarm_gateway::{
    ExecutorError, ExecutorEvent, ExecutorStream, FinishReason, InferenceExecutor,
    NormalizedRequest,
};
use modelswarm_identity::InstallationIdentity;
use modelswarm_node::verifydrafts::composed::{
    serve_sessions_composed, FamilyServing, RefuseFamilyLeases, RosterFamilyLeases,
};
use modelswarm_node::verifydrafts::engine_source::FamilyEngineSource;
use modelswarm_node::verifydrafts::{
    VerifyDraftsClient, VerifyDraftsClientConfig, VerifyDraftsServeConfig,
};
use modelswarm_runtime::SamplingParams;
use modelswarm_session::negotiation::{Backend, EngineDisclosure};
use modelswarm_session::verifydrafts::BatchVerifyEngine;
use modelswarm_telemetry::Telemetry;
use modelswarm_transport::libp2p_backend::Libp2pTransport;
use modelswarm_transport::message::{
    ChatMessage, InferenceRequest, Sampling as WireSampling, WireMessage,
};

/// A profile id that passes the msp1 form checks (serving.rs test pattern).
const TEST_PROFILE: &str = "msp1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// A DIFFERENT well-formed profile (the RC-L1 wrong-profile arm).
const OTHER_PROFILE: &str = "msp1:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

const ACCEPT_DEADLINE: Duration = Duration::from_secs(10);

/// A mock batch-verify engine with a scripted outcome list (the QUIC
/// venue test's pattern): one outcome per dispatched round, in order.
struct ScriptedEngine {
    disclosure: EngineDisclosure,
    outcomes: Mutex<VecDeque<(u32, Option<u32>)>>,
}

impl ScriptedEngine {
    fn new(disclosure: EngineDisclosure, outcomes: Vec<(u32, Option<u32>)>) -> Arc<Self> {
        Arc::new(Self {
            disclosure,
            outcomes: Mutex::new(outcomes.into()),
        })
    }
}

#[async_trait::async_trait]
impl BatchVerifyEngine for ScriptedEngine {
    async fn verify_window(
        &self,
        _window: &[u32],
        _params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), modelswarm_runtime::RuntimeError> {
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
        backend: Backend::Cpu,
        batch_verify: true,
        batch_window_max: window_max,
    }
}

/// The deterministic msp-v1 executor (the serving-bridge test's
/// FixedExecutor): "Hello swarm" + usage + completed.
struct FixedExecutor;

#[async_trait::async_trait]
impl InferenceExecutor for FixedExecutor {
    async fn execute(&self, request: NormalizedRequest) -> Result<ExecutorStream, ExecutorError> {
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.messages[0].role, "user");
        Ok(Box::pin(stream::iter(vec![
            ExecutorEvent::Accepted {
                queue_position: 0,
                eta_ms: 0,
            },
            ExecutorEvent::TokenDelta {
                delta: "Hello ".into(),
                index: 0,
            },
            ExecutorEvent::TokenDelta {
                delta: "swarm".into(),
                index: 1,
            },
            ExecutorEvent::Usage {
                prompt_tokens: 3,
                completion_tokens: 2,
                prefill_ms: 1.0,
                decode_ms: 2.0,
            },
            ExecutorEvent::Completed {
                finish_reason: FinishReason::Stop,
            },
        ])))
    }
}

fn rfc3339(plus_secs: i64) -> String {
    time::OffsetDateTime::now_utc()
        .saturating_add(time::Duration::seconds(plus_secs))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// Issues a valid consume lease for (profile, peer) under `key` and
/// returns the wire token (the serving.rs lease_helpers pattern,
/// parameterized so one hub key backs both vocabularies' arms).
fn lease_wire(key: &SigningKey, profile: &str, peer_id: &str) -> String {
    EligibilityLease::issue(
        peer_id,
        "test-installation",
        profile,
        rfc3339(-60),
        rfc3339(300),
        rfc3339(360),
        true,
        true,
        1,
        CapacityClass::GpuMid,
        1,
        "test-challenge",
        "test-nonce",
        1,
        key,
    )
    .to_wire()
}

/// The lease policy over a fresh test hub key.
fn policy_over(key: &SigningKey) -> modelswarm_node::serving::LeasePolicy {
    modelswarm_node::serving::LeasePolicy::from_hex(&hex::encode(key.verifying_key().to_bytes()))
        .unwrap()
}

/// The required demux pin: a SpecMessage (msp-v1) session and a
/// VerifyDrafts family session COEXIST on one listener — classified by
/// their first frames, both admitted through the one `Admission` gate,
/// the family's lease PRESENTED by the coordinator at session open and
/// admitted through the PRODUCTION source with an EMPTY roster (the
/// two-fresh-installations pairing), and the family's engine disclosure
/// reported from the INJECTED engine (the seam's real geometry: window 8,
/// batch true — not the hand-set `honest()` default `batch_verify:
/// false`).
#[tokio::test]
async fn one_listener_serves_both_vocabularies() {
    let server_identity = InstallationIdentity::from_bytes(&[0xE1; 32]);
    let coordinator = InstallationIdentity::from_bytes(&[0xE2; 32]);
    let requester = InstallationIdentity::from_bytes(&[0xE3; 32]);
    let telemetry = Arc::new(Telemetry::memory().0);

    let engine = ScriptedEngine::new(batch_engine(8), vec![(2, Some(901))]);
    let mut family_config =
        VerifyDraftsServeConfig::honest(TEST_PROFILE.to_string(), server_identity.clone());
    // The hand-set disclosure is the honest `batch_verify: false`; the
    // composed loop must override it with the injected engine's REAL
    // geometry — pinned by the client-side assertion below.
    family_config.session_idle = Duration::from_secs(60);

    let transport = Libp2pTransport::new(&server_identity).expect("server transport");
    let listener = transport
        .listen("127.0.0.1:0")
        .await
        .expect("loopback quic");
    let addr = listener.bound_addr().to_string();
    let expected_server_peer = transport.peer_id();

    // ONE test hub backs both vocabularies' lease arms: the msp-v1
    // requester presents its token on the wire; the family coordinator
    // PRESENTS its token in the session-open carrier (the roster below
    // stays EMPTY — presentation is the admission path, exactly the
    // shipped-desktop configuration where nothing feeds the roster).
    let hub = SigningKey::generate(&mut rand_core::OsRng);
    let policy = policy_over(&hub);
    let token = lease_wire(&hub, TEST_PROFILE, &requester.peer_id().to_string());
    let coordinator_lease = lease_wire(&hub, TEST_PROFILE, &coordinator.peer_id().to_string());
    let roster = RosterFamilyLeases::new(policy_over(&hub));
    assert!(roster.is_empty(), "presentation, not roster feeding");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let serving_telemetry = Arc::clone(&telemetry);
    tokio::spawn(serve_sessions_composed(
        modelswarm_node::serving::ServingInbox::new(
            listener,
            modelswarm_node::serving::RelaySlot::empty(),
        ),
        std::sync::Arc::new(modelswarm_identity::InstallationIdentity::from_bytes(
            &[0xA7; 32],
        )),
        Arc::new(FixedExecutor),
        TEST_PROFILE.to_string(),
        policy,
        FamilyServing {
            config: family_config,
            engine: Arc::new(FamilyEngineSource::Shared(engine)),
            lease: Arc::new(roster),
        },
        serving_telemetry,
        shutdown_rx,
    ));

    // ---- msp-v1 arm: a SpecMessage session over the SAME listener ------
    let requester_transport = Libp2pTransport::new(&requester).expect("requester transport");
    let mut msp_session = requester_transport
        .dial(&addr, &expected_server_peer, ACCEPT_DEADLINE)
        .await
        .expect("msp-v1 dial into the composed listener");
    msp_session
        .send(
            &WireMessage::InferenceRequest(InferenceRequest {
                request_id: "req-1".into(),
                profile_id: TEST_PROFILE.into(),
                capability_token: token,
                messages: vec![ChatMessage {
                    role: "user".into(),
                    content: "hi".into(),
                }],
                sampling: WireSampling {
                    temperature: 0.0,
                    top_p: 1.0,
                    top_k: 40,
                    seed: None,
                },
                max_tokens: 8,
                deadline_ms: 10_000,
                stream: true,
            }),
            Duration::from_secs(5),
        )
        .await
        .expect("msp-v1 request through the demux");
    let mut deltas = String::new();
    let mut finish = String::new();
    for _ in 0..4 {
        match msp_session.recv(Duration::from_secs(10)).await.unwrap() {
            WireMessage::TokenDelta(d) => deltas.push_str(&d.delta),
            WireMessage::Usage(_) => {}
            WireMessage::Completed(c) => finish = c.finish_reason,
            other => panic!("unexpected msp-v1 frame: {other:?}"),
        }
    }
    assert_eq!(deltas, "Hello swarm");
    assert_eq!(finish, "stop");

    // ---- family arm: a VerifyDrafts session over the SAME listener -----
    let wire = modelswarm_node::verifydrafts::dial_quic(
        &addr,
        &coordinator,
        &server_identity.verifying_key(),
        ACCEPT_DEADLINE,
    )
    .await
    .expect("family dial into the composed listener");
    let tel = Telemetry::memory().0;
    let mut family_config_client =
        VerifyDraftsClientConfig::new(TEST_PROFILE.to_string(), server_identity.verifying_key());
    family_config_client.lease = Some(coordinator_lease);
    let mut client =
        VerifyDraftsClient::negotiate(wire, coordinator.clone(), family_config_client, &tel)
            .await
            .expect("family session opened through the composed demux on the PRESENTED lease");
    // The disclosure is the INJECTED engine's real geometry (the seam
    // override), not the config's hand-set honest default.
    assert!(client.engine_disclosure().batch_verify);
    assert_eq!(client.engine_disclosure().batch_window_max, 8);
    assert_eq!(client.engine_disclosure().backend, Backend::Cpu);

    let r1 = client
        .round(&[71, 72], &tel)
        .await
        .expect("family round through the composed demux");
    assert_eq!(r1.committed, vec![71, 72, 901]);
    assert_eq!(client.committed_stream(), vec![71, 72, 901]);

    // The msp-v1 session is STILL live (connection reuse across the
    // family session's whole lifecycle — one listener, both vocabularies).
    drop(client.into_wire());
    drop(msp_session);
    drop(shutdown_tx);
}

/// The fail-closed ADR-026 seam: with no lease derivation for the
/// authenticated coordinator, the family session is refused BEFORE any
/// engine work (the scripted engine is never consumed) and the client
/// surfaces an honest transport failure — its fallback-to-single signal.
#[tokio::test]
async fn family_session_refused_without_lease() {
    let server_identity = InstallationIdentity::from_bytes(&[0xF1; 32]);
    let coordinator = InstallationIdentity::from_bytes(&[0xF2; 32]);
    let (telemetry, sink) = Telemetry::memory();
    let telemetry = Arc::new(telemetry);

    let engine = ScriptedEngine::new(batch_engine(8), vec![(1, Some(1))]);
    let family_config =
        VerifyDraftsServeConfig::honest(TEST_PROFILE.to_string(), server_identity.clone());

    let transport = Libp2pTransport::new(&server_identity).expect("server transport");
    let listener = transport
        .listen("127.0.0.1:0")
        .await
        .expect("loopback quic");
    let addr = listener.bound_addr().to_string();
    let policy = policy_over(&SigningKey::generate(&mut rand_core::OsRng));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let serving_telemetry = Arc::clone(&telemetry);
    let serving = tokio::spawn(serve_sessions_composed(
        modelswarm_node::serving::ServingInbox::new(
            listener,
            modelswarm_node::serving::RelaySlot::empty(),
        ),
        std::sync::Arc::new(modelswarm_identity::InstallationIdentity::from_bytes(
            &[0xA7; 32],
        )),
        Arc::new(NeverExecutor),
        TEST_PROFILE.to_string(),
        policy,
        FamilyServing {
            config: family_config,
            engine: Arc::new(FamilyEngineSource::Shared(engine)),
            lease: Arc::new(RefuseFamilyLeases),
        },
        serving_telemetry,
        shutdown_rx,
    ));

    let wire = modelswarm_node::verifydrafts::dial_quic(
        &addr,
        &coordinator,
        &server_identity.verifying_key(),
        ACCEPT_DEADLINE,
    )
    .await
    .expect("dial itself is lease-agnostic");
    let tel = Telemetry::memory().0;
    match VerifyDraftsClient::negotiate(
        wire,
        coordinator,
        VerifyDraftsClientConfig::new(TEST_PROFILE.to_string(), server_identity.verifying_key()),
        &tel,
    )
    .await
    {
        // The server ends the session after classifying the offer frame:
        // the client sees the transport failure, never an accept.
        Err(modelswarm_node::verifydrafts::ClientOpenError::Io(_)) => {}
        Ok(_) => panic!("a lease-less family session must never be accepted"),
        Err(other) => panic!("expected an honest transport failure, got {other}"),
    }

    // The refusal is telemetered with a stable label (ids/codes only).
    let events = sink.snapshot().join("\n");
    assert!(
        events.contains("verifydrafts.family_refused"),
        "the refusal must be telemetered: {events}"
    );
    assert!(
        events.contains("\"reason\":\"no_lease\"") || events.contains("\"reason\": \"no_lease\""),
        "the no-lease reason must be stable: {events}"
    );
    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("composed loop exits when the shutdown sender drops")
        .expect("composed loop task ok");
}

/// RC-L1, live on the composed daemon: a coordinator PRESENTING a lease
/// signed for ANOTHER profile is REFUSED before any engine work (the
/// scripted engine is never consumed) — the profile binding the security
/// disposition made a condition of the light-up, telemetered with the
/// msp-v1 gate's own classification.
#[tokio::test]
async fn family_session_refused_on_wrong_profile_lease() {
    let server_identity = InstallationIdentity::from_bytes(&[0xA1; 32]);
    let coordinator = InstallationIdentity::from_bytes(&[0xA2; 32]);
    let (telemetry, sink) = Telemetry::memory();
    let telemetry = Arc::new(telemetry);

    let engine = ScriptedEngine::new(batch_engine(8), vec![(1, Some(1))]);
    let family_config =
        VerifyDraftsServeConfig::honest(TEST_PROFILE.to_string(), server_identity.clone());

    let transport = Libp2pTransport::new(&server_identity).expect("server transport");
    let listener = transport
        .listen("127.0.0.1:0")
        .await
        .expect("loopback quic");
    let addr = listener.bound_addr().to_string();
    // The hub key is trusted; the coordinator PRESENTS a validly signed
    // lease for ANOTHER profile (empty roster — the presentation is the
    // whole claim) — a coordinator hosting a different model must not
    // verify against this daemon.
    let hub = SigningKey::generate(&mut rand_core::OsRng);
    let roster = RosterFamilyLeases::new(policy_over(&hub));
    assert!(roster.is_empty());
    let wrong_profile_lease = lease_wire(&hub, OTHER_PROFILE, &coordinator.peer_id().to_string());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let serving_telemetry = Arc::clone(&telemetry);
    let serving = tokio::spawn(serve_sessions_composed(
        modelswarm_node::serving::ServingInbox::new(
            listener,
            modelswarm_node::serving::RelaySlot::empty(),
        ),
        std::sync::Arc::new(modelswarm_identity::InstallationIdentity::from_bytes(
            &[0xA7; 32],
        )),
        Arc::new(NeverExecutor),
        TEST_PROFILE.to_string(),
        policy_over(&hub),
        FamilyServing {
            config: family_config,
            engine: Arc::new(FamilyEngineSource::Shared(engine)),
            lease: Arc::new(roster),
        },
        serving_telemetry,
        shutdown_rx,
    ));

    let wire = modelswarm_node::verifydrafts::dial_quic(
        &addr,
        &coordinator,
        &server_identity.verifying_key(),
        ACCEPT_DEADLINE,
    )
    .await
    .expect("dial itself is lease-agnostic");
    let tel = Telemetry::memory().0;
    let mut client_config =
        VerifyDraftsClientConfig::new(TEST_PROFILE.to_string(), server_identity.verifying_key());
    client_config.lease = Some(wrong_profile_lease);
    match VerifyDraftsClient::negotiate(wire, coordinator, client_config, &tel).await {
        Err(modelswarm_node::verifydrafts::ClientOpenError::Io(_)) => {}
        Ok(_) => panic!("a wrong-profile presented lease must never open a family session"),
        Err(other) => panic!("expected an honest transport failure, got {other}"),
    }

    // The refusal carries the msp-v1 gate's own classification label.
    let events = sink.snapshot().join("\n");
    assert!(
        events.contains("verifydrafts.family_refused"),
        "the refusal must be telemetered: {events}"
    );
    assert!(
        events.contains("\"reason\":\"profile_mismatch\"")
            || events.contains("\"reason\": \"profile_mismatch\""),
        "the wrong-profile reason must be stable: {events}"
    );
    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("composed loop exits when the shutdown sender drops")
        .expect("composed loop task ok");
}

/// An executor that must never run in the lease-refusal test.
struct NeverExecutor;

#[async_trait::async_trait]
impl InferenceExecutor for NeverExecutor {
    async fn execute(&self, _request: NormalizedRequest) -> Result<ExecutorStream, ExecutorError> {
        unreachable!("no msp-v1 request is ever accepted in this test")
    }
}
