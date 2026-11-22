//! ADR-032 QUIC venue (feature `verifydrafts`): the same lifecycle and
//! negative paths `verifydrafts_wiring.rs` pins over the staged TCP
//! backend, here over the REAL libp2p QUIC transport — two in-process
//! endpoints on loopback, real QUIC handshakes (the remote PeerId is
//! cryptographically authenticated by the transport itself), the real
//! length-prefixed JSON framing, and the transport crate's raw-JSON
//! passthrough (`Libp2pSession::send_json`/`recv_json`, the light-up
//! handoff's G1 gap, closed 2026-10-12).
//!
//! No machine B is involved: the ADR-018 honesty guard keeps the listener
//! loopback-only, and these tests bind `127.0.0.1:0` exactly like the
//! transport crate's own loopback QUIC tests.

#![cfg(feature = "verifydrafts")]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use modelswarm_identity::InstallationIdentity;
use modelswarm_node::verifydrafts::serve::{
    serve_verifydrafts_quic, serve_verifydrafts_session, ServeEndReason, VerifyDraftsServeConfig,
};
use modelswarm_node::verifydrafts::wire::{accept_quic, dial_quic};
use modelswarm_node::verifydrafts::{
    ClientOpenError, RoundFailure, VerifyDraftsClient, VerifyDraftsClientConfig, VerifyDraftsWire,
};
use modelswarm_session::negotiation::{Backend, EngineDisclosure};
use modelswarm_session::verifydrafts::BatchVerifyEngine;
use modelswarm_telemetry::Telemetry;
use modelswarm_transport::libp2p_backend::Libp2pTransport;

/// A profile id that passes the msp1 form checks (serving.rs test pattern).
const TEST_PROFILE: &str = "msp1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const ACCEPT_DEADLINE: Duration = Duration::from_secs(10);

/// A mock batch-verify engine with a scripted outcome list (the staged
/// wiring test's pattern): one outcome per dispatched round, in order;
/// exhaustion fails closed.
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
        _params: &modelswarm_runtime::SamplingParams,
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

/// Full session lifecycle over the real QUIC transport: negotiate → three
/// engaged rounds (full acceptance + bonus, mid-window rejection, EOG
/// present-as-null) → commits → clean teardown by client close — with the
/// remote PeerId on BOTH sides being the QUIC-authenticated ADR-020
/// derivation (the production-grade RC-1 binding).
#[tokio::test]
async fn lifecycle_round_trips_over_real_quic() {
    let server_identity = InstallationIdentity::from_bytes(&[0xA1; 32]);
    let client_identity = InstallationIdentity::from_bytes(&[0xA2; 32]);
    let telemetry = Arc::new(Telemetry::memory().0);

    let engine = ScriptedEngine::new(
        batch_engine(8),
        vec![(8, Some(901)), (3, Some(902)), (8, None)],
    );
    let mut config =
        VerifyDraftsServeConfig::honest(TEST_PROFILE.to_string(), server_identity.clone());
    config.engine = batch_engine(8);
    config.session_idle = Duration::from_secs(60);

    let transport = Libp2pTransport::new(&server_identity).expect("server transport");
    let mut listener = transport
        .listen("127.0.0.1:0")
        .await
        .expect("loopback quic");
    let addr = listener.bound_addr().to_string();
    let server = tokio::spawn(async move {
        let wire = accept_quic(&mut listener, ACCEPT_DEADLINE)
            .await
            .expect("quic accept authenticates the peer");
        serve_verifydrafts_session(wire, config, engine.clone(), &telemetry).await
    });

    let wire = dial_quic(
        &addr,
        &client_identity,
        &server_identity.verifying_key(),
        ACCEPT_DEADLINE,
    )
    .await
    .expect("quic dial + peer id binding");
    // The client side sees the SERVER's QUIC-authenticated PeerId — the
    // pinned derivation, never a payload claim.
    assert_eq!(wire.remote_peer_id(), server_identity.peer_id());
    let tel = Telemetry::memory().0;
    let mut client = VerifyDraftsClient::negotiate(
        wire,
        client_identity.clone(),
        VerifyDraftsClientConfig::new(TEST_PROFILE.to_string(), server_identity.verifying_key()),
        &tel,
    )
    .await
    .expect("offer accepted over quic");
    assert!(client.engine_disclosure().batch_verify);
    assert_eq!(client.engine_disclosure().batch_window_max, 8);

    // Round 1: full acceptance + bonus token.
    let r1 = client
        .round(&[11, 12, 13, 14, 15, 16, 17, 18], &tel)
        .await
        .expect("round 1 over quic");
    assert_eq!(r1.round, 1);
    assert_eq!(r1.accepted_prefix_len, 8);
    assert_eq!(r1.divergence_point, None);
    assert_eq!(r1.correction, Some(901));
    assert_eq!(r1.committed.len(), 9);

    // Round 2: mid-window rejection at index 3 + replacement token.
    let r2 = client
        .round(&[21, 22, 23, 24, 25, 26, 27, 28], &tel)
        .await
        .expect("round 2 over quic");
    assert_eq!(r2.accepted_prefix_len, 3);
    assert_eq!(r2.divergence_point, Some(3));
    assert_eq!(r2.correction, Some(902));
    assert_eq!(r2.committed, vec![21, 22, 23, 902]);

    // Round 3: EOG — full acceptance, correction present-as-null.
    let r3 = client
        .round(&[31, 32, 33, 34, 35, 36, 37, 38], &tel)
        .await
        .expect("round 3 over quic");
    assert_eq!(r3.accepted_prefix_len, 8);
    assert_eq!(r3.correction, None);
    assert_eq!(r3.committed.len(), 8);

    // The committed stream is exactly window-prefixes ++ corrections.
    let expected: Vec<u32> = [
        vec![11, 12, 13, 14, 15, 16, 17, 18, 901],
        vec![21, 22, 23, 902],
        vec![31, 32, 33, 34, 35, 36, 37, 38],
    ]
    .concat();
    assert_eq!(client.committed_stream(), expected);
    // RC-2: the per-verifier EWMA fed on every requester-measured round.
    assert!(client
        .timings()
        .ewma_ms(&server_identity.peer_id())
        .is_some());
    // All three outcomes passed the verify_pass_ms cross-check.
    assert_eq!(
        r1.cross_check,
        modelswarm_session::verifydrafts::CrossCheckOutcome::Ok
    );
    assert_eq!(
        r2.cross_check,
        modelswarm_session::verifydrafts::CrossCheckOutcome::Ok
    );
    assert_eq!(
        r3.cross_check,
        modelswarm_session::verifydrafts::CrossCheckOutcome::Ok
    );

    // Clean teardown: the client closes, the server reports honestly — and
    // the report's remote PeerId is the QUIC-authenticated client identity.
    drop(client.into_wire());
    let report = tokio::time::timeout(ACCEPT_DEADLINE, server)
        .await
        .expect("server settles on client close")
        .expect("server task ok");
    assert!(report.accepted);
    assert_eq!(report.remote_peer_id, client_identity.peer_id());
    assert_eq!(report.rounds_handled, 3);
    assert_eq!(report.rounds_committed, 3);
    assert_eq!(report.committed_output_tokens, 21);
    assert_eq!(report.ended_by, ServeEndReason::ClientClosed);
    assert_eq!(report.committed_prefix_hash.len(), 64);
}

/// §3 backend pairing over QUIC: a Vulkan requester against a CPU verifier
/// is refused with the honest `backend_mismatch` SessionReject.
#[tokio::test]
async fn backend_mismatch_rejects_honestly_over_quic() {
    let server_identity = InstallationIdentity::from_bytes(&[0xB1; 32]);
    let client_identity = InstallationIdentity::from_bytes(&[0xB2; 32]);
    let telemetry = Arc::new(Telemetry::memory().0);

    let engine = ScriptedEngine::new(batch_engine(8), vec![(1, Some(1))]);
    let config = VerifyDraftsServeConfig::honest(TEST_PROFILE.to_string(), server_identity.clone());

    let transport = Libp2pTransport::new(&server_identity).expect("server transport");
    let mut listener = transport
        .listen("127.0.0.1:0")
        .await
        .expect("loopback quic");
    let addr = listener.bound_addr().to_string();
    let server = tokio::spawn(async move {
        let wire = accept_quic(&mut listener, ACCEPT_DEADLINE)
            .await
            .expect("quic accept");
        serve_verifydrafts_session(wire, config, engine, &telemetry).await
    });

    let wire = dial_quic(
        &addr,
        &client_identity,
        &server_identity.verifying_key(),
        ACCEPT_DEADLINE,
    )
    .await
    .expect("quic dial");
    let mut client_config =
        VerifyDraftsClientConfig::new(TEST_PROFILE.to_string(), server_identity.verifying_key());
    client_config.verifier_backend = Backend::Vulkan; // E0: CPU ≠ Vulkan.
    let tel = Telemetry::memory().0;
    let opened = VerifyDraftsClient::negotiate(wire, client_identity, client_config, &tel).await;

    match opened {
        Err(ClientOpenError::Rejected(reason)) => assert_eq!(reason, "backend_mismatch"),
        Err(other) => panic!("expected backend_mismatch reject, got {other:?}"),
        Ok(_) => panic!("backend mismatch must refuse the session"),
    }
    let report = tokio::time::timeout(ACCEPT_DEADLINE, server)
        .await
        .expect("server settles after the reject")
        .expect("server task ok");
    assert!(!report.accepted);
    assert_eq!(
        report.ended_by,
        ServeEndReason::RejectedOffer(
            modelswarm_session::negotiation::SessionRejectReason::BackendMismatch
        )
    );
}

/// RC-1 over the real transport: when the gate's coordinator key is pinned
/// to a key the stream's QUIC-authenticated PeerId does NOT derive from,
/// every `VerifyDrafts` fails closed as `bad_frame` BEFORE any admission
/// stage — zero engine work, and the session survives for the honest
/// client to give up cleanly.
#[tokio::test]
async fn remote_peer_mismatch_fails_closed_bad_frame_over_quic() {
    let server_identity = InstallationIdentity::from_bytes(&[0xC1; 32]);
    let client_identity = InstallationIdentity::from_bytes(&[0xC2; 32]);
    let stranger = InstallationIdentity::from_bytes(&[0xC3; 32]);
    let telemetry = Arc::new(Telemetry::memory().0);

    let engine = ScriptedEngine::new(batch_engine(8), vec![(1, Some(1))]);
    let mut config =
        VerifyDraftsServeConfig::honest(TEST_PROFILE.to_string(), server_identity.clone());
    config.engine = batch_engine(8);
    // Roster-style pinning to a THIRD key: the QUIC-authenticated client
    // peer can never satisfy peer_id_for(pinned).
    config.pinned_coordinator_key = Some(stranger.verifying_key());

    let transport = Libp2pTransport::new(&server_identity).expect("server transport");
    let mut listener = transport
        .listen("127.0.0.1:0")
        .await
        .expect("loopback quic");
    let addr = listener.bound_addr().to_string();
    let server = tokio::spawn(async move {
        let wire = accept_quic(&mut listener, ACCEPT_DEADLINE)
            .await
            .expect("quic accept");
        serve_verifydrafts_session(wire, config, engine, &telemetry).await
    });

    let wire = dial_quic(
        &addr,
        &client_identity,
        &server_identity.verifying_key(),
        ACCEPT_DEADLINE,
    )
    .await
    .expect("quic dial");
    let tel = Telemetry::memory().0;
    let mut client = VerifyDraftsClient::negotiate(
        wire,
        client_identity,
        VerifyDraftsClientConfig::new(TEST_PROFILE.to_string(), server_identity.verifying_key()),
        &tel,
    )
    .await
    .expect("negotiation itself is peer-agnostic");

    // The client's request is VALIDLY signed by its own key — but that key
    // is not the pinned coordinator: fail-closed bad_frame, zero engine
    // work (the mock script is never consumed).
    match client
        .round(&[41, 42, 43], &tel)
        .await
        .expect_err("fail closed")
    {
        RoundFailure::Rejected { code, .. } => {
            assert_eq!(
                code,
                modelswarm_session::negotiation::FrameRejectReason::BadFrame
            );
        }
        other => panic!("expected bad_frame, got {other:?}"),
    }
    drop(client.into_wire());
    let report = tokio::time::timeout(ACCEPT_DEADLINE, server)
        .await
        .expect("server settles")
        .expect("server task ok");
    assert!(report.accepted);
    assert_eq!(report.rounds_handled, 0, "no round admitted");
    assert_eq!(report.rounds_committed, 0);
    assert_eq!(report.committed_output_tokens, 0);
    assert_eq!(report.ended_by, ServeEndReason::ClientClosed);
}

/// The QUIC accept loop (`serve_verifydrafts_quic` — the venue the msp-v1
/// bridge demuxes to): it serves a real negotiated session end-to-end, and
/// honors the bridge's shutdown lifecycle (stop when the watch sender
/// drops, exactly like `serve_sessions`).
#[tokio::test]
async fn serve_verifydrafts_quic_serves_and_stops() {
    let server_identity = InstallationIdentity::from_bytes(&[0xD1; 32]);
    let client_identity = InstallationIdentity::from_bytes(&[0xD2; 32]);
    let (serve_tel, serve_sink) = Telemetry::memory();
    let telemetry = Arc::new(serve_tel);

    let engine = ScriptedEngine::new(batch_engine(8), vec![(2, Some(901)), (2, Some(902))]);
    let mut config =
        VerifyDraftsServeConfig::honest(TEST_PROFILE.to_string(), server_identity.clone());
    config.engine = batch_engine(8);
    config.session_idle = Duration::from_secs(60);

    let transport = Libp2pTransport::new(&server_identity).expect("server transport");
    let listener = transport
        .listen("127.0.0.1:0")
        .await
        .expect("loopback quic");
    let addr = listener.bound_addr().to_string();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let serve_telemetry = Arc::clone(&telemetry);
    let serving = tokio::spawn(serve_verifydrafts_quic(
        listener,
        config,
        engine,
        serve_telemetry,
        shutdown_rx,
    ));

    let wire = dial_quic(
        &addr,
        &client_identity,
        &server_identity.verifying_key(),
        ACCEPT_DEADLINE,
    )
    .await
    .expect("quic dial into the serve loop");
    let tel = Telemetry::memory().0;
    let mut client = VerifyDraftsClient::negotiate(
        wire,
        client_identity,
        VerifyDraftsClientConfig::new(TEST_PROFILE.to_string(), server_identity.verifying_key()),
        &tel,
    )
    .await
    .expect("offer accepted through the serve loop");

    // One engaged round through the venue: the commit advances the chain.
    let r1 = client
        .round(&[71, 72], &tel)
        .await
        .expect("round through serve_verifydrafts_quic");
    assert_eq!(r1.committed, vec![71, 72, 901]);
    assert_eq!(client.committed_stream(), vec![71, 72, 901]);

    // Bridge lifecycle: dropping every watch sender stops the loop.
    drop(client.into_wire());
    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("serve loop exits when the shutdown sender drops")
        .expect("serve loop task ok");

    // The venue telemetered the session honestly (labels only).
    let events = serve_sink.snapshot().join("\n");
    assert!(
        events.contains("verifydrafts.session_ended"),
        "the serve loop must report the session end: {events}"
    );
    assert!(
        events.contains("\"reason\":\"client_closed\"")
            || events.contains("\"reason\": \"client_closed\""),
        "client close must be the reported reason: {events}"
    );
}
