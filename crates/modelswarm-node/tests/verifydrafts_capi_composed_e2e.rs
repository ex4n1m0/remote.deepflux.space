//! The COMPOSED-daemon real-engine end-to-end (ADR-032 §7 disposition
//! items i+ii; feature `verifydrafts-capi`, run owner-local): the same
//! pinned staged engine and the same exactness pins as
//! `verifydrafts_capi_e2e.rs`, but through `serve_sessions_composed` —
//! ONE listener, BOTH vocabularies — with the PRODUCTION lease source
//! (`RosterFamilyLeases`, RC-L1) fed by PRESENTED leases (ADR-032 §2
//! admission order, the 2026-10-12 activation): the roster stays EMPTY —
//! nothing feeds it, exactly the shipped-desktop configuration — and the
//! coordinator's hub-signed lease, PRESENTED in the session-open carrier,
//! is the whole claim (a valid presented lease opens the session on the
//! real engine; a WRONG-PROFILE presented lease refuses before any
//! engine work) while the msp-v1 arm answers through its own executor on
//! the same listener. This is the path two fresh desktops with earned
//! leases take to open a family session.
//!
//! Performance numbers are printed environment-labeled, never asserted.
//!
//! Gate (owner-local; staged pinned engine sets at
//! `%LOCALAPPDATA%\ModelSwarm\engine{,-vulkan}` + a verified GGUF;
//! `libp2p-backend` EXPLICIT — the composed daemon needs both features,
//! never implicit unification):
//!
//! ```text
//! MSP_LLAMA_SERVER=%LOCALAPPDATA%\ModelSwarm\engine\llama-server.exe ^
//! MSP_REAL_GGUF=<SmolLM2-135M-Instruct Q4_K_M path> ^
//! cargo test -p modelswarm-node --features verifydrafts-capi,libp2p-backend --test verifydrafts_capi_composed_e2e -- --ignored --nocapture
//! ```

#![cfg(feature = "verifydrafts-capi")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use modelswarm_gateway::{ExecutorError, InferenceExecutor, NormalizedRequest};
use modelswarm_identity::InstallationIdentity;
use modelswarm_node::verifydrafts::composed::{FamilyServing, RosterFamilyLeases};
use modelswarm_node::verifydrafts::engine_source::FamilyEngineSource;
use modelswarm_node::verifydrafts::{
    dial_quic, serve_sessions_composed, VerifyDraftsClient, VerifyDraftsClientConfig,
    VerifyDraftsServeConfig,
};
use modelswarm_runtime::capi::verify::VerifyBackend;
use modelswarm_runtime::capi::{CapiConfig, LlamaCppCapi};
use modelswarm_runtime::llamacpp::{EngineIdentity, LlamaCppAdapter, LlamaCppConfig};
use modelswarm_runtime::{InferenceRuntime as _, SamplingParams};
use modelswarm_session::verifydrafts::CrossCheckOutcome;
use modelswarm_telemetry::Telemetry;
use modelswarm_transport::libp2p_backend::Libp2pTransport;
use modelswarm_transport::message::WireMessage;

const FILLER: &str = "The swarm serves one exact profile per cohort and every peer verifies the artifact digest before hosting. ";
const N_CTX: u32 = 4096;
/// A profile id that passes the msp1 form checks (serving.rs test pattern).
const TEST_PROFILE: &str = "msp1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// A DIFFERENT well-formed profile (the RC-L1 wrong-profile arm).
const OTHER_PROFILE: &str = "msp1:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const ACCEPT_DEADLINE: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Staged-environment helpers (the plain E2E's pattern, verbatim)
// ---------------------------------------------------------------------------

fn sha256_of(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("read file for hashing");
    let digest = Sha256::digest(&bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn find_repo_root() -> PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    loop {
        if dir.join("runtime-pins.json").is_file() {
            return dir;
        }
        dir = dir.parent().expect("repo root reached").to_path_buf();
    }
}

struct Pins {
    tag: String,
    canonical_build_hash: String,
    files: serde_json::Map<String, serde_json::Value>,
}

fn load_pins() -> Pins {
    let root = find_repo_root();
    let raw = std::fs::read_to_string(root.join("runtime-pins.json")).expect("runtime-pins.json");
    let pins: serde_json::Value = serde_json::from_str(&raw).expect("pins parse");
    let platform = &pins["platforms"]["windows-x64"];
    Pins {
        tag: pins["tag"].as_str().expect("tag").to_string(),
        canonical_build_hash: pins["canonical_build_hash"]
            .as_str()
            .expect("canonical_build_hash")
            .to_string(),
        files: platform["files"].as_object().expect("files").clone(),
    }
}

fn verify_pinned(dir: &Path, files: &[&str], pins: &Pins) {
    for file in files {
        let expected = pins.files[*file]
            .as_str()
            .unwrap_or_else(|| panic!("runtime-pins.json has no sha256 entry for {file}"));
        let actual = sha256_of(&dir.join(file));
        assert_eq!(
            actual, expected,
            "sha256 mismatch for {file} — refusing to test an unpinned engine"
        );
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn spawn_server(exe: &Path, model: &Path, port: u16, bearer: &str) -> Child {
    let mut command = Command::new(exe);
    command
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "-m",
            &model.display().to_string(),
            "-c",
            &N_CTX.to_string(),
            "--no-webui",
            "--api-key",
            bearer,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    command.spawn().expect("spawn llama-server")
}

/// Kills the server on scope exit, panic paths included.
struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_healthy(base_url: &str, bearer: &str, timeout: Duration) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("client");
    let started = Instant::now();
    loop {
        assert!(started.elapsed() < timeout, "server never became healthy");
        let healthy = client
            .get(format!("{base_url}/health"))
            .bearer_auth(bearer)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if healthy {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn label(section: &str) {
    println!("\n=== {section} ===");
}

fn e2e_rfc3339(plus_secs: i64) -> String {
    time::OffsetDateTime::now_utc()
        .saturating_add(time::Duration::seconds(plus_secs))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

/// Issues a consume lease for (profile, peer) under `key` (the serving.rs
/// lease_helpers pattern; ONE hub key backs the whole composed daemon).
fn e2e_lease_wire(key: &ed25519_dalek::SigningKey, profile: &str, peer_id: &str) -> String {
    use modelswarm_eligibility::{CapacityClass, EligibilityLease};
    EligibilityLease::issue(
        peer_id,
        "e2e-installation",
        profile,
        e2e_rfc3339(-60),
        e2e_rfc3339(300),
        e2e_rfc3339(360),
        true,
        true,
        1,
        CapacityClass::GpuMid,
        1,
        "e2e-challenge",
        "e2e-nonce",
        1,
        key,
    )
    .to_wire()
}

/// A deterministic msp-v1 executor (the composed integration test's
/// FixedExecutor): "Hello swarm" — proves the msp-v1 vocabulary rides the
/// same listener while the family runs on the real engine.
struct ComposedFixedExecutor;

#[async_trait::async_trait]
impl InferenceExecutor for ComposedFixedExecutor {
    async fn execute(
        &self,
        request: NormalizedRequest,
    ) -> Result<modelswarm_gateway::ExecutorStream, ExecutorError> {
        use futures_util::stream;
        use modelswarm_gateway::{ExecutorEvent, FinishReason};
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
            ExecutorEvent::Completed {
                finish_reason: FinishReason::Stop,
            },
        ])))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "set MSP_LLAMA_SERVER and MSP_REAL_GGUF (+ optional MSP_CAPI_ENGINE_DIR)"]
async fn real_capi_engine_serves_verifydrafts_through_composed_daemon() {
    let started = Instant::now();
    let exe = PathBuf::from(std::env::var("MSP_LLAMA_SERVER").expect("MSP_LLAMA_SERVER"));
    let model = PathBuf::from(std::env::var("MSP_REAL_GGUF").expect("MSP_REAL_GGUF"));
    let engine_dir = std::env::var("MSP_CAPI_ENGINE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| exe.parent().expect("engine dir").to_path_buf());

    // ---- environment + pin verification (the plain E2E's staging) -------
    label("COMPOSED ENVIRONMENT");
    let pins = load_pins();
    verify_pinned(
        &engine_dir,
        &["llama-server.exe", "llama.dll", "ggml.dll", "ggml-base.dll"],
        &pins,
    );
    println!(
        "env: single-machine loopback, Windows x64, {} logical CPUs; NOT LAN, NOT a product claim",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0)
    );

    // ---- the HTTP ground-truth arm (same pinned binaries) ---------------
    let bearer = "verify-e2e-secret";
    let port = free_port();
    let base_url = format!("http://127.0.0.1:{port}");
    let server = ServerGuard(spawn_server(&exe, &model, port, bearer));
    wait_healthy(&base_url, bearer, Duration::from_secs(120)).await;

    let identity = EngineIdentity {
        version: pins.tag.clone(),
        build_hash: pins.canonical_build_hash.clone(),
    };
    let http = LlamaCppAdapter::new(LlamaCppConfig {
        base_url: base_url.clone(),
        bearer_token: bearer.to_string(),
        request_timeout: Duration::from_secs(120),
        engine: Some(identity.clone()),
        vocab: None,
        no_prompt_cache: false,
    })
    .expect("http adapter constructs");
    let http_handle = http.load("msp1:e2e-http").await.expect("http load");
    let sampling = SamplingParams::default();

    let mut main_prompt = String::new();
    while http.tokenize(&main_prompt).await.unwrap().len() < 64 {
        main_prompt.push_str(FILLER);
    }
    let ids_main = http.tokenize(&main_prompt).await.unwrap();
    let truth: Vec<u32> = {
        let mut t = Vec::new();
        let mut p = ids_main.clone();
        for _ in 0..24 {
            let token = http.decode_step(&http_handle, &p, &sampling).await.unwrap();
            t.push(token);
            p.push(token);
        }
        t
    };
    println!(
        "ground truth: main prompt {} tok + 24 greedy tokens (HTTP arm)",
        ids_main.len(),
    );

    // ---- the composed daemon: production lease source + real engine -----
    label("COMPOSED DAEMON (presented leases + Capi engine source)");
    let backend = VerifyBackend::of_bundle(&engine_dir).expect("backend of the staged bundle");
    assert_eq!(backend, VerifyBackend::Cpu, "this test stages the CPU set");
    let adapter = Arc::new(
        LlamaCppCapi::new(CapiConfig::new(&engine_dir, &model).with_engine(identity))
            .expect("capi adapter constructs"),
    );
    let adapter_probe = Arc::clone(&adapter);
    // The same constructor the DESKTOP drives through
    // `capi_family_source`; the source pins the session prompt as the
    // prefilled root (the G6 out-of-band file in production).
    let source = FamilyEngineSource::Capi {
        adapter,
        backend,
        profile_id: TEST_PROFILE.to_string(),
        prompt_tokens: ids_main.clone(),
    };
    let expected_disclosure = source.disclosure();
    println!(
        "engine source disclosure (real geometry): backend {}, batch_verify {}, window {}",
        expected_disclosure.backend,
        expected_disclosure.batch_verify,
        expected_disclosure.batch_window_max,
    );

    let server_identity = InstallationIdentity::from_bytes(&[0xAE; 32]);
    let coordinator = InstallationIdentity::from_bytes(&[0xAF; 32]);
    let wrong_profile_peer = InstallationIdentity::from_bytes(&[0xB0; 32]);
    let requester = InstallationIdentity::from_bytes(&[0xB1; 32]);

    // ONE test hub backs both vocabularies: the msp-v1 arm presents its
    // token on the wire per request; the family coordinators PRESENT
    // their leases in the session-open carrier — the PRODUCTION roster
    // stays EMPTY (nothing feeds it; the hub-signed presented token is
    // the whole claim, exactly the shipped-desktop configuration). The
    // family coordinator holds a valid lease for THIS profile; the second
    // peer a validly-signed lease for ANOTHER profile (must refuse).
    let hub = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let policy = modelswarm_node::serving::LeasePolicy::from_hex(&hex::encode(
        hub.verifying_key().to_bytes(),
    ))
    .unwrap();
    let roster = RosterFamilyLeases::new(policy.clone());
    assert!(
        roster.is_empty(),
        "presentation only — the roster is never fed"
    );
    let coordinator_lease = e2e_lease_wire(&hub, TEST_PROFILE, &coordinator.peer_id().to_string());
    let wrong_profile_lease = e2e_lease_wire(
        &hub,
        OTHER_PROFILE,
        &wrong_profile_peer.peer_id().to_string(),
    );

    let mut config =
        VerifyDraftsServeConfig::honest(TEST_PROFILE.to_string(), server_identity.clone());
    // The composed loop overrides the disclosure per session with the
    // engine's REAL geometry; session_idle shortened for teardown.
    config.session_idle = Duration::from_secs(60);

    let transport = Libp2pTransport::new(&server_identity).expect("server transport");
    let listener = transport
        .listen("127.0.0.1:0")
        .await
        .expect("loopback quic");
    let addr = listener.bound_addr().to_string();
    let expected_server_peer = transport.peer_id();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let telemetry = Arc::new(Telemetry::memory().0);
    let serving = tokio::spawn(serve_sessions_composed(
        modelswarm_node::serving::ServingInbox::new(
            listener,
            modelswarm_node::serving::RelaySlot::empty(),
        ),
        std::sync::Arc::new(modelswarm_identity::InstallationIdentity::from_bytes(
            &[0xA7; 32],
        )),
        Arc::new(ComposedFixedExecutor),
        TEST_PROFILE.to_string(),
        policy,
        FamilyServing {
            config,
            engine: Arc::new(source),
            lease: Arc::new(roster),
        },
        Arc::clone(&telemetry),
        shutdown_rx,
    ));

    // ---- RC-L1 live: the wrong-profile PRESENTED lease refuses BEFORE
    // the engine (session-open gate, empty roster) ------------------------
    label("RC-L1 (wrong-profile presented lease refuses)");
    let refused_wire = dial_quic(
        &addr,
        &wrong_profile_peer,
        &server_identity.verifying_key(),
        ACCEPT_DEADLINE,
    )
    .await
    .expect("dial itself is lease-agnostic");
    let tel = Telemetry::memory().0;
    let mut refused_config =
        VerifyDraftsClientConfig::new(TEST_PROFILE.to_string(), server_identity.verifying_key());
    refused_config.lease = Some(wrong_profile_lease);
    match VerifyDraftsClient::negotiate(refused_wire, wrong_profile_peer, refused_config, &tel)
        .await
    {
        Err(modelswarm_node::verifydrafts::ClientOpenError::Io(_)) => {}
        Ok(_) => panic!("a wrong-profile presented lease must never open a family session"),
        Err(other) => panic!("expected an honest transport failure, got {other}"),
    }
    println!("OK: refused with the honest session end (no accept frame)");

    // ---- msp-v1 through the SAME listener while the family runs ---------
    label("MSP-V1 ARM (same listener, own executor)");
    let requester_transport = Libp2pTransport::new(&requester).expect("requester transport");
    let mut msp_session = requester_transport
        .dial(&addr, &expected_server_peer, ACCEPT_DEADLINE)
        .await
        .expect("msp-v1 dial into the composed listener");
    msp_session
        .send(
            &WireMessage::InferenceRequest(modelswarm_transport::message::InferenceRequest {
                request_id: "req-1".into(),
                profile_id: TEST_PROFILE.into(),
                capability_token: e2e_lease_wire(
                    &hub,
                    TEST_PROFILE,
                    &requester.peer_id().to_string(),
                ),
                messages: vec![modelswarm_transport::message::ChatMessage {
                    role: "user".into(),
                    content: "hi".into(),
                }],
                sampling: modelswarm_transport::message::Sampling {
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
    for _ in 0..3 {
        match msp_session.recv(Duration::from_secs(10)).await.unwrap() {
            WireMessage::TokenDelta(d) => deltas.push_str(&d.delta),
            WireMessage::Completed(_) => {}
            other => panic!("unexpected msp-v1 frame: {other:?}"),
        }
    }
    assert_eq!(deltas, "Hello swarm");
    println!("OK: msp-v1 streamed through the composed listener");

    // ---- the family arm over the REAL engine ----------------------------
    label("FAMILY ARM (presented lease + real engine, empty roster)");
    let wire = dial_quic(
        &addr,
        &coordinator,
        &server_identity.verifying_key(),
        ACCEPT_DEADLINE,
    )
    .await
    .expect("family dial into the composed listener");
    let tel = Telemetry::memory().0;
    let mut family_client_config =
        VerifyDraftsClientConfig::new(TEST_PROFILE.to_string(), server_identity.verifying_key());
    family_client_config.lease = Some(coordinator_lease);
    let mut client =
        VerifyDraftsClient::negotiate(wire, coordinator.clone(), family_client_config, &tel)
            .await
            .expect("session opened through the composed demux on the PRESENTED lease");
    // The disclosure is the real engine's geometry (the composed loop's
    // per-session override), not the config's hand-set default.
    assert_eq!(client.engine_disclosure(), &expected_disclosure);
    assert!(client.engine_disclosure().batch_verify);
    println!(
        "OK: disclosure from real geometry — backend {}, window {}",
        client.engine_disclosure().backend,
        client.engine_disclosure().batch_window_max,
    );

    let r1 = client.round(&truth[..8], &tel).await.expect("round 1");
    assert_eq!(r1.accepted_prefix_len, 8, "full acceptance vs HTTP truth");
    assert_eq!(r1.correction, Some(truth[8]), "bonus = ground truth");
    assert_eq!(r1.cross_check, CrossCheckOutcome::Ok);
    println!(
        "OK: round 1 (8, bonus) vs HTTP truth; verify_pass_ms {}, round wall {} ms",
        r1.verify_pass_ms, r1.observed_wall_ms,
    );

    let mut window2: Vec<u32> = truth[9..17].to_vec();
    let wrong = (truth[13] + 1) % adapter_probe.vocab_size();
    assert_ne!(wrong, truth[13]);
    window2[4] = wrong;
    let r2 = client.round(&window2, &tel).await.expect("round 2");
    assert_eq!(r2.accepted_prefix_len, 4, "rejection lands at index 4");
    assert_eq!(r2.correction, Some(truth[13]), "replacement = ground truth");
    assert_eq!(r2.cross_check, CrossCheckOutcome::Ok);
    println!(
        "OK: round 2 rejected at index 4, ground-truth replacement; verify_pass_ms {}, round wall {} ms",
        r2.verify_pass_ms, r2.observed_wall_ms,
    );

    let expected: Vec<u32> = [truth[..9].to_vec(), truth[9..14].to_vec()].concat();
    assert_eq!(
        client.committed_stream(),
        expected,
        "committed = ground truth token-for-token"
    );
    println!(
        "OK: committed stream {} tokens == HTTP ground truth; total wall {} ms (staging incl. HTTP arm)",
        expected.len(),
        started.elapsed().as_millis(),
    );

    // ---- teardown ---------------------------------------------------------
    drop(client.into_wire());
    drop(msp_session);
    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("composed loop exits when the shutdown sender drops")
        .expect("composed loop task ok");
    drop(adapter_probe);
    let mut server = server;
    server.0.kill().expect("kill llama-server");
    let _ = server.0.wait();
    println!("\ncomposed-daemon real-engine end-to-end passed; server killed");
}
