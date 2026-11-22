//! REAL-engine end-to-end for the ADR-032 light-up tier (feature
//! `verifydrafts-capi`): the G4 bridge → the family serve loop → the REAL
//! QUIC transport → the requester client, against the PINNED staged
//! engine — `tests/capi_verify.rs`'s staged-environment pattern, composed
//! through this crate's seams instead of Runtime's test target.
//!
//! Chain under test (every hop real except the machine count):
//!
//! ```text
//! FamilyEngineSource::Capi (the injection seam)
//!   → CapiBatchVerifyEngine (the G4 trait bridge + the pinned PROMPT prefill)
//!   → serve_verifydrafts_quic (the §8 serve loop, TimingEngine measuring)
//!   → real libp2p QUIC (handshake-authenticated PeerIds)
//!   → VerifyDraftsClient (RC-3 admission, RC-2 EWMA/cross-check)
//! ```
//!
//! Exactness pins (vs the llama-server HTTP ground truth, both arms on
//! the same pinned binaries):
//! - the disclosure the client receives is the ENGINE's real geometry
//!   (CPU, `batch_verify: true`, the adapter's pinned window);
//! - a true greedy window fully accepts with the ground-truth BONUS;
//! - a corrupted window rejects at the exact divergence index with the
//!   ground-truth replacement;
//! - the committed stream equals the ground truth token-for-token;
//! - every round's `verify_pass_ms` passes the RC-2 cross-check.
//!
//! Performance numbers are printed environment-labeled, never asserted.
//!
//! Gate (owner-local; staged pinned engine sets at
//! `%LOCALAPPDATA%\ModelSwarm\engine{,-vulkan}` + a verified GGUF):
//!
//! ```text
//! MSP_LLAMA_SERVER=%LOCALAPPDATA%\ModelSwarm\engine\llama-server.exe ^
//! MSP_REAL_GGUF=<SmolLM2-135M-Instruct Q4_K_M path> ^
//! cargo test -p modelswarm-node --features verifydrafts-capi --test verifydrafts_capi_e2e -- --ignored --nocapture
//! ```

#![cfg(feature = "verifydrafts-capi")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use modelswarm_identity::InstallationIdentity;
use modelswarm_node::verifydrafts::engine_source::FamilyEngineSource;
use modelswarm_node::verifydrafts::{
    dial_quic, serve_verifydrafts_quic, VerifyDraftsClient, VerifyDraftsClientConfig,
    VerifyDraftsServeConfig,
};
use modelswarm_runtime::capi::verify::VerifyBackend;
use modelswarm_runtime::capi::{CapiConfig, LlamaCppCapi};
use modelswarm_runtime::llamacpp::{EngineIdentity, LlamaCppAdapter, LlamaCppConfig};
use modelswarm_runtime::{InferenceRuntime as _, SamplingParams};
use modelswarm_session::negotiation::Backend;
use modelswarm_session::verifydrafts::CrossCheckOutcome;
use modelswarm_session::verifydrafts::WINDOW_CAP as SESSION_WINDOW_CAP;
use modelswarm_telemetry::Telemetry;
use modelswarm_transport::libp2p_backend::Libp2pTransport;

const FILLER: &str = "The swarm serves one exact profile per cohort and every peer verifies the artifact digest before hosting. ";
const N_CTX: u32 = 4096;
/// A profile id that passes the msp1 form checks (serving.rs test pattern).
const TEST_PROFILE: &str = "msp1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ACCEPT_DEADLINE: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Staged-environment helpers (the runtime crate's capi test pattern)
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

// ---------------------------------------------------------------------------
// The end-to-end
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "set MSP_LLAMA_SERVER and MSP_REAL_GGUF (+ optional MSP_CAPI_ENGINE_DIR)"]
async fn real_capi_engine_serves_verifydrafts_over_quic() {
    let exe = PathBuf::from(std::env::var("MSP_LLAMA_SERVER").expect("MSP_LLAMA_SERVER"));
    let model = PathBuf::from(std::env::var("MSP_REAL_GGUF").expect("MSP_REAL_GGUF"));
    let engine_dir = std::env::var("MSP_CAPI_ENGINE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| exe.parent().expect("engine dir").to_path_buf());

    // ---- environment + pin verification ---------------------------------
    label("ENVIRONMENT");
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
    println!(
        "engine: pinned {} (canonical_build_hash {}), bundle sha256-verified; model {}",
        pins.tag,
        pins.canonical_build_hash,
        model.display(),
    );

    // ---- start the HTTP arm (ground truth) on the same binaries ----------
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
    let sampling = SamplingParams::default(); // greedy on both arms

    // Main prompt: long enough that greedy never reaches EOG in 24 tokens
    // (round 1 consumes truth[..9], round 2 truth[9..17]).
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

    // ---- the bridge through the injection seam ---------------------------
    label("ENGINE (seam -> bridge -> serve loop)");
    let backend = VerifyBackend::of_bundle(&engine_dir).expect("backend of the staged bundle");
    assert_eq!(backend, VerifyBackend::Cpu, "this test stages the CPU set");
    let adapter = Arc::new(
        LlamaCppCapi::new(CapiConfig::new(&engine_dir, &model).with_engine(identity))
            .expect("capi adapter constructs"),
    );
    let adapter_probe = Arc::clone(&adapter);
    let source = FamilyEngineSource::Capi {
        adapter,
        backend,
        profile_id: TEST_PROFILE.to_string(),
        prompt_tokens: ids_main.clone(),
    };
    // The seam yields the engine with the pinned prompt committed as the
    // PREFILLED root (the G3-family gap: the family wire never carries it).
    let engine = source.engine_for().await.expect("engine through the seam");
    let disclosure = engine.capabilities();
    assert_eq!(disclosure.backend, Backend::Cpu);
    assert!(disclosure.batch_verify);
    assert_eq!(disclosure.batch_window_max, SESSION_WINDOW_CAP);
    assert!(disclosure.is_valid_disclosure());
    println!(
        "OK: disclosure from real geometry — backend {}, batch_verify {}, window {}",
        disclosure.backend, disclosure.batch_verify, disclosure.batch_window_max,
    );

    // ---- the QUIC venue serving that engine ------------------------------
    let server_identity = InstallationIdentity::from_bytes(&[0x9E; 32]);
    let client_identity = InstallationIdentity::from_bytes(&[0x9F; 32]);
    let mut config =
        VerifyDraftsServeConfig::honest(TEST_PROFILE.to_string(), server_identity.clone());
    // The composed-daemon override discipline: the disclosure comes from
    // the engine's real geometry, never the hand-set field.
    config.engine = disclosure.clone();
    config.session_idle = Duration::from_secs(60);

    let transport = Libp2pTransport::new(&server_identity).expect("server transport");
    let listener = transport
        .listen("127.0.0.1:0")
        .await
        .expect("loopback quic");
    let addr = listener.bound_addr().to_string();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let telemetry = Arc::new(Telemetry::memory().0);
    let serving = tokio::spawn(serve_verifydrafts_quic(
        listener,
        config,
        Arc::clone(&engine),
        Arc::clone(&telemetry),
        shutdown_rx,
    ));

    // ---- the client over the REAL transport ------------------------------
    let wire = dial_quic(
        &addr,
        &client_identity,
        &server_identity.verifying_key(),
        ACCEPT_DEADLINE,
    )
    .await
    .expect("quic dial + peer id binding");
    let tel = Telemetry::memory().0;
    let mut client = VerifyDraftsClient::negotiate(
        wire,
        client_identity.clone(),
        VerifyDraftsClientConfig::new(TEST_PROFILE.to_string(), server_identity.verifying_key()),
        &tel,
    )
    .await
    .expect("offer accepted with the real engine's disclosure");
    assert_eq!(client.engine_disclosure(), &disclosure);

    // ---- round 1: the true greedy window fully accepts + the bonus ------
    label("ROUND 1 (true window: full accept + ground-truth bonus)");
    let r1 = client.round(&truth[..8], &tel).await.expect("round 1");
    assert_eq!(r1.accepted_prefix_len, 8, "full acceptance vs HTTP truth");
    assert_eq!(r1.divergence_point, None);
    assert_eq!(r1.correction, Some(truth[8]), "bonus = ground truth");
    assert_eq!(r1.cross_check, CrossCheckOutcome::Ok);
    println!(
        "OK: (8, Some(bonus)) vs HTTP truth; verify_pass_ms {} (engine-measured), round wall {} ms",
        r1.verify_pass_ms, r1.observed_wall_ms,
    );

    // ---- round 2: corruption at window index 4 rejects there ------------
    label("ROUND 2 (corruption at index 4: exact divergence + replacement)");
    let mut window2: Vec<u32> = truth[9..17].to_vec();
    let wrong = (truth[13] + 1) % adapter_probe.vocab_size();
    assert_ne!(wrong, truth[13]);
    window2[4] = wrong;
    let r2 = client.round(&window2, &tel).await.expect("round 2");
    assert_eq!(r2.accepted_prefix_len, 4, "rejection lands at index 4");
    assert_eq!(r2.divergence_point, Some(4));
    assert_eq!(r2.correction, Some(truth[13]), "replacement = ground truth");
    assert_eq!(r2.cross_check, CrossCheckOutcome::Ok);
    println!(
        "OK: rejected at index 4, replaced with the ground-truth token; verify_pass_ms {}, round wall {} ms",
        r2.verify_pass_ms, r2.observed_wall_ms,
    );

    // ---- the committed stream is the ground truth token-for-token -------
    let expected: Vec<u32> = [truth[..9].to_vec(), truth[9..14].to_vec()].concat();
    assert_eq!(
        client.committed_stream(),
        expected,
        "committed = window-prefixes ++ corrections, token-for-token vs HTTP"
    );
    // RC-2: the requester-measured EWMA fed on the real engine's rounds.
    assert!(client
        .timings()
        .ewma_ms(&server_identity.peer_id())
        .is_some());
    println!(
        "OK: committed stream {} tokens == ground truth; EWMA fed",
        expected.len(),
    );

    // ---- teardown ---------------------------------------------------------
    drop(client.into_wire());
    drop(shutdown_tx);
    tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("serve loop exits when the shutdown sender drops")
        .expect("serve loop task ok");
    drop(engine);
    drop(adapter_probe);
    let mut server = server;
    server.0.kill().expect("kill llama-server");
    let _ = server.0.wait();
    println!("\nreal-engine end-to-end passed; server killed");
}
