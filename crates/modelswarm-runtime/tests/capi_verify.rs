//! The REAL-trait engine test: `CapiVerifyEngine` (the production
//! batched-verify engine over the productionized C-API adapter, ADR-032
//! §1/§4) asserted THROUGH the architect's `BatchVerifyEngine` trait from
//! `modelswarm-session`.
//!
//! Why the trait impl lives HERE (the recorded trait gap): the trait is
//! defined in `modelswarm-session`, which already depends on
//! `modelswarm-runtime` for `RuntimeError`/`SamplingParams` — a lib-level
//! impl in the runtime crate would be a cyclic package dependency, which
//! Cargo rejects. A DEV-dependency cycle is legal, so this test file
//! implements the REAL trait for [`CapiVerifyEngineAsTrait`] (a newtype of
//! the engine) — the compile proof that the trait binds, and the runtime
//! proof that the engine is exact under it. `capi::verify` ships a clearly
//! labeled minimal local MIRROR of the trait as the lib-level stopgap; this
//! file is the authoritative shape check against the architect's contract.
//!
//! Gate (owner-local; staged pinned engine sets at
//! `%LOCALAPPDATA%\ModelSwarm\engine{,-vulkan}` + a verified GGUF):
//!
//! ```text
//! MSP_LLAMA_SERVER=%LOCALAPPDATA%\ModelSwarm\engine\llama-server.exe \
//! MSP_REAL_GGUF=<SmolLM2-135M-Instruct Q4_K_M path> \
//! cargo test -p modelswarm-runtime --features capi-adapter --test capi_verify -- --ignored --nocapture
//! ```
//!
//! Pins (all asserted, through the trait call unless noted):
//! - `capabilities()` from the adapter's REAL geometry (backend from the
//!   configured bundle, `batch_window_max` = the load-time warmup pin,
//!   clamped by ADR-032's WINDOW_CAP — cross-checked against the session
//!   crate's constant);
//! - full-window acceptance yields the bonus token, and the commit covers
//!   `accepted ++ [correction]`;
//! - mid-window rejection yields `(k, replacement)` and the SUBSEQUENT
//!   rounds stay token-for-token on the HTTP ground-truth continuation
//!   (continuation parity after KV rollback);
//! - EOG: full-acceptance bonus == EOG and rejection-replacement == EOG
//!   both yield `correction == None` with a prefix-only commit, and the
//!   engine refuses post-EOG windows fail-closed;
//! - a window over the disclosed cap is `413 payload_too_large` BEFORE any
//!   engine work (decode-call count and committed prefix unchanged);
//! - the adapter's KV token cap surfaces as the honest
//!   `429 kv_budget_exceeded` error (no panic, committed prefix unchanged);
//! - I4: ONE engine decode call per warm verify window.
//!
//! Performance numbers are printed environment-labeled, never asserted.
#![cfg(feature = "capi-adapter")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sha2::{Digest as _, Sha256};

use modelswarm_runtime::capi::verify::{VerifyBackend, VerifyEngineCaps};
use modelswarm_runtime::capi::{CapiConfig, CapiVerifyEngine, LlamaCppCapi};
use modelswarm_runtime::llamacpp::{EngineIdentity, LlamaCppAdapter, LlamaCppConfig};
use modelswarm_runtime::{InferenceRuntime, RuntimeError, SamplingParams};
use modelswarm_session::negotiation::{Backend as SessionBackend, EngineDisclosure};
use modelswarm_session::verifydrafts::{BatchVerifyEngine, WINDOW_CAP as SESSION_WINDOW_CAP};

const FILLER: &str = "The swarm serves one exact profile per cohort and every peer verifies the artifact digest before hosting. ";
const N_CTX: u32 = 4096;
/// SmolLM2-135M-Instruct chat form: a terse instruction whose greedy answer
/// terminates (the assistant emits its reply then the EOG token).
const EOS_PROMPT: &str =
    "<|im_start|>user\nReply with exactly one word and nothing else: hi<|im_end|>\n<|im_start|>assistant\n";

// ---------------------------------------------------------------------------
// The REAL-trait binding (compile proof + the serve-loop reference pattern)
// ---------------------------------------------------------------------------

/// Newtype implementing the architect's `BatchVerifyEngine` for the
/// production engine (see the module docs for why this lives in a test
/// target). The serve loop at light-up hosts exactly this adapter impl in
/// the node crate, which depends on both crates legally.
struct CapiVerifyEngineAsTrait(Arc<CapiVerifyEngine>);

/// Maps the runtime engine's real caps onto the session crate's
/// `EngineDisclosure` (ADR-032 §3 RC-8) — the serve-loop reference mapping.
fn to_disclosure(caps: VerifyEngineCaps) -> EngineDisclosure {
    EngineDisclosure {
        backend: match caps.backend {
            VerifyBackend::Cpu => SessionBackend::Cpu,
            VerifyBackend::Vulkan => SessionBackend::Vulkan,
        },
        batch_verify: caps.batch_verify,
        batch_window_max: caps.batch_window_max,
    }
}

#[async_trait]
impl BatchVerifyEngine for CapiVerifyEngineAsTrait {
    async fn verify_window(
        &self,
        window: &[u32],
        params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), RuntimeError> {
        self.0.verify_window(window, params).await
    }

    fn capabilities(&self) -> EngineDisclosure {
        to_disclosure(self.0.capabilities())
    }
}

#[test]
fn disclosure_mapping_covers_the_session_shape() {
    // Pure mapping pin (no engine needed): every runtime backend maps onto
    // the session vocabulary and the disclosure stays schema-valid.
    for backend in [VerifyBackend::Cpu, VerifyBackend::Vulkan] {
        let caps = VerifyEngineCaps {
            backend,
            batch_verify: true,
            batch_window_max: SESSION_WINDOW_CAP,
        };
        let disclosure = to_disclosure(caps);
        assert_eq!(
            disclosure.backend.as_str(),
            caps.backend.as_str(),
            "wire labels must agree"
        );
        assert!(disclosure.batch_verify);
        assert_eq!(disclosure.batch_window_max, SESSION_WINDOW_CAP);
        assert!(disclosure.is_valid_disclosure());
    }
}

// ---------------------------------------------------------------------------
// Staged-environment helpers (the established capi test pattern)
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

/// Per-handle engine decode-call count (the I4 assertion input).
async fn decode_calls(adapter: &LlamaCppCapi, handle_id: u64) -> u64 {
    adapter
        .kv_usage()
        .await
        .expect("kv_usage")
        .handles
        .into_iter()
        .find(|h| h.handle_id == handle_id)
        .unwrap_or_else(|| panic!("kv_usage lists handle {handle_id}"))
        .decode_calls
}

// ---------------------------------------------------------------------------
// The real-engine test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "set MSP_LLAMA_SERVER and MSP_REAL_GGUF (+ optional MSP_CAPI_ENGINE_DIR)"]
async fn capi_verify_engine_exact_through_the_session_trait() {
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

    // ---- start both runtimes on the same binaries -----------------------
    let bearer = "verify-engine-secret";
    let port = free_port();
    let base_url = format!("http://127.0.0.1:{port}");
    let server = ServerGuard(spawn_server(&exe, &model, port, bearer));
    wait_healthy(&base_url, bearer, Duration::from_secs(120)).await;

    let identity = EngineIdentity {
        version: pins.tag.clone(),
        build_hash: pins.canonical_build_hash.clone(),
    };
    let adapter = Arc::new(
        LlamaCppCapi::new(CapiConfig::new(&engine_dir, &model).with_engine(identity.clone()))
            .expect("capi adapter constructs"),
    );
    let eos = adapter
        .eos_id()
        .expect("the pinned vocab reports an EOS id");
    let vocab = {
        let metadata = modelswarm_types::read_metadata(&model).expect("gguf metadata");
        Arc::new(modelswarm_types::token_vocab(&metadata).expect("gguf tokenizer vocab"))
    };
    assert_eq!(vocab.eos_id, adapter.eos_id());

    // The engine under the REAL trait.
    let backend = VerifyBackend::of_bundle(&engine_dir).expect("backend of the staged bundle");
    assert_eq!(backend, VerifyBackend::Cpu, "this test stages the CPU set");
    let engine = Arc::new(
        CapiVerifyEngine::new(adapter.clone(), backend, "msp1:verify-main")
            .await
            .expect("engine loads"),
    );
    let engine_as_trait = CapiVerifyEngineAsTrait(Arc::clone(&engine));

    // ---- capabilities: the adapter's real geometry (RC-8) ----------------
    label("CAPABILITIES (through the trait; RC-8)");
    let disclosure = engine_as_trait.capabilities();
    let caps = engine.capabilities();
    assert_eq!(disclosure.backend, SessionBackend::Cpu);
    assert!(disclosure.batch_verify, "this engine batch-verifies");
    assert_eq!(disclosure.batch_window_max, adapter.verify_window_max());
    assert_eq!(disclosure.batch_window_max, SESSION_WINDOW_CAP);
    assert!(disclosure.is_valid_disclosure());
    assert_eq!(caps.batch_window_max, SESSION_WINDOW_CAP);
    assert_eq!(caps.backend, VerifyBackend::Cpu);
    assert!(caps.batch_verify);
    println!(
        "OK: backend {}, batch_verify {}, batch_window_max {} \
         (adapter verify geometry {}, ADR-032 WINDOW_CAP {SESSION_WINDOW_CAP})",
        disclosure.backend,
        disclosure.batch_verify,
        disclosure.batch_window_max,
        adapter.verify_window_max(),
    );

    // ---- prompts + HTTP ground truth -------------------------------------
    let http = LlamaCppAdapter::new(LlamaCppConfig {
        base_url: base_url.clone(),
        bearer_token: bearer.to_string(),
        request_timeout: Duration::from_secs(120),
        engine: Some(identity),
        vocab: Some(Arc::clone(&vocab)),
        no_prompt_cache: false,
    })
    .expect("http adapter constructs");
    let http_handle = http.load("msp1:verify-http").await.expect("http load");
    let sampling = SamplingParams::default(); // greedy on both adapters

    // Main prompt: long enough that greedy never reaches EOG in 32 tokens.
    let mut main_prompt = String::new();
    while http.tokenize(&main_prompt).await.unwrap().len() < 64 {
        main_prompt.push_str(FILLER);
    }
    let ids_main = http.tokenize(&main_prompt).await.unwrap();
    let truth: Vec<u32> = {
        let mut t = Vec::new();
        let mut p = ids_main.clone();
        for _ in 0..32 {
            let token = http.decode_step(&http_handle, &p, &sampling).await.unwrap();
            assert_ne!(
                Some(token),
                vocab.eos_id,
                "main prompt must not EOG in 32 tokens"
            );
            t.push(token);
            p.push(token);
        }
        t
    };

    // EOS prompt ground truth: a stream that stops BEFORE max_tokens
    // stopped at EOG (the server never emits the EOS token itself), so the
    // pre-EOG tokens AND the EOG position both come from the HTTP arm.
    let ids_eos = http.tokenize(EOS_PROMPT).await.unwrap();
    let pre_eos: Vec<u32> = http
        .decode_stream(
            &http_handle,
            &ids_eos,
            &sampling,
            64,
            Duration::from_secs(60),
        )
        .await
        .expect("eos ground-truth stream");
    let eos_pos = pre_eos.len();
    assert!(
        eos_pos >= 1,
        "the EOS prompt must produce at least one pre-EOG token"
    );
    assert!(
        eos_pos < disclosure.batch_window_max as usize,
        "the EOS prompt must terminate within 1..={} pre-EOG tokens for both EOG \
         sub-cases (got {eos_pos}); choose a different instruction",
        disclosure.batch_window_max
    );
    println!(
        "ground truth: main prompt {} tok + 32 greedy tokens; eos prompt {} tok, \
         EOG at position {eos_pos} (server-stopped stream)",
        ids_main.len(),
        ids_eos.len(),
    );

    // ---- 1. full-window accept + bonus + I4 (one engine pass) ------------
    label("FULL ACCEPT + BONUS + I4 (through the trait)");
    engine.prefill(&ids_main).await.expect("prefill");
    let window1: Vec<u32> = truth[..8].to_vec();
    let handle_id = engine.handle_id().await;
    let calls_before = decode_calls(&adapter, handle_id).await;
    let (accepted, correction) = engine_as_trait
        .verify_window(&window1, &sampling)
        .await
        .expect("verify window 1");
    let calls_after = decode_calls(&adapter, handle_id).await;
    assert_eq!(accepted, 8, "full acceptance of the true greedy window");
    assert_eq!(correction, Some(truth[8]), "bonus = ground truth");
    assert_eq!(
        calls_after - calls_before,
        1,
        "a verify_window through the trait must be exactly ONE engine decode call (ADR-032 I4)"
    );
    let mut expected_committed = ids_main.clone();
    expected_committed.extend_from_slice(&truth[..9]);
    assert_eq!(engine.committed_prefix().await, expected_committed);
    println!(
        "OK: (8, Some(bonus)) vs HTTP truth; 1 engine decode call ({calls_before} -> {calls_after}); \
         committed = prompt + truth[..9]"
    );

    // ---- 2. mid-window reject + continuation parity ----------------------
    label("MID-WINDOW REJECT + CONTINUATION PARITY (through the trait)");
    // Corrupt absolute position 13 (= window2 index 4): positions 9..13 are
    // the true greedy tokens (accepted), index 4 is wrong (rejected).
    let mut window2: Vec<u32> = truth[9..17].to_vec();
    let wrong = (truth[13] + 1) % adapter.vocab_size();
    assert_ne!(wrong, truth[13]);
    window2[4] = wrong;
    let (accepted, correction) = engine_as_trait
        .verify_window(&window2, &sampling)
        .await
        .expect("verify window 2");
    assert_eq!(accepted, 4, "rejection lands at window index 4");
    assert_eq!(correction, Some(truth[13]), "replacement = ground truth");
    // The next round continues on the corrected line: full acceptance and a
    // bonus on the true continuation — KV-rollback parity through the trait.
    let window3: Vec<u32> = truth[14..22].to_vec();
    let (accepted, correction) = engine_as_trait
        .verify_window(&window3, &sampling)
        .await
        .expect("verify window 3");
    assert_eq!(
        accepted, 8,
        "post-reject round fully accepts the true window"
    );
    assert_eq!(correction, Some(truth[22]), "bonus = ground truth");
    let mut expected_committed = ids_main.clone();
    expected_committed.extend_from_slice(&truth[..23]);
    assert_eq!(
        engine.committed_prefix().await,
        expected_committed,
        "the committed stream after reject + continuation must equal the HTTP ground truth"
    );
    println!("OK: rejected at index 4; rounds 2-3 committed prompt + truth[..23] token-for-token");

    // ---- 3. over-window-cap refusal BEFORE engine work -------------------
    label("WINDOW CAP (payload_too_large before any engine work, through the trait)");
    let committed_before = engine.committed_prefix().await;
    let oversized: Vec<u32> = vec![0; disclosure.batch_window_max as usize + 2];
    let calls_before = decode_calls(&adapter, handle_id).await;
    match engine_as_trait.verify_window(&oversized, &sampling).await {
        Err(RuntimeError::Api { status, code, .. }) => {
            assert_eq!(status, 413);
            assert_eq!(code, "payload_too_large");
        }
        other => panic!("oversized window must fail closed, got {other:?}"),
    }
    assert_eq!(
        decode_calls(&adapter, handle_id).await,
        calls_before,
        "the window-cap reject must do zero engine work"
    );
    assert_eq!(
        engine.committed_prefix().await,
        committed_before,
        "the refused window must not move the committed prefix"
    );
    println!(
        "OK: window {} + 2 -> payload_too_large, 0 engine calls, prefix unchanged",
        disclosure.batch_window_max
    );

    // ---- 4. EOG: bonus-EOG and replacement-EOG, prefix-only commit -------
    label("EOG (correction None, prefix-only commit; both engine paths, through the trait)");
    let garbage = (eos + 1) % adapter.vocab_size();
    assert_ne!(garbage, eos);

    // (a) Full acceptance whose BONUS is the EOG token.
    let engine_a = CapiVerifyEngine::new(adapter.clone(), backend, "msp1:verify-eos-a")
        .await
        .expect("eos engine a loads");
    let engine_a = CapiVerifyEngineAsTrait(Arc::new(engine_a));
    engine_a.0.prefill(&ids_eos).await.expect("prefill eos a");
    let (accepted, correction) = engine_a
        .verify_window(&pre_eos, &sampling)
        .await
        .expect("eos verify a");
    assert_eq!(
        accepted as usize, eos_pos,
        "the whole pre-EOG window is accepted (bonus-EOG path)"
    );
    assert_eq!(
        correction, None,
        "the EOG bonus surfaces as correction None"
    );
    let mut expected_eos_committed = ids_eos.clone();
    expected_eos_committed.extend_from_slice(&pre_eos);
    assert_eq!(
        engine_a.0.committed_prefix().await,
        expected_eos_committed,
        "prefix-only commit at EOG (no correction token appended)"
    );
    // Post-EOG the session is over: further windows refuse fail-closed.
    match engine_a.verify_window(&pre_eos[..1], &sampling).await {
        Err(RuntimeError::MalformedResponse(msg)) => {
            assert!(msg.contains("end-of-generation"), "got: {msg}");
        }
        other => panic!("post-EOG verify must refuse, got {other:?}"),
    }
    println!("OK: bonus-EOG -> ({eos_pos}, None); prefix-only commit; post-EOG refuse");

    // (b) Rejection whose REPLACEMENT is the EOG token: the true greedy
    // window extended with one garbage token — the target's own choice at
    // eos_pos is EOG, so the draft rejects there and EOG surfaces as the
    // (null) correction.
    let engine_b = CapiVerifyEngine::new(adapter.clone(), backend, "msp1:verify-eos-b")
        .await
        .expect("eos engine b loads");
    let engine_b = CapiVerifyEngineAsTrait(Arc::new(engine_b));
    engine_b.0.prefill(&ids_eos).await.expect("prefill eos b");
    let mut window_b = pre_eos.clone();
    window_b.push(garbage);
    let (accepted, correction) = engine_b
        .verify_window(&window_b, &sampling)
        .await
        .expect("eos verify b");
    assert_eq!(
        accepted as usize, eos_pos,
        "positions before EOG accept; the garbage token rejects (replacement-EOG path)"
    );
    assert_eq!(
        correction, None,
        "the EOG replacement surfaces as correction None"
    );
    assert_eq!(
        engine_b.0.committed_prefix().await,
        expected_eos_committed,
        "same prefix-only commit as the bonus path"
    );
    match engine_b.verify_window(&pre_eos[..1], &sampling).await {
        Err(RuntimeError::MalformedResponse(msg)) => {
            assert!(msg.contains("end-of-generation"), "got: {msg}");
        }
        other => panic!("post-EOG verify must refuse, got {other:?}"),
    }
    println!("OK: replacement-EOG -> ({eos_pos}, None); prefix-only commit; post-EOG refuse");

    // ---- 5. KV token cap: honest refusal, committed prefix untouched -----
    label("KV TOKEN CAP (honest kv_budget_exceeded through the trait)");
    {
        let cap = ids_main.len() as u64;
        let capped_adapter = Arc::new(
            LlamaCppCapi::new(
                CapiConfig::new(&engine_dir, &model)
                    .with_engine(EngineIdentity {
                        version: pins.tag.clone(),
                        build_hash: pins.canonical_build_hash.clone(),
                    })
                    .with_kv_token_cap(cap),
            )
            .expect("second adapter (same bundle) constructs"),
        );
        let capped_engine =
            CapiVerifyEngine::new(capped_adapter.clone(), backend, "msp1:verify-capped")
                .await
                .expect("capped engine loads");
        let capped_engine = CapiVerifyEngineAsTrait(Arc::new(capped_engine));
        capped_engine
            .0
            .prefill(&ids_main)
            .await
            .expect("capped prefill");
        // Round 1 passes (sync target = prefix-1 <= cap) and advances the
        // committed prefix past the cap; round 2's sync refuses BEFORE any
        // engine work with the honest error — a session cannot accumulate
        // unbounded KV.
        let w1: Vec<u32> = truth[..8].to_vec();
        let (accepted, correction) = capped_engine
            .verify_window(&w1, &sampling)
            .await
            .expect("round 1 under the cap verifies");
        assert_eq!(accepted, 8);
        assert_eq!(correction, Some(truth[8]));
        let committed_before = capped_engine.0.committed_prefix().await;
        let capped_handle = capped_engine.0.handle_id().await;
        let calls_before = decode_calls(&capped_adapter, capped_handle).await;
        let w2: Vec<u32> = truth[9..17].to_vec();
        match capped_engine.verify_window(&w2, &sampling).await {
            Err(RuntimeError::Api { status, code, .. }) => {
                assert_eq!(status, 429);
                assert_eq!(code, "kv_budget_exceeded");
            }
            other => panic!("over-KV-cap verify must fail honestly, got {other:?}"),
        }
        assert_eq!(
            decode_calls(&capped_adapter, capped_handle).await,
            calls_before,
            "the KV-cap reject must do zero engine work"
        );
        assert_eq!(
            capped_engine.0.committed_prefix().await,
            committed_before,
            "the refused verify must leave the committed prefix untouched"
        );
        println!(
            "OK: cap {cap}; round 1 verified, round 2 refused kv_budget_exceeded (0 engine calls, prefix unchanged)"
        );
    }

    drop(engine_a);
    drop(engine_b);
    drop(engine);
    drop(adapter);
    let mut server = server;
    server.0.kill().expect("kill llama-server");
    let _ = server.0.wait();
    println!("\nall trait-level engine pins passed; server killed");
}
