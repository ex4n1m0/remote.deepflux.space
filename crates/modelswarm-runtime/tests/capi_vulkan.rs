//! ADR-031 §5.4: real IN-PROCESS test on the VULKAN engine bundle.
//!
//! The E0 determinism finding (CPU ≠ Vulkan, `docs/verification/
//! e0-determinism-2026-10-07.md`) makes this mandatory before any
//! cross-peer verify claim: exactness is pinned WITHIN the Vulkan backend
//! (the adapter vs a Vulkan `llama-server` ground truth, token-for-token),
//! never across backends. The CPU↔Vulkan relationship is printed for the
//! record, not asserted.
//!
//! Gate: `cargo test -p modelswarm-runtime --features capi-adapter
//! --test capi_vulkan -- --ignored --nocapture` with
//! `MSP_CAPI_VULKAN_DIR` (the hash-verified engine-vulkan bundle) and
//! `MSP_REAL_GGUF` set. This binary must ONLY touch the Vulkan bundle:
//! backend registration is process-global (ADR-031 §2, one bundle per
//! process) — do not point it at the CPU engine dir.
//!
//! Pins (all asserted): bundle sha256s against the runtime-pins.json
//! windows-x64 VULKAN variant; tokenize parity with the Vulkan server;
//! 16-token greedy stream parity vs the Vulkan HTTP ground truth;
//! verification outcomes == the same ground truth; reject-path rollback +
//! single-mode continuation token-for-token; one engine pass per warm
//! verify (ADR-032 I4); KV usage reported and bounded. Performance is
//! printed environment-labeled, never asserted.
#![cfg(feature = "capi-adapter")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use modelswarm_runtime::capi::{CapiConfig, LlamaCppCapi};
use modelswarm_runtime::llamacpp::{EngineIdentity, LlamaCppAdapter, LlamaCppConfig};
use modelswarm_runtime::{InferenceRuntime, RuntimeError, SamplingParams};

const N_CTX: u32 = 4096;

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

/// Verifies the Vulkan variant files this test loads against
/// `runtime-pins.json` `platforms.windows-x64.variants.vulkan.files`
/// (refuses an unpinned engine). Returns (tag, canonical_build_hash).
fn verify_pinned_vulkan_files(dir: &Path) -> (String, String) {
    let root = find_repo_root();
    let raw = std::fs::read_to_string(root.join("runtime-pins.json")).expect("runtime-pins.json");
    let pins: serde_json::Value = serde_json::from_str(&raw).expect("pins parse");
    let files = pins["platforms"]["windows-x64"]["variants"]["vulkan"]["files"]
        .as_object()
        .expect("windows-x64 vulkan variant files");
    for file in [
        "llama.dll",
        "ggml.dll",
        "ggml-base.dll",
        "ggml-vulkan.dll",
        "llama-server.exe",
    ] {
        let expected = files[file]
            .as_str()
            .unwrap_or_else(|| panic!("no vulkan pin for {file}"));
        assert_eq!(
            sha256_of(&dir.join(file)),
            expected,
            "sha256 mismatch for {file} — refusing to test an unpinned engine"
        );
    }
    (
        pins["tag"].as_str().expect("tag").to_string(),
        pins["canonical_build_hash"]
            .as_str()
            .expect("canonical_build_hash")
            .to_string(),
    )
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// Spawns the VULKAN llama-server with the node's argv discipline (ADR-002:
/// loopback, bearer, --no-webui; ADR-024: no -ngl pin — the engine
/// auto-fits GPU layers, CPU fallback is the engine's to report).
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
    command.spawn().expect("spawn vulkan llama-server")
}

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
        assert!(
            started.elapsed() < timeout,
            "vulkan server never became healthy"
        );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "set MSP_CAPI_VULKAN_DIR (engine-vulkan bundle) and MSP_REAL_GGUF; needs a Vulkan-capable GPU"]
async fn capi_vulkan_inprocess_exactness() {
    let engine_dir = PathBuf::from(
        std::env::var("MSP_CAPI_VULKAN_DIR").expect("MSP_CAPI_VULKAN_DIR (engine-vulkan bundle)"),
    );
    let model = PathBuf::from(std::env::var("MSP_REAL_GGUF").expect("MSP_REAL_GGUF"));

    let (tag, build_hash) = verify_pinned_vulkan_files(&engine_dir);
    println!("env: single-machine, Windows x64; pinned {tag} VULKAN variant (canonical_build_hash {build_hash}); NOT LAN, NOT a product claim");
    println!(
        "model: {} ({:.1} MiB), ctx {N_CTX}, greedy; E0 note: CPU != Vulkan is ALLOWED — exactness is pinned WITHIN the Vulkan backend only",
        model.display(),
        std::fs::metadata(&model).expect("model stat").len() as f64 / (1024.0 * 1024.0)
    );

    // Vulkan HTTP ground truth (same binaries, same backend).
    let bearer = "vulkan-internal-secret";
    let port = free_port();
    let base_url = format!("http://127.0.0.1:{port}");
    let server = ServerGuard(spawn_server(
        &engine_dir.join("llama-server.exe"),
        &model,
        port,
        bearer,
    ));
    wait_healthy(&base_url, bearer, Duration::from_secs(180)).await;
    let identity = EngineIdentity {
        version: tag.clone(),
        build_hash: build_hash.clone(),
    };
    let vocab = {
        let metadata = modelswarm_types::read_metadata(&model).expect("gguf metadata");
        std::sync::Arc::new(modelswarm_types::token_vocab(&metadata).expect("gguf tokenizer vocab"))
    };
    let http = LlamaCppAdapter::new(LlamaCppConfig {
        base_url: base_url.clone(),
        bearer_token: bearer.to_string(),
        request_timeout: Duration::from_secs(180),
        engine: Some(identity),
        vocab: Some(vocab),
        no_prompt_cache: false,
    })
    .expect("vulkan http adapter constructs");

    // In-process adapter on the SAME vulkan bundle (backend registration
    // picks up ggml-vulkan.dll via ggml_backend_load_all_from_path).
    let capi_started = Instant::now();
    let capi = LlamaCppCapi::new(CapiConfig::new(&engine_dir, &model).with_engine(
        EngineIdentity {
            version: tag,
            build_hash,
        },
    ))
    .expect("capi adapter constructs on the vulkan bundle");
    println!(
        "capi adapter: model + context in {:.0} ms (in-process, vulkan bundle)",
        capi_started.elapsed().as_secs_f64() * 1000.0
    );

    let http_handle = http.load("msp1:vulkan").await.expect("http load");
    let capi_handle = capi.load("msp1:vulkan").await.expect("capi load");

    let prompt =
        "Explain in one short paragraph why exact-profile verification matters in a swarm:";
    let ids = http.tokenize(prompt).await.unwrap();
    let capi_ids = capi.tokenize(prompt).await.unwrap();
    assert_eq!(capi_ids, ids, "tokenize parity on the vulkan bundle");
    println!("OK: tokenize parity ({} tokens)", ids.len());

    // Warm both engines once.
    let _ = http
        .decode_stream(
            &http_handle,
            &ids,
            &SamplingParams::default(),
            4,
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let _ = capi
        .decode_stream(
            &capi_handle,
            &ids,
            &SamplingParams::default(),
            4,
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    // 16-token greedy stream parity WITHIN the vulkan backend.
    let sampling = SamplingParams::default();
    let http_tokens = http
        .decode_stream(&http_handle, &ids, &sampling, 16, Duration::from_secs(120))
        .await
        .unwrap();
    let capi_started = Instant::now();
    let capi_tokens = capi
        .decode_stream(&capi_handle, &ids, &sampling, 16, Duration::from_secs(120))
        .await
        .unwrap();
    let capi_ms = capi_started.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(
        capi_tokens, http_tokens,
        "greedy decode must be token-exact WITHIN the vulkan backend"
    );
    println!(
        "OK: {} stream tokens identical to the vulkan HTTP ground truth (capi total {capi_ms:.0} ms; perf printed, never asserted)",
        capi_tokens.len()
    );

    // Verification outcomes == the vulkan ground truth (self-drafted window).
    let window = 8u32;
    let truth: Vec<u32> = {
        let mut t = Vec::new();
        let mut p = ids.clone();
        for _ in 0..2 * (window + 1) {
            let tok = http.decode_step(&http_handle, &p, &sampling).await.unwrap();
            t.push(tok);
            p.push(tok);
        }
        t
    };
    let draft = capi.propose(&capi_handle, &ids, window).await.unwrap();
    assert_eq!(
        draft.as_slice(),
        &truth[..window as usize],
        "greedy self-draft = vulkan ground truth"
    );
    let outcome = capi
        .verify_drafts(&capi_handle, &ids, &draft, &sampling)
        .await
        .unwrap();
    assert_eq!(
        outcome.accepted.as_slice(),
        &truth[..window as usize],
        "full acceptance on the agreeing draft"
    );
    assert_eq!(
        outcome.bonus,
        Some(truth[window as usize]),
        "bonus = vulkan ground truth"
    );
    println!("OK: verify outcome == vulkan HTTP ground truth (8/8 + bonus)");

    // Reject-path rollback + single-mode continuation, token-for-token.
    // Corrupt position 0 EXPLICITLY (a shift-by-one is prompt-dependent: a
    // continuation that begins with a repeated token would legitimately
    // accept — observed on the Vulkan backend with this very prompt).
    let mut corrupted = draft.clone();
    let wrong = (truth[0] + 1) % capi.vocab_size();
    assert_ne!(wrong, truth[0], "vocab must have a second token");
    corrupted[0] = wrong;
    let outcome = capi
        .verify_drafts(&capi_handle, &ids, &corrupted, &sampling)
        .await
        .unwrap();
    assert!(
        outcome.accepted.is_empty(),
        "explicitly-wrong first token rejects at 0"
    );
    assert_eq!(outcome.bonus, Some(truth[0]), "replacement = truth[0]");
    let mut p = ids.clone();
    p.push(truth[0]);
    let next = capi.decode_step(&capi_handle, &p, &sampling).await.unwrap();
    assert_eq!(next, truth[1], "post-rollback continuation on truth");
    println!("OK: reject-path rollback + continuation token-exact on vulkan");

    // One engine pass per warm verify (ADR-032 I4) + KV accounting.
    let _ = capi
        .verify_drafts(&capi_handle, &ids, &draft, &sampling)
        .await
        .unwrap();
    let before = capi.kv_usage().await.unwrap();
    let _ = capi
        .verify_drafts(&capi_handle, &ids, &draft, &sampling)
        .await
        .unwrap();
    let after = capi.kv_usage().await.unwrap();
    let (b, a) = (
        before
            .handles
            .iter()
            .find(|h| h.handle_id == capi_handle.handle_id())
            .unwrap(),
        after
            .handles
            .iter()
            .find(|h| h.handle_id == capi_handle.handle_id())
            .unwrap(),
    );
    assert_eq!(
        a.decode_calls - b.decode_calls,
        1,
        "warm verify = exactly one engine decode call on vulkan (ADR-032 I4)"
    );
    println!(
        "OK: one engine pass per warm verify; kv tokens {} / cap {}, estimate {} MiB, engine state {} MiB",
        a.kv_tokens,
        a.kv_token_cap,
        a.kv_bytes_estimate / (1024 * 1024),
        a.state_bytes / (1024 * 1024),
    );

    // Oversized window refused before engine work.
    let mut oversized = draft.clone();
    oversized.resize(capi.verify_window_max() as usize + 1, 0);
    match capi
        .verify_drafts(&capi_handle, &ids, &oversized, &sampling)
        .await
    {
        Err(RuntimeError::Api {
            status: 413, code, ..
        }) => {
            assert_eq!(code, "payload_too_large");
        }
        other => panic!("oversized window must fail closed, got {other:?}"),
    }

    drop(capi);
    let mut server = server;
    server.0.kill().expect("kill vulkan llama-server");
    let _ = server.0.wait();
    println!("\nvulkan in-process test complete; server killed");
}
