//! llama-server sidecar supervision (Phase H3; ADR-008 engine bundling,
//! ADR-021 accepted engine decision).
//!
//! The node owns the pinned, unmodified `llama-server.exe` lifecycle:
//!
//! - every bundled engine file is hash-verified against the compile-time
//!   `runtime-pins.json` before launch (ADR-022 §6),
//! - the process is spawned loopback-only with a random per-run API key
//!   (ADR-002 internal bearer), `--no-webui`, and stdout/stderr discarded
//!   (engine logs may echo prompts — they are never persisted),
//! - a supervisor task restarts it on unexpected exit (bounded retries) and
//!   kills it when the node's shutdown channel flips,
//! - startup blocks until `/health` answers (model load) or times out.
//!
//! [`EngineHandle::runtime_config`] yields a ready
//! [`modelswarm_runtime::llamacpp::LlamaCppConfig`] including the pinned
//! engine identity and the exact token vocabulary parsed from the verified
//! GGUF (lossless token-id recovery, ADR-022 vocab).

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use modelswarm_runtime::llamacpp::{EngineIdentity, LlamaCppConfig};
use modelswarm_types::{read_metadata, token_vocab, TokenVocab};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};

/// The pinned engine manifest, baked in at compile time from the repo root.
pub const RUNTIME_PINS_JSON: &str = include_str!("../../../runtime-pins.json");

#[derive(Debug, Deserialize)]
struct RuntimePins {
    tag: String,
    /// The release anchor reported as `runtime.build_hash` on EVERY
    /// platform (ADR-022 §6): the windows-x64 archive sha of this release.
    canonical_build_hash: String,
    platforms: std::collections::BTreeMap<String, PlatformPins>,
}

#[derive(Debug, Deserialize)]
struct PlatformPins {
    /// Used by CI/install scripts to fetch the engine; kept here so the
    /// pins file is the single source of truth for every platform.
    #[serde(default)]
    #[allow(dead_code)]
    binary: String,
    #[serde(default)]
    #[allow(dead_code)]
    archive_url: String,
    #[serde(default)]
    #[allow(dead_code)]
    archive_sha256: String,
    #[serde(default)]
    bundle: Vec<String>,
    files: std::collections::BTreeMap<String, String>,
    /// GPU-accelerated engine builds of the SAME release tag (ADR-024).
    /// A variant bundle is verified exactly like the canonical set, but it
    /// never changes the reported identity: `canonical_build_hash` stays
    /// the anchor on every backend (the backend is a local execution
    /// detail, not a swarm-visible runtime change).
    #[serde(default)]
    variants: std::collections::BTreeMap<String, VariantPins>,
}

#[derive(Debug, Deserialize)]
struct VariantPins {
    #[serde(default)]
    #[allow(dead_code)]
    archive_url: String,
    #[serde(default)]
    #[allow(dead_code)]
    archive_sha256: String,
    #[serde(default)]
    bundle: Vec<String>,
    files: std::collections::BTreeMap<String, String>,
}

/// The pins entry for the OS/arch this binary was built for.
fn current_platform() -> &'static str {
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        "windows-x64"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "linux-x64"
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "macos-arm64"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "macos-x64"
    }
}

fn parse_pins() -> Result<RuntimePins, EngineError> {
    serde_json::from_str(RUNTIME_PINS_JSON)
        .map_err(|e| EngineError::Pins(format!("embedded runtime-pins.json invalid: {e}")))
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("engine pin verification failed: {0}")]
    Pins(String),
    #[error("engine io: {0}")]
    Io(String),
    #[error("engine spawn: {0}")]
    Spawn(String),
    #[error("engine health: server did not become ready within {timeout_ms} ms")]
    HealthTimeout { timeout_ms: u64 },
    #[error("engine vocabulary: {0}")]
    Vocab(String),
}

/// Everything needed to launch the engine sidecar.
#[derive(Debug, Clone)]
pub struct EngineSpec {
    /// Path to `llama-server.exe` (the pinned bundle directory).
    pub exe: PathBuf,
    /// Path to the verified GGUF artifact.
    pub model: PathBuf,
    /// Compute threads; `None` lets llama-server decide.
    pub threads: Option<u32>,
    /// KV context window (prompt + generation budget).
    pub ctx: u32,
    /// How long to wait for `/health` after spawn.
    pub startup_timeout: Duration,
    /// GPU offload layers (ADR-024): `Some(n)` passes `-ngl n` — used with
    /// a GPU-accelerated engine variant. `None` keeps the engine default
    /// (CPU: no offload).
    pub gpu_layers: Option<u32>,
    /// Backend label for telemetry/UI disclosure (e.g. "cpu", "vulkan").
    /// Reported locally only — never part of the wire runtime descriptor.
    pub backend: String,
}

impl Default for EngineSpec {
    fn default() -> Self {
        Self {
            exe: PathBuf::new(),
            model: PathBuf::new(),
            threads: None,
            ctx: 4096,
            startup_timeout: Duration::from_secs(120),
            gpu_layers: None,
            backend: "cpu".into(),
        }
    }
}

/// A running, health-verified engine sidecar. Dropping the node's shutdown
/// channel (or flipping it) terminates the child. `bearer` stays in the node
/// process — it never crosses into any UI.
pub struct EngineHandle {
    /// Loopback base URL, e.g. `http://127.0.0.1:8137`.
    pub base_url: String,
    /// The per-run random API key.
    pub bearer: String,
    pub port: u16,
    /// The pinned-engine identity (verified at launch).
    pub identity: EngineIdentity,
    /// Backend actually serving ("cpu" or a GPU variant name, ADR-024).
    pub backend: String,
    /// Exact token vocabulary from the verified GGUF.
    pub vocab: Arc<TokenVocab>,
}

/// Verifies the engine directory against the embedded pins and returns the
/// pinned identity. `exe`'s parent directory must contain every `bundle[]`
/// file with the exact pinned sha256 (extras are tolerated — dev machines
/// may unpack the full zip).
pub fn verify_engine_dir(exe: &Path) -> Result<EngineIdentity, EngineError> {
    verify_engine_variant(exe, None)
}

/// Variant-aware verification (ADR-024): `None` checks the canonical CPU
/// bundle; `Some(name)` checks `platforms[<platform>].variants[name]`.
/// Identity is identical for every variant of the same release tag.
pub fn verify_engine_variant(
    exe: &Path,
    variant: Option<&str>,
) -> Result<EngineIdentity, EngineError> {
    let pins = parse_pins()?;
    let platform = pins.platforms.get(current_platform()).ok_or_else(|| {
        EngineError::Pins(format!(
            "runtime-pins has no entry for {}",
            current_platform()
        ))
    })?;
    let (label, bundle, files) = match variant {
        None => ("canonical".to_string(), &platform.bundle, &platform.files),
        Some(name) => {
            let v = platform.variants.get(name).ok_or_else(|| {
                EngineError::Pins(format!(
                    "runtime-pins has no '{name}' variant for {platform_name}",
                    platform_name = current_platform()
                ))
            })?;
            (name.to_string(), &v.bundle, &v.files)
        }
    };
    let dir = exe
        .parent()
        .ok_or_else(|| EngineError::Pins("engine exe has no parent directory".into()))?;
    if !dir.is_dir() {
        return Err(EngineError::Pins(format!(
            "engine directory missing: {}",
            dir.display()
        )));
    }
    for file in bundle {
        let path = dir.join(file);
        let bytes = std::fs::read(&path)
            .map_err(|e| EngineError::Pins(format!("bundled file {file}: {e}")))?;
        // Not in the hash map: a symlink entry (unversioned .so/.dylib) —
        // its content is the linked file, already verified under its name.
        let Some(expected) = files.get(file) else {
            continue;
        };
        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != *expected {
            return Err(EngineError::Pins(format!(
                "bundled file {file}: sha256 {actual} != pinned {expected}"
            )));
        }
    }
    let _ = label;
    Ok(EngineIdentity {
        version: pins.tag.clone(),
        build_hash: pins.canonical_build_hash.clone(),
    })
}

/// Picks a free loopback port by briefly binding and dropping a listener.
fn ephemeral_port() -> Result<u16, EngineError> {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| EngineError::Io(e.to_string()))?;
    Ok(listener
        .local_addr()
        .map_err(|e| EngineError::Io(e.to_string()))?
        .port())
}

/// Spawns and supervises the engine. Returns once `/health` is green; the
/// supervisor task keeps the child alive (bounded restarts) until
/// `shutdown` fires or all senders drop, then kills it. Lifecycle events
/// (spawn failure, exit, restart, job-assign failure) go to the node
/// telemetry sink — a GUI-supervised node has no console to eprintln at.
pub async fn start_engine(
    spec: EngineSpec,
    shutdown: tokio::sync::watch::Receiver<bool>,
    telemetry: std::sync::Arc<modelswarm_telemetry::Telemetry>,
) -> Result<EngineHandle, EngineError> {
    let variant = if spec.backend == "cpu" {
        None
    } else {
        Some(spec.backend.as_str())
    };
    let identity = verify_engine_variant(&spec.exe, variant)?;
    let port = ephemeral_port()?;
    let bearer = modelswarm_identity::new_nonce();
    let base_url = format!("http://127.0.0.1:{port}");

    // Flips when the supervisor gives up (spawn failure or restart budget
    // exhausted) so the health loop fails in milliseconds instead of
    // waiting out the full startup timeout on a dead port (observed:
    // a load-time engine abort burning the whole 600 s GPU window).
    let dead = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    spawn_supervised(
        &spec,
        port,
        &bearer,
        shutdown.clone(),
        3, // bounded restart attempts per session
        std::sync::Arc::clone(&dead),
        telemetry,
    );

    // Block until healthy (model load) or timeout.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| EngineError::Io(e.to_string()))?;
    let started = Instant::now();
    loop {
        if *shutdown.borrow() {
            return Err(EngineError::Spawn(
                "node shut down while engine loaded".into(),
            ));
        }
        if dead.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(EngineError::Spawn(
                "engine exited before becoming healthy (load failed or restart budget exhausted)"
                    .into(),
            ));
        }
        if started.elapsed() >= spec.startup_timeout {
            return Err(EngineError::HealthTimeout {
                timeout_ms: spec.startup_timeout.as_millis() as u64,
            });
        }
        let healthy = client
            .get(format!("{base_url}/health"))
            .bearer_auth(&bearer)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if healthy {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    Ok(EngineHandle {
        base_url,
        bearer,
        port,
        backend: spec.backend.clone(),
        vocab: load_vocab(&spec.model)?,
        identity,
    })
}

fn spawn_supervised(
    spec: &EngineSpec,
    port: u16,
    bearer: &str,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    max_restarts: u32,
    dead: std::sync::Arc<std::sync::atomic::AtomicBool>,
    telemetry: std::sync::Arc<modelswarm_telemetry::Telemetry>,
) {
    let spec = spec.clone();
    let bearer = bearer.to_string();
    tokio::spawn(async move {
        let mut restarts_left = max_restarts;
        loop {
            let mut child = match launch(&spec, port, &bearer, &telemetry) {
                Ok(child) => child,
                Err(e) => {
                    telemetry.warn(
                        "engine.spawn_failed",
                        &[("code", "spawn"), ("detail", &e.to_string())],
                    );
                    dead.store(true, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            };
            tokio::select! {
                _ = shutdown.changed() => {
                    let _ = child.kill().await;
                    return;
                }
                status = child.wait() => {
                    if *shutdown.borrow() {
                        return;
                    }
                    if restarts_left == 0 {
                        telemetry.warn(
                            "engine.exited",
                            &[("code", "restart_budget_exhausted"), ("status", &format!("{status:?}"))],
                        );
                        dead.store(true, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                    restarts_left -= 1;
                    telemetry.warn(
                        "engine.restarting",
                        &[("restarts_left", &restarts_left.to_string()), ("status", &format!("{status:?}"))],
                    );
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    });
}

/// The exact llama-server argv (loopback-only, bearer-gated, no webui).
/// Pure so the arg contract (`-ngl` only for GPU variants) is testable.
fn engine_args(spec: &EngineSpec, port: u16, bearer: &str) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "--host".into(),
        "127.0.0.1".into(),
        "--port".into(),
        port.to_string(),
        "-m".into(),
        spec.model.display().to_string(),
        "-c".into(),
        spec.ctx.to_string(),
        "--no-webui".into(),
        "--api-key".into(),
        bearer.into(),
    ];
    if let Some(threads) = spec.threads {
        args.push("-t".into());
        args.push(threads.to_string());
    }
    if let Some(layers) = spec.gpu_layers {
        args.push("-ngl".into());
        args.push(layers.to_string());
    }
    args
}

fn launch(
    spec: &EngineSpec,
    port: u16,
    bearer: &str,
    // `_`-prefixed: the ONLY use is the Windows kill-on-close job-object
    // warning below — on non-Windows the parameter is intentionally unused
    // (found by the per-push non-Windows compile gate added at the 0.2.21
    // release train; underscore keeps the binding usable on Windows).
    _telemetry: &modelswarm_telemetry::Telemetry,
) -> Result<Child, EngineError> {
    let mut command = Command::new(&spec.exe);
    command
        .args(engine_args(spec, port, bearer))
        // Engine stdout/stderr are discarded by policy: they may echo prompt
        // text, and prompts are structurally never persisted (ADR-001).
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        // CREATE_NO_WINDOW: no console flash for the GUI-supervised node.
        // (tokio::process::Command has an inherent creation_flags on Windows.)
        command.creation_flags(0x0800_0000);
    }
    let child = command
        .spawn()
        .map_err(|e| EngineError::Spawn(format!("{}: {e}", spec.exe.display())))?;
    #[cfg(windows)]
    {
        // Force-killing the app (taskkill /F, crash) must never orphan the
        // engine (observed live 2026-10-06). A kill-on-close job object ties
        // the child's life to this process: when our handles close — however
        // the process dies — the OS terminates the engine. Best effort: the
        // graceful shutdown path (watch channel) already kills the child.
        if let Some(pid) = child.id() {
            if let Err(e) = modelswarm_winjob::assign_child(pid) {
                _telemetry.warn(
                    "engine.job_assign_failed",
                    &[("pid", &pid.to_string()), ("detail", &e.to_string())],
                );
            }
        }
    }
    Ok(child)
}

impl EngineHandle {
    /// Adapter configuration carrying the pinned identity + exact vocab.
    pub fn runtime_config(&self) -> LlamaCppConfig {
        LlamaCppConfig::new(&self.base_url, &self.bearer)
            .with_engine(self.identity.clone())
            .with_vocab(Arc::clone(&self.vocab))
    }
}

/// Loads the exact token vocabulary (bytes→id + EOS) from a GGUF artifact.
pub fn load_vocab(model: &Path) -> Result<Arc<TokenVocab>, EngineError> {
    let metadata = read_metadata(model)
        .map_err(|e| EngineError::Vocab(format!("{}: {e}", model.display())))?;
    let vocab = token_vocab(&metadata)
        .ok_or_else(|| EngineError::Vocab("GGUF has no tokenizer.ggml.tokens array".into()))?;
    Ok(Arc::new(vocab))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_pins_parse_and_cover_every_platform() {
        let pins = parse_pins().expect("pins parse");
        assert_eq!(pins.tag, "b11407");
        assert_eq!(
            pins.canonical_build_hash,
            "353c4aab423bff5cb6dc0e1d32e41a447990ab3d69a411b7f58ff48187c91a03"
        );
        for platform in ["windows-x64", "linux-x64", "macos-arm64", "macos-x64"] {
            let entry = pins
                .platforms
                .get(platform)
                .unwrap_or_else(|| panic!("missing platform {platform}"));
            assert!(!entry.bundle.is_empty(), "{platform} bundle empty");
            assert!(!entry.files.is_empty(), "{platform} files empty");
            assert_eq!(entry.archive_sha256.len(), 64, "{platform} archive sha");
        }
        // Every platform ships its server binary.
        assert!(pins.platforms["windows-x64"]
            .bundle
            .iter()
            .any(|f| f == "llama-server.exe"));
        for platform in ["linux-x64", "macos-arm64", "macos-x64"] {
            assert!(pins.platforms[platform]
                .bundle
                .iter()
                .any(|f| f == "llama-server"));
        }
    }

    #[test]
    fn vulkan_variant_pins_parse_and_carry_server() {
        let pins = parse_pins().expect("pins parse");
        let variant = pins.platforms["windows-x64"]
            .variants
            .get("vulkan")
            .expect("windows-x64 vulkan variant pinned");
        assert!(!variant.bundle.is_empty());
        assert!(variant.bundle.iter().any(|f| f == "llama-server.exe"));
        assert!(variant.bundle.iter().any(|f| f == "ggml-vulkan.dll"));
        for file in &variant.bundle {
            assert!(
                variant.files.contains_key(file),
                "vulkan bundle file {file} has no pinned sha256"
            );
        }
    }

    #[test]
    fn unknown_variant_name_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let err = verify_engine_variant(&dir.path().join("llama-server.exe"), Some("cuda"));
        assert!(matches!(err, Err(EngineError::Pins(_))), "{err:?}");
    }

    #[test]
    fn launch_args_include_ngl_only_for_gpu_layers() {
        let spec = |gpu: Option<u32>| EngineSpec {
            gpu_layers: gpu,
            ..EngineSpec::default()
        };
        let cpu = engine_args(&spec(None), 8137, "k");
        assert!(!cpu.contains(&"-ngl".to_string()));
        let gpu = engine_args(&spec(Some(999)), 8137, "k");
        let i = gpu.iter().position(|a| a == "-ngl").expect("-ngl present");
        assert_eq!(gpu[i + 1], "999");
        let host = gpu.iter().position(|a| a == "--host").unwrap();
        assert_eq!(gpu[host + 1], "127.0.0.1");
        assert!(gpu.contains(&"--no-webui".to_string()));
    }

    #[test]
    fn verify_engine_dir_fails_closed_on_tampering() {
        let dir = tempfile::tempdir().unwrap();
        // Empty dir: every bundle file missing -> error.
        let err = verify_engine_dir(&dir.path().join("llama-server.exe"));
        assert!(matches!(err, Err(EngineError::Pins(_))), "{err:?}");

        // A file with the right name but wrong bytes -> error.
        let pins = parse_pins().unwrap();
        let first = pins.platforms[current_platform()]
            .bundle
            .iter()
            .find(|f| pins.platforms[current_platform()].files.contains_key(*f))
            .unwrap()
            .clone();
        std::fs::write(dir.path().join(&first), b"tampered").unwrap();
        let err = verify_engine_dir(&dir.path().join("llama-server.exe"));
        assert!(matches!(err, Err(EngineError::Pins(_))), "{err:?}");
    }

    /// Real-engine smoke (Phase H3 gate): set MSP_LLAMA_SERVER + MSP_REAL_GGUF
    /// to the pinned llama-server.exe and the verified Qwen GGUF. Optional
    /// MSP_ENGINE_BACKEND (e.g. "vulkan") runs the ADR-024 GPU variant —
    /// layer offload is always engine-auto-fit (`gpu_layers: None`, ADR-024
    /// amendment: never pass a pinned -ngl).
    #[test]
    #[ignore = "set MSP_LLAMA_SERVER and MSP_REAL_GGUF"]
    fn real_engine_starts_serves_and_dies() {
        let exe = std::env::var("MSP_LLAMA_SERVER").expect("MSP_LLAMA_SERVER");
        let model = std::env::var("MSP_REAL_GGUF").expect("MSP_REAL_GGUF");
        let backend = std::env::var("MSP_ENGINE_BACKEND").unwrap_or_else(|_| "cpu".into());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let (_tx, rx) = tokio::sync::watch::channel(false);
            let spec = EngineSpec {
                exe: exe.into(),
                model: model.into(),
                // ADR-024 amendment (audit L1): the engine auto-fits layers
                // for every variant; a pinned -ngl is never passed.
                gpu_layers: None,
                backend: backend.clone(),
                ..EngineSpec::default()
            };
            let engine = start_engine(
                spec,
                rx,
                std::sync::Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            )
            .await
            .expect("engine starts");
            assert_eq!(engine.backend, backend);
            let config = engine.runtime_config();
            assert_eq!(engine.identity.version, "b11407");
            let adapter = modelswarm_runtime::llamacpp::LlamaCppAdapter::new(config).unwrap();

            use modelswarm_runtime::InferenceRuntime;
            let handle = adapter.load("msp1:real").await.unwrap();
            let ids = adapter.tokenize("Hello, swarm.").await.unwrap();
            assert!(!ids.is_empty());
            let sampling = modelswarm_runtime::SamplingParams::default();
            let a = adapter
                .decode_stream(&handle, &ids, &sampling, 8, Duration::from_secs(60))
                .await
                .unwrap();
            let b = adapter
                .decode_stream(&handle, &ids, &sampling, 8, Duration::from_secs(60))
                .await
                .unwrap();
            assert_eq!(a, b, "greedy decode must be deterministic");
            assert!(!a.is_empty());
            let text = adapter.detokenize(&a).await.unwrap();
            assert!(!text.is_empty());
            let metrics = adapter.metrics();
            assert!(
                metrics.decode_tokens_per_ms > 0.0,
                "measured decode rate required"
            );
            println!(
                "generated {text:?} at {:.1} tok/s",
                metrics.decode_tokens_per_ms * 1000.0
            );

            // Shutdown kills the child.
            let port = engine.port;
            drop(engine);
            _tx.send(true).ok();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let gone = reqwest::Client::new()
                .get(format!("http://127.0.0.1:{port}/health"))
                .send()
                .await;
            assert!(gone.is_err(), "engine must be dead after shutdown");
        });
    }

    /// P1 real-engine validation (never a required test): the true-streaming
    /// decode must be token-for-token identical to the per-token
    /// `decode_step` loop under greedy sampling (temperature 0), and the
    /// labeled TTFT/ITL numbers for both paths are printed for the
    /// verification record. Set MSP_LLAMA_SERVER + MSP_REAL_GGUF.
    #[test]
    #[ignore = "set MSP_LLAMA_SERVER and MSP_REAL_GGUF"]
    fn real_engine_streaming_parity_and_timings() {
        let exe = std::env::var("MSP_LLAMA_SERVER").expect("MSP_LLAMA_SERVER");
        let model = std::env::var("MSP_REAL_GGUF").expect("MSP_REAL_GGUF");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let (_tx, rx) = tokio::sync::watch::channel(false);
            let spec = EngineSpec {
                exe: exe.into(),
                model: model.into(),
                gpu_layers: None,
                ..EngineSpec::default()
            };
            let engine = start_engine(
                spec,
                rx,
                std::sync::Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            )
            .await
            .expect("engine starts");
            let adapter = modelswarm_runtime::llamacpp::LlamaCppAdapter::new(
                engine.runtime_config(),
            )
            .unwrap();
            use futures_util::StreamExt;
            use modelswarm_runtime::{DecodeEvent, InferenceRuntime, SamplingParams};

            let handle = adapter.load("msp1:real").await.unwrap();
            let sampling = SamplingParams::default();

            // Long prompt ≈ 1200+ tokens (the audit's 1215-token class).
            let filler = "The swarm serves one exact profile per cohort and every peer verifies the artifact digest before hosting. ";
            let mut long_prompt = String::new();
            while adapter.tokenize(&long_prompt).await.unwrap().len() < 1200 {
                long_prompt.push_str(filler);
            }
            let long_ids = adapter.tokenize(&long_prompt).await.unwrap();
            let short_ids = adapter.tokenize("Hello, swarm.").await.unwrap();
            let eos_id = engine.vocab.eos_id;

            for (label, prompt) in [("16-tok-class", &short_ids), ("1200-tok-class", &long_ids)] {
                let max_tokens = 32u32;
                // Warm the slot cache so both paths pay no cold prefill
                // (the audit measured that asymmetry separately).
                let _ = adapter
                    .decode_stream(&handle, prompt, &sampling, 1, Duration::from_secs(60))
                    .await
                    .unwrap();

                // BEFORE-path re-measurement: the per-token POST loop with
                // the growing prefix (what decode_stream used to do).
                let started = std::time::Instant::now();
                let mut loop_tokens = Vec::new();
                let mut prefix = prompt.clone();
                while loop_tokens.len() < max_tokens as usize {
                    let token = adapter
                        .decode_step(&handle, &prefix, &sampling)
                        .await
                        .unwrap();
                    if Some(token) == eos_id {
                        break;
                    }
                    prefix.push(token);
                    loop_tokens.push(token);
                }
                let loop_elapsed = started.elapsed();

                // AFTER path: one SSE connection, incremental events.
                let started = std::time::Instant::now();
                let mut stream = adapter.decode_stream_events(
                    &handle,
                    prompt,
                    &sampling,
                    max_tokens,
                    Duration::from_secs(60),
                );
                let mut ttft: Option<std::time::Duration> = None;
                let mut inter: Vec<std::time::Duration> = Vec::new();
                let mut last: Option<std::time::Instant> = None;
                let mut sse_tokens = Vec::new();
                let mut timings_seen = false;
                while let Some(event) = stream.next().await {
                    match event.unwrap() {
                        DecodeEvent::Token(id) => {
                            let now = std::time::Instant::now();
                            if ttft.is_none() {
                                ttft = Some(now - started);
                            } else if let Some(prev) = last {
                                inter.push(now - prev);
                            }
                            last = Some(now);
                            sse_tokens.push(id);
                        }
                        DecodeEvent::Timings(_) => timings_seen = true,
                    }
                }
                let sse_elapsed = started.elapsed();

                // PARITY: the release-gate claim of the streaming refactor.
                assert_eq!(
                    loop_tokens, sse_tokens,
                    "{label}: SSE stream must match the per-token loop token-for-token"
                );
                assert!(
                    timings_seen,
                    "{label}: pinned server reports final-chunk timings"
                );

                let itl_p50 = {
                    inter.sort();
                    inter.get(inter.len() / 2).copied()
                };
                println!(
                    "P1MEASURE label={label} prompt_tokens={} tokens={} | loop(before): {:0.1} ms/tok, total {:0.0} ms | sse(after): ttft {:0.1} ms, itl_p50 {:0.1} ms, total {:0.0} ms ({:0.1} ms/tok), parity=identical",
                    prompt.len(),
                    sse_tokens.len(),
                    loop_elapsed.as_secs_f64() * 1000.0 / loop_tokens.len().max(1) as f64,
                    loop_elapsed.as_secs_f64() * 1000.0,
                    ttft.map(|d| d.as_secs_f64() * 1000.0).unwrap_or(-1.0),
                    itl_p50.map(|d| d.as_secs_f64() * 1000.0).unwrap_or(-1.0),
                    sse_elapsed.as_secs_f64() * 1000.0,
                    sse_elapsed.as_secs_f64() * 1000.0 / sse_tokens.len().max(1) as f64,
                );
            }
        });
    }
}
