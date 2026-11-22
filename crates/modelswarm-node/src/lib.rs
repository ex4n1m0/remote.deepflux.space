//! Node composition: the Windows background daemon as a library.
//!
//! [`Node::start`] is the single composition point that wires every
//! prior-phase crate into one process (Phase G, ADR-010 ownership map):
//!
//! - **Telemetry** — one [`Telemetry`] over a JSONL [`FileSink`] under
//!   `<data_dir>/logs/node.jsonl`; every field passes the mandatory redactor
//!   (`modelswarm_telemetry::redact`), so prompts/tokens/secrets cannot reach
//!   the file by construction. The self-test proves it with a canary grep.
//! - **Store** — SQLite at `<data_dir>/state.sqlite` (ADR-017); the schema is
//!   privacy-shaped (no prompt/completion/secret columns, enforced by the
//!   store's own schema audit and re-checked here on the file the node
//!   actually created).
//! - **Identity** — per-installation Ed25519 key (ADR-004). The 32-byte seed
//!   is persisted at `<data_dir>/identity.seed`. **Honest boundary:** the file
//!   is written with 0600 permissions on Unix and plain file permissions on
//!   Windows; the ADR-004 destination is DPAPI / Windows Credential Manager,
//!   which is the recorded Phase F hardening replacement (see
//!   `docs/verification/phase-g-notes.md`). The seed is never logged,
//!   returned by `NodeHandle`, or sent to the webview.
//! - **Tracker** — a [`TrackerClient`] is constructed when `tracker_base` is
//!   configured, but [`Node::start`] makes **no network calls**; the CLI's
//!   opt-in `--check-tracker` is the only thing that pings it (a read-only
//!   `GET /health`).
//! - **Runtime** — selection is explicit (ADR-019): the TEST-ONLY
//!   [`MockRuntime`] compiles solely under `cfg(test)` or the off-by-default
//!   `node-selftest` feature (the binary's `--allow-mock-runtime` flag is
//!   refused loudly when the feature is absent). Mock is **local-loopback-only
//!   by policy**: the only executor wired in this phase serves the loopback
//!   gateway, the node constructs no P2P [`modelswarm_transport`] listener at
//!   all, and no tracker registration path exists — a mock node cannot appear
//!   in any roster. The production baseline is `LlamaCppAdapter` pointed at a
//!   loopback llama.cpp sidecar (ADR-002); sidecar *supervision* (download,
//!   spawn, health) is later work, so a non-mock node without a configured
//!   sidecar starts honestly runtime-less: the gateway answers
//!   `no_peer`/503 instead of pretending.
//! - **Gateway** — the OpenAI-compatible loopback server from
//!   `modelswarm-gateway`, driven here through its public `build_router` +
//!   `assert_loopback` surface. Loopback-only is structural: the node builds
//!   the `127.0.0.1` socket itself and re-asserts [`assert_loopback`] before
//!   binding (tested: a spawned node's address is loopback; non-loopback IPs
//!   are refused).
//!
//! What is deliberately NOT here yet: the full swarm executor
//! (`modelswarm_session::spec::SpeculativeExecutor`), transport listeners,
//! eligibility heartbeats, and lease acquisition arrive with the Phase H/F
//! wiring; this node serves only **local single-peer inference** through
//! [`SingleLocalExecutor`].

pub mod advisory;
pub mod artifact;
pub mod catalog;
pub use modelswarm_types::ModelProfileManifest as LocalManifest;
/// ADR-040 cloud executor: one OpenAI-compatible provider API behind the
/// gateway's InferenceExecutor (DeepSeek, OpenRouter). Key discipline:
/// the key is desktop-local, never logged, never hub-sent.
pub mod cloud_executor;
pub mod engine;
mod executor;
#[cfg(feature = "libp2p-backend")]
pub mod measure;
/// Receipts v2 on the wire (ADR-030 B2) — the libp2p serving surface's
/// companion; feature-gated with it.
#[cfg(feature = "libp2p-backend")]
pub mod receipt_wire;
#[cfg(feature = "libp2p-backend")]
pub mod relay_ticket_cache;
#[cfg(feature = "libp2p-backend")]
pub mod remote;
#[cfg(feature = "libp2p-backend")]
pub mod serving;
#[cfg(feature = "verifydrafts")]
pub mod verifydrafts;

#[cfg(any(test, feature = "node-selftest"))]
pub mod selftest;

pub use executor::{render_chatml, SingleLocalExecutor};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use modelswarm_gateway::{
    assert_loopback, build_router, GatewayError, GatewayState, ModelInfo, ProfileProvider,
    StaticProfiles, DEFAULT_MAX_OUTPUT_TOKENS, DEFAULT_PORT,
};
use modelswarm_identity::InstallationIdentity;
use modelswarm_runtime::llamacpp::{LlamaCppAdapter, LlamaCppConfig};
use modelswarm_runtime::InferenceRuntime;
use modelswarm_telemetry::{FileSink, Telemetry};
use modelswarm_tracker_api::TrackerClient;

/// Log file (JSONL, redacted) under `<data_dir>/logs/`.
pub const LOG_RELATIVE_PATH: &str = "logs/node.jsonl";
/// SQLite state file under `<data_dir>/`.
pub const STATE_FILE_NAME: &str = "state.sqlite";
/// Ed25519 seed file under `<data_dir>/` (SECRET; see the crate docs on the
/// DPAPI/Credential Manager Phase F hardening).
pub const SEED_FILE_NAME: &str = "identity.seed";
/// Env var naming a loopback llama.cpp sidecar base URL (ADR-002), e.g.
/// `http://127.0.0.1:8123`. The node does not spawn the sidecar (later
/// phase); when set, `run` serves through it.
pub const ENV_LLAMACPP_URL: &str = "MSP_LLAMACPP_URL";
/// Env var carrying the sidecar's internal bearer secret (ADR-002). Required
/// together with [`ENV_LLAMACPP_URL`]; the node never invents a secret.
pub const ENV_LLAMACPP_TOKEN: &str = "MSP_LLAMACPP_TOKEN";

/// Node startup configuration (see the crate docs for field semantics).
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Tracker base URL; when `None` the node is fully offline.
    pub tracker_base: Option<String>,
    /// Loopback gateway port; `0` asks the OS for an ephemeral port (tests).
    pub gateway_port: u16,
    /// Root directory for logs, state, and the identity seed.
    pub data_dir: PathBuf,
    /// The profile this installation hosts/serves (`msp1:…`); `None` serves
    /// nothing (`GET /v1/models` lists empty).
    pub profile_id: Option<String>,
    /// Select the TEST-ONLY mock runtime (ADR-019). Honored only when
    /// compiled with `cfg(test)` or the `node-selftest` feature; otherwise
    /// [`Node::start`] fails with [`NodeError::MockRuntimeNotCompiled`].
    pub mock: bool,
    /// Path to the pinned `llama-server.exe` (Phase H3). When set together
    /// with [`NodeConfig::engine_model`], the node spawns and supervises the
    /// engine and serves through it; takes precedence over the sidecar env
    /// vars.
    pub engine_binary: Option<PathBuf>,
    /// Path to a GPU-accelerated pinned engine variant (ADR-024), e.g.
    /// `engine-vulkan/llama-server.exe`. Tried FIRST when present; any
    /// verification/spawn/health failure falls back to the CPU engine with
    /// a visible `engine.gpu_fallback` telemetry event (honest CPU mode —
    /// never a silent downgrade).
    pub engine_gpu_binary: Option<PathBuf>,
    /// Path to the verified GGUF artifact the engine loads.
    pub engine_model: Option<PathBuf>,
    /// Compute threads for the engine; `None` = engine default.
    pub engine_threads: Option<u32>,
    /// ADR-040 C3: serve a CLOUD profile through a provider API instead
    /// of a local engine — the node serves through
    /// [`crate::cloud_executor::CloudApiExecutor`], no engine is spawned,
    /// and the profile advertised is the cloud profile. Mutually
    /// exclusive with the engine fields (start refuses both set).
    pub cloud: Option<crate::cloud_executor::CloudApiConfig>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            tracker_base: None,
            gateway_port: DEFAULT_PORT,
            data_dir: default_data_dir(),
            profile_id: None,
            mock: false,
            engine_binary: None,
            engine_gpu_binary: None,
            engine_model: None,
            engine_threads: None,
            cloud: None,
        }
    }
}

/// `%LOCALAPPDATA%\ModelSwarm\Data` on Windows, `~/.modelswarm` elsewhere,
/// `.modelswarm` when neither is resolvable.
///
/// The `Data` suffix (2026-10-08) keeps user state OUT of the Tauri NSIS
/// per-user install root, which is also `%LOCALAPPDATA%\ModelSwarm` —
/// without the split, uninstalling the app would DELETE the Ed25519
/// identity seed (ADR-004: lost key = re-enroll), the SQLite store, and
/// every downloaded model. Existing pre-split layouts are migrated once.
pub fn default_data_dir() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let root = PathBuf::from(local).join("ModelSwarm");
        migrate_pre_separation_layout(&root);
        return root.join("Data");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".modelswarm");
    }
    PathBuf::from(".modelswarm")
}

/// Moves the pre-split data layout (`%LOCALAPPDATA%\ModelSwarm\*` — the
/// install root) into `ModelSwarm\Data\`, exactly once. Runs when `Data`
/// holds neither an identity nor a store but the root does. `rename`
/// first (same volume — instant even for multi-GB model files), copy as
/// the fallback; failures leave the legacy files untouched (the next
/// call retries). App-managed `engine*/` directories stay at the root.
fn migrate_pre_separation_layout(root: &std::path::Path) {
    let data = root.join("Data");
    if data.join("identity.seed").exists() || data.join("state.sqlite").exists() {
        return; // already migrated (or fresh install)
    }
    if !root.join("identity.seed").is_file() && !root.join("state.sqlite").is_file() {
        return; // nothing legacy to move
    }
    let _ = std::fs::create_dir_all(&data);
    for name in [
        "identity.seed",
        "state.sqlite",
        "state.sqlite-wal",
        "state.sqlite-shm",
        "config.json",
        "session.token",
        "lease.id",
    ] {
        let from = root.join(name);
        if from.is_file() && std::fs::rename(&from, data.join(name)).is_err() {
            let _ = std::fs::copy(&from, data.join(name));
        }
    }
    for dir in ["logs", "models"] {
        let from = root.join(dir);
        if from.is_dir() && !data.join(dir).is_dir() {
            let _ = std::fs::rename(&from, data.join(dir));
        }
    }
}

/// Failures of node composition.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// Filesystem failure (data dir, log file, seed file).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// SQLite/store failure.
    #[error("store error: {0}")]
    Store(#[from] modelswarm_store::StoreError),
    /// Gateway bind/serve failure.
    #[error("gateway error: {0}")]
    Gateway(#[from] GatewayError),
    /// ADR-040 C3: the cloud executor could not be constructed (client
    /// build failure — never carries the key).
    #[error("cloud executor error: {0}")]
    CloudExecutor(String),
    /// `mock: true` was requested but the mock runtime is not compiled in
    /// (ADR-019 compile gate).
    #[error(
        "mock runtime requested but not compiled in: rebuild with --features node-selftest \
         (TEST-ONLY, ADR-019); production nodes never enable it"
    )]
    MockRuntimeNotCompiled,
    /// A llama.cpp sidecar was half-configured via env vars.
    #[error("llama.cpp sidecar misconfigured: {0} — set both {ENV_LLAMACPP_URL} and {ENV_LLAMACPP_TOKEN} or neither")]
    LlamaSidecarMisconfigured(String),
    /// The configured sidecar base URL is not loopback (ADR-002 / AGENTS.md 4).
    #[error("llama.cpp sidecar base URL must be loopback (127.0.0.1), got: {0}")]
    LlamaSidebackNotLoopback(String),
    /// The pinned engine failed to verify, start, or become healthy.
    #[error("engine error: {0}")]
    Engine(#[from] engine::EngineError),
}

/// Composition entry point. `Node` is a namespace, not a running value: the
/// returned [`NodeHandle`] is the running node.
pub struct Node;

impl Node {
    /// Wires telemetry, store, identity, (optional) tracker client, runtime,
    /// and the loopback gateway, then spawns the gateway server task.
    ///
    /// `shutdown` is the process-wide stop signal: the server exits
    /// gracefully when it flips to `true` (or when every sender is dropped).
    /// Makes no network calls of its own — the tracker client is only
    /// constructed.
    pub async fn start(
        config: NodeConfig,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<NodeHandle, NodeError> {
        std::fs::create_dir_all(&config.data_dir)?;
        let logs_dir = config.data_dir.join("logs");
        std::fs::create_dir_all(&logs_dir)?;

        // Telemetry first: everything after this can be logged.
        let sink = FileSink::open(&logs_dir.join("node.jsonl"))?;
        let telemetry = Arc::new(Telemetry::with_sink(Box::new(sink)));

        // Bind the gateway BEFORE spawning the engine (composition order
        // fix): a taken port fails here in milliseconds and no multi-GB
        // engine child is spawned-then-leaked for the whole session (the
        // desktop's port-conflict fallback retries with an ephemeral
        // port; the first attempt must leave nothing behind).
        // Loopback bind — structural, re-asserted (tested).
        let gateway_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.gateway_port);
        assert_loopback(gateway_addr.ip())?;
        let listener = tokio::net::TcpListener::bind(gateway_addr).await?;
        let local_addr = listener.local_addr()?;

        // Store (ADR-017) — privacy-shaped schema, migrations applied.
        let store = modelswarm_store::Store::open(config.data_dir.join(STATE_FILE_NAME))?;
        telemetry.info("store.opened", &[("file", STATE_FILE_NAME)]);

        // Identity (ADR-004) — load-or-create; seed file, never logged.
        let identity = Arc::new(load_or_create_identity(&config.data_dir, &telemetry)?);
        let installation_id = identity.installation_id();
        store.upsert_installation(&installation_id, &identity.public_key_bytes())?;
        telemetry.info(
            "identity.ready",
            &[("installation_id", &installation_id), ("key", "ed25519")],
        );

        // Pinned engine (Phase H3): spawn + supervise when configured.
        // ADR-024: a GPU variant is preferred when configured and present;
        // any failure falls back to the canonical CPU engine, visibly.
        let engine = match (&config.engine_binary, &config.engine_model) {
            (Some(exe), Some(model)) => {
                let mut started = None;
                if let Some(gpu_exe) = &config.engine_gpu_binary {
                    if gpu_exe.is_file() {
                        let spec = engine::EngineSpec {
                            exe: gpu_exe.clone(),
                            model: model.clone(),
                            threads: config.engine_threads,
                            // NO explicit -ngl: b11407's auto-fit aborts when
                            // a user-pinned layer count cannot fit FREE VRAM
                            // (observed with Qwen3.8-27B on a 16 GB 5080:
                            // "failed to fit params to free device memory:
                            // n_gpu_layers already set by user to 999").
                            // Left unset, the engine auto-fits: full offload
                            // when it fits, partial offload when it doesn't.
                            gpu_layers: None,
                            backend: "vulkan".into(),
                            // First GPU load of a large model can include
                            // shader compilation — minutes on a cold driver
                            // cache. Later loads are much faster.
                            startup_timeout: std::time::Duration::from_secs(600),
                            ..engine::EngineSpec::default()
                        };
                        match engine::start_engine(spec, shutdown.clone(), Arc::clone(&telemetry))
                            .await
                        {
                            Ok(handle) => started = Some(handle),
                            Err(e) => telemetry.warn(
                                "engine.gpu_fallback",
                                &[("variant", "vulkan"), ("reason", &e.to_string())],
                            ),
                        }
                    }
                }
                let handle = match started {
                    Some(handle) => handle,
                    None => {
                        let spec = engine::EngineSpec {
                            exe: exe.clone(),
                            model: model.clone(),
                            threads: config.engine_threads,
                            ..engine::EngineSpec::default()
                        };
                        engine::start_engine(spec, shutdown.clone(), Arc::clone(&telemetry)).await?
                    }
                };
                telemetry.info(
                    "engine.started",
                    &[
                        ("port", &handle.port.to_string()),
                        ("version", handle.identity.version.as_str()),
                        ("build_hash", handle.identity.build_hash.as_str()),
                        ("backend", handle.backend.as_str()),
                    ],
                );
                Some(handle)
            }
            (None, None) => None,
            _ => {
                return Err(NodeError::LlamaSidecarMisconfigured(
                    "engine_binary and engine_model must be set together".to_string(),
                ))
            }
        };

        // Runtime selection (ADR-019).
        let runtime = select_runtime(&config, &telemetry, engine.as_ref())?;
        // The handle keeps the SAME runtime instance (ADR-034: the desktop
        // derives the family pin and drafts the probe's pairing window
        // through the node — the sidecar's bearer secret never crosses the
        // process boundary, ADR-002).
        let handle_runtime = runtime.clone();
        if let Some(runtime) = &runtime {
            let descriptor = runtime.id();
            telemetry.info(
                "runtime.selected",
                &[
                    ("name", descriptor.name()),
                    ("version", descriptor.version()),
                    ("build_hash", descriptor.build_hash()),
                ],
            );
        } else {
            telemetry.info(
                "runtime.unavailable",
                &[(
                    "reason",
                    "no llama.cpp sidecar configured; gateway will answer no_peer until one is",
                )],
            );
        }

        // Tracker client (constructed only; no calls — see crate docs).
        let tracker = config
            .tracker_base
            .as_deref()
            .map(|base| Arc::new(TrackerClient::new(base, Arc::clone(&identity))));
        if config.mock && tracker.is_some() {
            telemetry.warn(
                "tracker.mock_mode",
                &[(
                    "policy",
                    "mock node will never register or serve remote peers (ADR-019)",
                )],
            );
        }
        if let Some(base) = &config.tracker_base {
            telemetry.info("tracker.configured", &[("base", base.as_str())]);
        }

        // (The advisory digest plane that used to be wired here is
        // DELETED by the 2026-10-15 owner directive — the provider-key
        // era ended. The node hosts no advisory machinery anymore; the
        // ASSISTANT plane lives in `modelswarm_node::advisory` and is
        // constructed by the desktop against this node's own gateway
        // while hosting. The chat-wall suite pins that nothing in this
        // composition ever calls it.)

        // Gateway wiring. ADR-040 C3: a cloud configuration serves
        // through the provider executor (no engine, no runtime); the
        // local path is unchanged.
        if config.cloud.is_some() && config.engine_binary.is_some() {
            return Err(NodeError::CloudExecutor(
                "cloud and engine_binary are mutually exclusive".into(),
            ));
        }
        let executor: Arc<dyn modelswarm_gateway::InferenceExecutor> = match &config.cloud {
            Some(cloud_cfg) => Arc::new(
                crate::cloud_executor::CloudApiExecutor::new(cloud_cfg.clone())
                    .map_err(NodeError::CloudExecutor)?,
            ),
            None => Arc::new(
                SingleLocalExecutor::new(runtime, config.profile_id.clone())
                    .with_telemetry(Arc::clone(&telemetry)),
            ),
        };
        let profiles: Arc<dyn ProfileProvider> = match &config.profile_id {
            Some(profile) => Arc::new(StaticProfiles::new(vec![ModelInfo {
                id: profile.clone(),
                max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
            }])),
            None => Arc::new(StaticProfiles::new(Vec::new())),
        };
        let state = GatewayState::new(executor.clone(), profiles);

        let mut shutdown_rx = shutdown.clone();
        let handle_shutdown_rx = shutdown_rx.clone();
        let server_telemetry = Arc::clone(&telemetry);
        let server = tokio::spawn(async move {
            let app = build_router(state);
            let serve = axum::serve(listener, app).with_graceful_shutdown(async move {
                loop {
                    if shutdown_rx.changed().await.is_err() {
                        break; // all senders dropped → stop
                    }
                    if *shutdown_rx.borrow_and_update() {
                        break;
                    }
                }
            });
            if let Err(error) = serve.await {
                server_telemetry.error("gateway.failed", &[("error", &error.to_string())]);
            }
        });

        telemetry.metrics.incr("node.starts");
        telemetry.info(
            "node.started",
            &[
                ("installation_id", &installation_id),
                ("gateway_addr", &local_addr.to_string()),
                (
                    "profile_id",
                    config.profile_id.as_deref().unwrap_or("(none)"),
                ),
                ("mock", &config.mock.to_string()),
                ("tracker", &(config.tracker_base.is_some()).to_string()),
            ],
        );

        Ok(NodeHandle {
            local_addr,
            installation_id,
            profile_id: config.profile_id,
            mock: config.mock,
            data_dir: config.data_dir,
            tracker,
            engine_port: engine.as_ref().map(|e| e.port),
            engine_identity: engine.as_ref().map(|e| e.identity.clone()),
            engine_backend: engine.as_ref().map(|e| e.backend.clone()),
            runtime: handle_runtime,
            executor: Some(executor),
            shutdown_rx: handle_shutdown_rx,
            server,
        })
    }
}

/// A running node composition.
pub struct NodeHandle {
    /// The bound gateway address (always loopback; asserted at bind).
    pub local_addr: SocketAddr,
    /// `installationId` (base58(SHA-256(pubkey))) — public label only.
    pub installation_id: String,
    /// The configured profile id, if any.
    pub profile_id: Option<String>,
    /// Whether the TEST-ONLY mock runtime is active (ADR-019 labeling).
    pub mock: bool,
    /// The node's data directory (logs, state, seed live under it).
    pub data_dir: PathBuf,
    /// The tracker client, when `tracker_base` was configured. Carries NO
    /// secret material in its public surface; the identity seed stays in the
    /// node process.
    pub tracker: Option<Arc<TrackerClient>>,
    /// The supervised engine's loopback port, when one was started.
    pub engine_port: Option<u16>,
    /// The supervised pinned runtime — the SAME instance the gateway
    /// executor serves through — when one was configured. Lets the desktop
    /// compose ADR-034's family-pin derivation ([`Self::engine_tokenize`])
    /// and the probe's coordinator-side drafting
    /// ([`Self::engine_propose_window`]) through the node, so the
    /// sidecar's bearer secret never crosses the process boundary
    /// (ADR-002: only the Rust node talks to the sidecar).
    pub runtime: Option<Arc<dyn InferenceRuntime>>,
    /// The supervised engine's pinned identity (tag + canonical build
    /// hash) — lets attachés (the ADR-032 family engine bridge) label
    /// their in-process engine with the SAME pin the sidecar verified
    /// against, instead of the zero placeholder.
    pub engine_identity: Option<modelswarm_runtime::llamacpp::EngineIdentity>,
    /// The serving executor (F0(3)): lets the desktop attach the P2P
    /// serving bridge to the SAME executor the local gateway uses.
    pub executor: Option<Arc<dyn modelswarm_gateway::InferenceExecutor>>,
    /// Cloned shutdown receiver: attachés (P2P serving) die with the node.
    pub shutdown_rx: tokio::sync::watch::Receiver<bool>,
    /// The backend the engine actually serves on ("cpu" or a GPU variant
    /// name, ADR-024); `None` when no engine was started.
    pub engine_backend: Option<String>,
    server: tokio::task::JoinHandle<()>,
}

impl NodeHandle {
    /// Resolves when the gateway server task has exited (graceful shutdown
    /// completed or the task failed). Consumes the handle (the server task
    /// is joined exactly once).
    pub async fn stopped(self) {
        let _ = self.server.await;
    }

    /// Tokenizes `text` under the supervised engine's PINNED tokenizer (the
    /// sidecar's `/tokenize` surface — ADR-034 rule 3: "the C-API
    /// adapter's tokenizer or the sidecar's tokenization surface, any
    /// surface yielding the pinned engine's token ids"). Errors honestly
    /// when no engine is supervised (engine-less gateway / mock node) or
    /// the engine refused the call.
    pub async fn engine_tokenize(&self, text: &str) -> Result<Vec<u32>, String> {
        runtime_tokenize(self.runtime.as_ref(), text).await
    }

    /// The coordinator's GREEDY CONTINUATION of a token-id prefix through
    /// THIS node's own hosting engine (ADR-034 rule 6b: the family probe's
    /// pairing window is drafted by the coordinator's pinned engine — its
    /// hosting sidecar; no second engine on the coordinator). May return
    /// fewer than `window` ids when the engine emits EOS early (an honest
    /// short window, never padded).
    pub async fn engine_propose_window(
        &self,
        profile_id: &str,
        prefix: &[u32],
        window: u32,
    ) -> Result<Vec<u32>, String> {
        let runtime = self.runtime.as_ref();
        runtime_propose_window(runtime, profile_id, prefix, window).await
    }
}

/// The free-function core of [`NodeHandle::engine_tokenize`] — public so
/// the desktop can run the same seam over a cloned runtime handle
/// (testable with the mock runtime without a live node).
pub async fn runtime_tokenize(
    runtime: Option<&Arc<dyn InferenceRuntime>>,
    text: &str,
) -> Result<Vec<u32>, String> {
    let runtime = runtime.ok_or("no supervised engine")?;
    runtime.tokenize(text).await.map_err(|e| e.to_string())
}

/// The free-function core of [`NodeHandle::engine_propose_window`] —
/// public for the desktop's probe path (see [`runtime_tokenize`]).
pub async fn runtime_propose_window(
    runtime: Option<&Arc<dyn InferenceRuntime>>,
    profile_id: &str,
    prefix: &[u32],
    window: u32,
) -> Result<Vec<u32>, String> {
    let runtime = runtime.ok_or("no supervised engine")?;
    let handle = runtime
        .load(profile_id)
        .await
        .map_err(|e| format!("engine load: {e}"))?;
    runtime
        .propose(&handle, prefix, window)
        .await
        .map_err(|e| format!("engine propose: {e}"))
}

/// The detokenization seam for ADR-036's elected family-verified chat
/// path: decodes the session's committed token stream (the coordinator's
/// OWN committed data — the ids this machine drafted and the peers
/// verified) back to text under the pinned engine's tokenizer. Public
/// free-function so the desktop composes it over a cloned runtime handle
/// without a live node (the same pattern as [`runtime_tokenize`]).
pub async fn runtime_detokenize(
    runtime: Option<&Arc<dyn InferenceRuntime>>,
    ids: &[u32],
) -> Result<String, String> {
    let runtime = runtime.ok_or("no supervised engine")?;
    runtime.detokenize(ids).await.map_err(|e| e.to_string())
}

/// Picks the runtime per ADR-019:
///
/// - `mock` → `MockRuntime`, **only** when compiled under `cfg(test)` or the
///   `node-selftest` feature; otherwise a loud [`NodeError`]. When active the
///   selection prints a stderr banner and logs a warning: the mock runtime is
///   TEST-ONLY and local-loopback-only — it never serves remote peers (the
///   node wires no transport listener and no registration path).
/// - otherwise → `LlamaCppAdapter` over the loopback sidecar named by
///   [`ENV_LLAMACPP_URL`]/[`ENV_LLAMACPP_TOKEN`], or `None` (honest
///   runtime-less node; the gateway answers `no_peer`).
fn select_runtime(
    config: &NodeConfig,
    telemetry: &Telemetry,
    engine: Option<&engine::EngineHandle>,
) -> Result<Option<Arc<dyn InferenceRuntime>>, NodeError> {
    if config.mock {
        #[cfg(any(test, feature = "node-selftest"))]
        {
            const BANNER: &str = "\n\
                *****************************************************************\n\
                *  WARNING: MOCK RUNTIME ACTIVE (TEST-ONLY, ADR-019)            *\n\
                *  This node serves synthetic output ONLY on loopback.          *\n\
                *  It refuses to serve prompts to remote peers and never joins   *\n\
                *  any swarm roster. Do not use for real inference.              *\n\
                *****************************************************************";
            eprintln!("{BANNER}");
            telemetry.warn(
                "runtime.mock_active",
                &[
                    (
                        "policy",
                        "ADR-019: TEST-ONLY, excluded from any product claim",
                    ),
                    ("scope", "local-loopback-only; no remote serving"),
                ],
            );
            return Ok(Some(Arc::new(modelswarm_runtime::MockRuntime::new(
                0x5EED_0000_0000_0001,
                1.0,
            ))));
        }
        #[cfg(not(any(test, feature = "node-selftest")))]
        {
            let _ = telemetry;
            return Err(NodeError::MockRuntimeNotCompiled);
        }
    }

    // A supervised pinned engine takes precedence over ambient env vars.
    if let Some(engine) = engine {
        let adapter = LlamaCppAdapter::new(engine.runtime_config())
            .map_err(|e| NodeError::LlamaSidecarMisconfigured(e.to_string()))?;
        return Ok(Some(Arc::new(adapter)));
    }

    let url = std::env::var(ENV_LLAMACPP_URL);
    let token = std::env::var(ENV_LLAMACPP_TOKEN);
    match (url, token) {
        (Ok(url), Ok(token)) => {
            if !is_loopback_url(&url) {
                return Err(NodeError::LlamaSidebackNotLoopback(url));
            }
            let adapter = LlamaCppAdapter::new(LlamaCppConfig::new(url, token))
                .map_err(|e| NodeError::LlamaSidecarMisconfigured(e.to_string()))?;
            Ok(Some(Arc::new(adapter)))
        }
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => Err(NodeError::LlamaSidecarMisconfigured(
            "exactly one of the sidecar env vars is set".to_string(),
        )),
        (Err(_), Err(_)) => Ok(None),
    }
}

/// Accepts only `http://127.0.0.1…` or `http://localhost…` (ADR-002 loopback).
fn is_loopback_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("http://127.0.0.1")
        .or_else(|| url.strip_prefix("http://localhost"));
    match rest {
        Some(suffix) => suffix.is_empty() || suffix.starts_with(':') || suffix.starts_with('/'),
        None => false,
    }
}

/// Loads `<data_dir>/identity.seed` (exactly 32 bytes) or generates a fresh
/// identity and persists it. Never logs the seed; logs only load-vs-create.
pub fn load_or_create_identity(
    data_dir: &Path,
    telemetry: &Telemetry,
) -> Result<InstallationIdentity, NodeError> {
    let seed_path = data_dir.join(SEED_FILE_NAME);
    match std::fs::read(&seed_path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            telemetry.info("identity.loaded", &[("file", SEED_FILE_NAME)]);
            Ok(InstallationIdentity::from_bytes(&seed))
        }
        Ok(wrong_len) => {
            // Corrupt seed: refuse rather than silently replace an identity
            // the user may care about (lost key = re-enroll, ADR-004).
            Err(NodeError::Io(std::io::Error::other(format!(
                "{} has {} bytes; expected exactly 32 — move it aside to re-enroll",
                seed_path.display(),
                wrong_len.len()
            ))))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let identity = InstallationIdentity::generate();
            persist_seed(&seed_path, &identity.to_bytes())?;
            telemetry.info("identity.created", &[("file", SEED_FILE_NAME)]);
            Ok(identity)
        }
        Err(error) => Err(error.into()),
    }
}

/// Persists the seed with owner-only permissions where the platform has them.
///
/// Windows honesty (recorded in `docs/verification/phase-g-notes.md`): NTFS
/// has no POSIX mode bits; this write relies on the user-profile directory
/// ACL. The ADR-004 destination — DPAPI (`CryptProtectData`) or Windows
/// Credential Manager — is the recorded Phase F hardening replacement.
fn persist_seed(path: &Path, seed: &[u8; 32]) -> std::io::Result<()> {
    std::fs::write(path, seed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use modelswarm_gateway::GatewayError;

    fn config(data_dir: &Path) -> NodeConfig {
        NodeConfig {
            gateway_port: 0, // ephemeral: parallel tests must not share 11435
            data_dir: data_dir.to_path_buf(),
            ..NodeConfig::default()
        }
    }

    async fn start_stopped_node(cfg: NodeConfig) -> (NodeHandle, tokio::sync::watch::Sender<bool>) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = Node::start(cfg, rx).await.expect("node starts");
        (handle, tx)
    }

    #[test]
    fn default_config_shape() {
        let cfg = NodeConfig::default();
        assert_eq!(cfg.gateway_port, DEFAULT_PORT);
        assert!(!cfg.mock);
        assert!(cfg.tracker_base.is_none());
        assert!(cfg.profile_id.is_none());
        // (default_data_dir's install-root/data-root split is covered by
        // pre_separation_layout_migrates_once_into_data — asserting it here
        // would touch the real %LOCALAPPDATA% layout from a unit test.)
    }

    /// Install-root/data-root separation (2026-10-08): a pre-split layout
    /// migrates into `Data/` once, idempotently; engine dirs stay put.
    #[test]
    fn pre_separation_layout_migrates_once_into_data() {
        let root = tempfile::tempdir().unwrap();
        // Legacy layout: state at the root, engine dirs are app files.
        std::fs::write(root.path().join("identity.seed"), b"seed").unwrap();
        std::fs::write(root.path().join("config.json"), b"{}").unwrap();
        std::fs::write(root.path().join("session.token"), b"tok").unwrap();
        std::fs::create_dir_all(root.path().join("models").join("msp1_x")).unwrap();
        std::fs::write(
            root.path().join("models").join("msp1_x").join("model.gguf"),
            b"gguf",
        )
        .unwrap();
        std::fs::create_dir_all(root.path().join("engine")).unwrap();
        std::fs::write(root.path().join("engine").join("llama-server.exe"), b"exe").unwrap();

        super::migrate_pre_separation_layout(root.path());

        let data = root.path().join("Data");
        assert!(data.join("identity.seed").is_file());
        assert!(data.join("config.json").is_file());
        assert!(data.join("session.token").is_file());
        assert!(data
            .join("models")
            .join("msp1_x")
            .join("model.gguf")
            .is_file());
        assert!(root
            .path()
            .join("engine")
            .join("llama-server.exe")
            .is_file());
        assert!(!root.path().join("identity.seed").exists(), "renamed away");
        assert!(
            !root.path().join("models").exists(),
            "models moved wholesale"
        );

        // Idempotent: a second run must not move anything or fail.
        super::migrate_pre_separation_layout(root.path());
        assert!(data.join("identity.seed").is_file());
    }

    /// Real-engine GPU-preference test (ADR-024): set MSP_LLAMA_SERVER_CPU,
    /// MSP_LLAMA_SERVER_GPU (the engine-vulkan bundle) and MSP_REAL_GGUF.
    /// Proves the production path the desktop's Start button drives: GPU
    /// variant verified + spawned with -ngl inside the (extended) startup
    /// window, node telemetry carries backend=vulkan, the gateway serves,
    /// and shutdown leaves no process behind (kill-on-close job object).
    #[test]
    #[ignore = "set MSP_LLAMA_SERVER_CPU, MSP_LLAMA_SERVER_GPU and MSP_REAL_GGUF"]
    fn real_node_prefers_gpu_variant() {
        let cpu = std::env::var("MSP_LLAMA_SERVER_CPU").expect("MSP_LLAMA_SERVER_CPU");
        let gpu = std::env::var("MSP_LLAMA_SERVER_GPU").expect("MSP_LLAMA_SERVER_GPU");
        let model = std::env::var("MSP_REAL_GGUF").expect("MSP_REAL_GGUF");
        let dir = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let cfg = NodeConfig {
                gateway_port: 0,
                data_dir: dir.path().to_path_buf(),
                profile_id: Some("msp1:real".to_string()),
                engine_binary: Some(cpu.into()),
                engine_gpu_binary: Some(gpu.into()),
                engine_model: Some(model.into()),
                ..NodeConfig::default()
            };
            let (tx, rx) = tokio::sync::watch::channel(false);
            let node = Node::start(cfg, rx)
                .await
                .expect("node starts on GPU engine");
            assert_eq!(
                node.engine_backend.as_deref(),
                Some("vulkan"),
                "GPU variant must win when healthy"
            );
            // The gateway must actually serve through the engine.
            let addr = node.local_addr;
            let body = serde_json::json!({
                "model": "msp1:real",
                "messages": [{"role": "user", "content": "Say ok."}],
                "max_tokens": 8,
            });
            let resp = reqwest::Client::new()
                .post(format!("http://{addr}/v1/chat/completions"))
                .json(&body)
                .send()
                .await
                .expect("gateway responds");
            assert!(
                resp.status().is_success(),
                "chat must succeed: {}",
                resp.status()
            );
            drop(node);
            tx.send(true).ok();
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        });
    }

    #[test]
    fn loopback_url_guard() {
        assert!(is_loopback_url("http://127.0.0.1:8123"));
        assert!(is_loopback_url("http://localhost:8123"));
        assert!(is_loopback_url("http://127.0.0.1"));
        assert!(!is_loopback_url("http://0.0.0.0:8123"));
        assert!(!is_loopback_url("http://192.168.1.5:8123"));
        assert!(!is_loopback_url("https://127.0.0.1:8123"));
        assert!(!is_loopback_url("http://127.0.0.1.evil.test:8123"));
    }

    #[tokio::test]
    async fn gateway_binds_loopback_only_and_refuses_non_loopback() {
        // The guard itself refuses external addresses.
        for refused in ["0.0.0.0", "192.168.1.5", "8.8.8.8", "::"] {
            let ip: IpAddr = refused.parse().unwrap();
            assert!(
                matches!(assert_loopback(ip), Err(GatewayError::NotLoopback(_))),
                "{refused} must be refused"
            );
        }
        // And a spawned node is structurally loopback: the node builds the
        // socket address itself; the config only carries a port.
        let dir = tempfile::tempdir().unwrap();
        let (handle, tx) = start_stopped_node(config(dir.path())).await;
        assert!(handle.local_addr.ip().is_loopback());
        assert_eq!(handle.local_addr.ip().to_string(), "127.0.0.1");
        tx.send(true).unwrap();
        handle.stopped().await;
    }

    #[tokio::test]
    async fn identity_survives_restart_and_is_recorded_in_store() {
        let dir = tempfile::tempdir().unwrap();
        let (handle, tx) = start_stopped_node(config(dir.path())).await;
        let first = handle.installation_id.clone();
        tx.send(true).unwrap();
        handle.stopped().await;

        let (handle, tx) = start_stopped_node(config(dir.path())).await;
        assert_eq!(
            handle.installation_id, first,
            "identity must persist across restarts"
        );
        tx.send(true).unwrap();
        handle.stopped().await;

        // Seed file: present, exactly 32 bytes.
        let seed = std::fs::read(dir.path().join(SEED_FILE_NAME)).unwrap();
        assert_eq!(seed.len(), 32);

        // Store recorded the installation row.
        let conn = rusqlite::Connection::open(dir.path().join(STATE_FILE_NAME)).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM installations WHERE id = ?1",
                rusqlite::params![first],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn corrupt_seed_is_refused_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path()).unwrap();
        std::fs::write(dir.path().join(SEED_FILE_NAME), b"short").unwrap();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let error = match Node::start(config(dir.path()), rx).await {
            Ok(_) => panic!("a corrupt seed file must be refused, not replaced"),
            Err(error) => error,
        };
        assert!(matches!(error, NodeError::Io(_)), "got: {error:?}");
        drop(tx);
    }

    #[tokio::test]
    async fn self_test_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let report = selftest::run(dir.path(), 0)
            .await
            .expect("self-test passes");
        assert!(report.tokens > 0, "some SSE tokens must arrive");
        assert!(report.redacted_logs);
        assert!(handle_redaction_canary_absent(dir.path()));

        // Identity persisted (32-byte seed) + store opened by the node.
        let seed = std::fs::read(dir.path().join(SEED_FILE_NAME)).unwrap();
        assert_eq!(seed.len(), 32);
        assert!(dir.path().join(STATE_FILE_NAME).exists());

        assert_privacy_columns(dir.path().join(STATE_FILE_NAME));
    }

    /// Re-reads the node's own log file and asserts the canary is absent —
    /// the redaction gate checked independently of the report object.
    fn handle_redaction_canary_absent(data_dir: &Path) -> bool {
        let logs = std::fs::read_to_string(data_dir.join(LOG_RELATIVE_PATH)).unwrap();
        !logs.contains(selftest::CANARY)
    }

    /// The store the node created has no privacy-forbidden column names in
    /// ANY table (mirrors the store crate's own schema audit, run against the
    /// file this node actually opened).
    fn assert_privacy_columns(db: PathBuf) {
        let conn = rusqlite::Connection::open(db).unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(!tables.is_empty(), "migrations must have created tables");
        const FORBIDDEN: &[&str] = &[
            "prompt",
            "completion",
            "message",
            "content",
            "conversation",
            "secret",
            "token",
            "api_key",
            "password",
            "private",
        ];
        for table in &tables {
            let columns: Vec<String> = conn
                .prepare(&format!("PRAGMA table_info({table})"))
                .unwrap()
                .query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            for column in columns {
                let lower = column.to_ascii_lowercase();
                for forbidden in FORBIDDEN {
                    assert!(
                        !lower.contains(forbidden),
                        "privacy-forbidden column {column:?} in table {table:?}"
                    );
                }
            }
        }
    }

    /// ADR-034 seams: `engine_tokenize` maps text through the runtime's
    /// pinned tokenizer, and both seams fail HONESTLY (a stable label,
    /// never a panic) when no engine is supervised. The mock runtime's
    /// tokenizer is the UTF-8 byte sequence, so the mapping is exact.
    #[tokio::test]
    async fn engine_seams_tokenize_and_fail_closed_without_a_runtime() {
        let none = runtime_tokenize(None, "pin").await;
        assert_eq!(none.unwrap_err(), "no supervised engine");
        let none = runtime_propose_window(None, "msp1:x", &[1, 2], 8).await;
        assert_eq!(none.unwrap_err(), "no supervised engine");

        let runtime: Arc<dyn InferenceRuntime> = Arc::new(modelswarm_runtime::MockRuntime::new(
            0x5EED_0000_0000_0002,
            1.0,
        ));
        let ids = runtime_tokenize(Some(&runtime), "pin").await.unwrap();
        assert_eq!(ids, vec![u32::from(b'p'), u32::from(b'i'), u32::from(b'n')]);

        // The propose seam loads the profile and returns a bounded greedy
        // continuation of the prefix (deterministic per the mock's
        // splitmix64 mixing: two identical calls propose identical ids).
        let prefix = vec![u32::from(b'p'), u32::from(b'i'), u32::from(b'n')];
        let window = runtime_propose_window(Some(&runtime), "msp1:x", &prefix, 8)
            .await
            .unwrap();
        assert!(!window.is_empty() && window.len() <= 8, "bounded window");
        assert!(window.iter().all(|t| (*t as usize) < 256), "mock vocab");
        let again = runtime_propose_window(Some(&runtime), "msp1:x", &prefix, 8)
            .await
            .unwrap();
        assert_eq!(window, again, "greedy continuation is deterministic");
    }
}
