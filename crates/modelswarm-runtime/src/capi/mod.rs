//! `LlamaCppCapi`: IN-PROCESS runtime over the pinned llama.cpp C API
//! (P16 spike, feature `capi-adapter`, OFF by default; productionized under
//! the ADR-031 §5 gate — see `docs/verification/adr-031-productionization-
//! 2026-10-11.md`).
//!
//! Where the production [`crate::LlamaCppAdapter`] speaks HTTP to the pinned
//! `llama-server` sidecar (ADR-002/021), this research adapter loads the
//! *same pinned binaries* in-process (`llama.dll` from the hash-verified
//! engine bundle — see [`ffi`]) and drives the public C API directly. It is
//! the cooperative-mode research path the 9.6 pass-1 dry run justified:
//! per-round prefix re-post over the request/reply wire measured 1.07–3.36×
//! slower than the independently executed fastest single
//! (`experiments/reports/PASS-1-LOOPBACK-DRYRUN.md`).
//!
//! Capabilities this adapter exists to prove (all measured in the loopback
//! test, environment-labeled):
//!
//! - **Prefix/KV reuse across rounds** — the context retains its KV; each
//!   round decodes only the *delta* tokens. No prefix is ever re-posted.
//!   Rollback (draft rejection, divergence) uses `llama_memory_seq_rm`.
//! - **Logits access** — every batch row's logits are readable
//!   (`llama_get_logits_ith`), which exact speculative verification needs.
//! - **Batched linear draft verification** — k draft tokens verified in ONE
//!   `llama_decode` call (logits on every row) against the same sampler
//!   chain the pinned server uses, then a single KV rollback to the
//!   rejection point. Tree verification (branching drafts in one call) is
//!   NOT implemented: the C API exposes the primitives (`seq_cp`,
//!   multi-sequence batches) but no tree-attention mask construction; linear
//!   verify is the documented fallback (honest spike scope).
//!
//! ## ADR-031 §5 productionization (this revision)
//!
//! 1. **Shape-stable batching.** b11407 keeps two cached graph results,
//!    `gf_res_prev[n_outputs > 0]`, and only reuses the one used by the
//!    PREVIOUS decode; switching between a 0-output decode and a ≥1-output
//!    decode pays a full scheduler reset + graph rebuild + re-allocation
//!    (measured 8–27 ms per call on the dev machine — the real mechanism
//!    behind the spike's "graph_reserve-class" shape churn; see the
//!    verification doc). The adapter therefore defaults to
//!    [`CapiConfig::uniform_outputs`] — every decode requests at least the
//!    final row's logits, exactly what llama-server's own pipeline does —
//!    and pools one `llama_batch` per handle at full capacity so
//!    steady-state decodes perform no per-call batch allocation. A load-time
//!    warmup decode at the maximum verify geometry sizes the output buffer
//!    once; verify windows of differing widths reuse the reserved graph
//!    (measured: free).
//! 2. **`spawn_blocking` offload.** Every engine call that can block
//!    (context creation, tokenize/detokenize, decode/eval, KV rollback,
//!    sampling, state sizing) runs on the tokio blocking pool; the async
//!    executor only awaits. A tokio runtime is therefore REQUIRED for this
//!    adapter (research consumers — bench, session, sim — all run tokio).
//! 3. **Per-handle KV RAM accounting.** Each handle's KV occupancy (tokens)
//!    is bounded by [`CapiConfig::kv_token_cap`] (default: the context
//!    window) with an honest `kv_budget_exceeded` error, an adapter-wide
//!    byte budget bounds concurrent handles ([`CapiConfig::kv_byte_budget`],
//!    estimated from the model's public GQA dimensions), and
//!    [`LlamaCppCapi::kv_usage`] reports per-handle usage (plus the
//!    engine-reported `llama_state_get_size`) for telemetry. Totals are also
//!    surfaced through [`crate::RuntimeMetrics::kv_bytes_estimate`] and
//!    `engine_decode_calls`.
//! 4. **Vulkan in-process** is exercised by the env-gated
//!    `tests/capi_vulkan.rs` (same registration path, one bundle per
//!    process — see below; E0 CPU≠Vulkan means exactness is pinned
//!    WITHIN a backend, never across).
//! 5. One pinned engine bundle per process, fail-closed: a second adapter
//!    construction naming a DIFFERENT bundle directory is refused (backend
//!    registration is process-global; ADR-031 §2).
//!
//! Trait conformance: implements the unchanged [`crate::InferenceRuntime`]
//! shape (ADR-019), overrides `propose` (greedy self-continuation, ADR-021 —
//! KV-cheap), and adds verification as an inherent method (`verify_drafts`)
//! rather than a trait change; folding it into the trait is the scheduler's
//! gated follow-up decision.
//!
//! Research-only posture: production serving stays on the HTTP adapter; the
//! feature is off by default and the node never enables it.

mod ffi;
pub mod verify;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;

pub use ffi::LlamaLib;
use ffi::{ContextPtr, Logits, PooledBatch};
pub use verify::{BatchVerifyEngineMirror, CapiVerifyEngine, VerifyBackend, VerifyEngineCaps};

use crate::{
    DecodeEvent, DecodeEventStream, Handle, KvCommitment, RuntimeDescriptor, RuntimeError,
    RuntimeMetrics, SamplingParams, TaskId,
};

/// Budget for one `propose` window (matches the HTTP adapter's default
/// request timeout class).
const PROPOSE_BUDGET: Duration = Duration::from_secs(60);

/// ADR-032 §1 frozen cap: `WINDOW_CAP = 32` tokens per verify window. The
/// adapter's default `verify_window_max` matches it; larger draft windows
/// are rejected before any engine work.
pub const WINDOW_CAP: u32 = 32;

/// f16 K/V cells (the pinned engine's default `type_k`/`type_v`), 2 bytes.
const KV_CELL_BYTES: u64 = 2;

/// Builder-style configuration for [`LlamaCppCapi`].
#[derive(Debug, Clone)]
pub struct CapiConfig {
    /// Hash-verified engine bundle directory containing `llama.dll` (or the
    /// per-OS C-API library) and its ggml dependencies.
    pub engine_dir: PathBuf,
    /// Path to the verified GGUF artifact (sha-verified upstream by the
    /// artifact manager; this adapter re-derives nothing).
    pub model_path: PathBuf,
    /// Context window (prompt + generation budget); mirrors the server's
    /// `-c` so loopback comparisons see identical capacity.
    pub n_ctx: u32,
    /// Compute threads for decode; `None` = engine default (what
    /// `llama-server` uses when `-t` is not passed).
    pub n_threads: Option<u32>,
    /// Pinned-engine identity for `id()`.
    pub engine: Option<crate::llamacpp::EngineIdentity>,
    /// Largest draft window `verify_drafts` accepts (1..=[`WINDOW_CAP`]).
    /// Also pins the context's output reservation (`n_outputs_max`) and the
    /// load-time warmup geometry, so every steady-state verify reuses the
    /// reserved graph regardless of width.
    pub verify_window_max: u32,
    /// ADR-031 §5.1 shape stability: request logits on the final row of
    /// EVERY decode (including prefill deltas) so the engine never switches
    /// between its 0-output and ≥1-output graph slots — the measured 8–27 ms
    /// per-transition churn. Mirrors llama-server's pipeline. Disable only
    /// to reproduce the churn in measurements.
    pub uniform_outputs: bool,
    /// Per-handle KV token bound (default: `n_ctx`). A sync/verify target
    /// longer than this cap fails with `kv_budget_exceeded` BEFORE any
    /// engine work — a session cannot accumulate unbounded KV across verify
    /// rounds.
    pub kv_token_cap: Option<u64>,
    /// Adapter-wide KV byte budget across ALL handles (estimated from the
    /// model's public GQA dimensions × `n_ctx`; see [`LlamaCppCapi::kv_usage`]
    /// for the engine-reported cross-check). `load()` refuses a new handle
    /// whose estimate would exceed it (`kv_budget_exceeded`). `None` =
    /// unbounded (reported, not enforced) — research default.
    pub kv_byte_budget: Option<u64>,
    /// Load-time warmup: one max-geometry decode (all-rows logits) then a
    /// full KV clear, sizing the engine's output buffer and exercising the
    /// reserved graph shapes once so steady-state calls are
    /// allocation-stable. The warmup leaves no KV and does not count
    /// against `decode_calls`.
    pub warmup: bool,
}

impl CapiConfig {
    /// Configuration with the defaults used by the node's engine spec
    /// (`ctx = 4096`, threads = engine default).
    pub fn new(engine_dir: impl Into<PathBuf>, model_path: impl Into<PathBuf>) -> Self {
        Self {
            engine_dir: engine_dir.into(),
            model_path: model_path.into(),
            n_ctx: 4096,
            n_threads: None,
            engine: None,
            verify_window_max: WINDOW_CAP,
            uniform_outputs: true,
            kv_token_cap: None,
            kv_byte_budget: None,
            warmup: true,
        }
    }

    /// Attaches the pinned-engine identity.
    pub fn with_engine(mut self, engine: crate::llamacpp::EngineIdentity) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Sets the max verify window (clamped to 1..=[`WINDOW_CAP`] at use).
    pub fn with_verify_window_max(mut self, window: u32) -> Self {
        self.verify_window_max = window;
        self
    }

    /// Overrides uniform-output shape stability (measurement A/B only).
    pub fn with_uniform_outputs(mut self, uniform: bool) -> Self {
        self.uniform_outputs = uniform;
        self
    }

    /// Sets the per-handle KV token cap.
    pub fn with_kv_token_cap(mut self, cap: u64) -> Self {
        self.kv_token_cap = Some(cap);
        self
    }

    /// Sets the adapter-wide KV byte budget.
    pub fn with_kv_byte_budget(mut self, budget: u64) -> Self {
        self.kv_byte_budget = Some(budget);
        self
    }

    /// Enables/disables the load-time warmup decode.
    pub fn with_warmup(mut self, warmup: bool) -> Self {
        self.warmup = warmup;
        self
    }

    /// Effective verify-window pin (1..=WINDOW_CAP).
    pub fn effective_verify_window(&self) -> u32 {
        self.verify_window_max.clamp(1, WINDOW_CAP)
    }

    /// Effective per-handle KV token cap.
    pub fn effective_kv_token_cap(&self) -> u64 {
        self.kv_token_cap.unwrap_or(u64::from(self.n_ctx))
    }
}

/// Outcome of one exact speculative verification round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutcome {
    /// Draft tokens accepted (a prefix of `draft`), token-exact under the
    /// declared sampling contract.
    pub accepted: Vec<u32>,
    /// The verifier's own next token: the replacement at the rejection
    /// point, or the bonus token after full acceptance (`None` only when
    /// generation ended at an EOG token).
    pub bonus: Option<u32>,
}

/// Per-handle KV accounting snapshot (telemetry surface; see
/// [`LlamaCppCapi::kv_usage`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandleKvUsage {
    /// Runtime handle id.
    pub handle_id: u64,
    /// Profile the handle was loaded for.
    pub profile_id: String,
    /// Tokens currently occupying the handle's KV (sequence 0).
    pub kv_tokens: u64,
    /// Effective per-handle token cap.
    pub kv_token_cap: u64,
    /// Capacity-based KV byte estimate for this handle (constant from load:
    /// the engine pre-allocates the KV for the full context window).
    pub kv_bytes_estimate: u64,
    /// Engine-reported `llama_state_get_size` (used-state bytes: KV contents
    /// + output buffers — an upper-bound proxy for live usage).
    pub state_bytes: u64,
    /// Engine `llama_decode` calls on this handle since load (post-warmup).
    /// The ADR-032 I4 one-pass property is pinned against this counter.
    pub decode_calls: u64,
}

/// Adapter-wide KV usage report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvUsageReport {
    /// One entry per live handle.
    pub handles: Vec<HandleKvUsage>,
    /// Sum of per-handle capacity estimates.
    pub total_kv_bytes_estimate: u64,
    /// Configured adapter-wide byte budget, when set.
    pub kv_byte_budget: Option<u64>,
}

/// Per-handle decode state: the engine context, its POOLED batch, and the
/// adapter's bookkeeping of what is in its KV (the token `trail`), which KV
/// position the current logits rows end at, and the engine decode-call
/// count. Invariant: `trail` holds exactly the tokens decoded into sequence
/// 0; sampled-but-not-decoded tokens are never in it.
struct HandleState {
    ctx: ContextPtr,
    batch: PooledBatch,
    /// Profile the handle was loaded for (telemetry).
    profile_id: String,
    trail: Vec<u32>,
    /// KV position of the last output row of the most recent decode
    /// (`None` when no logits are live). Rows are only valid until the next
    /// decode, exactly like the engine's own output buffer.
    last_output_pos: Option<u32>,
    /// Engine `llama_decode` calls since load (reset after the warmup; the
    /// ADR-032 I4 one-pass property is pinned against this counter).
    decode_calls: u64,
}

struct Shared {
    metrics: RwLock<RuntimeMetrics>,
    next_handle: AtomicU64,
    handles: Mutex<HashMap<u64, Arc<Mutex<HandleState>>>>,
    /// TaskId of the most recent `cancel` call (0 = none); decode loops
    /// observe it between steps (cooperative, deadline-class cancellation —
    /// the same approximation as the HTTP adapter's abort-on-disconnect).
    cancelled: AtomicU64,
    /// Sum of per-handle KV capacity estimates (byte-budget accounting).
    kv_bytes_estimate: AtomicU64,
    /// Total engine decode calls across handles (telemetry).
    decode_calls: AtomicU64,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            metrics: RwLock::new(RuntimeMetrics::default()),
            next_handle: AtomicU64::new(1),
            handles: Mutex::new(HashMap::new()),
            cancelled: AtomicU64::new(0),
            kv_bytes_estimate: AtomicU64::new(0),
            decode_calls: AtomicU64::new(0),
        }
    }
}

/// Cloneable engine core: everything the blocking tasks need to drive the
/// pinned engine (the model/vocab pair, geometry pins, KV accounting
/// inputs). Spawned into `tokio::task::spawn_blocking` closures; engine
/// calls on one handle remain serialized by that handle's mutex.
#[derive(Clone)]
struct Engine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    lib: Arc<LlamaLib>,
    model: ffi::ModelPtr,
    vocab: *const ffi::LlamaVocab,
    eos_id: Option<u32>,
    n_ctx: u32,
    /// Compute threads; `None` = engine default.
    n_threads: Option<u32>,
    /// Pinned verify geometry (rows = window + 1).
    verify_window: u32,
    uniform_outputs: bool,
    kv_token_cap: u64,
    kv_bytes_per_handle: u64,
    kv_byte_budget: Option<u64>,
    shared: Arc<Shared>,
}

impl Engine {
    fn context(&self, handle: &Handle) -> Result<Arc<Mutex<HandleState>>, RuntimeError> {
        self.inner
            .shared
            .handles
            .lock()
            .map_err(|_| RuntimeError::Http("capi-adapter: state lock poisoned".into()))?
            .get(&handle.handle_id())
            .cloned()
            .ok_or(RuntimeError::NotLoaded(handle.handle_id()))
    }

    /// Runs `f` under the handle's mutex on the tokio blocking pool — the
    /// ADR-031 §5.2 offload discipline for every engine call.
    async fn with_handle<T, F>(&self, handle: &Handle, f: F) -> Result<T, RuntimeError>
    where
        T: Send + 'static,
        F: FnOnce(&EngineInner, &mut HandleState) -> Result<T, RuntimeError> + Send + 'static,
    {
        let context = self.context(handle)?;
        let engine = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut state = context
                .lock()
                .map_err(|_| RuntimeError::Http("capi-adapter: state lock poisoned".into()))?;
            f(&engine.inner, &mut state)
        })
        .await
        .map_err(|e| RuntimeError::Http(format!("capi-adapter: engine task failed: {e}")))??;
        Ok(result)
    }
}

/// In-process [`crate::InferenceRuntime`] over the pinned llama.cpp C API.
///
/// Construction loads the pinned C-API library, initializes the backend
/// (process-global, once, one bundle per process — fail-closed on a second,
/// different bundle), loads the model and runs an ABI canary against the
/// engine's default parameters. Each `load()` creates a fresh context (own
/// KV and pooled batch) sharing the one model.
pub struct LlamaCppCapi {
    engine: Engine,
    config: CapiConfig,
}

// `Send`/`Sync` are implemented in `ffi.rs` (the crate's single unsafe
// scope): the adapter's only raw pointer beyond the owned wrappers is the
// `vocab` inside `EngineInner` (derived from the owned `ModelPtr` and freed
// together with it), and every engine call is serialized by the owning
// handle's mutex.

/// Process-global backend bring-up guard: `llama_backend_init` once, then
/// `ggml_backend_load_all_from_path(<bundle dir>)` once for the FIRST
/// bundle (modern llama.cpp refuses to load a model until the bundle's
/// ggml backends are registered — the server does this internally at
/// startup). A second construction naming a DIFFERENT bundle directory
/// fails closed (ADR-031 §2: registration is process-global; silently
/// keeping the first registration would mis-attribute the backend).
static BACKEND_READY: OnceLock<Result<PathBuf, String>> = OnceLock::new();

/// Pure decision core of the one-bundle-per-process guard (unit-tested).
fn bundle_guard_decision(registered: Option<&PathBuf>, requested: &PathBuf) -> Result<(), String> {
    match registered {
        None => Ok(()),
        Some(dir) if dir == requested => Ok(()),
        Some(dir) => Err(format!(
            "a different engine bundle is already registered in this process ({}); \
             ADR-031 §2: exactly one pinned bundle per process — refusing {}",
            dir.display(),
            requested.display()
        )),
    }
}

/// Capacity-based KV byte estimate from the model's public GQA dimensions:
/// `2 (K+V) × n_layer × n_ctx × n_head_kv × head_dim × 2 B (f16)`. The
/// engine pre-allocates the KV for the full window at context creation, so
/// this is the per-handle RAM/VRAM footprint from load (before offload
/// accounting); `llama_state_get_size` cross-checks the USED state.
fn estimate_kv_bytes(n_layer: u32, n_head_kv: u32, head_dim: u64, n_ctx: u32) -> u64 {
    if n_layer == 0 || n_head_kv == 0 || head_dim == 0 || n_ctx == 0 {
        return 0;
    }
    2 * KV_CELL_BYTES * u64::from(n_layer) * u64::from(n_head_kv) * head_dim * u64::from(n_ctx)
}

impl LlamaCppCapi {
    /// Loads the pinned library + model and runs the ABI canary. Blocking
    /// (library + model load); wrap in `spawn_blocking` at the call site if
    /// invoked from async context — the trait methods below do exactly that
    /// for their engine work.
    pub fn new(config: CapiConfig) -> Result<Self, RuntimeError> {
        let err = |message: String| RuntimeError::Http(format!("capi-adapter: {message}"));
        let lib = Arc::new(
            LlamaLib::load(&config.engine_dir)
                .map_err(|e| err(format!("pinned library load: {e}")))?,
        );
        let requested_bundle = config
            .engine_dir
            .canonicalize()
            .unwrap_or_else(|_| config.engine_dir.clone());
        let backend_ready =
            BACKEND_READY.get_or_init(|| match bundle_guard_decision(None, &requested_bundle) {
                Ok(()) => {
                    lib.backend_init();
                    match lib.load_bundle_backends() {
                        Ok(()) => Ok(requested_bundle.clone()),
                        Err(e) => Err(format!("backend registry: {e}")),
                    }
                }
                Err(e) => Err(e),
            });
        let registered = backend_ready.as_ref().map_err(|e| err(e.clone()))?;
        bundle_guard_decision(Some(registered), &requested_bundle).map_err(err)?;

        // ABI canary: the default-params struct round-trip must land on the
        // documented b11407 shape. A future pin that changes the layout
        // surfaces HERE as a construction error, never as silent corruption.
        let defaults = lib.context_default_params();
        if defaults.n_batch < 256
            || defaults.n_ctx == 0
            || defaults.n_seq_max != 1
            || defaults.n_threads < -1
        {
            return Err(err(format!(
                "ABI canary failed: b11407 context defaults look wrong \
                 (n_ctx={}, n_batch={}, n_seq_max={}, n_threads={})",
                defaults.n_ctx, defaults.n_batch, defaults.n_seq_max, defaults.n_threads
            )));
        }

        let model = lib
            .load_model(&config.model_path, lib.model_default_params())
            .map_err(|e| err(format!("model load: {e}")))?;
        let vocab = lib.vocab(&model);
        let n_vocab = lib.vocab_n_tokens(vocab);
        if n_vocab == 0 {
            return Err(err("model reports an empty vocabulary".into()));
        }
        lib.set_cached_vocab_n_tokens(n_vocab);
        let eos_id = {
            let eos = lib.vocab_eos(vocab);
            (eos >= 0).then_some(eos as u32)
        };
        // KV RAM accounting input (public GQA dimensions; head_dim = n_embd
        // / n_head). GQA models: n_head_kv < n_head.
        let n_layer = lib.model_n_layer(&model);
        let n_head = lib.model_n_head(&model);
        let n_head_kv = lib.model_n_head_kv(&model).max(1);
        let head_dim = if n_head > 0 {
            u64::from(lib.model_n_embd(&model)) / u64::from(n_head)
        } else {
            0
        };
        let kv_bytes_per_handle = estimate_kv_bytes(n_layer, n_head_kv, head_dim, config.n_ctx);
        let verify_window = config.effective_verify_window();
        let engine = Engine {
            inner: Arc::new(EngineInner {
                lib,
                model,
                vocab,
                eos_id,
                n_ctx: config.n_ctx,
                n_threads: config.n_threads,
                verify_window,
                uniform_outputs: config.uniform_outputs,
                kv_token_cap: config.effective_kv_token_cap(),
                kv_bytes_per_handle,
                kv_byte_budget: config.kv_byte_budget,
                shared: Arc::new(Shared::default()),
            }),
        };
        Ok(Self { engine, config })
    }

    /// The model's EOS token id from the pinned GGUF vocabulary.
    pub fn eos_id(&self) -> Option<u32> {
        self.engine.inner.eos_id
    }

    /// Vocabulary size (logits row width).
    pub fn vocab_size(&self) -> u32 {
        self.engine
            .inner
            .lib
            .vocab_n_tokens(self.engine.inner.vocab)
    }

    /// The pinned verify-window geometry (rows = window + 1).
    pub fn verify_window_max(&self) -> u32 {
        self.engine.inner.verify_window
    }

    fn lock_poisoned() -> RuntimeError {
        RuntimeError::Http("capi-adapter: state lock poisoned".into())
    }
}

impl EngineInner {
    /// Synchronizes the context's KV to `target`: rolls back to the longest
    /// common prefix (`llama_memory_seq_rm`) and decodes only the delta.
    /// This is the structural fix for the per-round prefix re-post cost —
    /// the prefix is never evaluated, serialized or shipped twice.
    ///
    /// When `keep_last_logits` is set, the final position's logits are live
    /// on return; if the target is already the trail but its tail logits
    /// are stale, the last token alone is rolled back and re-evaluated (a
    /// single-token cost, never a prefix cost).
    ///
    /// Under `uniform_outputs` the delta decodes request the final row's
    /// logits even when the caller does not need them: b11407 caches two
    /// graph slots (`gf_res_prev[n_outputs > 0]`) and only reuses the slot
    /// the previous decode used, so alternating 0-output and ≥1-output
    /// decodes pays a scheduler reset + re-allocation per transition
    /// (measured 8–27 ms; ADR-031 §5.1). One extra logits row costs a
    /// single lm_head pass (≪ the churn).
    fn sync(
        &self,
        state: &mut HandleState,
        target: &[u32],
        keep_last_logits: bool,
    ) -> Result<(), RuntimeError> {
        if target.is_empty() {
            return Err(RuntimeError::MalformedResponse(
                "sync of an empty token span".to_string(),
            ));
        }
        if target.len() as u64 > self.kv_token_cap {
            return Err(RuntimeError::Api {
                status: 429,
                code: "kv_budget_exceeded".to_string(),
                message: format!(
                    "{} tokens exceed the per-handle KV cap of {} (context window {}); \
                     the session must not accumulate unbounded KV",
                    target.len(),
                    self.kv_token_cap,
                    self.n_ctx
                ),
            });
        }
        if target.len() as u64 > u64::from(self.n_ctx) {
            return Err(RuntimeError::Api {
                status: 400,
                code: "prompt_too_long".to_string(),
                message: format!(
                    "{} tokens exceed the context window of {}",
                    target.len(),
                    self.n_ctx
                ),
            });
        }
        let common = common_prefix_len(&state.trail, target);
        if common < state.trail.len() {
            let ok = self.lib.memory_seq_rm(&state.ctx, common as ffi::LlamaPos);
            if !ok {
                return Err(RuntimeError::Api {
                    status: 500,
                    code: "kv_rollback_refused".to_string(),
                    message: format!("llama_memory_seq_rm refused rollback to position {common}"),
                });
            }
            state.trail.truncate(common);
        }
        // The pinned batch geometry: deltas request the final row's logits
        // under `uniform_outputs` (ADR-031 §5.1 — never switch graph slots).
        let logits_mode = |want: Logits| {
            if self.uniform_outputs {
                want.promote()
            } else {
                want
            }
        };
        if common < target.len() {
            let started = Instant::now();
            let delta = &target[common..];
            let mode = logits_mode(if keep_last_logits {
                Logits::Last
            } else {
                Logits::None
            });
            self.decode_into(state, delta, mode)?;
            state.trail.extend_from_slice(delta);
            self.record_prefill(delta.len() as u64, started.elapsed());
            return Ok(());
        }
        // trail == target already.
        if keep_last_logits && state.last_output_pos != Some((target.len() - 1) as u32) {
            let cut = (target.len() - 1) as ffi::LlamaPos;
            let ok = self.lib.memory_seq_rm(&state.ctx, cut);
            if !ok {
                return Err(RuntimeError::Api {
                    status: 500,
                    code: "kv_rollback_refused".to_string(),
                    message: format!("tail-logits rollback to {cut} refused"),
                });
            }
            state.trail.truncate(target.len() - 1);
            let tail = target[target.len() - 1];
            self.decode_into(state, std::slice::from_ref(&tail), Logits::Last)?;
            state.trail.push(tail);
        }
        Ok(())
    }

    /// One pooled `llama_decode` call; updates `last_output_pos` and the
    /// decode-call accounting per the mode.
    fn decode_into(
        &self,
        state: &mut HandleState,
        tokens: &[u32],
        mode: Logits,
    ) -> Result<(), RuntimeError> {
        if tokens.is_empty() {
            return Ok(());
        }
        let start = state.trail.len() as u32;
        self.lib
            .decode_pooled(&mut state.ctx, &mut state.batch, tokens, mode)
            .map_err(|rc| RuntimeError::Api {
                status: 500,
                code: "decode_failed".to_string(),
                message: format!("llama_decode rc={rc}"),
            })?;
        state.decode_calls += 1;
        self.shared.decode_calls.fetch_add(1, Ordering::Relaxed);
        state.last_output_pos = match mode {
            Logits::None => None,
            _ => Some(start + tokens.len() as u32 - 1),
        };
        Ok(())
    }

    /// Samples the next token given that the context is synced to `prefix`.
    /// The sampled token is NOT added to the trail (it has not been decoded).
    fn sample_next(
        &self,
        state: &mut HandleState,
        prefix: &[u32],
        sampling: &SamplingParams,
    ) -> Result<u32, RuntimeError> {
        self.sync(state, prefix, true)?;
        self.sample_row(state, -1, sampling)
    }

    /// Decodes `token` (one position) and samples its logits row. Returns
    /// the NEXT token (not yet decoded). Used by stream steps + propose.
    fn step_sampled(&self, state: &mut HandleState, token: u32) -> Result<u32, RuntimeError> {
        let started = Instant::now();
        self.decode_into(state, std::slice::from_ref(&token), Logits::Last)?;
        state.trail.push(token);
        let next = self.sample_row(state, -1, &SamplingParams::default())?;
        self.record_decode(1, started.elapsed());
        Ok(next)
    }

    fn sample_row(
        &self,
        state: &mut HandleState,
        row: i32,
        sampling: &SamplingParams,
    ) -> Result<u32, RuntimeError> {
        let mut chain = self
            .lib
            .build_chain(sampling)
            .map_err(|e| RuntimeError::Http(format!("capi-adapter: sampler: {e}")))?;
        Ok(self.lib.sample(&mut chain, &mut state.ctx, row))
    }

    /// Load-time warmup (ADR-031 §5.1): ONE max-geometry decode with
    /// all-rows logits, read one logits row, then a full KV clear. Sizes
    /// the engine's output buffer and exercises the reserved graph shapes
    /// once; leaves zero KV and resets the decode-call accounting (warmup
    /// is load-time, not session work).
    fn warmup(&self, state: &mut HandleState) -> Result<(), RuntimeError> {
        let rows = (self.verify_window as u64 + 1).min(u64::from(self.n_ctx)) as usize;
        let tokens = vec![0u32; rows];
        if self.decode_into(state, &tokens, Logits::All).is_err() {
            // Warmup failure is not fatal to construction semantics, but it
            // MUST be loud: steady-state shape stability was not established.
            return Err(RuntimeError::Api {
                status: 500,
                code: "warmup_failed".to_string(),
                message: "warmup decode at max verify geometry failed".to_string(),
            });
        }
        // Touch one logits row so the output path is fully materialized.
        if self.lib.logits_row(&mut state.ctx, 0).is_none() {
            return Err(RuntimeError::Api {
                status: 500,
                code: "warmup_failed".to_string(),
                message: "warmup logits row unavailable".to_string(),
            });
        }
        if !self.lib.memory_seq_rm_all(&state.ctx) {
            return Err(RuntimeError::Api {
                status: 500,
                code: "warmup_failed".to_string(),
                message: "warmup KV clear refused".to_string(),
            });
        }
        state.trail.clear();
        state.last_output_pos = None;
        // Per-handle accounting excludes the load-time warmup (the adapter
        // total keeps it: it is real engine work telemetry).
        state.decode_calls = 0;
        Ok(())
    }

    fn record_prefill(&self, tokens: u64, elapsed: Duration) {
        let micros = elapsed.as_micros();
        if tokens > 0 && micros > 0 {
            if let Ok(mut metrics) = self.shared.metrics.write() {
                metrics.prefill_tokens_per_ms = tokens as f64 / (micros as f64 / 1000.0);
            }
        }
    }

    fn record_decode(&self, tokens: u64, elapsed: Duration) {
        let micros = elapsed.as_micros();
        if tokens > 0 && micros > 0 {
            if let Ok(mut metrics) = self.shared.metrics.write() {
                metrics.decode_tokens_per_ms = tokens as f64 / (micros as f64 / 1000.0);
            }
        }
    }

    /// EXACT SPECULATIVE VERIFICATION core (the cooperative capability; the
    /// async wrapper handles offload + metrics). See
    /// [`LlamaCppCapi::verify_drafts`] for the contract.
    fn verify_locked(
        &self,
        state: &mut HandleState,
        prefix: &[u32],
        draft: &[u32],
        sampling: &SamplingParams,
    ) -> Result<VerifyOutcome, RuntimeError> {
        if draft.is_empty() {
            // Degenerate round: just produce the verifier's next token.
            let token = self.sample_next(state, prefix, sampling)?;
            return Ok(VerifyOutcome {
                accepted: Vec::new(),
                bonus: (!self.is_eog_at(token)).then_some(token),
            });
        }
        // 1. KV to prefix minus its last token (no logits rows needed — the
        //    batch below re-decodes that token with all rows live).
        self.sync(state, &prefix[..prefix.len() - 1], false)?;
        // 2. One batched decode: [prefix_last, draft…] with all rows live.
        let mut batch: Vec<u32> = Vec::with_capacity(draft.len() + 1);
        batch.push(prefix[prefix.len() - 1]);
        batch.extend_from_slice(draft);
        self.decode_into(state, &batch, Logits::All)?;
        state.trail.clear();
        state.trail.extend_from_slice(prefix);
        state.trail.extend_from_slice(draft);

        // 3. Accept while the target's own sampler choice matches the draft.
        let mut chain = self
            .lib
            .build_chain(sampling)
            .map_err(|e| RuntimeError::Http(format!("capi-adapter: sampler: {e}")))?;
        let mut accepted = 0usize;
        let mut replacement: Option<u32> = None;
        for (i, draft_token) in draft.iter().enumerate() {
            let verifier_token = self.lib.sample(&mut chain, &mut state.ctx, i as i32);
            if verifier_token == *draft_token {
                accepted += 1;
            } else {
                replacement = Some(verifier_token);
                break;
            }
        }
        if accepted == draft.len() {
            // Full acceptance: bonus token from the final row (not decoded).
            let bonus = self
                .lib
                .sample(&mut chain, &mut state.ctx, draft.len() as i32);
            if self.is_eog_at(bonus) {
                return Ok(VerifyOutcome {
                    accepted: draft.to_vec(),
                    bonus: None,
                });
            }
            return Ok(VerifyOutcome {
                accepted: draft.to_vec(),
                bonus: Some(bonus),
            });
        }
        // 4. Roll back to the rejection point.
        let keep = prefix.len() + accepted;
        let rollback_ok = self.lib.memory_seq_rm(&state.ctx, keep as ffi::LlamaPos);
        if !rollback_ok {
            return Err(RuntimeError::Api {
                status: 500,
                code: "kv_rollback_refused".to_string(),
                message: format!("verify rollback to {keep} refused"),
            });
        }
        state.trail.truncate(keep);
        state.last_output_pos = None;
        let replacement = replacement.expect("rejection path sets a replacement");
        if self.is_eog_at(replacement) {
            return Ok(VerifyOutcome {
                accepted: draft[..accepted].to_vec(),
                bonus: None,
            });
        }
        Ok(VerifyOutcome {
            accepted: draft[..accepted].to_vec(),
            bonus: Some(replacement),
        })
    }

    fn is_eog_at(&self, token: u32) -> bool {
        self.lib.vocab_is_eog(self.vocab, token)
    }
}

/// Longest common prefix length of two token slices.
fn common_prefix_len(a: &[u32], b: &[u32]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

impl LlamaCppCapi {
    /// EXACT SPECULATIVE VERIFICATION (the cooperative capability; inherent
    /// method — see the module docs). Verifies `draft` continuing `prefix`
    /// in ONE batched decode:
    ///
    /// 1. sync the KV to `prefix` **without** its last token,
    /// 2. one `llama_decode` batch of `[prefix_last, draft…]` with logits on
    ///    every row — row `i` is the target distribution at draft position
    ///    `i` (the final row additionally yields the bonus token),
    /// 3. accept `draft[i]` while the sampler chain (the same chain the
    ///    pinned server uses) would sample it from row `i`,
    /// 4. on the first rejection roll the KV back to the rejection point
    ///    (`llama_memory_seq_rm`); the replacement token is sampled from the
    ///    rejecting row.
    ///
    /// The verifier context is left at `prefix + accepted` with the
    /// replacement/bonus token sampled but NOT decoded — the caller's next
    /// round feeds it back through `prefix` and the KV grows by the delta,
    /// exactly like every other sync. Windows longer than the adapter's
    /// pinned `verify_window_max` are rejected BEFORE any engine work
    /// (ADR-032 §1/RC-8: `payload_too_large`).
    pub async fn verify_drafts(
        &self,
        handle: &Handle,
        prefix: &[u32],
        draft: &[u32],
        sampling: &SamplingParams,
    ) -> Result<VerifyOutcome, RuntimeError> {
        if prefix.is_empty() {
            return Err(RuntimeError::MalformedResponse(
                "verify_drafts with empty prefix; prefill first".to_string(),
            ));
        }
        if draft.len() as u64 > u64::from(self.engine.inner.verify_window) {
            return Err(RuntimeError::Api {
                status: 413,
                code: "payload_too_large".to_string(),
                message: format!(
                    "draft window {} exceeds the pinned verify window {} (before any engine work)",
                    draft.len(),
                    self.engine.inner.verify_window
                ),
            });
        }
        if prefix.len() + draft.len() + 1 >= self.engine.inner.n_ctx as usize {
            return Err(RuntimeError::Api {
                status: 400,
                code: "prompt_too_long".to_string(),
                message: format!(
                    "prefix {} + draft {} exceed the context window of {}",
                    prefix.len(),
                    draft.len(),
                    self.engine.inner.n_ctx
                ),
            });
        }
        let started = Instant::now();
        let draft = draft.to_vec();
        let prefix = prefix.to_vec();
        let sampling = *sampling;
        let outcome = self
            .engine
            .with_handle(handle, move |inner, state| {
                inner.verify_locked(state, &prefix, &draft, &sampling)
            })
            .await?;
        self.engine
            .inner
            .record_decode(outcome.accepted.len() as u64 + 1, started.elapsed());
        Ok(outcome)
    }

    /// Per-handle KV accounting snapshot (ADR-031 §5.3): tokens vs cap, the
    /// capacity-based byte estimate, the engine-reported used-state bytes
    /// (`llama_state_get_size` — walks the memory module, hence offloaded),
    /// and the per-handle decode-call count. The adapter-wide total is the
    /// byte-budget enforcement input.
    pub async fn kv_usage(&self) -> Result<KvUsageReport, RuntimeError> {
        let engine = self.engine.clone();
        tokio::task::spawn_blocking(move || {
            let inner = &engine.inner;
            let handles_guard = inner
                .shared
                .handles
                .lock()
                .map_err(|_| LlamaCppCapi::lock_poisoned())?;
            let mut handles = Vec::with_capacity(handles_guard.len());
            let mut total = 0u64;
            for (handle_id, context) in handles_guard.iter() {
                let state = context.lock().map_err(|_| LlamaCppCapi::lock_poisoned())?;
                let estimate = inner.kv_bytes_per_handle;
                total += estimate;
                handles.push(HandleKvUsage {
                    handle_id: *handle_id,
                    profile_id: state.profile_id.clone(),
                    kv_tokens: state.trail.len() as u64,
                    kv_token_cap: inner.kv_token_cap,
                    kv_bytes_estimate: estimate,
                    state_bytes: inner.lib.state_get_size(&state.ctx),
                    decode_calls: state.decode_calls,
                });
            }
            handles.sort_by_key(|h| h.handle_id);
            Ok(KvUsageReport {
                handles,
                total_kv_bytes_estimate: total,
                kv_byte_budget: inner.kv_byte_budget,
            })
        })
        .await
        .map_err(|e| RuntimeError::Http(format!("capi-adapter: kv_usage task failed: {e}")))?
    }
}

#[async_trait]
impl crate::InferenceRuntime for LlamaCppCapi {
    fn id(&self) -> RuntimeDescriptor {
        match &self.config.engine {
            Some(engine) => {
                RuntimeDescriptor::new("llama.cpp-capi", &engine.version, &engine.build_hash)
                    .expect("pinned descriptor is valid")
            }
            // Dev/test setups without a pin report the same zero placeholder
            // class as the HTTP adapter; never a claimed build.
            None => RuntimeDescriptor::new("llama.cpp-capi", "adapter-capi-v1", "0".repeat(64))
                .expect("static descriptor is valid"),
        }
    }

    async fn load(&self, profile_id: &str) -> Result<Handle, RuntimeError> {
        if profile_id.is_empty() {
            return Err(RuntimeError::InvalidProfile(profile_id.to_string()));
        }
        // KV byte-budget check BEFORE creating the context (the engine
        // pre-allocates the full-window KV at creation — the cost is real
        // even if never used).
        if let Some(budget) = self.engine.inner.kv_byte_budget {
            let committed = self
                .engine
                .inner
                .shared
                .kv_bytes_estimate
                .load(Ordering::Relaxed);
            let projected = committed + self.engine.inner.kv_bytes_per_handle;
            if projected > budget {
                return Err(RuntimeError::Api {
                    status: 429,
                    code: "kv_budget_exceeded".to_string(),
                    message: format!(
                        "loading another handle would commit ~{} KiB of KV ({} KiB already \
                         committed across handles) over the {} KiB adapter budget",
                        self.engine.inner.kv_bytes_per_handle / 1024,
                        committed / 1024,
                        budget / 1024
                    ),
                });
            }
        }
        let handle_id = self
            .engine
            .inner
            .shared
            .next_handle
            .fetch_add(1, Ordering::Relaxed);
        let engine = self.engine.clone();
        let profile = profile_id.to_string();
        let warmup = self.config.warmup;
        let state = tokio::task::spawn_blocking(move || {
            let inner = &engine.inner;
            let mut params = inner.lib.context_default_params();
            params.n_ctx = inner.n_ctx;
            // Logical batch = the full window: one llama_decode per prefill,
            // never the engine's n_batch abort landmine (b11407 asserts
            // n_tokens <= n_batch; defaults are 2048 vs our 4096 ctx).
            params.n_batch = inner.n_ctx;
            // Pinned output reservation (ADR-031 §5.1): the reserved graph's
            // output head covers exactly the max verify geometry, and the
            // load-time warmup sizes the output buffer to the same bound —
            // steady-state calls never grow it.
            params.n_outputs_max = inner.verify_window + 1;
            if let Some(threads) = inner.n_threads {
                params.n_threads = threads as i32;
                params.n_threads_batch = threads as i32;
            }
            let ctx = inner
                .lib
                .init_context(&inner.model, params)
                .map_err(|e| RuntimeError::Http(format!("capi-adapter: context: {e}")))?;
            // ABI canary #2: the engine must hand back exactly the context
            // size we wrote at offset 0 of the params struct.
            if inner.lib.n_ctx(&ctx) != inner.n_ctx {
                return Err(RuntimeError::Http(format!(
                    "capi-adapter: ABI canary failed — requested n_ctx {} but the engine \
                     allocated {}",
                    inner.n_ctx,
                    inner.lib.n_ctx(&ctx)
                )));
            }
            let batch = inner
                .lib
                .pooled_batch(inner.n_ctx)
                .map_err(|e| RuntimeError::Http(format!("capi-adapter: pooled batch: {e}")))?;
            let mut state = HandleState {
                ctx,
                batch,
                profile_id: profile,
                trail: Vec::new(),
                last_output_pos: None,
                decode_calls: 0,
            };
            if warmup {
                inner.warmup(&mut state)?;
            }
            Ok(state)
        })
        .await
        .map_err(|e| RuntimeError::Http(format!("capi-adapter: load task failed: {e}")))??;

        // Register + commit accounting only after a fully-created handle.
        self.engine
            .inner
            .shared
            .handles
            .lock()
            .map_err(|_| Self::lock_poisoned())?
            .insert(handle_id, Arc::new(Mutex::new(state)));
        self.engine
            .inner
            .shared
            .kv_bytes_estimate
            .fetch_add(self.engine.inner.kv_bytes_per_handle, Ordering::Relaxed);
        Ok(Handle::new(profile_id, handle_id))
    }

    async fn tokenize(&self, text: &str) -> Result<Vec<u32>, RuntimeError> {
        // add_special=true / parse_special=true matches the pinned server's
        // /tokenize behavior (pinned token-for-token by the loopback test).
        let engine = self.engine.clone();
        let text = text.to_string();
        tokio::task::spawn_blocking(move || {
            engine
                .inner
                .lib
                .tokenize(engine.inner.vocab, &text, true, true)
                .map_err(|e| RuntimeError::Http(format!("capi-adapter: tokenize: {e}")))
        })
        .await
        .map_err(|e| RuntimeError::Http(format!("capi-adapter: tokenize task failed: {e}")))?
    }

    async fn detokenize(&self, ids: &[u32]) -> Result<String, RuntimeError> {
        let engine = self.engine.clone();
        let ids = ids.to_vec();
        tokio::task::spawn_blocking(move || {
            engine
                .inner
                .lib
                .detokenize(engine.inner.vocab, &ids)
                .map_err(|e| RuntimeError::Http(format!("capi-adapter: detokenize: {e}")))
        })
        .await
        .map_err(|e| RuntimeError::Http(format!("capi-adapter: detokenize task failed: {e}")))?
    }

    async fn prefill(&self, handle: &Handle, ids: &[u32]) -> Result<KvCommitment, RuntimeError> {
        if ids.is_empty() {
            return Err(RuntimeError::MalformedResponse(
                "prefill of empty token span".to_string(),
            ));
        }
        let ids = ids.to_vec();
        self.engine
            .with_handle(handle, move |inner, state| {
                inner.sync(state, &ids, false)?;
                Ok(KvCommitment::new(0, &ids))
            })
            .await
    }

    async fn decode_step(
        &self,
        handle: &Handle,
        prefix: &[u32],
        sampling: &SamplingParams,
    ) -> Result<u32, RuntimeError> {
        if prefix.is_empty() {
            return Err(RuntimeError::MalformedResponse(
                "decode_step with empty prefix; prefill first".to_string(),
            ));
        }
        let started = Instant::now();
        let prefix = prefix.to_vec();
        let sampling = *sampling;
        let token = self
            .engine
            .with_handle(handle, move |inner, state| {
                inner.sample_next(state, &prefix, &sampling)
            })
            .await?;
        self.engine.inner.record_decode(1, started.elapsed());
        Ok(token)
    }

    /// Incremental in-process decode: sync once, then one-token decode
    /// steps. Every engine call runs on the blocking pool (ADR-031 §5.2);
    /// the async side only sequences steps and observes the deadline and
    /// cancellation flag between them.
    fn decode_stream_events<'a>(
        &'a self,
        handle: &'a Handle,
        prefix: &'a [u32],
        sampling: &'a SamplingParams,
        max_tokens: u32,
        deadline: Duration,
    ) -> DecodeEventStream<'a> {
        let engine = match self.engine.context(handle) {
            Ok(engine) => engine,
            Err(e) => {
                return Box::pin(futures_util::stream::once(async move { Err(e) }));
            }
        };
        struct StreamState {
            engine: Engine,
            context: Arc<Mutex<HandleState>>,
            /// Full working prefix (prompt + produced tokens).
            working: Vec<u32>,
            /// Last sampled token (not yet decoded into the KV).
            last_token: Option<u32>,
            sampling: SamplingParams,
            produced: u32,
            started: Instant,
            done: bool,
        }
        let state = StreamState {
            engine: self.engine.clone(),
            context: engine,
            working: prefix.to_vec(),
            last_token: None,
            sampling: *sampling,
            produced: 0,
            started: Instant::now(),
            done: max_tokens == 0 || prefix.is_empty(),
        };
        Box::pin(futures_util::stream::unfold(
            state,
            move |mut state| async move {
                if state.done || state.produced >= max_tokens {
                    return None;
                }
                if state.started.elapsed() >= deadline {
                    state.done = true;
                    return Some((
                        Err(RuntimeError::Timeout {
                            after_ms: crate::duration_ms_u64(deadline),
                        }),
                        state,
                    ));
                }
                if let Some(task) = cancelled_task(&state.engine) {
                    state.done = true;
                    return Some((Err(RuntimeError::Cancelled(task)), state));
                }
                let outcome = {
                    let engine = state.engine.clone();
                    let context = Arc::clone(&state.context);
                    let working = state.working.clone();
                    let last_token = state.last_token;
                    let sampling = state.sampling;
                    tokio::task::spawn_blocking(move || {
                        let Ok(mut handle_state) = context.lock() else {
                            return Err(RuntimeError::Http(
                                "capi-adapter: state lock poisoned".into(),
                            ));
                        };
                        match last_token {
                            // First event: sync (delta decode) + sample.
                            None => {
                                engine
                                    .inner
                                    .sample_next(&mut handle_state, &working, &sampling)
                            }
                            // Subsequent: one-token decode + sample.
                            Some(last) => engine.inner.step_sampled(&mut handle_state, last),
                        }
                    })
                    .await
                    .unwrap_or_else(|e| {
                        Err(RuntimeError::Http(format!(
                            "capi-adapter: stream task failed: {e}"
                        )))
                    })
                };
                let token = match outcome {
                    Ok(token) => token,
                    Err(e) => {
                        state.done = true;
                        return Some((Err(e), state));
                    }
                };
                if state
                    .engine
                    .inner
                    .lib
                    .vocab_is_eog(state.engine.inner.vocab, token)
                {
                    return None;
                }
                state.working.push(token);
                state.last_token = Some(token);
                state.produced += 1;
                Some((Ok(DecodeEvent::Token(token)), state))
            },
        ))
    }

    fn metrics(&self) -> RuntimeMetrics {
        let mut metrics = self
            .engine
            .inner
            .shared
            .metrics
            .read()
            .map(|m| *m)
            .unwrap_or_default();
        metrics.kv_bytes_estimate = self
            .engine
            .inner
            .shared
            .kv_bytes_estimate
            .load(Ordering::Relaxed);
        metrics.engine_decode_calls = self
            .engine
            .inner
            .shared
            .decode_calls
            .load(Ordering::Relaxed);
        metrics
    }

    fn cancel(&self, task: TaskId) -> Result<(), RuntimeError> {
        self.engine
            .inner
            .shared
            .cancelled
            .store(task.0, Ordering::Relaxed);
        Ok(())
    }

    /// Greedy self-continuation (ADR-021 unforked subset) — KV-cheap: the
    /// prefix is synced once and every proposal is a one-token decode.
    async fn propose(
        &self,
        handle: &Handle,
        prefix: &[u32],
        window: u32,
    ) -> Result<Vec<u32>, RuntimeError> {
        if window == 0 || prefix.is_empty() {
            return Ok(Vec::new());
        }
        let window = window.min(self.engine.inner.verify_window);
        let prefix = prefix.to_vec();
        let started = Instant::now();
        let draft = self
            .engine
            .with_handle(handle, move |inner, state| {
                let default = SamplingParams::default();
                let mut draft = Vec::with_capacity(window as usize);
                let mut current = inner.sample_next(state, &prefix, &default)?;
                while draft.len() < window as usize {
                    if inner.is_eog_at(current) || started.elapsed() >= PROPOSE_BUDGET {
                        break;
                    }
                    draft.push(current);
                    if draft.len() == window as usize {
                        break;
                    }
                    current = inner.step_sampled(state, current)?;
                }
                Ok(draft)
            })
            .await?;
        Ok(draft)
    }
}

/// Observes and clears the cooperative cancellation flag (deadline-class,
/// same approximation as the HTTP adapter).
fn cancelled_task(engine: &Engine) -> Option<TaskId> {
    let raw = engine.inner.shared.cancelled.swap(0, Ordering::Relaxed);
    (raw > 0).then_some(TaskId(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_prefix_lengths() {
        assert_eq!(common_prefix_len(&[1, 2, 3], &[1, 2, 4]), 2);
        assert_eq!(common_prefix_len(&[1, 2], &[1, 2, 3, 4]), 2);
        assert_eq!(common_prefix_len(&[], &[1]), 0);
        assert_eq!(common_prefix_len(&[5], &[5]), 1);
    }

    #[test]
    fn config_defaults_mirror_the_engine_spec() {
        let config = CapiConfig::new("engine", "model.gguf");
        assert_eq!(config.n_ctx, 4096);
        assert!(config.n_threads.is_none());
        assert!(config.engine.is_none());
        assert_eq!(config.verify_window_max, WINDOW_CAP);
        assert!(config.uniform_outputs);
        assert_eq!(config.effective_kv_token_cap(), 4096);
        assert!(config.kv_byte_budget.is_none());
        assert!(config.warmup);
    }

    #[test]
    fn verify_window_clamps_to_the_adr032_cap() {
        let config = CapiConfig::new("e", "m").with_verify_window_max(999);
        assert_eq!(config.effective_verify_window(), WINDOW_CAP);
        let config = CapiConfig::new("e", "m").with_verify_window_max(0);
        assert_eq!(config.effective_verify_window(), 1);
    }

    #[test]
    fn kv_byte_estimate_follows_gqa_dimensions() {
        // 2 (K+V) x 2 B (f16) x n_layer x n_ctx x n_head_kv x head_dim.
        // SmolLM2-135M class: 30 layers, 9 KV heads, head 64, ctx 4096
        // -> 2*2*30*9*64*4096 = 283,115,520 B (~270 MiB f16 K+V).
        let bytes = estimate_kv_bytes(30, 9, 64, 4096);
        assert_eq!(
            bytes,
            2 * KV_CELL_BYTES * 30 * 9 * 64 * 4096,
            "formula: 2*2B*n_layer*n_head_kv*head_dim*n_ctx"
        );
        // Degenerate inputs estimate zero, never divide-by-zero.
        assert_eq!(estimate_kv_bytes(0, 9, 64, 4096), 0);
        assert_eq!(estimate_kv_bytes(30, 0, 64, 4096), 0);
        assert_eq!(estimate_kv_bytes(30, 9, 0, 4096), 0);
        assert_eq!(estimate_kv_bytes(30, 9, 64, 0), 0);
    }

    #[test]
    fn bundle_guard_allows_one_bundle_and_fails_closed_on_a_second() {
        let a = PathBuf::from("C:/engine");
        let b = PathBuf::from("C:/engine-vulkan");
        assert!(bundle_guard_decision(None, &a).is_ok());
        assert!(bundle_guard_decision(Some(&a), &a).is_ok());
        let err =
            bundle_guard_decision(Some(&a), &b).expect_err("different bundle must fail closed");
        assert!(err.contains("one pinned bundle per process"), "{err}");
    }
}
