//! Inference runtime abstraction (`docs/research/runtime-trait-spec.md`,
//! ADR-002, ADR-019) with two adapters: the production-baseline
//! [`LlamaCppAdapter`] (HTTP client to the pinned loopback llama.cpp server)
//! and the TEST-ONLY deterministic [`MockRuntime`] behind the off-by-default
//! `mock-runtime` feature.
//!
//! # Trait-shape decisions (frozen for later phases)
//!
//! - The trait is object-safe and uses `async_trait`; `id`, `metrics`, and
//!   `cancel` are synchronous, every inference path is async.
//! - [`RuntimeDescriptor`] here is the *runtime-identity* type
//!   (`name`/`version`/`build_hash`). It is deliberately NOT
//!   `modelswarm_types::RuntimeDescriptor`, which is the manifest-pinned
//!   catalog descriptor that only admits `llama.cpp`. A mock or research
//!   runtime must be able to name itself (e.g. `"mock"`, ADR-019).
//! - [`InferenceRuntime::propose`] has a default implementation returning
//!   [`RuntimeError::Unsupported`]; only speculative-capable runtimes
//!   (MockRuntime today, a Phase-D research adapter later) override it.
//! - [`InferenceRuntime::decode_stream`] has a default implementation that
//!   loops [`InferenceRuntime::decode_step`] under the caller's deadline.
//!   Adapters may override it (MockRuntime does, to observe cancellation).
//! - [`InferenceRuntime::decode_stream_events`] is the incremental variant:
//!   events arrive as the engine produces them (one SSE connection on the
//!   llama.cpp adapter; the default wraps `decode_stream` collect-then-emit).
//!   `decode_stream` remains the materialized API every existing consumer
//!   (bench, session, sim) is written against.
//! - [`KvCommitment`]'s digest is `sha256(token_span || token ids)` — the
//!   documented llama.cpp-era approximation from the runtime trait spec
//!   (exact KV introspection is not exposed by llama.cpp).

pub mod llamacpp;

#[cfg(feature = "mock-runtime")]
pub mod mock;

/// P16 research spike: in-process runtime over the pinned llama.cpp C API.
/// Feature-gated OFF by default; production serving stays on the HTTP
/// adapter (ADR-021). The unsafe FFI surface is confined to
/// `capi::ffi` (see its module docs for the pinned-binary identity story).
#[cfg(feature = "capi-adapter")]
pub mod capi;

pub use llamacpp::LlamaCppAdapter;

#[cfg(feature = "capi-adapter")]
pub use capi::{CapiConfig, CapiVerifyEngine, LlamaCppCapi, VerifyOutcome};

#[cfg(feature = "mock-runtime")]
pub use mock::{
    MockRuntime, MOCK_DECODE_TOKENS_PER_MS, MOCK_PREFILL_TOKENS_PER_MS, MOCK_RUNTIME_NAME,
    MOCK_VOCAB,
};

use std::time::Duration;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use sha2::{Digest as ShaDigest, Sha256};

/// Identity of a runtime build. See the crate docs for why this is a separate
/// type from the manifest-pinned descriptor in `modelswarm-types`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuntimeDescriptor {
    name: String,
    version: String,
    build_hash: String,
}

impl RuntimeDescriptor {
    /// Validates `name`/`version` (non-empty) and `build_hash`
    /// (64 lowercase hex characters) and wraps them.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        build_hash: impl Into<String>,
    ) -> Result<Self, RuntimeError> {
        let name = name.into();
        let version = version.into();
        let build_hash = build_hash.into();
        if name.is_empty() {
            return Err(RuntimeError::InvalidDescriptor("name is empty".into()));
        }
        if version.is_empty() {
            return Err(RuntimeError::InvalidDescriptor("version is empty".into()));
        }
        if build_hash.len() != 64 || !is_lower_hex(&build_hash) {
            return Err(RuntimeError::InvalidDescriptor(format!(
                "build_hash must be 64 lowercase hex chars: {build_hash:?}"
            )));
        }
        Ok(Self {
            name,
            version,
            build_hash,
        })
    }

    /// Runtime name, e.g. `llama.cpp` or `mock`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Runtime version label.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// 64-hex build identity digest.
    pub fn build_hash(&self) -> &str {
        &self.build_hash
    }
}

/// A loaded model instance handle. Opaque outside the owning runtime.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Handle {
    profile_id: String,
    handle_id: u64,
}

impl Handle {
    /// Wraps a profile id and runtime-assigned handle id.
    pub fn new(profile_id: impl Into<String>, handle_id: u64) -> Self {
        Self {
            profile_id: profile_id.into(),
            handle_id,
        }
    }

    /// The profile this handle was loaded for.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Runtime-assigned handle id.
    pub fn handle_id(&self) -> u64 {
        self.handle_id
    }
}

/// Approximate KV-cache commitment over a prefilled token span
/// (runtime-trait spec: "hash of KV-state digest + token span"; llama.cpp
/// does not expose exact KV state, so the digest covers the span + ids).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvCommitment {
    /// Inclusive-exclusive token span `[start, end)` covered by the prefill.
    pub token_span: (u32, u32),
    /// 64-hex sha256 over the span and token ids.
    pub digest: String,
}

impl KvCommitment {
    /// Derives the commitment digest for `ids` occupying `[start, start+len)`.
    pub fn new(start: u32, ids: &[u32]) -> Self {
        let end = start + ids.len() as u32;
        let mut hasher = Sha256::new();
        hasher.update(start.to_le_bytes());
        hasher.update(end.to_le_bytes());
        for id in ids {
            hasher.update(id.to_le_bytes());
        }
        Self {
            token_span: (start, end),
            digest: hex64(&hasher.finalize()),
        }
    }
}

/// Throughput and backlog snapshot of a runtime.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct RuntimeMetrics {
    /// Prefill throughput measured by the adapter (tokens per millisecond).
    pub prefill_tokens_per_ms: f64,
    /// Decode throughput measured by the adapter (tokens per millisecond).
    pub decode_tokens_per_ms: f64,
    /// Number of admitted-but-unfinished tasks.
    pub queue_depth: u32,
    /// Adapter-wide engine KV RAM estimate in bytes across live handles
    /// (ADR-031 §5.3 per-handle KV accounting; 0 for adapters without
    /// accounting — the HTTP sidecar's memory is process-level, not
    /// per-handle). Capacity-based estimate, cross-checkable against the
    /// engine-reported used-state bytes via the capi adapter's `kv_usage`.
    pub kv_bytes_estimate: u64,
    /// Total engine decode calls observed by the adapter (ADR-032 I4
    /// telemetry input; 0 for adapters that do not count).
    pub engine_decode_calls: u64,
}

/// Sampling parameters carried by decode calls (msp-v1 §6.2 `sampling`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SamplingParams {
    /// Greediness; clamped to `[0, 2]` by callers (msp-v1 §6.4).
    pub temperature: f32,
    /// Nucleus bound; clamped to `(0, 1]` by callers.
    pub top_p: f32,
    /// Top-k bound; clamped to `[1, 200]`.
    pub top_k: u32,
    /// Deterministic sampling seed, when the runtime is seedable.
    pub seed: Option<u64>,
}

impl Default for SamplingParams {
    fn default() -> Self {
        // Neutral defaults; `top_k` mirrors the llama.cpp server default.
        Self {
            temperature: 1.0,
            top_p: 1.0,
            top_k: 40,
            seed: None,
        }
    }
}

/// Identifier of an in-flight task, used for cancellation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskId(pub u64);

impl std::fmt::Display for TaskId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "task-{}", self.0)
    }
}

/// Server-reported phase split of one decode (the pinned b11407 server's
/// final SSE chunk `timings`). When the server does not report timings,
/// [`DecodeEvent::Timings`] is never emitted and callers fall back to
/// client-side measurement.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DecodeTimings {
    /// Prompt-eval token count (`prompt_n`).
    pub prompt_tokens: u64,
    /// Prompt-eval wall time in milliseconds (`prompt_ms`).
    pub prompt_ms: f64,
    /// Generated token count (`predicted_n`).
    pub completion_tokens: u64,
    /// Decode wall time in milliseconds (`predicted_ms`).
    pub decode_ms: f64,
}

/// Event emitted by [`InferenceRuntime::decode_stream_events`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DecodeEvent {
    /// One committed generated token. EOS is never emitted as a token; the
    /// stream ends there (exact parity with `decode_stream`'s Vec output).
    Token(u32),
    /// Final server-reported phase timings; emitted at most once, after the
    /// last token and before the stream ends.
    Timings(DecodeTimings),
}

/// Incremental decode stream returned by
/// [`InferenceRuntime::decode_stream_events`].
pub type DecodeEventStream<'a> = std::pin::Pin<
    Box<dyn futures_util::Stream<Item = Result<DecodeEvent, RuntimeError>> + Send + 'a>,
>;

/// Errors produced by inference runtimes.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum RuntimeError {
    /// The runtime does not implement this capability (e.g. `propose` on
    /// llama.cpp; Phase-D research adapter required).
    #[error("runtime capability not supported: {0}")]
    Unsupported(String),
    /// HTTP transport failure talking to the runtime server.
    #[error("http transport failure: {0}")]
    Http(String),
    /// The operation exceeded its deadline.
    #[error("operation timed out after {after_ms} ms")]
    Timeout { after_ms: u64 },
    /// The runtime server answered a non-success status.
    #[error("runtime api error {status} {code}: {message}")]
    Api {
        /// HTTP status code.
        status: u16,
        /// Machine-readable error code from the server, when present.
        code: String,
        /// Human-readable message.
        message: String,
    },
    /// The runtime server answered something we could not parse.
    #[error("malformed runtime response: {0}")]
    MalformedResponse(String),
    /// The requested profile id is not valid for this runtime.
    #[error("invalid profile id: {0}")]
    InvalidProfile(String),
    /// A token id is outside the runtime's vocabulary.
    #[error("token id {0} outside runtime vocabulary")]
    TokenOutOfRange(u32),
    /// The task was cancelled through [`InferenceRuntime::cancel`].
    #[error("task {0} was cancelled")]
    Cancelled(TaskId),
    /// A handle was used that the runtime never loaded (or has evicted).
    #[error("handle {0} is not loaded")]
    NotLoaded(u64),
    /// A runtime descriptor failed validation.
    #[error("invalid runtime descriptor: {0}")]
    InvalidDescriptor(String),
}

/// One inference backend behind a common interface (runtime-trait spec).
///
/// Implementations must be deterministic given identical inputs and seeds
/// wherever the call is pure (tokenization, decoding with a fixed seed) so
/// benchmark cells stay reproducible.
#[async_trait]
pub trait InferenceRuntime: Send + Sync {
    /// Identity of this runtime build.
    fn id(&self) -> RuntimeDescriptor;

    /// Verifies the runtime can serve `profile_id` and returns a handle.
    async fn load(&self, profile_id: &str) -> Result<Handle, RuntimeError>;

    /// Deterministic, idempotent tokenization.
    async fn tokenize(&self, text: &str) -> Result<Vec<u32>, RuntimeError>;

    /// Inverse of [`InferenceRuntime::tokenize`].
    async fn detokenize(&self, ids: &[u32]) -> Result<String, RuntimeError>;

    /// Prefills `ids` and returns the KV commitment for the span.
    async fn prefill(&self, handle: &Handle, ids: &[u32]) -> Result<KvCommitment, RuntimeError>;

    /// One autoregressive decode step given the committed prefix.
    async fn decode_step(
        &self,
        handle: &Handle,
        prefix: &[u32],
        sampling: &SamplingParams,
    ) -> Result<u32, RuntimeError>;

    /// Decodes up to `max_tokens` tokens, streaming steps internally until
    /// the deadline. Returns the produced token ids, or
    /// [`RuntimeError::Timeout`]/[`RuntimeError::Cancelled`] on interruption.
    async fn decode_stream(
        &self,
        handle: &Handle,
        prefix: &[u32],
        sampling: &SamplingParams,
        max_tokens: u32,
        deadline: Duration,
    ) -> Result<Vec<u32>, RuntimeError> {
        let started = tokio::time::Instant::now();
        let mut produced = Vec::new();
        let mut working_prefix = prefix.to_vec();
        for _ in 0..max_tokens {
            if started.elapsed() > deadline {
                return Err(RuntimeError::Timeout {
                    after_ms: duration_ms_u64(deadline),
                });
            }
            let token = self.decode_step(handle, &working_prefix, sampling).await?;
            working_prefix.push(token);
            produced.push(token);
        }
        Ok(produced)
    }

    /// Incremental decode: same contract as [`InferenceRuntime::decode_stream`]
    /// (up to `max_tokens` tokens, EOS-terminated, under `deadline`), but
    /// events arrive as the engine produces them instead of after the whole
    /// completion materializes. The default implementation wraps
    /// `decode_stream` (collect-then-emit) so adapters without native
    /// streaming stay conformant; the llama.cpp adapter overrides it with a
    /// single SSE request.
    fn decode_stream_events<'a>(
        &'a self,
        handle: &'a Handle,
        prefix: &'a [u32],
        sampling: &'a SamplingParams,
        max_tokens: u32,
        deadline: Duration,
    ) -> DecodeEventStream<'a> {
        Box::pin(
            futures_util::stream::once(async move {
                let tokens = self
                    .decode_stream(handle, prefix, sampling, max_tokens, deadline)
                    .await?;
                let events = futures_util::stream::iter(
                    tokens.into_iter().map(|id| Ok(DecodeEvent::Token(id))),
                );
                Ok::<_, RuntimeError>(events)
            })
            .try_flatten(),
        )
    }

    /// Current throughput and queue metrics.
    fn metrics(&self) -> RuntimeMetrics;

    /// Requests cancellation of `task`; implementations must free the
    /// serving slot within a bounded deadline.
    fn cancel(&self, task: TaskId) -> Result<(), RuntimeError>;

    /// Speculative proposal of `window` tokens continuing `prefix`
    /// (Phase-D hooks). The default marks the capability unsupported;
    /// overrides return drafts whose per-position correctness probability
    /// is the runtime's configured draft accuracy (MockRuntime experiments).
    async fn propose(
        &self,
        _handle: &Handle,
        _prefix: &[u32],
        _window: u32,
    ) -> Result<Vec<u32>, RuntimeError> {
        Err(RuntimeError::Unsupported("propose".to_string()))
    }
}

pub(crate) fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn hex64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).expect("nibble"));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).expect("nibble"));
    }
    out
}

/// splitmix64 mixer (public-domain reference implementation). Used by the
/// mock runtime; kept unconditionally so the pure function is testable.
#[cfg_attr(not(feature = "mock-runtime"), allow(dead_code))]
pub(crate) fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

pub(crate) fn duration_ms_u64(d: Duration) -> u64 {
    d.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_descriptor_validates_fields() {
        let d = RuntimeDescriptor::new("llama.cpp", "b4271", "a".repeat(64)).unwrap();
        assert_eq!(d.name(), "llama.cpp");
        assert_eq!(d.version(), "b4271");
        assert_eq!(d.build_hash(), &"a".repeat(64));

        assert_eq!(
            RuntimeDescriptor::new("", "v", "a".repeat(64)).unwrap_err(),
            RuntimeError::InvalidDescriptor("name is empty".to_string())
        );
        assert_eq!(
            RuntimeDescriptor::new("mock", "", "a".repeat(64)).unwrap_err(),
            RuntimeError::InvalidDescriptor("version is empty".to_string())
        );
        assert!(RuntimeDescriptor::new("mock", "v", "A".repeat(64)).is_err());
        assert!(RuntimeDescriptor::new("mock", "v", "a".repeat(63)).is_err());
    }

    #[test]
    fn kv_commitment_covers_span_and_ids() {
        let a = KvCommitment::new(0, &[1, 2, 3]);
        let b = KvCommitment::new(0, &[1, 2, 3]);
        let c = KvCommitment::new(1, &[1, 2, 3]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.token_span, (0, 3));
        assert_eq!(a.digest.len(), 64);
        assert!(is_lower_hex(&a.digest));
    }

    #[test]
    fn splitmix64_is_deterministic_and_avalanching() {
        assert_eq!(splitmix64(42), splitmix64(42));
        assert_ne!(splitmix64(42), splitmix64(43));
        assert_ne!(splitmix64(0), 0);
    }

    #[tokio::test]
    async fn default_decode_stream_events_matches_decode_stream() {
        use futures_util::StreamExt;
        // Minimal runtime exercising only the default `decode_stream_events`
        // wrapper: its token sequence must equal `decode_stream` exactly.
        struct FixedStep;
        #[async_trait]
        impl InferenceRuntime for FixedStep {
            fn id(&self) -> RuntimeDescriptor {
                RuntimeDescriptor::new("fixed", "1", "a".repeat(64)).unwrap()
            }
            async fn load(&self, profile_id: &str) -> Result<Handle, RuntimeError> {
                Ok(Handle::new(profile_id, 1))
            }
            async fn tokenize(&self, text: &str) -> Result<Vec<u32>, RuntimeError> {
                Ok(vec![u32::try_from(text.len()).unwrap_or(0)])
            }
            async fn detokenize(&self, _ids: &[u32]) -> Result<String, RuntimeError> {
                Ok(String::new())
            }
            async fn prefill(
                &self,
                _handle: &Handle,
                _ids: &[u32],
            ) -> Result<KvCommitment, RuntimeError> {
                panic!("not under test")
            }
            async fn decode_step(
                &self,
                _handle: &Handle,
                prefix: &[u32],
                _sampling: &SamplingParams,
            ) -> Result<u32, RuntimeError> {
                Ok(u32::try_from(prefix.len()).unwrap_or(0) + 7)
            }
            fn metrics(&self) -> RuntimeMetrics {
                RuntimeMetrics::default()
            }
            fn cancel(&self, _task: TaskId) -> Result<(), RuntimeError> {
                Ok(())
            }
        }
        let runtime = FixedStep;
        let handle = runtime.load("msp1:t").await.unwrap();
        let sampling = SamplingParams::default();
        let expected = runtime
            .decode_stream(&handle, &[1, 2, 3], &sampling, 5, Duration::from_secs(5))
            .await
            .unwrap();
        let events: Vec<Result<DecodeEvent, RuntimeError>> = runtime
            .decode_stream_events(&handle, &[1, 2, 3], &sampling, 5, Duration::from_secs(5))
            .collect()
            .await;
        let tokens: Vec<u32> = events
            .into_iter()
            .map(|e| match e {
                Ok(DecodeEvent::Token(id)) => id,
                other => panic!("expected token event, got {other:?}"),
            })
            .collect();
        assert_eq!(tokens, expected);
        // [1,2,3] → len 3 → 10, then the prefix grows each step.
        assert_eq!(tokens, vec![10, 11, 12, 13, 14]);
    }
}
