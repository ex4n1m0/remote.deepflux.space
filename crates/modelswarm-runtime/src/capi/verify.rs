//! `CapiVerifyEngine`: the production batched-verify ENGINE over the
//! productionized C-API adapter (ADR-032 §1/§4 — the real implementation
//! behind the session crate's `BatchVerifyEngine` contract; the serve loop
//! composes the two at light-up).
//!
//! # What this engine is
//!
//! One adapter-backed verifier session: a pinned [`LlamaCppCapi`], one
//! loaded [`Handle`], and the verifier's own committed continuation
//! (the token stream the engine has verified so far — prompt plus every
//! committed window token and correction). [`CapiVerifyEngine::verify_window`]
//! is the ADR-032 §1 semantics over the adapter's productionized
//! [`LlamaCppCapi::verify_drafts`] path:
//!
//! - ONE batched engine pass per window (`[prefix_last, window…]` with
//!   logits on every row, the engine's own sampler chain under `params`);
//! - on the first rejection, a single KV rollback at that position and the
//!   replacement token as the correction;
//! - full-window acceptance yields the bonus (lookahead) token as the
//!   correction;
//! - `correction == None` exactly at end-of-generation (the bonus or the
//!   replacement was an EOG token);
//! - every blocking engine call stays on the tokio blocking pool
//!   (ADR-031 §5.2 — `verify_drafts`/`load`/`prefill` already offload; the
//!   engine adds no synchronous engine work).
//!
//! The engine tracks the committed prefix itself because the wire family
//! never re-sends it: the coordinator sends only `window_tokens`, the
//! hash chain carries the commitment (ADR-032 §1 rule 2). After a verify
//! the committed stream is `old_committed ++ accepted ++ [correction]`
//! (no correction token at EOG — prefix-only commit), exactly the
//! `PrefixCommit` preimage the gate recomputes.
//!
//! # Capability disclosure (RC-8)
//!
//! [`CapiVerifyEngine::capabilities`] reports the adapter's REAL geometry:
//! `batch_window_max` is the productionized max verify window — the
//! construction-pinned geometry the load-time warmup sizes the output
//! buffer for ([`CapiConfig::verify_window_max`], clamped to
//! [`WINDOW_CAP`]) — and `batch_verify` is always `true` (this engine
//! exists because the adapter batch-verifies). The backend comes from the
//! configured engine bundle (CPU vs Vulkan — ADR-024/E0: pairing is per
//! backend family); supply it explicitly or via
//! [`VerifyBackend::of_bundle`].
//!
//! # Fail-closed refusals BEFORE any engine work
//!
//! - an EMPTY window is malformed (ADR-032 §1: nothing to verify);
//! - a window longer than the disclosed `batch_window_max` (hence
//!   `min(WINDOW_CAP, batch_window_max)`) is `413 payload_too_large`
//!   before any engine work (ADR-032 §2 stage 10 / RC-8);
//! - verifying before `prefill`, or after an EOG outcome, is a
//!   `MalformedResponse` contract violation (a session ends at EOG);
//! - the adapter's KV/token caps refuse with the honest
//!   `429 kv_budget_exceeded` error (never a panic), and a refused verify
//!   leaves the committed prefix untouched.
//!
//! # Trait-gap note (recorded in the handoff)
//!
//! The architect-owned trait
//! `modelswarm_session::verifydrafts::BatchVerifyEngine` lives in
//! `modelswarm-session`, which ALREADY depends on `modelswarm-runtime`
//! (for `RuntimeError`/`SamplingParams`). Implementing that trait for a
//! type in THIS crate would require `modelswarm-runtime` to depend on
//! `modelswarm-session` — a cyclic package dependency Cargo rejects.
//! Until the trait is re-homed (or the serve loop, which depends on both
//! crates, hosts the adapter impl), this module provides
//! [`BatchVerifyEngineMirror`]: a MINIMAL LOCAL MIRROR of the trait's
//! exact shape (same method signatures; the disclosure type mirrored by
//! [`VerifyEngineCaps`]), implemented for [`CapiVerifyEngine`] as a
//! compile-proof, clearly labeled as such. The REAL trait is proven
//! implementable and engine-exact in `tests/capi_verify.rs`, which
//! dev-depends on `modelswarm-session` (dev-dependency cycles are legal)
//! and implements it for a newtype wrapper around this engine.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use super::{LlamaCppCapi, VerifyOutcome, WINDOW_CAP};
use crate::{Handle, InferenceRuntime as _, RuntimeError, SamplingParams};

/// Engine backend family for disclosure (mirrors the session crate's
/// `negotiation::Backend` vocabulary — ADR-032 §3, from E0/ADR-024: greedy
/// determinism is per backend family, CPU ≠ Vulkan, never mixed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifyBackend {
    /// CPU (any thread count): E0-proven identical continuations.
    Cpu,
    /// Vulkan (any GPU vendor): E0-proven identical continuations.
    Vulkan,
}

impl VerifyBackend {
    /// Stable wire/record label (same strings as the session crate's
    /// `Backend::as_str`).
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyBackend::Cpu => "cpu",
            VerifyBackend::Vulkan => "vulkan",
        }
    }

    /// Detects the backend family of a pinned engine bundle from its
    /// contents: the Vulkan variant of `runtime-pins.json` ships
    /// `ggml-vulkan.dll`, the CPU set does not. Returns `None` when `dir`
    /// does not look like a C-API bundle at all (no
    /// [`LlamaLib::library_file_name`] present — see `ffi` for the per-OS
    /// names), so a mis-staged directory fails closed instead of guessing.
    ///
    /// Detection is a convenience for configuration; the authoritative
    /// statement is which bundle the operator staged and verified.
    pub fn of_bundle(dir: &Path) -> Option<Self> {
        if !dir
            .join(super::ffi::LlamaLib::library_file_name())
            .is_file()
        {
            return None;
        }
        Some(if dir.join("ggml-vulkan.dll").is_file() {
            VerifyBackend::Vulkan
        } else {
            VerifyBackend::Cpu
        })
    }
}

impl std::fmt::Display for VerifyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The engine's capability disclosure (minimal local mirror of the session
/// crate's `negotiation::EngineDisclosure` — same three fields, ADR-032 §3
/// RC-8): what `capabilities()` reports for a [`CapiVerifyEngine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyEngineCaps {
    /// The backend this engine actually verifies under.
    pub backend: VerifyBackend,
    /// Always `true` for this engine: the C-API adapter verifies a window
    /// in ONE batched pass (ADR-031 productionization gate PASSED).
    pub batch_verify: bool,
    /// The largest window this engine verifies in one pass,
    /// `1..=WINDOW_CAP`; here the adapter's construction-pinned verify
    /// geometry (the load-time warmup sizing).
    pub batch_window_max: u32,
}

/// MINIMAL LOCAL MIRROR of `modelswarm_session::verifydrafts::
/// BatchVerifyEngine` — COMPILE-PROOF ONLY (see the trait-gap note in the
/// module docs and the runtime handoff). Method signatures are identical
/// to the architect's trait modulo the mirrored disclosure type; the real
/// trait is implemented for a newtype of [`CapiVerifyEngine`] in
/// `tests/capi_verify.rs` (dev-dependency cycle, legal in Cargo).
#[async_trait]
pub trait BatchVerifyEngineMirror: Send + Sync {
    /// Executes the one batched pass for `window` under `params`.
    async fn verify_window(
        &self,
        window: &[u32],
        params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), RuntimeError>;
    /// The engine's own capability disclosure (RC-8); its
    /// `batch_window_max` bounds admission before any engine work.
    fn capabilities(&self) -> VerifyEngineCaps;
}

/// Per-session verifier state under the engine's lock: the loaded handle
/// and the verifier's own committed continuation.
struct VerifySession {
    handle: Handle,
    /// The committed stream the next window continues (prompt ++ all
    /// committed window tokens and corrections). Equals the token set the
    /// adapter's KV trail holds minus the last token whenever that token
    /// was a sampled-but-not-decoded correction (the adapter's next sync
    /// decodes exactly that delta — one engine pass per verify, I4).
    committed: Vec<u32>,
    /// Set when a verify outcome hit end-of-generation (correction
    /// `None`): the session is over; further windows are refused
    /// fail-closed. Cleared by a fresh `prefill`.
    finished: bool,
}

/// The production batched-verify engine: one verifier session over the
/// productionized C-API adapter. Construct one per cooperative session on
/// an adapter you already hold (multiple engines may share an adapter —
/// one handle each; the one-bundle-per-process guard still applies to the
/// ADAPTER, ADR-031 §2).
///
/// ```
/// // Shape (requires the capi-adapter feature and a staged pinned engine
/// // to actually run — see tests/capi_verify.rs for the full pattern):
/// # async fn demo(adapter: std::sync::Arc<
/// #     modelswarm_runtime::capi::LlamaCppCapi>) -> Result<(), Box<dyn std::error::Error>> {
/// use modelswarm_runtime::capi::verify::{CapiVerifyEngine, VerifyBackend};
/// let engine = CapiVerifyEngine::new(
///     adapter,
///     VerifyBackend::Cpu,
///     "msp1:<profile>",
/// )
/// .await?;
/// engine.prefill(&[1, 2, 3]).await?; // the session prompt (tokenized upstream)
/// let (accepted_len, correction) = engine
///     .verify_window(&[4, 5, 6], &modelswarm_runtime::SamplingParams::default())
///     .await?;
/// # let _ = (accepted_len, correction);
/// # Ok(())
/// # }
/// ```
pub struct CapiVerifyEngine {
    adapter: Arc<LlamaCppCapi>,
    backend: VerifyBackend,
    session: Mutex<VerifySession>,
}

impl CapiVerifyEngine {
    /// Loads a fresh handle on `adapter` for `profile_id` and returns a
    /// session-scoped verify engine verifying under `backend`. Blocking
    /// work (context creation + warmup) is offloaded by the adapter's
    /// `load` (ADR-031 §5.2).
    pub async fn new(
        adapter: Arc<LlamaCppCapi>,
        backend: VerifyBackend,
        profile_id: &str,
    ) -> Result<Self, RuntimeError> {
        let handle = adapter.load(profile_id).await?;
        Ok(Self {
            adapter,
            backend,
            session: Mutex::new(VerifySession {
                handle,
                committed: Vec::new(),
                finished: false,
            }),
        })
    }

    /// Commits the session prompt (the PREFILLED root). A re-prefill
    /// REPLACES the committed root (a new session on the same handle);
    /// the adapter's sync rolls the KV back/forward to exactly `prompt`.
    pub async fn prefill(&self, prompt: &[u32]) -> Result<(), RuntimeError> {
        if prompt.is_empty() {
            return Err(RuntimeError::MalformedResponse(
                "verify engine prefill of empty prompt".to_string(),
            ));
        }
        let mut session = self.session.lock().await;
        self.adapter.prefill(&session.handle, prompt).await?;
        session.committed = prompt.to_vec();
        session.finished = false;
        Ok(())
    }

    /// ONE batched engine pass verifying `window` against the engine's
    /// own continuation under `params` (ADR-032 §1): returns
    /// `(accepted_len, correction)` — the number of leading window tokens
    /// the engine itself would have sampled, and the replacement token on
    /// rejection / bonus token on full acceptance (`None` exactly at
    /// end-of-generation). On success the committed stream advances to
    /// `committed ++ window[..accepted_len] ++ [correction]` (prefix-only
    /// at EOG); on error it does not move.
    pub async fn verify_window(
        &self,
        window: &[u32],
        params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), RuntimeError> {
        if window.is_empty() {
            // ADR-032 §1: an empty window is malformed — nothing to verify.
            return Err(RuntimeError::MalformedResponse(
                "verify_window with empty draft window".to_string(),
            ));
        }
        // Stage-10 mirror (RC-8): the DISCLOSED cap bounds the window
        // before any engine work. batch_window_max <= WINDOW_CAP by
        // construction (the adapter clamps the pin), so this is exactly
        // min(WINDOW_CAP, batch_window_max).
        let caps = self.capabilities();
        debug_assert!((1..=WINDOW_CAP).contains(&caps.batch_window_max));
        if window.len() > caps.batch_window_max as usize {
            return Err(RuntimeError::Api {
                status: 413,
                code: "payload_too_large".to_string(),
                message: format!(
                    "draft window {} exceeds the engine's disclosed batch_window_max {} \
                     (before any engine work)",
                    window.len(),
                    caps.batch_window_max
                ),
            });
        }
        let mut session = self.session.lock().await;
        if session.finished {
            return Err(RuntimeError::MalformedResponse(
                "verify_window after end-of-generation (the session is over)".to_string(),
            ));
        }
        if session.committed.is_empty() {
            return Err(RuntimeError::MalformedResponse(
                "verify_window before prefill; commit the session prompt first".to_string(),
            ));
        }
        // The one pass (the adapter enforces its own window/context/KV
        // caps and offloads every blocking call). Honest errors propagate;
        // the committed prefix moves only on success.
        let VerifyOutcome { accepted, bonus } = self
            .adapter
            .verify_drafts(&session.handle, &session.committed, window, params)
            .await?;
        session.committed.extend_from_slice(&accepted);
        if let Some(token) = bonus {
            session.committed.push(token);
        } else {
            // correction None is exactly EOG (full-accept bonus or
            // rejection replacement was an EOG token): the commit covers
            // the accepted prefix only, and the session is over.
            session.finished = true;
        }
        Ok((accepted.len() as u32, bonus))
    }

    /// The engine's real capability disclosure (RC-8): backend from the
    /// configured bundle, `batch_verify: true`, and `batch_window_max`
    /// from the adapter's productionized max verify geometry (the
    /// construction pin the load-time warmup sizes).
    pub fn capabilities(&self) -> VerifyEngineCaps {
        VerifyEngineCaps {
            backend: self.backend,
            batch_verify: true,
            batch_window_max: self.adapter.verify_window_max(),
        }
    }

    /// Snapshot of the verifier's committed continuation (the exact token
    /// stream the next window continues — the I1 audit input).
    pub async fn committed_prefix(&self) -> Vec<u32> {
        self.session.lock().await.committed.clone()
    }

    /// The runtime handle this engine's session loaded (KV-accounting
    /// key for `LlamaCppCapi::kv_usage`).
    pub async fn handle_id(&self) -> u64 {
        self.session.lock().await.handle.handle_id()
    }
}

/// Compile-proof mirror impl (see [`BatchVerifyEngineMirror`]). The REAL
/// architect-owned trait is bound to this engine in `tests/capi_verify.rs`.
#[async_trait]
impl BatchVerifyEngineMirror for CapiVerifyEngine {
    async fn verify_window(
        &self,
        window: &[u32],
        params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), RuntimeError> {
        CapiVerifyEngine::verify_window(self, window, params).await
    }

    fn capabilities(&self) -> VerifyEngineCaps {
        CapiVerifyEngine::capabilities(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_labels_match_the_session_vocabulary() {
        assert_eq!(VerifyBackend::Cpu.as_str(), "cpu");
        assert_eq!(VerifyBackend::Vulkan.as_str(), "vulkan");
        assert_eq!(VerifyBackend::Cpu.to_string(), "cpu");
        assert_eq!(VerifyBackend::Vulkan.to_string(), "vulkan");
    }

    #[test]
    fn backend_detection_fails_closed_on_a_non_bundle() {
        let tmp = std::env::temp_dir();
        // A directory without the C-API library is not a bundle: None,
        // never a guess.
        assert_eq!(VerifyBackend::of_bundle(&tmp), None);
    }

    #[test]
    fn backend_detection_separates_cpu_and_vulkan_bundles() {
        let base = std::env::temp_dir().join("msp-verify-backend-detect");
        let cpu = base.join("cpu");
        let vulkan = base.join("vulkan");
        let lib = super::super::ffi::LlamaLib::library_file_name();
        std::fs::create_dir_all(&cpu).expect("mkdir cpu");
        std::fs::create_dir_all(&vulkan).expect("mkdir vulkan");
        std::fs::write(cpu.join(lib), b"").expect("stage lib (cpu)");
        std::fs::write(vulkan.join(lib), b"").expect("stage lib (vulkan)");
        std::fs::write(vulkan.join("ggml-vulkan.dll"), b"").expect("stage vulkan dll");
        assert_eq!(VerifyBackend::of_bundle(&cpu), Some(VerifyBackend::Cpu));
        assert_eq!(
            VerifyBackend::of_bundle(&vulkan),
            Some(VerifyBackend::Vulkan)
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn the_adr032_window_cap_is_the_session_cap() {
        // The adapter's clamp and the trait-level stage-10 rule both key
        // off WINDOW_CAP = 32 (ADR-032 §1 frozen); the session crate pins
        // the same constant (`verifydrafts::WINDOW_CAP`). If either side
        // ever moves, this pin forces the reconciliation.
        assert_eq!(WINDOW_CAP, 32);
    }
}
