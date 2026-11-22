//! The G4 engine bridge (feature `verifydrafts-capi` — implies
//! `verifydrafts` and Runtime's `capi-adapter`): hosts the architect's
//! [`BatchVerifyEngine`] impl for Runtime's production
//! [`CapiVerifyEngine`].
//!
//! # Why the impl lives here
//!
//! `modelswarm-session` already depends on `modelswarm-runtime` (for
//! `RuntimeError`/`SamplingParams`), so the trait cannot be implemented
//! for a runtime-crate type in the runtime LIB — a reverse package
//! dependency, which Cargo rejects as cyclic (Runtime's handoff §4, the
//! recorded trait gap). The node crate depends on both legally, and
//! Runtime's `tests/capi_verify.rs` already proved the exact pattern
//! (`CapiVerifyEngineAsTrait`, a dev-dependency cycle binding the trait in
//! a test target): this module is that pattern's production-hosted twin —
//! the newtype impl the composed daemon wires in through
//! [`super::engine_source::FamilyEngineSource`].
//!
//! # What the bridge adds
//!
//! - [`capi_disclosure`]: Runtime's `to_disclosure` reference mapping
//!   (their `tests/capi_verify.rs`), hosted in the seat that can name both
//!   types — the honest `EngineDisclosure` built from the engine's REAL
//!   geometry (ADR-032 §3 RC-8: backend from the staged bundle,
//!   `batch_verify: true`, `batch_window_max` from the adapter's
//!   construction-pinned verify window).
//! - The PREFILLED root: the family wire never carries the session prompt
//!   (see [`super::engine_source`] — the G3-family gap), so
//!   [`CapiBatchVerifyEngine::new`] commits the daemon-pinned prompt via
//!   `CapiVerifyEngine::prefill` before the engine is ever handed to a
//!   serve loop. A raw `CapiVerifyEngine` without a prefill refuses every
//!   window fail-closed; the bridge makes that impossible to forget.
//!
//! Everything adjudicating stays in the session crate; everything exact
//! stays in Runtime's engine. The bridge only binds the two.

use std::sync::Arc;

use async_trait::async_trait;

use modelswarm_runtime::capi::verify::{VerifyBackend, VerifyEngineCaps};
use modelswarm_runtime::capi::CapiVerifyEngine;
use modelswarm_runtime::{RuntimeError, SamplingParams};
use modelswarm_session::negotiation::{Backend, EngineDisclosure};
use modelswarm_session::verifydrafts::BatchVerifyEngine;

/// Maps the runtime engine's real caps onto the session crate's
/// `EngineDisclosure` (ADR-032 §3 RC-8) — Runtime's `to_disclosure`
/// reference mapping (their `tests/capi_verify.rs`), hosted here so the
/// serve loop never hand-writes a disclosure the engine could report
/// itself.
pub fn capi_disclosure(caps: VerifyEngineCaps) -> EngineDisclosure {
    EngineDisclosure {
        backend: match caps.backend {
            VerifyBackend::Cpu => Backend::Cpu,
            VerifyBackend::Vulkan => Backend::Vulkan,
        },
        batch_verify: caps.batch_verify,
        batch_window_max: caps.batch_window_max,
    }
}

/// The production engine behind the architect's trait: a newtype of
/// Runtime's [`CapiVerifyEngine`] with the session prompt committed as
/// the PREFILLED root. One per family session (one runtime handle each;
/// the shared adapter enforces the one-bundle-per-process guard).
pub struct CapiBatchVerifyEngine {
    inner: Arc<CapiVerifyEngine>,
}

impl CapiBatchVerifyEngine {
    /// Loads a fresh engine session on `adapter` (the runtime handle label
    /// is `profile_id` — local KV bookkeeping only) and commits
    /// `prompt_tokens` as the PREFILLED root. The prompt MUST be the same
    /// tokenized prompt the coordinator's session chains its windows on —
    /// the daemon pins it from configuration because the family wire
    /// never carries it (see the module docs).
    pub async fn new(
        adapter: Arc<modelswarm_runtime::capi::LlamaCppCapi>,
        backend: VerifyBackend,
        profile_id: String,
        prompt_tokens: Vec<u32>,
    ) -> Result<Self, RuntimeError> {
        let engine = CapiVerifyEngine::new(adapter, backend, &profile_id).await?;
        engine.prefill(&prompt_tokens).await?;
        Ok(Self {
            inner: Arc::new(engine),
        })
    }

    /// The engine's raw runtime caps (the pre-mapping form; the trait's
    /// `capabilities()` is the session-vocabulary form).
    pub fn caps(&self) -> VerifyEngineCaps {
        self.inner.capabilities()
    }
}

#[async_trait]
impl BatchVerifyEngine for CapiBatchVerifyEngine {
    async fn verify_window(
        &self,
        window: &[u32],
        params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), RuntimeError> {
        // The inherent method (not the mirror trait): one batched pass,
        // caps/KV refusals before engine work, the committed prefix
        // advancing only on success — all Runtime's, unchanged.
        self.inner.verify_window(window, params).await
    }

    fn capabilities(&self) -> EngineDisclosure {
        capi_disclosure(self.inner.capabilities())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use modelswarm_session::verifydrafts::WINDOW_CAP as SESSION_WINDOW_CAP;

    /// The disclosure mapping pin (Runtime's
    /// `disclosure_mapping_covers_the_session_shape`, mirrored at the
    /// bridge): every runtime backend maps onto the session vocabulary
    /// with agreeing wire labels, and the disclosure stays schema-valid.
    #[test]
    fn disclosure_mapping_pins_the_runtime_reference() {
        for backend in [VerifyBackend::Cpu, VerifyBackend::Vulkan] {
            let caps = VerifyEngineCaps {
                backend,
                batch_verify: true,
                batch_window_max: SESSION_WINDOW_CAP,
            };
            let disclosure = capi_disclosure(caps);
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

    /// ADR-032's window cap is frozen at 32 on BOTH sides (Runtime's
    /// `the_adr032_window_cap_is_the_session_cap` pin, mirrored): if
    /// either crate ever moves it, this forces the reconciliation before
    /// any disclosure crosses the wire.
    #[test]
    fn the_adr032_window_caps_agree() {
        assert_eq!(SESSION_WINDOW_CAP, modelswarm_runtime::capi::WINDOW_CAP);
        assert_eq!(SESSION_WINDOW_CAP, 32);
    }

    /// Compile proof (the whole point of the G4 bridge): the production
    /// engine binds the architect's REAL trait — not the mirror — in this
    /// crate, with no dependency cycle.
    #[test]
    fn the_bridge_binds_the_real_trait() {
        fn binds<E: BatchVerifyEngine>() {}
        binds::<CapiBatchVerifyEngine>();
    }
}
