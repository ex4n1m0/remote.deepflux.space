//! The composed daemon's family-engine seam (ADR-032 light-up tier,
//! feature `verifydrafts`).
//!
//! The serve paths stay engine-agnostic behind
//! `Arc<dyn BatchVerifyEngine>` (the [`super::serve::serve_verifydrafts_session`]
//! argument — the existing TimingEngine seam's pattern: the loop wraps
//! whatever it is given and measures it). THIS type is the one place that
//! knows WHICH engine backs the family:
//!
//! - [`FamilyEngineSource::Shared`] — one fixed engine for every session:
//!   the mock/stub venue of the plain serve paths and every scripted test;
//! - [`FamilyEngineSource::Capi`] (only under `verifydrafts-capi`, the G4
//!   bridge) — Runtime's production [`CapiVerifyEngine`], constructed
//!   fresh per family session (one handle per session on the shared
//!   adapter; multiple engines may share an adapter — the
//!   one-bundle-per-process guard applies to the ADAPTER, ADR-031 §2) and
//!   PREFILLED with the pinned session prompt.
//!
//! # The prompt gap (recorded, out-of-band pinning)
//!
//! The family's wire and gate never carry the session PROMPT — the
//! coordinator's draft windows chain on the prefix hash, and the verifier
//! must already hold the same prompt in engine KV
//! ([`modelswarm_session::verifydrafts::BatchVerifyEngine`] has no
//! prefill surface; the wiring handoff's G3 records the offer's missing
//! profile/params binding — the prompt is the same family of gap). The
//! seam therefore pins the prompt from daemon configuration, exactly as
//! `VerifyDraftsServeConfig` pins the profile id and sampling parameters,
//! and the Capi variant commits it as the PREFILLED root at engine
//! construction — before any window can arrive.
//!
//! # How the offer-form-v3 fields interact with the prefill (ADR-032
//! revision 4 §3/G3 + the compose handoff's G6, folded 2026-10-12)
//!
//! The v3 offer's `profile_id` and `generation_params_hash` are
//! negotiation-time DISCOVERY: the serve loop compares both against its
//! own pinned config and rejects `profile_mismatch` / `params_mismatch`
//! before any accept. That closes the pairing half of the prefill
//! assumption: the engine behind this seam is loaded under the daemon's
//! pinned profile, and every `verify_window` pass runs under the pinned
//! sampling parameters — a coordinator whose profile or params differ can
//! no longer open the session at all, so the prefilled KV can never be
//! consumed by a mismatched pairing. The PROMPT itself remains out of
//! band: nothing in the offer (or any family frame) commits the
//! coordinator's prompt, so the daemon's `prompt_tokens` and the
//! coordinator's session prompt must still be pinned to the same
//! tokenization by configuration. The residual gap — no
//! prompt(-hash) commitment exists on the wire, so a misconfigured
//! pairing is detectable only through acceptance collapse / audit
//! divergence — is RECORDED, not improvised: closing it needs a
//! freeze-ADR decision (a prompt-hash echo or commitment field), and this
//! seam remains the single place to feed whatever lands
//! (`FamilyEngineSource::Capi { prompt_tokens }`).

#[cfg(feature = "verifydrafts-capi")]
use std::path::PathBuf;
use std::sync::Arc;

use modelswarm_runtime::RuntimeError;
use modelswarm_session::negotiation::EngineDisclosure;
use modelswarm_session::verifydrafts::BatchVerifyEngine;

/// Where the composed daemon's family sessions get their batch-verify
/// engine. Cloning the source is not needed: the composed loop holds one
/// and asks it for an engine per accepted family session
/// ([`FamilyEngineSource::engine_for`]).
pub enum FamilyEngineSource {
    /// One shared engine for every family session (the mock/stub venue of
    /// the plain serve paths and tests). A shared engine serializes its
    /// sessions through one `verify_window` — acceptable for scripted
    /// engines; the production venue constructs per-session engines.
    Shared(Arc<dyn BatchVerifyEngine>),
    /// The production engine: a fresh `CapiVerifyEngine` per family
    /// session, prefilled with `prompt_tokens` (the out-of-band pinned
    /// session prompt — see the module docs). Available only under the
    /// `verifydrafts-capi` feature (which enables Runtime's
    /// `capi-adapter` and the G4 bridge hosting the architect's trait for
    /// the engine).
    #[cfg(feature = "verifydrafts-capi")]
    Capi {
        /// The shared pinned C-API adapter (already constructed over the
        /// hash-verified engine bundle; one adapter per process).
        adapter: Arc<modelswarm_runtime::capi::LlamaCppCapi>,
        /// The backend family the bundle was staged as (E0: CPU ≠ Vulkan;
        /// supply what was staged and verified —
        /// `VerifyBackend::of_bundle` detects it from bundle contents).
        backend: modelswarm_runtime::capi::verify::VerifyBackend,
        /// The runtime handle label for per-session loads (local KV
        /// bookkeeping only).
        profile_id: String,
        /// The pinned session prompt (token ids), committed as the
        /// engine's PREFILLED root at construction. MUST be non-empty.
        prompt_tokens: Vec<u32>,
    },
}

impl FamilyEngineSource {
    /// Yields the engine for ONE family session, prefilled and ready for
    /// its first `verify_window`. Errors are local engine-loading
    /// failures (the composed loop refuses the session honestly — the
    /// coordinator falls back to single, never silently).
    pub async fn engine_for(&self) -> Result<Arc<dyn BatchVerifyEngine>, RuntimeError> {
        self.engine_for_root(None).await
    }

    /// The ADR-036 form of the same seam: `root` overrides the
    /// daemon-pinned neutral prompt with the session's OWN prefilled root
    /// — for a carrier session, the user's conversation as token ids
    /// (`Some(prompt_tokens)`); `None` keeps the ADR-034 neutral pin.
    /// Under `verifydrafts-capi` this constructs a FRESH per-session
    /// engine (KV residency is bounded by the session: the returned
    /// handle's drop tears the engine down); the `Shared` variant yields
    /// the injected engine unchanged (the scripted/test venue — no KV).
    pub async fn engine_for_root(
        &self,
        root: Option<&[u32]>,
    ) -> Result<Arc<dyn BatchVerifyEngine>, RuntimeError> {
        match self {
            Self::Shared(engine) => {
                // The scripted/test venue ignores the root (no KV); the
                // binding keeps the signature honest for both variants.
                let _ = root;
                Ok(Arc::clone(engine))
            }
            #[cfg(feature = "verifydrafts-capi")]
            Self::Capi {
                adapter,
                backend,
                profile_id,
                prompt_tokens,
            } => {
                let tokens = root.unwrap_or(prompt_tokens);
                if tokens.is_empty() {
                    return Err(RuntimeError::MalformedResponse(
                        "family engine source configured with an empty pinned prompt".to_string(),
                    ));
                }
                let engine = super::engine_bridge::CapiBatchVerifyEngine::new(
                    Arc::clone(adapter),
                    *backend,
                    profile_id.clone(),
                    tokens.to_vec(),
                )
                .await?;
                Ok(Arc::new(engine))
            }
        }
    }

    /// The disclosure this source's engines will report (the Shared
    /// variant's own capabilities; the Capi variant's real geometry —
    /// `batch_verify: true`, the adapter's pinned verify window, the
    /// staged backend). Callers that need the exact per-session disclosure
    /// should use [`Self::engine_for`] and read the engine's own
    /// `capabilities()` — the authoritative form.
    pub fn disclosure(&self) -> EngineDisclosure {
        match self {
            Self::Shared(engine) => engine.capabilities(),
            #[cfg(feature = "verifydrafts-capi")]
            Self::Capi {
                adapter, backend, ..
            } => super::engine_bridge::capi_disclosure(
                modelswarm_runtime::capi::verify::VerifyEngineCaps {
                    backend: *backend,
                    batch_verify: true,
                    batch_window_max: adapter.verify_window_max(),
                },
            ),
        }
    }
}

/// Constructs the production [`FamilyEngineSource::Capi`] over an
/// INSTALLED pinned bundle — the daemon-composition entry the desktop's
/// hosting start calls (ADR-032 §7 disposition item ii). `engine_dirs`
/// are the installed bundle candidates in preference order (e.g. the
/// daemon's serving variant first); the first one whose C-API library is
/// detectable (`VerifyBackend::of_bundle` — a file check, nothing loaded)
/// wins and is CONSTRUCTED exactly once — a second, different bundle can
/// never register in one process (ADR-031 §2's one-bundle guard), so the
/// fallback is chosen before any load, not after a failure.
///
/// The backend is DETECTED from the winning bundle (the disclosure
/// reports what the bundle really is, never a hand-set value), the
/// adapter load is blocking so it runs under `spawn_blocking`, and a
/// candidate list with no C-API bundle (or a failed construction) errors
/// honestly — the caller falls back to plain serving, never silently.
///
/// `prompt_tokens` is the daemon-pinned session prompt (the G6-family
/// out-of-band gap: the family wire never carries it; an EMPTY prompt is
/// accepted here but refuses every session at
/// [`FamilyEngineSource::engine_for`], fail-closed).
#[cfg(feature = "verifydrafts-capi")]
pub async fn capi_family_source(
    engine_dirs: Vec<PathBuf>,
    model_path: PathBuf,
    engine: Option<modelswarm_runtime::llamacpp::EngineIdentity>,
    profile_id: String,
    prompt_tokens: Vec<u32>,
) -> Result<Arc<FamilyEngineSource>, RuntimeError> {
    let (engine_dir, backend) = engine_dirs
        .iter()
        .find_map(|dir| {
            modelswarm_runtime::capi::verify::VerifyBackend::of_bundle(dir).map(|b| (dir.clone(), b))
        })
        .ok_or_else(|| {
            RuntimeError::MalformedResponse(format!(
                "no C-API engine bundle among {} — the family engine needs a pinned bundle with the C-API library",
                engine_dirs
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
    let mut config = modelswarm_runtime::capi::CapiConfig::new(engine_dir, model_path);
    if let Some(identity) = engine {
        config = config.with_engine(identity);
    }
    // `LlamaCppCapi::new` loads the library AND the model — blocking by
    // contract; keep the async context responsive.
    let adapter =
        tokio::task::spawn_blocking(move || modelswarm_runtime::capi::LlamaCppCapi::new(config))
            .await
            .map_err(|e| {
                RuntimeError::MalformedResponse(format!("engine load task failed: {e}"))
            })??;
    Ok(Arc::new(FamilyEngineSource::Capi {
        adapter: Arc::new(adapter),
        backend,
        profile_id,
        prompt_tokens,
    }))
}

/// The source's disclosed geometry as JSON — the desktop status surface
/// (state fields only; the authoritative per-session form stays the
/// engine's own `capabilities()`).
pub fn disclosure_json(source: &FamilyEngineSource) -> serde_json::Value {
    let disclosure = source.disclosure();
    serde_json::json!({
        "backend": disclosure.backend.as_str(),
        "batch_verify": disclosure.batch_verify,
        "batch_window_max": disclosure.batch_window_max,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use modelswarm_runtime::SamplingParams;
    use modelswarm_session::negotiation::Backend;

    /// A fixed-outcome engine (no state): full acceptance plus a bonus.
    struct FixedEngine;

    #[async_trait::async_trait]
    impl BatchVerifyEngine for FixedEngine {
        async fn verify_window(
            &self,
            window: &[u32],
            _params: &SamplingParams,
        ) -> Result<(u32, Option<u32>), RuntimeError> {
            Ok((window.len() as u32, Some(999)))
        }

        fn capabilities(&self) -> EngineDisclosure {
            EngineDisclosure {
                backend: Backend::Cpu,
                batch_verify: true,
                batch_window_max: 8,
            }
        }
    }

    /// The Shared seam: `engine_for` yields the injected engine (mock/stub
    /// venue), its capabilities flow unchanged, and its passes work
    /// through the yielded `Arc<dyn BatchVerifyEngine>`.
    #[tokio::test]
    async fn shared_source_yields_the_injected_engine() {
        let source = FamilyEngineSource::Shared(Arc::new(FixedEngine));
        assert_eq!(source.disclosure().batch_window_max, 8);
        let engine = source.engine_for().await.expect("shared engine yields");
        assert_eq!(engine.capabilities().batch_window_max, 8);
        assert!(engine.capabilities().batch_verify);
        assert!(engine.capabilities().is_valid_disclosure());
        let (accepted, correction) = engine
            .verify_window(&[1, 2, 3], &SamplingParams::default())
            .await
            .expect("pass through the seam");
        assert_eq!((accepted, correction), (3, Some(999)));
    }

    /// The status surface mirrors the disclosure exactly (backend label,
    /// batch flag, window) — the desktop's UI shows the engine's real
    /// geometry from this JSON, never a hand-set field.
    #[test]
    fn disclosure_json_mirrors_the_source_geometry() {
        let source = FamilyEngineSource::Shared(Arc::new(FixedEngine));
        let json = disclosure_json(&source);
        assert_eq!(json["backend"], "cpu");
        assert_eq!(json["batch_verify"], true);
        assert_eq!(json["batch_window_max"], 8);
    }

    /// A candidate list with no C-API bundle (missing dirs, or bundles
    /// without the library) fails the constructor HONESTLY — the caller
    /// falls back to plain serving, never a half-inited family (the
    /// desktop's degrade path). No load is attempted: the failure is the
    /// cheap file check.
    #[cfg(feature = "verifydrafts-capi")]
    #[tokio::test]
    async fn capi_source_fails_closed_on_a_missing_bundle() {
        let missing = std::env::temp_dir().join("modelswarm-no-such-bundle");
        let error = match capi_family_source(
            vec![missing],
            std::env::temp_dir().join("model.gguf"),
            None,
            "msp1:x".to_string(),
            vec![1, 2, 3],
        )
        .await
        {
            Ok(_) => panic!("a missing bundle must fail the constructor"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("no C-API engine bundle"),
            "honest reason, got: {error}"
        );
    }
}
