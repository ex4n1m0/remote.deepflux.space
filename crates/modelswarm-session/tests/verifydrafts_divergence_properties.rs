//! ADR-032 divergence/boundary properties for the verifier-side
//! [`VerifyDraftsGate`] (implementation plan §3.6, file 2 of 2; venue:
//! per-push, default features — §7 execution-venue matrix, item 5).
//!
//! For random windows and mock engine outcomes (plan §3.6 final
//! paragraph): on rejection `divergence_point == accepted_prefix_len` and
//! `accepted_prefix_len < len(window)`; on acceptance
//! `divergence_point == null` and `accepted_prefix_len == len`;
//! `correction` is present except the pinned EOG case (F-2); the
//! committed set is always `window[..accepted] ++ [correction]`; plus the
//! boundary sweep `len ∈ {1, 31, 32, 33} × batch_window_max ∈ {1, 8, 32}`
//! (ADR-032 §7 fixture row 3 generalized).

use modelswarm_identity::InstallationIdentity;

/// The QUIC remote PeerId a serve loop would supply for this
/// coordinator identity (RC-1: admitted requests must carry it).
fn peer_of(c: &InstallationIdentity) -> String {
    modelswarm_identity::peer_id_for(&c.verifying_key().to_bytes())
}
use modelswarm_runtime::SamplingParams;
use modelswarm_session::negotiation::{
    Backend, EngineDisclosure, FrameRejectReason, SessionBudget,
};
use modelswarm_session::verifydrafts::{
    batch_generation_params_hash, sign_verify_drafts, AdmissionDecision, BatchVerifyEngine,
    CommitApplyOutcome, DispatchOutcome, VerifyDrafts, VerifyDraftsGate, VerifyDraftsGateConfig,
    COOPERATIVE_PROTOCOL_VERSION, WINDOW_CAP,
};
use modelswarm_session::{compute_prefix_hash, CommitPrefix, GENESIS_PREFIX_HASH};
use proptest::prelude::*;
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// 2026-10-12T00:00:00Z (the fixture anchor).
const NOW: u64 = 1_791_763_200_000;

fn profile() -> String {
    format!("msp1:{}", "ab".repeat(32))
}
fn params_hash() -> String {
    batch_generation_params_hash(&SamplingParams::default()).unwrap()
}
fn fixture_id(seed: u8) -> InstallationIdentity {
    InstallationIdentity::from_bytes(&[seed; 32])
}

struct MockEngine {
    disclosure: EngineDisclosure,
    outcome: Mutex<(u32, Option<u32>)>,
    calls: AtomicUsize,
}

impl MockEngine {
    fn new(batch_window_max: u32, outcome: (u32, Option<u32>)) -> Self {
        Self {
            disclosure: EngineDisclosure {
                backend: Backend::Cpu,
                batch_verify: true,
                batch_window_max,
            },
            outcome: Mutex::new(outcome),
            calls: AtomicUsize::new(0),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl BatchVerifyEngine for MockEngine {
    async fn verify_window(
        &self,
        window: &[u32],
        _params: &SamplingParams,
    ) -> Result<(u32, Option<u32>), modelswarm_runtime::RuntimeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let (accepted, correction) = *self.outcome.lock().unwrap();
        Ok((accepted.min(window.len() as u32), correction))
    }
    fn capabilities(&self) -> EngineDisclosure {
        self.disclosure.clone()
    }
}

fn gate(batch_window_max: u32, coordinator: &InstallationIdentity) -> VerifyDraftsGate {
    VerifyDraftsGate::new(VerifyDraftsGateConfig {
        session_id: "sess-div".to_string(),
        profile_id: profile(),
        generation_params_hash: params_hash(),
        committed_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
        coordinator_key: coordinator.verifying_key(),
        verifier_installation_id: fixture_id(0x22).installation_id(),
        engine: EngineDisclosure {
            backend: Backend::Cpu,
            batch_verify: true,
            batch_window_max,
        },
        budget: SessionBudget {
            max_endpoints: 1,
            max_endpoint_seconds: 3600,
            max_output_tokens: 100_000,
        },
        lease_expires_at_ms: NOW + 3_600_000,
        sampling_params: SamplingParams::default(),
        verifier_next_seq: 4,
    })
    .unwrap()
}

/// Distinctive ids (privacy-visible if they ever leak into a frame).
fn window_of(len: usize) -> Vec<u32> {
    (0..len).map(|i| 9_100_000 + i as u32).collect()
}

fn request_frame(
    coordinator: &InstallationIdentity,
    seq: u64,
    round: u64,
    nonce: &str,
    parent: &str,
    window: &[u32],
) -> Value {
    let mut msg = VerifyDrafts {
        session_id: "sess-div".to_string(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
        seq,
        round,
        profile_id: profile(),
        parent_prefix_hash: parent.to_string(),
        generation_params_hash: params_hash(),
        window_tokens: window.to_vec(),
        proposer_id: "12D3KooProposer".to_string(),
        nonce: nonce.to_string(),
        deadline_ms: 2_500,
        sender: coordinator.installation_id(),
        signature: String::new(),
    };
    msg.signature = sign_verify_drafts(&msg, coordinator).unwrap();
    serde_json::to_value(&msg).unwrap()
}

proptest! {
    /// The divergence shape for random windows × mock outcomes (§3.6):
    /// `divergence_point == accepted_prefix_len < len` on rejection,
    /// `null` + full length on acceptance; `correction` present except
    /// the pinned EOG case; the committed set is always
    /// `window[..accepted] ++ [correction]` and `new_prefix_hash` is the
    /// independent recomputation over exactly that set (ADR-032 §1).
    #[test]
    fn divergence_shape_holds_for_random_windows_and_outcomes(
        len in 1usize..=32,
        accepted in 0u32..=31,
        correction in proptest::option::of(9_200_000u32..9_300_000),
        nonce_seed in any::<u64>(),
    ) {
        let len = len.min(32);
        let accepted = accepted.min(len as u32);
        let window = window_of(len);
        let coordinator = fixture_id(0x31);
        let engine = MockEngine::new(32, (accepted, correction));
        let mut g = gate(32, &coordinator);
        let frame = request_frame(
            &coordinator,
            1,
            1,
            &format!("div-nonce-{nonce_seed}"),
            GENESIS_PREFIX_HASH,
            &window,
        );
        assert!(matches!(
            g.admit_verify_drafts(&frame, NOW, NOW, &peer_of(&coordinator)),
            AdmissionDecision::Admitted { .. }
        ));

        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let outcome = rt.block_on(g.dispatch_outstanding(&engine, NOW, NOW + 35));
        let DispatchOutcome::Dispatched(result) = outcome else {
            panic!("dispatch failed: {outcome:?}");
        };
        prop_assert_eq!(engine.calls(), 1, "exactly ONE pass per VerifyDrafts");
        prop_assert_eq!(result.accepted_prefix_len, accepted);
        prop_assert_eq!(result.round, 1);
        prop_assert_eq!(result.nonce_echo, format!("div-nonce-{nonce_seed}"));
        prop_assert_eq!(result.seq, 4, "the VERIFIER's own counter");
        prop_assert_eq!(result.sender, fixture_id(0x22).installation_id());

        if accepted < len as u32 {
            prop_assert_eq!(result.divergence_point, Some(accepted));
        } else {
            prop_assert_eq!(result.divergence_point, None);
        }

        // The committed set: window[..accepted] ++ [correction]; at EOG
        // (F-2) correction is null and the commit covers the prefix only.
        let mut committed = window[..accepted as usize].to_vec();
        if let Some(token) = correction {
            committed.push(token);
        }
        prop_assert_eq!(result.correction, correction);
        let recomputed =
            compute_prefix_hash(GENESIS_PREFIX_HASH, &committed).unwrap();
        prop_assert_eq!(
            result.new_prefix_hash.clone(), recomputed,
            "new_prefix_hash recomputes over (parent ‖ accepted ‖ [correction])"
        );

        // A reproducing commit advances the gate's own chain (RC-4), the
        // duplicate is a remembered no-op, and the ledger grew by exactly
        // the committed count (I8).
        let commit = CommitPrefix {
            session_id: "sess-div".to_string(),
            round: 1,
            previous_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
            accepted_token_ids: committed.clone(),
            new_prefix_hash: result.new_prefix_hash.clone(),
            model_profile_id: profile(),
            generation_params_hash: params_hash(),
            sender: coordinator.installation_id(),
        };
        prop_assert_eq!(g.apply_prefix_commit(&commit), CommitApplyOutcome::Advanced { round: 1 });
        prop_assert_eq!(g.committed_output_tokens(), committed.len() as u64);
        prop_assert_eq!(g.committed_prefix_hash(), result.new_prefix_hash);
        prop_assert_eq!(g.apply_prefix_commit(&commit), CommitApplyOutcome::DuplicateRound);
        prop_assert_eq!(g.committed_output_tokens(), committed.len() as u64);
    }
}

proptest! {
    /// Random boundary windows against random disclosures: admission is
    /// exactly `len <= min(WINDOW_CAP, batch_window_max)` (RC-8) with ZERO
    /// engine passes on the reject side.
    #[test]
    fn cap_boundary_admits_iff_len_fits_the_effective_cap(
        len in 1usize..=40,
        batch_window_max in 1u32..=32,
        nonce_seed in any::<u64>(),
    ) {
        let coordinator = fixture_id(0x31);
        let engine = MockEngine::new(batch_window_max, (1, Some(9_300_001)));
        let mut g = gate(batch_window_max, &coordinator);
        let window = window_of(len);
        let frame = request_frame(
            &coordinator,
            1,
            1,
            &format!("cap-nonce-{nonce_seed}"),
            GENESIS_PREFIX_HASH,
            &window,
        );
        let effective = WINDOW_CAP.min(batch_window_max) as usize;
        let decision = g.admit_verify_drafts(&frame, NOW, NOW, &peer_of(&coordinator));
        if len > effective {
            let rejected = matches!(
                decision,
                AdmissionDecision::FrameRejected(f) if f.code == FrameRejectReason::PayloadTooLarge
            );
            prop_assert!(rejected);
            prop_assert_eq!(engine.calls(), 0, "cap reject is BEFORE any engine work");
        } else {
            let admitted = matches!(decision, AdmissionDecision::Admitted { .. });
            prop_assert!(admitted);
        }
    }
}

/// The pinned deterministic boundary sweep of the plan:
/// len ∈ {1, 31, 32, 33} × batch_window_max ∈ {1, 8, 32} — the
/// `verifydrafts-3-boundary.json` shape generalized over the full cross
/// product, including the committed/chain advance on the admit side and
/// the EOG prefix-only commit (F-2).
#[test]
fn deterministic_boundary_sweep_len_x_batch_window_max() {
    let coordinator = fixture_id(0x31);
    for batch_window_max in [1u32, 8, 32] {
        for len in [1usize, 31, 32, 33] {
            let effective = (WINDOW_CAP.min(batch_window_max)) as usize;
            let admitted = len <= effective;
            // Full acceptance on the admit side; EOG (correction None)
            // exercises the prefix-only commit.
            let engine = MockEngine::new(batch_window_max, (len as u32, None));
            let mut g = gate(batch_window_max, &coordinator);
            let window = window_of(len);
            let frame = request_frame(
                &coordinator,
                1,
                1,
                &format!("sweep-{batch_window_max}-{len}"),
                GENESIS_PREFIX_HASH,
                &window,
            );
            let decision = g.admit_verify_drafts(&frame, NOW, NOW, &peer_of(&coordinator));
            if !admitted {
                assert!(
                    matches!(
                        decision,
                        AdmissionDecision::FrameRejected(f)
                            if f.code == FrameRejectReason::PayloadTooLarge
                    ),
                    "len {len} over bwm {batch_window_max} must be payload_too_large"
                );
                assert_eq!(engine.calls(), 0);
                continue;
            }
            assert!(
                matches!(decision, AdmissionDecision::Admitted { .. }),
                "len {len} under bwm {batch_window_max} must admit"
            );
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            let DispatchOutcome::Dispatched(result) =
                rt.block_on(g.dispatch_outstanding(&engine, NOW, NOW + 35))
            else {
                panic!("dispatch failed");
            };
            assert_eq!(engine.calls(), 1);
            // Full acceptance: no divergence, EOG correction null, the
            // commit covers the accepted prefix only (F-2).
            assert_eq!(result.accepted_prefix_len, len as u32);
            assert_eq!(result.divergence_point, None);
            assert_eq!(result.correction, None);
            assert_eq!(
                result.new_prefix_hash,
                compute_prefix_hash(GENESIS_PREFIX_HASH, &window).unwrap()
            );
            let commit = CommitPrefix {
                session_id: "sess-div".to_string(),
                round: 1,
                previous_prefix_hash: GENESIS_PREFIX_HASH.to_string(),
                accepted_token_ids: window.clone(),
                new_prefix_hash: result.new_prefix_hash.clone(),
                model_profile_id: profile(),
                generation_params_hash: params_hash(),
                sender: coordinator.installation_id(),
            };
            assert_eq!(
                g.apply_prefix_commit(&commit),
                CommitApplyOutcome::Advanced { round: 1 }
            );
            assert_eq!(g.committed_prefix_hash(), result.new_prefix_hash);

            // The next round may GAP (RC-5(c)) and must chain onto the new
            // committed hash (I3).
            let next_window = window_of(len.min(effective));
            let next = request_frame(
                &coordinator,
                2,
                7, // gap over round 1
                &format!("sweep-next-{batch_window_max}-{len}"),
                &result.new_prefix_hash,
                &next_window,
            );
            assert!(matches!(
                g.admit_verify_drafts(&next, NOW, NOW, &peer_of(&coordinator)),
                AdmissionDecision::Admitted { round: 7, .. }
            ));
        }
    }
}
