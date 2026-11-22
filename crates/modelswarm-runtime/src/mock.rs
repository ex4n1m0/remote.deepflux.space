//! TEST-ONLY deterministic toy decoder (ADR-019). Compiled solely under the
//! `mock-runtime` feature; every artifact it produces is excluded from any
//! product claim and must be labeled "TEST-ONLY mock backend".
//!
//! - Vocab: exactly 256 integer token ids (one per byte value); tokenization
//!   is the UTF-8 byte sequence, detokenization is its inverse.
//! - `next_token = f(prefix_hash, seed)` via splitmix64 mixing: fully
//!   deterministic given the same prefix and sampling seed.
//! - `draft_accuracy` knob: [`MockRuntime::propose`] drafts the *true* next
//!   token with probability `draft_accuracy`, else a deterministically wrong
//!   one — enabling acceptance-rate experiments (accuracy 0 ⇒ every draft is
//!   wrong; 1.0 ⇒ every draft is right).
//! - Synthetic throughput constants are exposed through
//!   [`crate::InferenceRuntime::metrics`] so benchmark latency models read
//!   one source of truth.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;

use crate::{
    duration_ms_u64, splitmix64, Handle, KvCommitment, RuntimeDescriptor, RuntimeError,
    RuntimeMetrics, SamplingParams, TaskId,
};
use sha2::{Digest as ShaDigest, Sha256};

/// Runtime name recorded in benchmark manifests for mock runs (ADR-019).
pub const MOCK_RUNTIME_NAME: &str = "mock";
/// Mock vocabulary size: token ids `0..256` (one per byte value).
pub const MOCK_VOCAB: u32 = 256;
/// Synthetic prefill throughput (tokens/ms) reported by metrics.
pub const MOCK_PREFILL_TOKENS_PER_MS: f64 = 2.0;
/// Synthetic decode throughput (tokens/ms): one token every 8 ms.
pub const MOCK_DECODE_TOKENS_PER_MS: f64 = 0.125;
/// Salt mixing the draft-accuracy draw so proposals and decodes decorrelate.
const DRAFT_SALT: u64 = 0x0BAD_F00D_0BAD_F00D;
/// Salt folding sampling parameters into the decode hash.
const SAMPLING_SALT: u64 = 0x5EED_5A7E_0000_0001;

#[derive(Debug, Default)]
struct MockState {
    loaded: HashMap<u64, String>,
    cancelled: HashSet<TaskId>,
    active: HashSet<TaskId>,
}

/// Deterministic in-process runtime for tests and the Phase C harness.
#[derive(Debug)]
pub struct MockRuntime {
    seed: u64,
    draft_accuracy: f32,
    step_delay: Duration,
    next_id: AtomicU64,
    state: Mutex<MockState>,
}

impl MockRuntime {
    /// New mock runtime with the given global seed and draft accuracy
    /// (clamped to `0.0..=1.0`).
    pub fn new(seed: u64, draft_accuracy: f32) -> Self {
        Self {
            seed,
            draft_accuracy: draft_accuracy.clamp(0.0, 1.0),
            step_delay: Duration::ZERO,
            next_id: AtomicU64::new(1),
            state: Mutex::new(MockState::default()),
        }
    }

    /// Perfect-draft runtime (accuracy 1.0).
    pub fn perfect_draft(seed: u64) -> Self {
        Self::new(seed, 1.0)
    }

    /// Always-wrong-draft runtime (accuracy 0.0).
    pub fn wrong_draft(seed: u64) -> Self {
        Self::new(seed, 0.0)
    }

    /// Artificial per-step wall delay (tests for deadline/cancel paths).
    pub fn with_step_delay(mut self, delay: Duration) -> Self {
        self.step_delay = delay;
        self
    }

    /// The runtime's global seed.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// The configured draft accuracy.
    pub fn draft_accuracy(&self) -> f32 {
        self.draft_accuracy
    }

    /// True when this runtime reports itself as the mock backend.
    pub fn is_mock(&self) -> bool {
        true
    }

    /// Ids of currently active decode tasks (test hook for cancellation).
    pub fn active_tasks(&self) -> Vec<TaskId> {
        let state = self.state.lock().expect("mock state");
        let mut ids: Vec<TaskId> = state.active.iter().copied().collect();
        ids.sort_unstable();
        ids
    }

    fn check_loaded(&self, handle: &Handle) -> Result<(), RuntimeError> {
        let state = self.state.lock().expect("mock state");
        match state.loaded.contains_key(&handle.handle_id()) {
            true => Ok(()),
            false => Err(RuntimeError::NotLoaded(handle.handle_id())),
        }
    }

    fn check_tokens(ids: &[u32]) -> Result<(), RuntimeError> {
        ids.iter().try_for_each(|t| match *t < MOCK_VOCAB {
            true => Ok(()),
            false => Err(RuntimeError::TokenOutOfRange(*t)),
        })
    }

    /// FNV-1a over the token ids of the prefix.
    fn prefix_hash(prefix: &[u32]) -> u64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for token in prefix {
            hash ^= u64::from(*token);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        hash
    }

    fn sampling_hash(sampling: &SamplingParams) -> u64 {
        let mut mixed = SAMPLING_SALT;
        for part in [
            sampling.seed.unwrap_or(0),
            u64::from(sampling.temperature.to_bits()),
            u64::from(sampling.top_p.to_bits()),
            u64::from(sampling.top_k),
        ] {
            mixed ^= part;
            mixed = splitmix64(mixed);
        }
        mixed
    }

    /// Deterministic next-token function: splitmix64 over
    /// `(prefix_hash, sampling)`, reduced into the 256-token vocabulary.
    pub fn next_token(prefix: &[u32], sampling: &SamplingParams) -> u32 {
        let mixed = splitmix64(Self::prefix_hash(prefix) ^ Self::sampling_hash(sampling));
        (mixed % u64::from(MOCK_VOCAB)) as u32
    }

    /// Deterministically wrong token (never equal to `correct`).
    fn wrong_token(correct: u32, draw: u64) -> u32 {
        let offset = 1 + (draw % u64::from(MOCK_VOCAB - 1));
        ((u64::from(correct) + offset) % u64::from(MOCK_VOCAB)) as u32
    }
}

#[async_trait]
impl crate::InferenceRuntime for MockRuntime {
    fn id(&self) -> RuntimeDescriptor {
        // Stable digest of the mock runtime name: this build has no binary
        // artifact, so its "build hash" is the identity digest of the name.
        let digest = crate::hex64(&Sha256::digest(MOCK_RUNTIME_NAME.as_bytes()));
        RuntimeDescriptor::new(
            MOCK_RUNTIME_NAME,
            concat!("mock-runtime-v", env!("CARGO_PKG_VERSION")),
            digest,
        )
        .expect("static mock descriptor is valid")
    }

    async fn load(&self, profile_id: &str) -> Result<Handle, RuntimeError> {
        if profile_id.is_empty() {
            return Err(RuntimeError::InvalidProfile(profile_id.to_string()));
        }
        let handle_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.state
            .lock()
            .expect("mock state")
            .loaded
            .insert(handle_id, profile_id.to_string());
        Ok(Handle::new(profile_id, handle_id))
    }

    async fn tokenize(&self, text: &str) -> Result<Vec<u32>, RuntimeError> {
        Ok(text.as_bytes().iter().map(|b| u32::from(*b)).collect())
    }

    async fn detokenize(&self, ids: &[u32]) -> Result<String, RuntimeError> {
        Self::check_tokens(ids)?;
        let bytes: Vec<u8> = ids.iter().map(|t| *t as u8).collect();
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn prefill(&self, handle: &Handle, ids: &[u32]) -> Result<KvCommitment, RuntimeError> {
        self.check_loaded(handle)?;
        Self::check_tokens(ids)?;
        Ok(KvCommitment::new(0, ids))
    }

    async fn decode_step(
        &self,
        handle: &Handle,
        prefix: &[u32],
        sampling: &SamplingParams,
    ) -> Result<u32, RuntimeError> {
        self.check_loaded(handle)?;
        Self::check_tokens(prefix)?;
        if self.step_delay > Duration::ZERO {
            tokio::time::sleep(self.step_delay).await;
        }
        Ok(Self::next_token(prefix, sampling))
    }

    async fn decode_stream(
        &self,
        handle: &Handle,
        prefix: &[u32],
        sampling: &SamplingParams,
        max_tokens: u32,
        deadline: Duration,
    ) -> Result<Vec<u32>, RuntimeError> {
        let task = TaskId(self.next_id.fetch_add(1, Ordering::Relaxed));
        {
            let mut state = self.state.lock().expect("mock state");
            state.active.insert(task);
        }
        let result = async {
            let started = tokio::time::Instant::now();
            let mut working_prefix = prefix.to_vec();
            let mut produced = Vec::new();
            for _ in 0..max_tokens {
                if self
                    .state
                    .lock()
                    .expect("mock state")
                    .cancelled
                    .contains(&task)
                {
                    return Err(RuntimeError::Cancelled(task));
                }
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
        .await;
        self.state.lock().expect("mock state").active.remove(&task);
        result
    }

    fn metrics(&self) -> RuntimeMetrics {
        RuntimeMetrics {
            prefill_tokens_per_ms: MOCK_PREFILL_TOKENS_PER_MS,
            decode_tokens_per_ms: MOCK_DECODE_TOKENS_PER_MS,
            // The mock has no engine KV; the ADR-031 §5.3 accounting fields
            // stay 0 (documented additive defaults for adapters without
            // accounting).
            kv_bytes_estimate: 0,
            engine_decode_calls: 0,
            queue_depth: self
                .state
                .lock()
                .expect("mock state")
                .active
                .len()
                .try_into()
                .unwrap_or(u32::MAX),
        }
    }

    fn cancel(&self, task: TaskId) -> Result<(), RuntimeError> {
        let mut state = self.state.lock().expect("mock state");
        if state.active.contains(&task) {
            state.cancelled.insert(task);
            Ok(())
        } else {
            Err(RuntimeError::Unsupported(format!(
                "no active task {task:?} to cancel"
            )))
        }
    }

    async fn propose(
        &self,
        handle: &Handle,
        prefix: &[u32],
        window: u32,
    ) -> Result<Vec<u32>, RuntimeError> {
        self.check_loaded(handle)?;
        Self::check_tokens(prefix)?;
        // Proposals continue the *default-sampling* continuation of the
        // prefix: the draft-accuracy knob is then the ONLY error source when
        // the verifier decodes with default sampling too — the property the
        // acceptance-rate experiments rely on. The runtime's global seed
        // still drives the correct/wrong draw, keeping runs deterministic.
        let sampling = SamplingParams::default();
        let base_hash = Self::prefix_hash(prefix) ^ self.seed;
        let mut draft = Vec::with_capacity(window as usize);
        let mut working = prefix.to_vec();
        for k in 0..window {
            let true_token = Self::next_token(&working, &sampling);
            let draw = splitmix64(base_hash ^ DRAFT_SALT ^ u64::from(k));
            let uniform = (draw >> 11) as f64 / (1u64 << 53) as f64;
            let token = if uniform < f64::from(self.draft_accuracy) {
                true_token
            } else {
                Self::wrong_token(true_token, splitmix64(draw ^ 0x0BAD_F00D_0000_0002))
            };
            working.push(token);
            draft.push(token);
        }
        Ok(draft)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InferenceRuntime;

    fn sampling(seed: u64) -> SamplingParams {
        SamplingParams {
            seed: Some(seed),
            ..SamplingParams::default()
        }
    }

    #[tokio::test]
    async fn same_seed_produces_identical_streams_over_100_cases() {
        let mut distinct = HashSet::new();
        for case in 0..100u64 {
            let seed = 0x5EED_0000 + case;
            let prompt: Vec<u32> = vec![104, 101, 108, 108, 111, case as u32 % 256];
            let a = MockRuntime::new(seed, 0.5);
            let b = MockRuntime::new(seed, 0.5);
            let ha = a.load("msp1:mock").await.unwrap();
            let hb = b.load("msp1:mock").await.unwrap();
            let sa = sampling(seed);
            let stream_a = a
                .decode_stream(&ha, &prompt, &sa, 32, Duration::from_secs(30))
                .await
                .unwrap();
            let stream_b = b
                .decode_stream(&hb, &prompt, &sa, 32, Duration::from_secs(30))
                .await
                .unwrap();
            assert_eq!(stream_a, stream_b, "case {case}: same seed must match");
            assert_eq!(stream_a.len(), 32);
            distinct.insert(stream_a);
        }
        assert!(
            distinct.len() >= 2,
            "different seeds should not collapse to one stream"
        );
    }

    #[tokio::test]
    async fn draft_accuracy_zero_always_proposes_wrong() {
        let runtime = MockRuntime::wrong_draft(99);
        let handle = runtime.load("msp1:mock").await.unwrap();
        let s = SamplingParams::default();
        let mut prefix = vec![1, 2, 3, 4, 5];
        for round in 0..200 {
            let draft = runtime.propose(&handle, &prefix, 1).await.unwrap();
            let truth = runtime.decode_step(&handle, &prefix, &s).await.unwrap();
            assert_ne!(
                draft[0], truth,
                "round {round}: accuracy 0 must never draft the true token"
            );
            prefix.push(truth);
        }
    }

    #[tokio::test]
    async fn draft_accuracy_one_always_proposes_right() {
        let runtime = MockRuntime::perfect_draft(7);
        let handle = runtime.load("msp1:mock").await.unwrap();
        let s = SamplingParams::default();
        let mut prefix = vec![9, 8, 7];
        for round in 0..200 {
            let draft = runtime.propose(&handle, &prefix, 4).await.unwrap();
            assert_eq!(draft.len(), 4);
            for (k, drafted) in draft.iter().enumerate() {
                let truth = runtime.decode_step(&handle, &prefix, &s).await.unwrap();
                assert_eq!(
                    drafted, &truth,
                    "round {round} position {k}: accuracy 1.0 must always draft the true token"
                );
                prefix.push(truth);
            }
        }
    }

    #[tokio::test]
    async fn tokenize_detokenize_round_trip() {
        let runtime = MockRuntime::new(1, 0.5);
        let text = "deterministic toy decoder";
        let ids = runtime.tokenize(text).await.unwrap();
        assert!(ids.iter().all(|t| *t < MOCK_VOCAB));
        assert_eq!(runtime.detokenize(&ids).await.unwrap(), text);
        assert_eq!(
            runtime.tokenize(text).await.unwrap(),
            ids,
            "tokenization is idempotent"
        );
    }

    #[tokio::test]
    async fn vocab_and_token_validation() {
        let runtime = MockRuntime::new(1, 0.5);
        assert_eq!(
            runtime.detokenize(&[256]).await.unwrap_err(),
            RuntimeError::TokenOutOfRange(256)
        );
        let handle = runtime.load("msp1:mock").await.unwrap();
        assert_eq!(
            runtime.prefill(&handle, &[999]).await.unwrap_err(),
            RuntimeError::TokenOutOfRange(999)
        );
    }

    #[tokio::test]
    async fn unloaded_handle_is_rejected() {
        let runtime = MockRuntime::new(1, 0.5);
        let ghost = Handle::new("msp1:mock", 4242);
        assert_eq!(
            runtime.prefill(&ghost, &[1]).await.unwrap_err(),
            RuntimeError::NotLoaded(4242)
        );
    }

    #[tokio::test]
    async fn deadline_expires_mid_stream() {
        let runtime = MockRuntime::new(3, 0.5).with_step_delay(Duration::from_millis(5));
        let handle = runtime.load("msp1:mock").await.unwrap();
        let err = runtime
            .decode_stream(
                &handle,
                &[1, 2, 3],
                &sampling(3),
                200,
                Duration::from_millis(40),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, RuntimeError::Timeout { .. }));
    }

    #[tokio::test]
    async fn cancel_stops_active_stream() {
        let runtime =
            std::sync::Arc::new(MockRuntime::new(4, 0.5).with_step_delay(Duration::from_millis(2)));
        let handle = runtime.load("msp1:mock").await.unwrap();
        let worker = runtime.clone();
        let sampling = sampling(4);
        let task_handle = tokio::spawn(async move {
            worker
                .decode_stream(
                    &handle,
                    &[5, 6, 7],
                    &sampling,
                    5_000,
                    Duration::from_secs(30),
                )
                .await
        });
        // Wait until the task registers itself, then cancel it.
        let task_id = loop {
            let active = runtime.active_tasks();
            if let Some(id) = active.first() {
                break *id;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        };
        runtime.cancel(task_id).unwrap();
        match task_handle.await.unwrap().unwrap_err() {
            RuntimeError::Cancelled(id) => assert_eq!(id, task_id),
            other => panic!("expected Cancelled, got {other:?}"),
        }
        assert_eq!(runtime.metrics().queue_depth, 0, "slot freed");
        // Cancelling a finished task is an error, not a hang.
        assert!(runtime.cancel(task_id).is_err());
    }

    #[tokio::test]
    async fn metrics_expose_synthetic_rates() {
        let runtime = MockRuntime::new(5, 0.5);
        let metrics = runtime.metrics();
        assert_eq!(metrics.prefill_tokens_per_ms, MOCK_PREFILL_TOKENS_PER_MS);
        assert_eq!(metrics.decode_tokens_per_ms, MOCK_DECODE_TOKENS_PER_MS);
        assert_eq!(metrics.queue_depth, 0);
        assert_eq!(runtime.id().name(), MOCK_RUNTIME_NAME);
        assert_eq!(runtime.id().build_hash().len(), 64);
    }

    #[tokio::test]
    async fn default_propose_is_unsupported_on_llama_adapter_shape() {
        // The trait default must hold for runtimes that do not override it;
        // verify via a minimal anonymous implementation.
        struct NoPropose;
        #[async_trait]
        impl crate::InferenceRuntime for NoPropose {
            fn id(&self) -> RuntimeDescriptor {
                RuntimeDescriptor::new("x", "1", "a".repeat(64)).unwrap()
            }
            async fn load(&self, _: &str) -> Result<Handle, RuntimeError> {
                Ok(Handle::new("p", 1))
            }
            async fn tokenize(&self, _: &str) -> Result<Vec<u32>, RuntimeError> {
                Ok(vec![])
            }
            async fn detokenize(&self, _: &[u32]) -> Result<String, RuntimeError> {
                Ok(String::new())
            }
            async fn prefill(&self, _: &Handle, _: &[u32]) -> Result<KvCommitment, RuntimeError> {
                panic!("not under test")
            }
            async fn decode_step(
                &self,
                _: &Handle,
                _: &[u32],
                _: &SamplingParams,
            ) -> Result<u32, RuntimeError> {
                panic!("not under test")
            }
            fn metrics(&self) -> RuntimeMetrics {
                RuntimeMetrics::default()
            }
            fn cancel(&self, _: TaskId) -> Result<(), RuntimeError> {
                Ok(())
            }
        }
        let runtime = NoPropose;
        let handle = Handle::new("p", 1);
        assert_eq!(
            runtime.propose(&handle, &[1], 4).await.unwrap_err(),
            RuntimeError::Unsupported("propose".to_string())
        );
    }
}
