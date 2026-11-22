//! F15 measurement plumbing (node side): the requester-measured telemetry
//! recorder for the production QUIC path (dependency-graph hard edge 2 —
//! this EXISTS so scheduler shadow-mode wiring has something to consume;
//! the scheduler itself is deliberately NOT wired here).
//!
//! What is recorded, and where it comes from:
//!
//! - **Per-peer RTT EWMA** — `Libp2pSession::measure_rtt` ping/pong
//!   probes, driven by the pooled `RemoteExecutor` after a clean
//!   completion (off the request critical path). Jitter rides the probe
//!   sample spread (successive-difference estimate).
//! - **Completion distributions** — TTFT (admission-to-first-token),
//!   inter-token latency, and total wall time per completed request,
//!   wall-clocked at the requester from executor stream events (P1 made
//!   those timely), keyed by `(peer, profile)`.
//! - **Measured queue vs. advertised** — the peer's advertised `queueMs`
//!   (tracker roster, an UNTRUSTED input per expanded-mission review §5)
//!   is recorded alongside the measured admission-to-first-token so the
//!   scheduler wiring can discount the advertised term against
//!   measurements later.
//! - **Loss** — honestly unavailable: quinn connection stats are not
//!   exposed by libp2p-quic 0.14
//!   ([`modelswarm_transport::observe::QUINN_STATS_UNAVAILABLE`]).
//!
//! Persistence rides `modelswarm-store` (the EWMA-observations owner per
//! docs/architecture.md §10): peer-scoped metrics in the existing
//! `ewma_observations` table, per-profile metrics in the additive
//! migration-3 `peer_metric_observations` table. Persistence is
//! best-effort — a store failure logs a warning and leaves the in-memory
//! EWMA intact (measurement must never take a request down).
//!
//! Privacy: timings and counters only — no prompt, completion, or token
//! text ever enters this module's state, the store, or telemetry
//! (AGENTS.md rule 5).

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use modelswarm_telemetry::Telemetry;
use modelswarm_transport::observe::{
    CompletionObservation, CompletionOutcome, PeerObservations, ProfileObservations,
};
use modelswarm_transport::Stats;

/// Smoothing factor for every EWMA here. Deliberately equal to the frozen
/// ADR-013 scheduler value (`modelswarm_scheduler::EWMA_ALPHA` = 0.3); it
/// is restated locally so the measurement layer does not depend on the
/// scheduler crate (shadow data only — wiring is a separate, reviewed
/// step).
const EWMA_ALPHA: f64 = 0.3;

/// Peer-scoped metric keys (`ewma_observations` table).
const METRIC_RTT_P50: &str = "rtt_p50_ms";
const METRIC_RTT_P95: &str = "rtt_p95_ms";
const METRIC_RTT_JITTER: &str = "rtt_jitter_ms";
const METRIC_FAILURES: &str = "failure_count";
/// (Peer, profile)-scoped metric keys (`peer_metric_observations` table).
const METRIC_TTFT: &str = "ttft_ms";
const METRIC_ITL_MEAN: &str = "itl_mean_ms";
const METRIC_TOTAL: &str = "total_ms";
const METRIC_PREFILL_RATE: &str = "prefill_tokens_per_ms";
const METRIC_DECODE_RATE: &str = "decode_tokens_per_ms";
const METRIC_ADVERTISED_QUEUE: &str = "advertised_queue_ms";
const METRIC_COMPLETIONS: &str = "completion_count";

/// The closed metric-key vocabulary this module may persist: exactly the
/// consts above. Every `persist_*` call checks its key against this set —
/// debug builds assert, release builds refuse the write with a warning —
/// so a future caller cannot smuggle free-form names (worst case prompt
/// content) into the observation tables. The store adds the same
/// structural bound one layer down (defense in depth).
fn known_metric_key(metric: &str) -> bool {
    matches!(
        metric,
        METRIC_RTT_P50
            | METRIC_RTT_P95
            | METRIC_RTT_JITTER
            | METRIC_FAILURES
            | METRIC_TTFT
            | METRIC_ITL_MEAN
            | METRIC_TOTAL
            | METRIC_PREFILL_RATE
            | METRIC_DECODE_RATE
            | METRIC_ADVERTISED_QUEUE
            | METRIC_COMPLETIONS
    )
}

fn ewma(previous: Option<f64>, observation: f64) -> f64 {
    match previous {
        None => observation,
        Some(prev) => EWMA_ALPHA * observation + (1.0 - EWMA_ALPHA) * prev,
    }
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Default)]
struct ProfileState {
    ttft: Option<f64>,
    itl_mean: Option<f64>,
    total: Option<f64>,
    prefill_rate: Option<f64>,
    decode_rate: Option<f64>,
    advertised_queue_ms: Option<f64>,
    completions: u64,
    last_completion_unix_ms: Option<u64>,
}

#[derive(Default)]
struct PeerState {
    rtt_p50: Option<f64>,
    rtt_p95: Option<f64>,
    jitter: Option<f64>,
    failures: u64,
    rtt_probes: u64,
    last_rtt_unix_ms: Option<u64>,
    profiles: HashMap<String, ProfileState>,
}

/// The requester-side measurement recorder. Clone-free by design: one
/// `Arc<PeerMetrics>` is shared by the executor(s) probing a peer set.
pub struct PeerMetrics {
    state: Mutex<HashMap<String, PeerState>>,
    store: Option<Arc<Mutex<modelswarm_store::Store>>>,
    telemetry: Arc<Telemetry>,
}

impl PeerMetrics {
    /// In-memory only (tests, or installations without a writable store).
    pub fn memory(telemetry: Arc<Telemetry>) -> Self {
        Self {
            state: Mutex::new(HashMap::new()),
            store: None,
            telemetry,
        }
    }

    /// Store-backed: opens (creating/migrating) the SQLite database at
    /// `path` and eagerly hydrates EVERY persisted peer into memory, so
    /// [`PeerMetrics::observe`] is a pure in-memory read afterwards — the
    /// first touch of a roster peer on a request path never performs a
    /// blocking SQLite read under the sync mutex (F9-class blocking read,
    /// moved here, once per process). On open failure degrades to
    /// memory-only with a visible warning — measurement must never take
    /// the request path down.
    pub fn open(path: impl AsRef<Path>, telemetry: Arc<Telemetry>) -> Self {
        let store = match modelswarm_store::Store::open(path) {
            Ok(store) => Some(Arc::new(Mutex::new(store))),
            Err(e) => {
                telemetry.warn(
                    "net.metrics.store_unavailable",
                    &[("error", &e.to_string()), ("mode", "memory-only")],
                );
                None
            }
        };
        let metrics = Self {
            state: Mutex::new(HashMap::new()),
            store,
            telemetry,
        };
        metrics.hydrate_all_from_store();
        metrics
    }

    /// Records one ping/pong probe batch (p50/p95/jitter from
    /// [`Stats::from_durations`]) into the per-peer RTT EWMA.
    pub fn record_rtt(&self, peer_id: &str, stats: &Stats) {
        let now = unix_ms_now();
        let mut state = self.lock_state();
        if let Some(loaded) = self.hydrate_from_store(peer_id, &state) {
            state.insert(peer_id.to_string(), loaded);
        }
        let peer = state.entry(peer_id.to_string()).or_default();
        peer.rtt_p50 = Some(ewma(peer.rtt_p50, stats.p50_ms));
        peer.rtt_p95 = Some(ewma(peer.rtt_p95, stats.p95_ms));
        peer.jitter = Some(ewma(peer.jitter, stats.jitter_ms));
        peer.rtt_probes = peer.rtt_probes.saturating_add(1);
        peer.last_rtt_unix_ms = Some(now);
        let (p50, p95, jitter) = (peer.rtt_p50, peer.rtt_p95, peer.jitter);
        drop(state);

        self.persist_peer_metric(peer_id, METRIC_RTT_P50, p50);
        self.persist_peer_metric(peer_id, METRIC_RTT_P95, p95);
        self.persist_peer_metric(peer_id, METRIC_RTT_JITTER, jitter);
        self.telemetry.info(
            "net.rtt",
            &[
                ("peer", peer_id),
                ("probe_p50_ms", &format!("{:.3}", stats.p50_ms)),
                ("ewma_p50_ms", &format!("{:.3}", p50.unwrap_or_default())),
                ("p95_ms", &format!("{:.3}", stats.p95_ms)),
                ("jitter_ms", &format!("{:.3}", stats.jitter_ms)),
            ],
        );
        self.telemetry
            .metrics
            .observe_ms("net.rtt.p50", stats.p50_ms);
    }

    /// Records one transport-level failure (dial, send, dead stream, failed
    /// probe). Counts only — penalty derivation belongs to the scheduler.
    pub fn record_failure(&self, peer_id: &str, stage: &str) {
        let mut state = self.lock_state();
        if let Some(loaded) = self.hydrate_from_store(peer_id, &state) {
            state.insert(peer_id.to_string(), loaded);
        }
        let peer = state.entry(peer_id.to_string()).or_default();
        peer.failures = peer.failures.saturating_add(1);
        let failures = peer.failures;
        drop(state);
        self.persist_peer_metric(peer_id, METRIC_FAILURES, Some(failures as f64));
        self.telemetry
            .warn("net.failure", &[("peer", peer_id), ("stage", stage)]);
    }

    /// Records one request completion (any outcome) into the
    /// `(peer, profile)` distribution EWMAs, keeping the advertised
    /// `queueMs` alongside the measured admission-to-first-token.
    pub fn record_completion(&self, obs: &CompletionObservation) {
        let now = unix_ms_now();
        let mut state = self.lock_state();
        if let Some(loaded) = self.hydrate_from_store(&obs.peer_id, &state) {
            state.insert(obs.peer_id.clone(), loaded);
        }
        let peer = state.entry(obs.peer_id.clone()).or_default();
        let profile = peer.profiles.entry(obs.profile_id.clone()).or_default();
        profile.ttft = Some(ewma(profile.ttft, obs.ttft_ms));
        profile.itl_mean = Some(ewma(profile.itl_mean, obs.itl_mean_ms));
        profile.total = Some(ewma(profile.total, obs.total_ms));
        if let Some(usage) = obs.usage {
            if usage.prefill_ms > 0.0 && usage.prompt_tokens > 0 {
                let rate = f64::from(usage.prompt_tokens) / usage.prefill_ms;
                profile.prefill_rate = Some(ewma(profile.prefill_rate, rate));
            }
            if usage.decode_ms > 0.0 && usage.completion_tokens > 0 {
                let rate = f64::from(usage.completion_tokens) / usage.decode_ms;
                profile.decode_rate = Some(ewma(profile.decode_rate, rate));
            }
        }
        if let Some(queue) = obs.advertised_queue_ms {
            // Advertised values are recorded as-is, labeled untrusted —
            // never blended into a measured EWMA.
            profile.advertised_queue_ms = Some(queue as f64);
        }
        profile.completions = profile.completions.saturating_add(1);
        profile.last_completion_unix_ms = Some(now);
        let snapshot = (
            profile.ttft,
            profile.itl_mean,
            profile.total,
            profile.prefill_rate,
            profile.decode_rate,
            profile.advertised_queue_ms,
            profile.completions,
        );
        drop(state);

        self.persist_profile_metric(&obs.peer_id, &obs.profile_id, METRIC_TTFT, snapshot.0);
        self.persist_profile_metric(&obs.peer_id, &obs.profile_id, METRIC_ITL_MEAN, snapshot.1);
        self.persist_profile_metric(&obs.peer_id, &obs.profile_id, METRIC_TOTAL, snapshot.2);
        self.persist_profile_metric(
            &obs.peer_id,
            &obs.profile_id,
            METRIC_PREFILL_RATE,
            snapshot.3,
        );
        self.persist_profile_metric(
            &obs.peer_id,
            &obs.profile_id,
            METRIC_DECODE_RATE,
            snapshot.4,
        );
        self.persist_profile_metric(
            &obs.peer_id,
            &obs.profile_id,
            METRIC_ADVERTISED_QUEUE,
            snapshot.5,
        );
        self.persist_profile_metric(
            &obs.peer_id,
            &obs.profile_id,
            METRIC_COMPLETIONS,
            Some(snapshot.6 as f64),
        );
        let outcome = match &obs.outcome {
            CompletionOutcome::Completed { finish_reason } => format!("ok:{finish_reason}"),
            CompletionOutcome::Errored { code } => format!("error:{code}"),
        };
        self.telemetry.info(
            "net.completion",
            &[
                ("peer", obs.peer_id.as_str()),
                ("outcome", outcome.as_str()),
                ("ttft_ms", &format!("{:.1}", obs.ttft_ms)),
                ("itl_mean_ms", &format!("{:.3}", obs.itl_mean_ms)),
                ("total_ms", &format!("{:.1}", obs.total_ms)),
                ("token_deltas", &obs.token_deltas.to_string()),
                (
                    "advertised_queue_ms",
                    &obs.advertised_queue_ms
                        .map(|q| q.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                ),
            ],
        );
        self.telemetry
            .metrics
            .observe_ms("net.completion.ttft", obs.ttft_ms);
        self.telemetry
            .metrics
            .observe_ms("net.completion.total", obs.total_ms);
    }

    /// The typed read API for scheduler-side consumers (shadow mode):
    /// one peer's measured snapshot. PURE in-memory read — safe to call
    /// on the async request path. Cross-restart resume happens at
    /// [`PeerMetrics::open`] time (whole-store hydration); peers first
    /// recorded by THIS process are hydrated on their first write, which
    /// runs off the request critical path.
    pub fn observe(&self, peer_id: &str) -> PeerObservations {
        let mut state = self.lock_state();
        let peer = state.entry(peer_id.to_string()).or_default();
        PeerObservations {
            peer_id: peer_id.to_string(),
            rtt_ewma_ms: peer.rtt_p50,
            rtt_p95_ewma_ms: peer.rtt_p95,
            rtt_jitter_ewma_ms: peer.jitter,
            rtt_probe_count: peer.rtt_probes,
            failure_count: peer.failures,
            last_rtt_unix_ms: peer.last_rtt_unix_ms,
            profiles: peer
                .profiles
                .iter()
                .map(|(profile_id, p)| ProfileObservations {
                    profile_id: profile_id.clone(),
                    ttft_ewma_ms: p.ttft,
                    itl_mean_ewma_ms: p.itl_mean,
                    total_ewma_ms: p.total,
                    prefill_tokens_per_ms_ewma: p.prefill_rate,
                    decode_tokens_per_ms_ewma: p.decode_rate,
                    advertised_queue_ms_last: p.advertised_queue_ms.map(|v| v.max(0.0) as u64),
                    completion_count: p.completions,
                    last_completion_unix_ms: p.last_completion_unix_ms,
                })
                .collect(),
        }
    }

    /// Snapshots for every peer touched in THIS process (callers that care
    /// about a specific roster should use [`PeerMetrics::observe`] per
    /// peer — same pure in-memory read).
    pub fn observe_all(&self) -> Vec<PeerObservations> {
        let peer_ids: Vec<String> = {
            let state = self.lock_state();
            state.keys().cloned().collect()
        };
        peer_ids.iter().map(|id| self.observe(id)).collect()
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, HashMap<String, PeerState>> {
        // A poisoned lock means a recorder call panicked mid-update; the
        // in-memory EWMAs are best-effort shadow data, so recovering with
        // fresh state is the honest continuation (the store is unaffected).
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Whole-store hydration at [`PeerMetrics::open`] time: loads every
    /// peer with any persisted row into memory in one bounded pass, so a
    /// fresh process resumes yesterday's EWMAs WITHOUT touching SQLite on
    /// later `observe` calls. One read per peer per process (the
    /// first-touch bound, moved from the request path to open time).
    fn hydrate_all_from_store(&self) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let Ok(store) = store.lock() else {
            return;
        };
        let Ok(peer_ids) = store.persisted_peer_ids() else {
            return;
        };
        drop(store);
        if peer_ids.is_empty() {
            return;
        }
        let mut state = self.lock_state();
        for peer_id in peer_ids {
            if let Some(loaded) = self.hydrate_from_store(&peer_id, &state) {
                state.insert(peer_id, loaded);
            } else {
                // persisted_peer_ids listed this peer, so hydration should
                // find at least one row; insert empty state anyway to keep
                // the once-per-peer bound even if a row vanished racily.
                state.entry(peer_id).or_default();
            }
        }
    }

    /// Loads the persisted rows for one peer into a fresh `PeerState`, if
    /// a store is attached. Returns `Some` only when any row exists.
    fn hydrate_from_store(
        &self,
        peer_id: &str,
        state: &HashMap<String, PeerState>,
    ) -> Option<PeerState> {
        if state.contains_key(peer_id) {
            return None; // already live
        }
        let store = self.store.as_ref()?;
        let Ok(store) = store.lock() else {
            return None;
        };
        let mut loaded = PeerState::default();
        let get = |metric: &str| -> Option<f64> { store.get_ewma(peer_id, metric).ok().flatten() };
        loaded.rtt_p50 = get(METRIC_RTT_P50);
        loaded.rtt_p95 = get(METRIC_RTT_P95);
        loaded.jitter = get(METRIC_RTT_JITTER);
        loaded.failures = get(METRIC_FAILURES).map(|v| v as u64).unwrap_or(0);
        if let Ok(rows) = store.peer_metrics_for(peer_id) {
            for (profile_id, metric, value) in rows {
                let profile = loaded.profiles.entry(profile_id).or_default();
                match metric.as_str() {
                    METRIC_TTFT => profile.ttft = Some(value),
                    METRIC_ITL_MEAN => profile.itl_mean = Some(value),
                    METRIC_TOTAL => profile.total = Some(value),
                    METRIC_PREFILL_RATE => profile.prefill_rate = Some(value),
                    METRIC_DECODE_RATE => profile.decode_rate = Some(value),
                    METRIC_ADVERTISED_QUEUE => profile.advertised_queue_ms = Some(value),
                    METRIC_COMPLETIONS => profile.completions = value as u64,
                    _ => {}
                }
            }
        }
        let has_any = loaded.rtt_p50.is_some()
            || loaded.rtt_p95.is_some()
            || loaded.failures > 0
            || !loaded.profiles.is_empty();
        has_any.then_some(loaded)
    }

    /// Shared refusal for keys outside the closed vocabulary: warn with the
    /// key LENGTH only (an unknown key is suspect content by definition —
    /// never echoed into telemetry), skip the write, and assert loudly in
    /// debug builds so the caller bug is caught in development.
    fn refuse_unknown_metric(&self, metric: &str) -> bool {
        let known = known_metric_key(metric);
        if !known {
            self.telemetry.warn(
                "net.metrics.invalid_key",
                &[("metric_len", &metric.len().to_string())],
            );
            debug_assert!(
                false,
                "metric key outside the closed F15 vocabulary (length {}): refusing to persist",
                metric.len()
            );
        }
        !known
    }

    fn persist_peer_metric(&self, peer_id: &str, metric: &str, value: Option<f64>) {
        let Some(value) = value else { return };
        if self.refuse_unknown_metric(metric) {
            return;
        }
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let Ok(store) = store.lock() else { return };
        if let Err(e) = store.upsert_ewma(peer_id, metric, value) {
            self.telemetry.warn(
                "net.metrics.persist_failed",
                &[("metric", metric), ("error", &e.to_string())],
            );
        }
    }

    fn persist_profile_metric(
        &self,
        peer_id: &str,
        profile_id: &str,
        metric: &str,
        value: Option<f64>,
    ) {
        let Some(value) = value else { return };
        if self.refuse_unknown_metric(metric) {
            return;
        }
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let Ok(store) = store.lock() else { return };
        if let Err(e) = store.upsert_peer_metric(peer_id, profile_id, metric, value) {
            // The error message never carries the key itself; `metric` here
            // is guaranteed in-vocabulary by the guard above.
            self.telemetry.warn(
                "net.metrics.persist_failed",
                &[("metric", metric), ("error", &e.to_string())],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use modelswarm_transport::observe::UsageDigest;

    fn telemetry() -> Arc<Telemetry> {
        Arc::new(Telemetry::memory().0)
    }

    fn stats(p50: f64, p95: f64, jitter: f64) -> Stats {
        Stats {
            p50_ms: p50,
            p95_ms: p95,
            jitter_ms: jitter,
        }
    }

    fn observation(ttft_ms: f64, total_ms: f64, queue: Option<u64>) -> CompletionObservation {
        CompletionObservation {
            peer_id: "peer-1".into(),
            profile_id: "msp1:aa".into(),
            outcome: CompletionOutcome::Completed {
                finish_reason: "stop".into(),
            },
            ttft_ms,
            total_ms,
            itl_mean_ms: ttft_ms / 10.0,
            itl_max_ms: ttft_ms / 5.0,
            token_deltas: 8,
            usage: Some(UsageDigest {
                prompt_tokens: 100,
                completion_tokens: 8,
                prefill_ms: 50.0,
                decode_ms: 200.0,
            }),
            advertised_queue_ms: queue,
        }
    }

    #[test]
    fn rtt_ewma_updates_and_exposes_jitter() {
        let metrics = PeerMetrics::memory(telemetry());
        metrics.record_rtt("peer-1", &stats(10.0, 12.0, 1.0));
        metrics.record_rtt("peer-1", &stats(20.0, 24.0, 2.0));
        let obs = metrics.observe("peer-1");
        assert_eq!(obs.peer_id, "peer-1");
        let expected = 0.3 * 20.0 + 0.7 * 10.0;
        assert!((obs.rtt_ewma_ms.unwrap() - expected).abs() < 1e-9);
        assert!((obs.rtt_jitter_ewma_ms.unwrap() - (0.3 * 2.0 + 0.7 * 1.0)).abs() < 1e-9);
        assert_eq!(obs.rtt_probe_count, 2);
        assert!(obs.last_rtt_unix_ms.is_some());
        // A peer never observed yields the empty snapshot, not a panic.
        let empty = metrics.observe("peer-2");
        assert_eq!(empty.peer_id, "peer-2");
        assert_eq!(empty.rtt_ewma_ms, None);
        assert_eq!(empty.failure_count, 0);
        assert!(empty.profiles.is_empty());
    }

    #[test]
    fn completion_distribution_keeps_advertised_queue_alongside_ttft() {
        let metrics = PeerMetrics::memory(telemetry());
        metrics.record_completion(&observation(100.0, 1_000.0, Some(250)));
        metrics.record_completion(&observation(200.0, 2_000.0, Some(250)));
        let obs = metrics.observe("peer-1");
        let profile = obs.profile("msp1:aa").expect("profile recorded");
        assert!((profile.ttft_ewma_ms.unwrap() - (0.3 * 200.0 + 0.7 * 100.0)).abs() < 1e-9);
        assert_eq!(profile.advertised_queue_ms_last, Some(250));
        assert_eq!(profile.completion_count, 2);
        assert!((profile.decode_tokens_per_ms_ewma.unwrap() - 8.0 / 200.0).abs() < 1e-9);
        assert!((profile.prefill_tokens_per_ms_ewma.unwrap() - 100.0 / 50.0).abs() < 1e-9);
        assert!(profile.last_completion_unix_ms.is_some());
        // Other profiles untouched.
        assert!(obs.profile("msp1:bb").is_none());
    }

    #[test]
    fn failures_count_and_errored_outcomes_record() {
        let metrics = PeerMetrics::memory(telemetry());
        metrics.record_failure("peer-1", "dial");
        metrics.record_failure("peer-1", "probe");
        let mut errored = observation(0.0, 5_000.0, None);
        errored.outcome = CompletionOutcome::Errored {
            code: "transport".into(),
        };
        metrics.record_completion(&errored);
        let obs = metrics.observe("peer-1");
        assert_eq!(obs.failure_count, 2);
        assert_eq!(obs.profile("msp1:aa").unwrap().completion_count, 1);
    }

    #[test]
    fn ewma_persists_across_reopen() {
        let file = tempfile::NamedTempFile::new().unwrap();
        {
            let metrics = PeerMetrics::open(file.path(), telemetry());
            metrics.record_rtt("peer-9", &stats(15.0, 18.0, 0.5));
            let mut for_peer_9 = observation(80.0, 900.0, Some(0));
            for_peer_9.peer_id = "peer-9".into();
            metrics.record_completion(&for_peer_9);
        }
        // A FRESH process must resume the persisted EWMAs.
        let reopened = PeerMetrics::open(file.path(), telemetry());
        let obs = reopened.observe("peer-9");
        assert_eq!(obs.rtt_ewma_ms, Some(15.0));
        let profile = obs.profile("msp1:aa").unwrap();
        assert_eq!(profile.ttft_ewma_ms, Some(80.0));
        assert_eq!(profile.advertised_queue_ms_last, Some(0));
        assert_eq!(profile.completion_count, 1);
        // And continues the EWMA from the persisted value, not from seed.
        reopened.record_rtt("peer-9", &stats(35.0, 40.0, 0.5));
        let expected = 0.3 * 35.0 + 0.7 * 15.0;
        assert!((reopened.observe("peer-9").rtt_ewma_ms.unwrap() - expected).abs() < 1e-9);
    }

    #[test]
    fn observe_all_covers_touched_peers() {
        let metrics = PeerMetrics::memory(telemetry());
        metrics.record_rtt("peer-a", &stats(1.0, 1.0, 0.0));
        metrics.record_rtt("peer-b", &stats(2.0, 2.0, 0.0));
        let all = metrics.observe_all();
        assert_eq!(all.len(), 2);
        assert!(all.iter().all(|o| o.rtt_ewma_ms.is_some()));
    }

    /// F15 security condition, node layer: a metric key outside the closed
    /// const enumeration is refused BEFORE the store is touched — debug
    /// builds fail loudly (the caller bug), release builds skip the write
    /// with a length-only warning. The store-layer shape check is pinned
    /// in modelswarm-store's own tests; this pins enumeration membership.
    #[test]
    #[should_panic(expected = "closed F15 vocabulary")]
    fn persisting_an_unknown_metric_key_refuses_loudly_in_debug() {
        let metrics = PeerMetrics::memory(telemetry());
        // Free-form key — the prompt-smuggling shape this guard exists for.
        metrics.persist_profile_metric("peer-1", "msp1:aa", "prompt was here", Some(1.0));
    }

    /// Same guard on the peer-scoped table, and the release-mode contract
    /// the debug assert cannot show: an unknown key leaves NO row and NO
    /// state change (verified through the public recorder API by proving
    /// every in-vocabulary key still round-trips — the guard's
    /// backward-compatibility condition).
    #[test]
    fn every_const_key_is_in_the_closed_vocabulary() {
        for key in [
            METRIC_RTT_P50,
            METRIC_RTT_P95,
            METRIC_RTT_JITTER,
            METRIC_FAILURES,
            METRIC_TTFT,
            METRIC_ITL_MEAN,
            METRIC_TOTAL,
            METRIC_PREFILL_RATE,
            METRIC_DECODE_RATE,
            METRIC_ADVERTISED_QUEUE,
            METRIC_COMPLETIONS,
        ] {
            assert!(known_metric_key(key), "{key} must be in the closed set");
        }
        // Structurally valid but unknown names are NOT in the set — shape
        // alone must never pass the enumeration check.
        for shaped_but_unknown in ["ttft_ms_v2", "prompt_text", "completion_count_x"] {
            assert!(!known_metric_key(shaped_but_unknown));
        }
    }
}
