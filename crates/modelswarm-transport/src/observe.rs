//! F15 measurement plumbing: node-local observation types for the
//! production QUIC path (dependency-graph hard edge 2 — scheduler wiring
//! consumes these; the scheduler itself is NOT wired here).
//!
//! These are pure data types. They carry **timings and counters only** —
//! never prompt or completion content, never token text (AGENTS.md rule 5;
//! the store's privacy audit is the structural backstop for anything
//! persisted downstream). The recorder that fills them lives in
//! `modelswarm-node::measure`; the transport crate only defines the
//! shapes so any consumer (scheduler, diagnostics, experiments) can read
//! measurements without depending on node internals.
//!
//! # What is measured vs. honestly unavailable
//!
//! - RTT: measured by the requester with in-band `Control` ping/pong
//!   probes ([`crate::Control`]; msp-v1 defines no ping — this is
//!   transport bookkeeping, not protocol surface).
//! - Jitter: derived from successive ping-sample differences
//!   ([`crate::Stats::jitter_ms`], RFC 3550-style).
//! - Completion distributions (TTFT / inter-token latency / total): the
//!   requester wall-clocks its own stream events.
//! - Loss: **NOT measured**. quinn's per-connection statistics
//!   (`Connection::stats()` — RTT estimate, lost-packet counters) are not
//!   reachable through libp2p-quic 0.14: the wrapped `quinn::Connection`
//!   is private and `Connection` exposes only the `StreamMuxer` trait
//!   surface. [`QUINN_STATS_UNAVAILABLE`] records this so consumers and
//!   docs can cite it instead of guessing.

use serde::{Deserialize, Serialize};

/// Honest unavailability record for quinn-level transport statistics
/// (loss counts, congestion-window RTT estimates). Re-check when
/// libp2p-quic exposes the underlying connection.
pub const QUINN_STATS_UNAVAILABLE: &str =
    "quinn connection stats (loss, smoothed RTT) are not exposed by libp2p-quic 0.14";

/// Serving-reported usage digest captured from one `Usage` frame
/// (counts and the serving peer's own phase timings only).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct UsageDigest {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    /// Serving-side prefill phase, milliseconds.
    pub prefill_ms: f64,
    /// Serving-side decode phase, milliseconds.
    pub decode_ms: f64,
}

/// How one request's stream terminated at the requester.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionOutcome {
    /// Clean terminal frame (`stop` | `length` | `cancelled`).
    Completed { finish_reason: String },
    /// Terminal error (stable code; never peer-supplied message text).
    Errored { code: String },
}

/// One measured request completion, request-side wall-clock.
///
/// `ttft_ms` is the requester's admission-to-first-token observation:
/// request-sent → first `TokenDelta` received. It therefore INCLUDES
/// network RTT, any serving-side queueing, and prefill — it is the
/// measured counterpart the scheduler can compare against the peer's
/// self-reported `queueMs` (advertised values are untrusted inputs, not
/// measurements — expanded-mission review §5).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompletionObservation {
    pub peer_id: String,
    pub profile_id: String,
    pub outcome: CompletionOutcome,
    /// Request-sent → first token received (ms); 0.0 when no token arrived.
    pub ttft_ms: f64,
    /// Request-sent → terminal event received (ms).
    pub total_ms: f64,
    /// Mean inter-token latency over `TokenDelta` arrivals (ms); 0.0 with
    /// fewer than two deltas.
    pub itl_mean_ms: f64,
    /// Largest gap between successive `TokenDelta` arrivals (ms).
    pub itl_max_ms: f64,
    /// Number of `TokenDelta` frames observed.
    pub token_deltas: u32,
    /// The `Usage` frame, when the stream produced one.
    pub usage: Option<UsageDigest>,
    /// The peer's advertised `queueMs` known to the requester at request
    /// time (tracker roster), when known — recorded alongside the measured
    /// admission-to-first-token for advertised-vs-measured comparison.
    pub advertised_queue_ms: Option<u64>,
}

/// Per-(peer, profile) measured distribution snapshot the scheduler can
/// consume (shadow mode first — nothing here selects peers).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ProfileObservations {
    pub profile_id: String,
    /// EWMA of measured admission-to-first-token (ms).
    pub ttft_ewma_ms: Option<f64>,
    /// EWMA of mean inter-token latency (ms).
    pub itl_mean_ewma_ms: Option<f64>,
    /// EWMA of total request wall time (ms).
    pub total_ewma_ms: Option<f64>,
    /// EWMA of serving-reported prefill throughput (tokens/ms), from
    /// `Usage` frames (prompt_tokens / prefill_ms).
    pub prefill_tokens_per_ms_ewma: Option<f64>,
    /// EWMA of serving-reported decode throughput (tokens/ms), from
    /// `Usage` frames (completion_tokens / decode_ms).
    pub decode_tokens_per_ms_ewma: Option<f64>,
    /// Last advertised `queueMs` recorded for this pair (untrusted input,
    /// kept for comparison only).
    pub advertised_queue_ms_last: Option<u64>,
    /// Count of completed (any outcome) recorded requests.
    pub completion_count: u64,
    /// Unix epoch milliseconds of the last recorded completion.
    pub last_completion_unix_ms: Option<u64>,
}

/// Per-peer measured snapshot: the typed read API for scheduler-side
/// consumers. All values are requester-measured EWMAs unless explicitly
/// named `advertised`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PeerObservations {
    pub peer_id: String,
    /// EWMA of ping/pong round-trip p50 (ms).
    pub rtt_ewma_ms: Option<f64>,
    /// EWMA of ping/pong round-trip p95 (ms).
    pub rtt_p95_ewma_ms: Option<f64>,
    /// EWMA of ping-sample jitter (ms) — the only network-quality signal
    /// available without quinn stats (see [`QUINN_STATS_UNAVAILABLE`]).
    pub rtt_jitter_ewma_ms: Option<f64>,
    /// Ping/pong probe batches recorded.
    pub rtt_probe_count: u64,
    /// Transport-level failures (dial, send, dead stream, failed probe).
    pub failure_count: u64,
    /// Unix epoch milliseconds of the last RTT probe.
    pub last_rtt_unix_ms: Option<u64>,
    /// Per-profile completion distributions (TTFT/ITL/total).
    pub profiles: Vec<ProfileObservations>,
}

impl PeerObservations {
    /// The observations for one profile, if any were recorded.
    pub fn profile(&self, profile_id: &str) -> Option<&ProfileObservations> {
        self.profiles.iter().find(|p| p.profile_id == profile_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_observation_serializes_timings_only() {
        let obs = CompletionObservation {
            peer_id: "12D3KooWTest".into(),
            profile_id: "msp1:abc".into(),
            outcome: CompletionOutcome::Completed {
                finish_reason: "stop".into(),
            },
            ttft_ms: 12.5,
            total_ms: 340.0,
            itl_mean_ms: 20.0,
            itl_max_ms: 41.0,
            token_deltas: 16,
            usage: Some(UsageDigest {
                prompt_tokens: 120,
                completion_tokens: 16,
                prefill_ms: 90.0,
                decode_ms: 300.0,
            }),
            advertised_queue_ms: Some(0),
        };
        let v = serde_json::to_value(&obs).unwrap();
        let text = v.to_string();
        // The honest-unavailable constant is exactly that.
        assert!(QUINN_STATS_UNAVAILABLE.contains("not exposed"));
        // Serializable shape is stable (timing/count fields only).
        assert!(text.contains("\"ttft_ms\":12.5"));
        assert!(text.contains("\"token_deltas\":16"));
        assert!(text.contains("\"finish_reason\":\"stop\""));
        let back: CompletionObservation = serde_json::from_value(v).unwrap();
        assert_eq!(back, obs);
    }

    #[test]
    fn peer_observations_lookup_by_profile() {
        let mut obs = PeerObservations {
            peer_id: "p".into(),
            profiles: vec![ProfileObservations {
                profile_id: "msp1:one".into(),
                ttft_ewma_ms: Some(5.0),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(obs.profile("msp1:one").unwrap().ttft_ewma_ms, Some(5.0));
        assert!(obs.profile("msp1:missing").is_none());
        obs.profiles.clear();
        assert!(obs.profile("msp1:one").is_none());
    }
}
