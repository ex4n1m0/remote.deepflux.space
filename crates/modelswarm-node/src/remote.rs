//! F1: the requesting side — [`RemoteExecutor`] turns one serving peer
//! into an [`InferenceExecutor`] (docs/reviews/phase-f-research).
//!
//! Each request dials the peer with a FRESH client transport (one live
//! session per client instance is the transport's tested pattern), sends
//! one `InferenceRequest`, and re-emits the peer's
//! `TokenDelta`/`Usage`/`Completed` frames as executor events. Failures
//! map to ADR-007 semantics: a dial/send failure before any token is
//! [`ExecutorError::Retryable`] (the gateway may fail over or fall back
//! to local); a failure after streaming began becomes an
//! `ExecutorEvent::Error` — never a fabricated continuation, never a
//! silent regeneration.
//!
//! F2B (ADR-014, 2026-10-15): the dial is DIRECT-FIRST over ALL
//! advertised candidates with honest relay fallback
//! ([`Libp2pTransport::dial_with_fallback`]). Circuit candidates
//! (`<relay>/p2p-circuit[/p2p/<dst>]`) ride the peer record's existing
//! multiaddr list, so a peer behind NAT stays reachable. Every failed
//! attempt is reported per-attempt through the EXISTING vocabulary
//! (`net.failure` / stage=`dial` rows via the attached [`PeerMetrics`],
//! plus the stderr diagnostics this module always printed); the winning
//! path is exposed as [`RemoteExecutor::pooled_dial_path`] so callers
//! label relayed replies as relayed — never as direct.
//!
//! Selection (fastest eligible peer, EWMA probing) is deliberately NOT
//! here: this executor serves ONE peer; the choosing/swarm layer stacks
//! on top once live measurements exist (F1.5).
//!
//! F15 measurement plumbing: when a [`PeerMetrics`] handle is attached
//! ( [`RemoteExecutor::with_metrics`] ), every completed request records
//! its requester-side distribution (TTFT / inter-token latency / total)
//! and, after a clean completion, an idle ping/pong RTT probe runs on
//! the pooled session BEFORE it returns to the pool — off the request
//! critical path. Shadow data only: nothing here selects peers.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use futures_util::stream::{self, Stream};
use modelswarm_gateway::{
    ExecutorError, ExecutorEvent, ExecutorStream, FinishReason, InferenceExecutor,
    NormalizedMessage, NormalizedRequest,
};
use modelswarm_identity::InstallationIdentity;
use modelswarm_transport::libp2p_backend::{
    DialAttempt, DialPath, Libp2pSession, Libp2pTransport, PeerId,
};
use modelswarm_transport::message::{
    ChatMessage as WireChat, InferenceRequest as WireRequest, JobReceipt, ReceiptAck,
    Sampling as WireSampling, StreamError as WireStreamError, WireMessage,
};
use modelswarm_transport::observe::{CompletionObservation, CompletionOutcome, UsageDigest};

use crate::measure::PeerMetrics;
use crate::relay_ticket_cache::RelayTicketCache;

/// F2B: per-attempt budget for DIRECT candidates — deliberately SHORT:
/// a blackholed cross-NAT QUIC dial burns the whole per-attempt budget,
/// and the relay leg must not be starved behind it (Network handoff
/// 2026-10-15 guidance; `dial_with_fallback` has one budget per call, so
/// the node splits the phases around it).
const DIRECT_DIAL_DEADLINE: Duration = Duration::from_secs(5);
/// F2B: per-attempt budget for RELAY (circuit) candidates — generous:
/// the circuit handshake is a QUIC connection to the relay plus the
/// CONNECT exchange (a few WAN RTTs).
const RELAY_DIAL_DEADLINE: Duration = Duration::from_secs(10);
const IO_DEADLINE: Duration = Duration::from_secs(30);
/// ADR-030 B3: the receipt_ack is best-effort — a short deadline so a
/// wedged send can never hang the stream tail (the serving side moves
/// on after its own timeout; the accounting POST is the durable act).
const ACK_DEADLINE: Duration = Duration::from_secs(2);
/// F15: ping/pong probes per post-completion RTT batch.
const RTT_PROBE_SAMPLES: usize = 3;
/// F15: bound for one full probe batch (all samples).
const RTT_PROBE_DEADLINE: Duration = Duration::from_secs(2);

/// One remote serving peer.
#[derive(Debug, Clone)]
pub struct RemotePeer {
    /// The peer's PRIMARY advertised multiaddr, e.g.
    /// `/ip4/192.168.1.5/udp/4001/quic-v1`. F2B: this may itself be a
    /// circuit address (`<relay>/p2p-circuit[/p2p/<dst>]`) when the peer
    /// advertises no direct reachability — `dial_with_fallback`
    /// classifies it either way.
    pub addr: String,
    /// The ADR-020 PeerId the QUIC handshake must verify.
    pub peer_id: String,
}

/// Executes requests against a single remote serving peer, REUSING one
/// QUIC session across sequential requests (connection reuse): the
/// per-request handshake (~1 RTT + crypto) is paid once, not per chat
/// message. The pool self-heals — a broken session is dropped and the
/// next request dials fresh.
pub struct RemoteExecutor {
    peer: RemotePeer,
    identity: InstallationIdentity,
    pool: Arc<tokio::sync::Mutex<Option<Libp2pSession>>>,
    /// F15 shadow measurements; `None` keeps the executor measurement-free
    /// (all pre-F15 callers unchanged).
    metrics: Option<Arc<PeerMetrics>>,
    /// The peer's advertised `queueMs` as last known to the requester
    /// (refreshed per roster lookup via
    /// [`RemoteExecutor::set_advertised_queue_ms`]); recorded alongside
    /// measured admission-to-first-token. Advertised values are untrusted
    /// inputs, never measurements.
    advertised_queue_ms: StdMutex<Option<u64>>,
    /// F2B: the peer's additional advertised candidate multiaddrs (direct
    /// or circuit), refreshed per roster lookup via
    /// [`RemoteExecutor::set_candidate_addrs`] — the same freshness
    /// pattern as `set_advertised_queue_ms`. `peer.addr` is always
    /// candidate #1; these follow in advertised order, deduplicated.
    candidate_addrs: StdMutex<Vec<String>>,
    /// F2B: the dial path of the session currently pooled/serving —
    /// `Some(DialPath::Relayed { .. })` means replies come through the
    /// relay and must be labeled as such (ADR-014 rule 5).
    pooled_path: StdMutex<Option<DialPath>>,
    /// F2B: the per-attempt failures of the most recent dial (the honest
    /// report callers fold into their existing dial-failure surfaces).
    last_attempts: StdMutex<Vec<DialAttempt>>,
    /// ADR-038 §6.4 row 8: the node's relay admission ticket cache.
    /// `None` (all pre-row-8 callers) keeps the documented pre-wiring
    /// behavior — no pre-flight offer, third-party relays dial directly,
    /// an MSP relay's gate refuses the hop exchange with the upstream
    /// verbatim label. When attached, every FRESH dial transport
    /// presents the cached ticket on its relay legs.
    relay_tickets: Option<Arc<RelayTicketCache>>,
    /// ADR-030 B3: the counter-signed receipt of the most recent
    /// completed request (stashed by the stream tail, taken by the
    /// requester-side caller for the accounting POST). One chat turn at
    /// a time on the desktop path; a pooled executor shared by
    /// concurrent streams would race this slot — documented, not
    /// designed for, in v0.2.30.
    last_receipt: Arc<StdMutex<Option<JobReceipt>>>,
}

impl RemoteExecutor {
    pub fn new(peer: RemotePeer, identity: InstallationIdentity) -> Self {
        Self {
            peer,
            identity,
            pool: Arc::new(tokio::sync::Mutex::new(None)),
            metrics: None,
            advertised_queue_ms: StdMutex::new(None),
            candidate_addrs: StdMutex::new(Vec::new()),
            pooled_path: StdMutex::new(None),
            last_attempts: StdMutex::new(Vec::new()),
            relay_tickets: None,
            last_receipt: Arc::new(StdMutex::new(None)),
        }
    }

    /// Attaches the F15 measurement recorder (shadow data only).
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<PeerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Attaches the node's relay admission ticket cache (ADR-038 §6.4
    /// row 8): every dial transport this executor constructs carries the
    /// cached ticket into the `/msp/relay-ticket/1` pre-flight on relay
    /// legs. The cache is READ at dial time — heartbeat refreshes keep
    /// reaching sessions dialed later, no rebuild needed.
    #[must_use]
    pub fn with_relay_tickets(mut self, tickets: Arc<RelayTicketCache>) -> Self {
        self.relay_tickets = Some(tickets);
        self
    }

    /// Refreshes the peer's advertised `queueMs` from the latest roster
    /// (call per lookup; pooled executors outlive single rosters).
    pub fn set_advertised_queue_ms(&self, queue_ms: Option<u64>) {
        *self
            .advertised_queue_ms
            .lock()
            .expect("advertised queue lock") = queue_ms;
    }

    /// F2B: refreshes the peer's additional advertised candidate
    /// multiaddrs from the latest roster (direct AND circuit addresses —
    /// circuit addrs ride the tracker's existing `addresses` list). The
    /// primary `peer.addr` stays candidate #1; duplicates of it are
    /// dropped here. Call per lookup; pooled executors outlive single
    /// rosters.
    pub fn set_candidate_addrs(&self, addrs: Vec<String>) {
        let mut guard = self.candidate_addrs.lock().expect("candidate addr lock");
        *guard = addrs;
        if let Some(primary) = guard.iter().position(|a| *a == self.peer.addr) {
            guard.remove(primary);
        }
    }

    /// F2B: the dial path of the session currently pooled/serving —
    /// callers label the reply's mode with it (a relayed reply must never
    /// read as direct; ADR-014 rule 5). `None` when no dial has happened
    /// yet (or the executor is un-pooled test usage).
    pub fn pooled_dial_path(&self) -> Option<DialPath> {
        self.pooled_path.lock().expect("dial path lock").clone()
    }

    /// ADR-030 B3: takes the counter-signed receipt the last completed
    /// request stashed (None when the peer sent no receipt or the
    /// countersign refused it). Taking clears the slot — one receipt is
    /// POSTed exactly once.
    pub fn take_last_receipt(&self) -> Option<JobReceipt> {
        self.last_receipt.lock().expect("receipt stash lock").take()
    }

    /// F2B: the per-attempt failures of the most recent dial, in attempt
    /// order — transport report data for the caller's existing
    /// dial-failure diagnostics (kind, addr, error text).
    pub fn last_dial_attempts(&self) -> Vec<DialAttempt> {
        self.last_attempts.lock().expect("dial report lock").clone()
    }

    fn record_failure(&self, stage: &'static str) {
        if let Some(metrics) = &self.metrics {
            metrics.record_failure(&self.peer.peer_id, stage);
        }
    }
}

fn wire_request(request: &NormalizedRequest) -> WireRequest {
    WireRequest {
        request_id: request.request_id.clone(),
        profile_id: request.profile_id.clone(),
        capability_token: request
            .capability_token
            .clone()
            .unwrap_or_else(|| "f1-unverified".into()),
        messages: request
            .messages
            .iter()
            .map(|m: &NormalizedMessage| WireChat {
                role: m.role.clone(),
                content: m.content.clone(),
            })
            .collect(),
        sampling: WireSampling {
            temperature: f64::from(request.sampling.temperature),
            top_p: f64::from(request.sampling.top_p),
            top_k: request.sampling.top_k,
            seed: request.sampling.seed,
        },
        max_tokens: request.max_tokens,
        deadline_ms: request.deadline_ms,
        stream: true,
    }
}

/// Maps one inbound frame to an executor event (None = end of stream).
fn frame_to_event(frame: WireMessage) -> Option<Result<ExecutorEvent, WireStreamError>> {
    match frame {
        WireMessage::TokenDelta(d) => Some(Ok(ExecutorEvent::TokenDelta {
            delta: d.delta,
            index: d.index,
        })),
        WireMessage::Usage(u) => Some(Ok(ExecutorEvent::Usage {
            prompt_tokens: u.prompt_tokens,
            completion_tokens: u.completion_tokens,
            prefill_ms: f64::from(u.prefill_ms),
            decode_ms: f64::from(u.decode_ms),
        })),
        WireMessage::Completed(c) => Some(Ok(ExecutorEvent::Completed {
            finish_reason: match c.finish_reason.as_str() {
                "length" => FinishReason::Length,
                "cancelled" => FinishReason::Cancelled,
                _ => FinishReason::Stop,
            },
        })),
        WireMessage::Cancelled(_) => Some(Ok(ExecutorEvent::Completed {
            finish_reason: FinishReason::Cancelled,
        })),
        WireMessage::StreamError(e) => Some(Err(e)),
        // ADR-043 §3: the §6.3 `accepted` admission confirmation from a
        // serving peer's fair queue — informational; the stream continues
        // exactly as before (the pre-existing Accepted arms downstream are
        // no-ops by design).
        WireMessage::Accepted(a) => Some(Ok(ExecutorEvent::Accepted {
            queue_position: a.queue_position,
            eta_ms: u64::from(a.eta_ms),
        })),
        // Handshake frames never appear mid-request on this path.
        _ => None,
    }
}

/// Requester-side wall-clock record for one in-flight request (F15).
#[derive(Default)]
struct Timeline {
    first_token_at: Option<Instant>,
    last_token_at: Option<Instant>,
    itl_sum_ms: f64,
    itl_max_ms: f64,
    token_deltas: u32,
    usage: Option<UsageDigest>,
}

impl Timeline {
    fn on_token(&mut self) {
        let now = Instant::now();
        if let Some(last) = self.last_token_at {
            let ms = now.duration_since(last).as_secs_f64() * 1_000.0;
            self.itl_sum_ms += ms;
            self.itl_max_ms = self.itl_max_ms.max(ms);
        }
        self.first_token_at.get_or_insert(now);
        self.last_token_at = Some(now);
        self.token_deltas += 1;
    }
}

/// Everything the stream needs to finalize one observation.
struct StreamContext {
    peer_id: String,
    profile_id: String,
    advertised_queue_ms: Option<u64>,
    admitted_at: Instant,
    metrics: Option<Arc<PeerMetrics>>,
    /// ADR-030 B3: the requester identity (receipt countersign) and the
    /// stash the counter-signed receipt lands in for the caller's
    /// accounting POST.
    identity: InstallationIdentity,
    receipt_out: Arc<StdMutex<Option<JobReceipt>>>,
}

fn finalize_observation(ctx: &StreamContext, timeline: &Timeline, outcome: CompletionOutcome) {
    let Some(metrics) = &ctx.metrics else {
        return;
    };
    let ttft_ms = timeline
        .first_token_at
        .map(|t| t.duration_since(ctx.admitted_at).as_secs_f64() * 1_000.0)
        .unwrap_or(0.0);
    let total_ms = Instant::now().duration_since(ctx.admitted_at).as_secs_f64() * 1_000.0;
    let itl_count = timeline.token_deltas.saturating_sub(1);
    metrics.record_completion(&CompletionObservation {
        peer_id: ctx.peer_id.clone(),
        profile_id: ctx.profile_id.clone(),
        outcome,
        ttft_ms,
        total_ms,
        itl_mean_ms: if itl_count > 0 {
            timeline.itl_sum_ms / f64::from(itl_count)
        } else {
            0.0
        },
        itl_max_ms: timeline.itl_max_ms,
        token_deltas: timeline.token_deltas,
        usage: timeline.usage,
        advertised_queue_ms: ctx.advertised_queue_ms,
    });
}

/// Deposits a healthy session back into the executor pool (no-op when the
/// pool is already holding one or is in use).
fn return_to_pool(session: Libp2pSession, pool: &Arc<tokio::sync::Mutex<Option<Libp2pSession>>>) {
    if let Ok(mut guard) = pool.try_lock() {
        if guard.is_none() {
            *guard = Some(session);
        }
    }
}

/// Circuit candidates (F2B): a multiaddr carrying `/p2p-circuit` —
/// `<relay>/p2p-circuit[/p2p/<dst>]`. This split ONLY routes candidates
/// into their budget phase (short direct / generous relay);
/// [`Libp2pTransport::dial_with_fallback`] does the authoritative
/// classification inside each phase.
fn is_circuit_addr(addr: &str) -> bool {
    addr.contains("/p2p-circuit")
}

/// One F2B dial phase: dials `candidates` (all one kind — the caller
/// split them) through [`Libp2pTransport::dial_with_fallback`] with
/// `per_attempt` and returns the winner plus the honest per-attempt
/// report. An EMPTY candidate list is a no-op — no fabricated
/// "no candidates" attempt row, no dial at all.
async fn dial_phase(
    client: &Libp2pTransport,
    candidates: &[String],
    expected_peer: &PeerId,
    per_attempt: Duration,
) -> (Option<(Libp2pSession, DialPath)>, Vec<DialAttempt>) {
    if candidates.is_empty() {
        return (None, Vec::new());
    }
    match client
        .dial_with_fallback(candidates, expected_peer, per_attempt)
        .await
    {
        Ok((session, path)) => (Some((session, path)), Vec::new()),
        Err((_, attempts)) => (None, attempts),
    }
}

/// F15: after a clean completion, probe RTT on the now-idle session and
/// only then return it to the pool. The probe rides the serving side's
/// between-requests recv (which answers pings transparently). A failed
/// probe drops the session — the next request self-heals with a fresh
/// dial — and records a failure observation.
async fn probe_and_return(
    session: Libp2pSession,
    pool: Arc<tokio::sync::Mutex<Option<Libp2pSession>>>,
    metrics: Arc<PeerMetrics>,
    peer_id: String,
) {
    let mut session = session;
    match session
        .measure_rtt(RTT_PROBE_SAMPLES, RTT_PROBE_DEADLINE)
        .await
    {
        Ok(stats) => {
            metrics.record_rtt(&peer_id, &stats);
            return_to_pool(session, &pool);
        }
        Err(_) => metrics.record_failure(&peer_id, "rtt_probe"),
    }
}

fn stream_events(
    session: Libp2pSession,
    pool: Arc<tokio::sync::Mutex<Option<Libp2pSession>>>,
    ctx: StreamContext,
) -> impl Stream<Item = ExecutorEvent> {
    // Terminal frames (Completed/Cancelled) END the exchange per the
    // protocol. A CLEAN terminal runs the F15 RTT probe (when metrics are
    // attached) and then returns the session to the pool for the next
    // request (connection reuse); errors drop it so the next request
    // dials fresh.
    stream::unfold(
        (Some(session), pool, false, Timeline::default(), ctx),
        |(slot, pool, done, mut timeline, ctx)| async move {
            if done {
                return None;
            }
            let mut session = match slot {
                Some(s) => s,
                None => return None,
            };
            let frame = match session.recv(IO_DEADLINE).await {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("modelswarm-node: remote stream read failed: {e}");
                    finalize_observation(
                        &ctx,
                        &timeline,
                        CompletionOutcome::Errored {
                            code: "transport".into(),
                        },
                    );
                    if let Some(metrics) = &ctx.metrics {
                        metrics.record_failure(&ctx.peer_id, "stream_read");
                    }
                    return Some((
                        ExecutorEvent::Error {
                            code: "transport".into(),
                            retryable: false,
                            interrupted_after_tokens: None,
                        },
                        (None, pool, true, timeline, ctx),
                    ));
                }
            };
            // ADR-030 B3: capture the Completed frame's receipt before
            // `frame_to_event` consumes it — the countersign happens in
            // the Completed arm below, on the still-open session (the
            // ack needs it before the session re-pools).
            let receipt_wire = match &frame {
                WireMessage::Completed(c) => c.job_receipt.clone(),
                _ => None,
            };
            match frame_to_event(frame) {
                // Server closed the session: end cleanly, drop it — but
                // the observation still records what was measured.
                None => {
                    finalize_observation(
                        &ctx,
                        &timeline,
                        CompletionOutcome::Errored {
                            code: "connection_closed".into(),
                        },
                    );
                    None
                }
                Some(Ok(event)) => match &event {
                    ExecutorEvent::TokenDelta { .. } => {
                        timeline.on_token();
                        Some((event, (Some(session), pool, false, timeline, ctx)))
                    }
                    ExecutorEvent::Usage {
                        prompt_tokens,
                        completion_tokens,
                        prefill_ms,
                        decode_ms,
                    } => {
                        timeline.usage = Some(UsageDigest {
                            prompt_tokens: *prompt_tokens,
                            completion_tokens: *completion_tokens,
                            prefill_ms: *prefill_ms,
                            decode_ms: *decode_ms,
                        });
                        Some((event, (Some(session), pool, false, timeline, ctx)))
                    }
                    ExecutorEvent::Completed { finish_reason } => {
                        let finish_reason = format!("{finish_reason:?}").to_lowercase();
                        finalize_observation(
                            &ctx,
                            &timeline,
                            CompletionOutcome::Completed { finish_reason },
                        );
                        // ADR-030 B3 (requester half): counter-sign the
                        // server's receipt with THIS installation, ack it
                        // best-effort on the open session, and stash the
                        // final object for the caller's accounting POST.
                        // A refused countersign (naming mismatch, absent
                        // roles) degrades to a receipt-less completion —
                        // the chat reply is never hostage to accounting.
                        if let Some(wire) = receipt_wire {
                            match crate::receipt_wire::countersign(
                                &wire,
                                &ctx.identity,
                                &ctx.peer_id,
                                // The remote-executor path is the plain
                                // msp-v1 §6 pull — no SessionOffer rides
                                // it, so no negotiated preset exists and
                                // the receipt must honestly stay
                                // `unspecified` (INV-4).
                                None,
                            ) {
                                Ok(final_wire) => {
                                    let ack = WireMessage::ReceiptAck(ReceiptAck {
                                        request_id: final_wire.request_id.clone(),
                                    });
                                    if let Err(e) = session.send(&ack, ACK_DEADLINE).await {
                                        eprintln!(
                                            "modelswarm-node: receipt ack best-effort failed: {e}"
                                        );
                                    }
                                    *ctx.receipt_out.lock().expect("receipt stash lock") =
                                        Some(final_wire);
                                }
                                Err(why) => {
                                    eprintln!(
                                        "modelswarm-node: receipt countersign refused: {why}"
                                    );
                                }
                            }
                        }
                        match &ctx.metrics {
                            Some(metrics) => {
                                let metrics = Arc::clone(metrics);
                                let peer_id = ctx.peer_id.clone();
                                tokio::spawn(probe_and_return(
                                    session,
                                    pool.clone(),
                                    metrics,
                                    peer_id,
                                ));
                            }
                            None => return_to_pool(session, &pool),
                        }
                        Some((event, (None, pool, true, timeline, ctx)))
                    }
                    // Accepted never appears on this wire path today.
                    ExecutorEvent::Accepted { .. } | ExecutorEvent::Error { .. } => {
                        Some((event, (Some(session), pool, false, timeline, ctx)))
                    }
                },
                Some(Err(wire_error)) => {
                    eprintln!(
                        "modelswarm-node: remote peer refused: {} {}",
                        wire_error.code, wire_error.message
                    );
                    let code = wire_error.code.clone();
                    finalize_observation(
                        &ctx,
                        &timeline,
                        CompletionOutcome::Errored { code: code.clone() },
                    );
                    Some((
                        ExecutorEvent::Error {
                            code: wire_error.code,
                            retryable: wire_error.retryable_peer_hint,
                            interrupted_after_tokens: None,
                        },
                        (None, pool, true, timeline, ctx),
                    ))
                }
            }
        },
    )
}

#[async_trait::async_trait]
impl InferenceExecutor for RemoteExecutor {
    async fn execute(&self, request: NormalizedRequest) -> Result<ExecutorStream, ExecutorError> {
        let expected_peer: PeerId =
            self.peer
                .peer_id
                .parse()
                .map_err(|_| ExecutorError::Fatal {
                    code: format!("bad_peer_id: {}", self.peer.peer_id),
                })?;
        // Pooled connection reuse: take a warm session if the pool holds
        // one, otherwise dial fresh.
        let mut guard = self.pool.lock().await;
        let session = match guard.take() {
            Some(s) => s,
            None => {
                let client =
                    Libp2pTransport::new(&self.identity).map_err(|e| ExecutorError::Fatal {
                        code: format!("transport: {e}"),
                    })?;
                // ADR-038 §6.4 row 8: hand the cached admission ticket to
                // this fresh dial transport BEFORE any relay leg — the
                // pre-flight then presents it (or skips the offer while
                // the cache is empty, the documented pre-wiring posture).
                if let Some(tickets) = &self.relay_tickets {
                    tickets.attach_to(&client);
                }
                // F2B (ADR-014): direct-first over ALL advertised
                // candidates, honest relay fallback. The two phases below
                // split only the per-attempt BUDGET (short for direct so
                // a cross-NAT blackhole cannot starve the relay leg,
                // generous for relay) — ordering and classification stay
                // `dial_with_fallback`'s own (direct candidates in list
                // order, then circuit candidates in list order).
                let mut candidates: Vec<String> = vec![self.peer.addr.clone()];
                for extra in self
                    .candidate_addrs
                    .lock()
                    .expect("candidate addr lock")
                    .iter()
                {
                    if !candidates.contains(extra) {
                        candidates.push(extra.clone());
                    }
                }
                let direct: Vec<String> = candidates
                    .iter()
                    .filter(|addr| !is_circuit_addr(addr))
                    .cloned()
                    .collect();
                let relay: Vec<String> = candidates
                    .iter()
                    .filter(|addr| is_circuit_addr(addr))
                    .cloned()
                    .collect();
                let mut attempts: Vec<DialAttempt> = Vec::new();
                let (winner, direct_attempts) =
                    dial_phase(&client, &direct, &expected_peer, DIRECT_DIAL_DEADLINE).await;
                attempts.extend(direct_attempts);
                let (session, path) = match winner {
                    Some((session, path)) => (session, path),
                    None => {
                        let (winner, relay_attempts) =
                            dial_phase(&client, &relay, &expected_peer, RELAY_DIAL_DEADLINE).await;
                        attempts.extend(relay_attempts);
                        match winner {
                            Some((session, path)) => (session, path),
                            None => {
                                // Every failed attempt is reported
                                // per-attempt through the EXISTING
                                // vocabulary (`net.failure` /
                                // stage=`dial` rows via the attached
                                // metrics; the stderr diagnostics this
                                // module always printed) — no new event
                                // names.
                                for attempt in &attempts {
                                    eprintln!(
                                        "modelswarm-node: remote dial failed ({} {}): {}",
                                        attempt.kind, attempt.addr, attempt.error
                                    );
                                }
                                for _ in &attempts {
                                    self.record_failure("dial");
                                }
                                *self.last_attempts.lock().expect("dial report lock") = attempts;
                                return Err(ExecutorError::Retryable {
                                    peer_hint: Some(self.peer.peer_id.clone()),
                                });
                            }
                        }
                    }
                };
                // Failed attempts before a WIN are still telemetered (a
                // direct blackhole followed by a relay win must be
                // visible), and the winning path labels the pooled
                // session for the reply's mode honesty.
                for attempt in &attempts {
                    eprintln!(
                        "modelswarm-node: remote dial attempt failed ({} {}): {}",
                        attempt.kind, attempt.addr, attempt.error
                    );
                }
                for _ in &attempts {
                    self.record_failure("dial");
                }
                *self.pooled_path.lock().expect("dial path lock") = Some(path);
                *self.last_attempts.lock().expect("dial report lock") = attempts;
                session
            }
        };
        drop(guard);
        let mut session = session;
        // ADR-030 B3: one receipt slot per execution — a stale receipt
        // from a previous request can never be POSTed for this one.
        self.last_receipt.lock().expect("receipt stash lock").take();
        let ctx = StreamContext {
            peer_id: self.peer.peer_id.clone(),
            profile_id: request.profile_id.clone(),
            advertised_queue_ms: *self
                .advertised_queue_ms
                .lock()
                .expect("advertised queue lock"),
            // Admission time: the request leaves right now — measured
            // admission-to-first-token starts at this instant (F15).
            admitted_at: Instant::now(),
            metrics: self.metrics.clone(),
            identity: self.identity.clone(),
            receipt_out: Arc::clone(&self.last_receipt),
        };
        if let Err(e) = session
            .send(
                &WireMessage::InferenceRequest(wire_request(&request)),
                IO_DEADLINE,
            )
            .await
        {
            eprintln!("modelswarm-node: remote send failed: {e}");
            self.record_failure("send");
            return Err(ExecutorError::Retryable {
                peer_hint: Some(self.peer.peer_id.clone()),
            });
        }
        Ok(Box::pin(stream_events(
            session,
            std::sync::Arc::clone(&self.pool),
            ctx,
        )))
    }
}

/// F1.5 chooser: remote-first with honest local fallback. If a serving
/// peer is known for the profile, requests go there; ANY pre-first-token
/// failure (dial, send, retryable error) falls back to the LOCAL
/// executor — the requester never notices unless the remote was slower.
/// After the first streamed token, remote failures are surfaced as
/// honest interrupted errors (ADR-007: no cross-peer retry mid-stream).
///
/// v1 policy is deliberately this simple: one remote peer, no EWMA, no
/// hedging. Live latency measurement (fastest-peer selection) stacks
/// above this once real WAN numbers exist (phase-f-research, F1.5).
pub struct FailoverExecutor {
    remote: std::sync::Arc<RemoteExecutor>,
    local: std::sync::Arc<dyn InferenceExecutor>,
}

impl FailoverExecutor {
    pub fn new(
        remote: std::sync::Arc<RemoteExecutor>,
        local: std::sync::Arc<dyn InferenceExecutor>,
    ) -> Self {
        Self { remote, local }
    }
}

#[async_trait::async_trait]
impl InferenceExecutor for FailoverExecutor {
    async fn execute(&self, request: NormalizedRequest) -> Result<ExecutorStream, ExecutorError> {
        match self.remote.execute(request.clone()).await {
            Ok(stream) => Ok(stream),
            Err(ExecutorError::Retryable { .. }) => {
                eprintln!("modelswarm-node: remote peer failed pre-token; falling back to local");
                self.local.execute(request).await
            }
            // Fatal remote errors (bad peer id, transport build) also
            // degrade to local — the request itself is still servable.
            Err(ExecutorError::Fatal { code }) => {
                eprintln!("modelswarm-node: remote executor fatal ({code}); falling back to local");
                self.local.execute(request).await
            }
            Err(ExecutorError::NoPeer) => self.local.execute(request).await,
        }
    }
}

#[cfg(test)]
mod failover_tests {
    use super::*;
    use crate::serving::serve_sessions;
    use futures_util::StreamExt;
    use modelswarm_gateway::{ExecutorError, ExecutorStream, NormalizedRequest};
    use modelswarm_identity::InstallationIdentity;
    use modelswarm_transport::libp2p_backend::Libp2pTransport;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn request(profile: &str) -> NormalizedRequest {
        NormalizedRequest {
            request_id: "req-fo".into(),
            profile_id: profile.into(),
            capability_token: None,
            messages: vec![modelswarm_gateway::NormalizedMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
            sampling: modelswarm_gateway::Sampling {
                temperature: 0.0,
                top_p: 1.0,
                top_k: 40,
                seed: None,
            },
            max_tokens: 8,
            deadline_ms: 10_000,
            stream: true,
        }
    }

    struct CountingExecutor {
        label: &'static str,
        calls: AtomicUsize,
    }
    #[async_trait::async_trait]
    impl modelswarm_gateway::InferenceExecutor for CountingExecutor {
        async fn execute(
            &self,
            _request: NormalizedRequest,
        ) -> Result<ExecutorStream, ExecutorError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Box::pin(futures_util::stream::iter(vec![
                ExecutorEvent::TokenDelta {
                    delta: self.label.into(),
                    index: 0,
                },
                ExecutorEvent::Completed {
                    finish_reason: modelswarm_gateway::FinishReason::Stop,
                },
            ])))
        }
    }

    async fn collect(stream: ExecutorStream) -> String {
        let mut text = String::new();
        futures_util::pin_mut!(stream);
        while let Some(event) = stream.next().await {
            if let ExecutorEvent::TokenDelta { delta, .. } = event {
                text.push_str(&delta);
            }
        }
        text
    }

    #[tokio::test]
    async fn remote_up_answers_come_from_the_peer() {
        let server_identity = InstallationIdentity::from_bytes(&[37u8; 32]);
        let client_identity = InstallationIdentity::from_bytes(&[38u8; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let listener = server.listen("127.0.0.1:0").await.unwrap();
        let peer = RemotePeer {
            addr: listener.bound_addr().to_string(),
            peer_id: server.peer_id().to_string(),
        };
        let client_peer_id = Libp2pTransport::new(&client_identity)
            .unwrap()
            .peer_id()
            .to_string();
        let profile = crate::serving::lease_helpers::TEST_PROFILE;
        let (policy, token) =
            crate::serving::lease_helpers::policy_and_lease(profile, &client_peer_id);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let remote_executor = Arc::new(CountingExecutor {
            label: "REMOTE",
            calls: AtomicUsize::new(0),
        });
        tokio::spawn(serve_sessions(
            listener,
            std::sync::Arc::new(crate::serving::lease_helpers::server_identity()),
            remote_executor.clone(),
            profile.into(),
            policy,
            std::sync::Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            rx,
        ));

        let local = Arc::new(CountingExecutor {
            label: "LOCAL",
            calls: AtomicUsize::new(0),
        });
        let mut with_lease = request(profile);
        with_lease.capability_token = Some(token);
        let fo = FailoverExecutor::new(
            Arc::new(RemoteExecutor::new(peer, client_identity)),
            local.clone(),
        );

        let text = collect(fo.execute(with_lease).await.unwrap()).await;
        assert_eq!(text, "REMOTE");
        assert_eq!(
            local.calls.load(Ordering::SeqCst),
            0,
            "local untouched when remote is up"
        );
        assert_eq!(remote_executor.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn remote_down_falls_back_to_local_honestly() {
        // No listener at that address: the dial must fail and the local
        // executor answers instead.
        let client_identity = InstallationIdentity::from_bytes(&[39u8; 32]);
        // A REAL PeerId derivation with an unreachable address: the DIAL
        // must fail (a placeholder-style base58 string would fail
        // `PeerId::parse` first and never reach the dial at all).
        let peer = RemotePeer {
            addr: "/ip4/127.0.0.1/udp/9/udt".into(), // nothing listens here
            peer_id: Libp2pTransport::new(&InstallationIdentity::from_bytes(&[83u8; 32]))
                .unwrap()
                .peer_id()
                .to_string(),
        };
        let local = Arc::new(CountingExecutor {
            label: "LOCAL",
            calls: AtomicUsize::new(0),
        });
        let fo = FailoverExecutor::new(
            Arc::new(RemoteExecutor::new(peer, client_identity)),
            local.clone(),
        );
        let text = collect(fo.execute(request("msp1:fo")).await.unwrap()).await;
        assert_eq!(text, "LOCAL");
        assert_eq!(local.calls.load(Ordering::SeqCst), 1);
    }

    /// ADR-038 §6.4 row 8: an attached ticket cache changes NOTHING on a
    /// direct dial — the admission pre-flight lives on RELAY legs only,
    /// so a direct candidate never offers `/msp/relay-ticket/1`. The
    /// cached token is the golden accept vector's (fixture-signed, long
    /// expired by wall clock): even a stale ticket must not perturb the
    /// direct path, because the node's supply is read only when a relay
    /// leg exists (`dial_with_fallback`'s circuit phase).
    #[tokio::test]
    async fn attached_relay_tickets_leave_direct_dials_untouched() {
        let server_identity = InstallationIdentity::from_bytes(&[93u8; 32]);
        let client_identity = InstallationIdentity::from_bytes(&[94u8; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let listener = server.listen("127.0.0.1:0").await.unwrap();
        let peer = RemotePeer {
            addr: listener.bound_addr().to_string(),
            peer_id: server.peer_id().to_string(),
        };
        let client_peer_id = Libp2pTransport::new(&client_identity)
            .unwrap()
            .peer_id()
            .to_string();
        let profile = crate::serving::lease_helpers::TEST_PROFILE;
        let (policy, token) =
            crate::serving::lease_helpers::policy_and_lease(profile, &client_peer_id);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_sessions(
            listener,
            std::sync::Arc::new(crate::serving::lease_helpers::server_identity()),
            Arc::new(CountingExecutor {
                label: "REMOTE",
                calls: AtomicUsize::new(0),
            }),
            profile.into(),
            policy,
            std::sync::Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            rx,
        ));

        // The cache holds the golden vector token (read from
        // protocol/vectors/relay-ticket-1.json, never inlined).
        let vector_path = format!(
            "{}/../../protocol/vectors/relay-ticket-1.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let vector: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&vector_path).expect("vector file"))
                .expect("vector JSON");
        let cache = std::sync::Arc::new(crate::relay_ticket_cache::RelayTicketCache::new());
        cache.store(vector["token"].as_str().expect("token"));

        let mut with_lease = request(profile);
        with_lease.capability_token = Some(token);
        let remote = RemoteExecutor::new(peer, client_identity).with_relay_tickets(cache);
        let text = collect(remote.execute(with_lease).await.unwrap()).await;
        assert_eq!(text, "REMOTE", "direct dial must not see the pre-flight");
    }
}

#[cfg(test)]
mod lan_proof {
    use super::*;
    use crate::load_or_create_identity;
    use futures_util::StreamExt;
    use modelswarm_gateway::{
        ExecutorEvent, InferenceExecutor, NormalizedMessage, NormalizedRequest,
    };
    use modelswarm_telemetry::Telemetry;
    use modelswarm_tracker_api::TrackerClient;
    use std::time::Duration;

    /// F0(5)/F1 LAN CROSS-MACHINE PROOF (ignored; env-gated):
    /// MSP_LAN_PROFILE=<profile id> MSP_DATA_DIR=<ModelSwarm data dir>
    /// MSP_EXCLUDE_ADDR=<own advertised multiaddr> — looks the profile up
    /// on the PRODUCTION tracker with the real installation identity,
    /// dials the first OTHER peer advertising a real QUIC multiaddr, and
    /// streams one real completion from that machine.
    #[tokio::test]
    #[ignore = "set MSP_LAN_PROFILE, MSP_DATA_DIR and MSP_EXCLUDE_ADDR"]
    async fn lan_cross_machine_completion() {
        let profile = std::env::var("MSP_LAN_PROFILE").expect("MSP_LAN_PROFILE");
        let data_dir = std::env::var("MSP_DATA_DIR").expect("MSP_DATA_DIR");
        let exclude = std::env::var("MSP_EXCLUDE_ADDR").unwrap_or_default();
        let tracker_url = std::env::var("MSP_TRACKER")
            .unwrap_or_else(|_| "https://modelswarm.deepflux.space".into());

        let dir = std::path::PathBuf::from(&data_dir);
        let logs = dir.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let sink = modelswarm_telemetry::FileSink::open(&logs.join("node.jsonl")).unwrap();
        let telemetry = Telemetry::with_sink(Box::new(sink));
        let identity = load_or_create_identity(&dir, &telemetry).unwrap();

        let tracker = TrackerClient::new(
            &tracker_url,
            std::sync::Arc::new(load_or_create_identity(&dir, &telemetry).unwrap()),
        );
        // The roster endpoint needs an enrolled session (X-MSP-Session);
        // prefer the app's persisted session, else enroll on the fly
        // (production auto-approves devices).
        if let Ok(token) = std::fs::read_to_string(dir.join("session.token")) {
            let token = token.trim().to_string();
            if !token.is_empty() {
                tracker.set_session(token);
            }
        }
        if !tracker.has_session() {
            let start = tracker.device_start().await.unwrap();
            let device_code = start["deviceCode"].as_str().expect("deviceCode");
            let mut session = None;
            for _ in 0..10 {
                match tracker.device_complete(device_code).await {
                    Ok(v) => {
                        session = v["token"].as_str().map(str::to_string);
                        break;
                    }
                    Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                }
            }
            tracker.set_session(session.expect("device enrollment completes (auto-approve)"));
        }
        let peers = tracker.lookup(&profile, 10).await.unwrap();
        println!("roster: {} peers for this profile", peers.len());
        for p in &peers {
            println!(
                "  peer {} addr {:?} slots {}",
                p.peer_id, p.addresses, p.free_slots
            );
        }
        // Structural self-exclusion: MSP_EXCLUDE_ADDR is treated as a
        // substring (any peer advertising it — e.g. our own multiaddr — is
        // skipped), so the proof always dials the OTHER machine.
        let candidate = peers
            .iter()
            .find(|p| {
                p.free_slots > 0
                    && p.addresses.iter().any(|a| {
                        a.ends_with("quic-v1")
                            && !a.contains("0.0.0.0")
                            && (exclude.is_empty() || !a.contains(&exclude))
                    })
            })
            .expect("no other serving peer with a real address on the roster");
        let addr = candidate
            .addresses
            .iter()
            .find(|a| {
                a.ends_with("quic-v1")
                    && !a.contains("0.0.0.0")
                    && (exclude.is_empty() || !a.contains(&exclude))
            })
            .unwrap()
            .clone();
        println!(
            "dialing {addr} (peer {}…)",
            &candidate.peer_id[..16.min(candidate.peer_id.len())]
        );

        let executor = RemoteExecutor::new(
            RemotePeer {
                addr,
                peer_id: candidate.peer_id.clone(),
            },
            identity,
        );
        let started = std::time::Instant::now();
        let mut stream = executor
            .execute(NormalizedRequest {
                request_id: format!("lan-proof-{}", modelswarm_identity::new_nonce()),
                profile_id: profile.clone(),
                capability_token: (async {
                    // F3 gated path: earn a consume lease the honest way —
                    // hosting challenge timed against THIS machine's real
                    // engine (the app is hosting this profile).
                    let lease_id = std::fs::read_to_string(dir.join("lease.id"))
                        .ok()?
                        .trim()
                        .to_string();
                    let started = std::time::Instant::now();
                    let probe: serde_json::Value = reqwest::Client::new()
                        .post("http://127.0.0.1:11435/v1/chat/completions")
                        .timeout(Duration::from_secs(60))
                        .json(&serde_json::json!({
                            "model": profile,
                            "messages": [{ "role": "user", "content": "Say ok." }],
                            "max_tokens": 8,
                            "temperature": 0.0,
                            "stream": false,
                        }))
                        .send()
                        .await
                        .ok()?
                        .json()
                        .await
                        .ok()?;
                    probe["choices"][0]["message"]["content"].as_str()?;
                    let total_ms = started.elapsed().as_millis() as u64;
                    let ch = tracker
                        .challenge_start(&lease_id, profile.as_str())
                        .await
                        .ok()?;
                    let ch_id = ch["challengeId"].as_str()?.to_string();
                    tracker
                        .challenge_complete(&lease_id, profile.as_str(), &ch_id, total_ms, total_ms)
                        .await
                        .ok()?;
                    let issued = tracker
                        .request_lease(&lease_id, profile.as_str())
                        .await
                        .ok()?;
                    println!("lease earned (challenge {} ms)", total_ms);
                    Some(issued.lease)
                })
                .await,
                messages: vec![NormalizedMessage {
                    role: "user".into(),
                    content: "Say exactly: cross-machine swarm serving works.".into(),
                }],
                sampling: modelswarm_gateway::Sampling {
                    temperature: 0.0,
                    top_p: 1.0,
                    top_k: 40,
                    seed: None,
                },
                max_tokens: 24,
                deadline_ms: 60_000,
                stream: true,
            })
            .await
            .expect("remote execute starts");

        let mut text = String::new();
        let mut completion_tokens = 0u32;
        while let Some(event) = stream.next().await {
            match event {
                ExecutorEvent::TokenDelta { delta, .. } => text.push_str(&delta),
                ExecutorEvent::Usage {
                    completion_tokens: t,
                    ..
                } => completion_tokens = t,
                ExecutorEvent::Completed { finish_reason } => {
                    println!("finish: {finish_reason:?}");
                    break;
                }
                ExecutorEvent::Error { code, .. } => panic!("stream error: {code}"),
                ExecutorEvent::Accepted { .. } => {}
            }
        }
        let secs = started.elapsed().as_secs_f64();
        println!("REMOTE REPLY ({completion_tokens} tokens, {secs:.1}s): {text}");
        assert!(!text.trim().is_empty(), "remote peer must produce tokens");
    }
}

#[cfg(test)]
mod reuse_tests {
    use super::*;
    use crate::serving::serve_sessions;
    use futures_util::StreamExt;
    use modelswarm_gateway::{ExecutorError, ExecutorStream, NormalizedMessage, NormalizedRequest};
    use modelswarm_identity::InstallationIdentity;
    use modelswarm_transport::libp2p_backend::Libp2pTransport;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Connection reuse: TWO sequential requests through ONE
    /// RemoteExecutor reuse the same QUIC session (one dial, one serving
    /// session, both requests served) — the per-request handshake
    /// disappears.
    #[tokio::test]
    async fn two_requests_reuse_one_session() {
        struct CountingExecutor {
            served: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl modelswarm_gateway::InferenceExecutor for CountingExecutor {
            async fn execute(
                &self,
                _request: NormalizedRequest,
            ) -> Result<ExecutorStream, ExecutorError> {
                let n = self.served.fetch_add(1, Ordering::SeqCst);
                Ok(Box::pin(futures_util::stream::iter(vec![
                    ExecutorEvent::TokenDelta {
                        delta: format!("answer-{n}"),
                        index: 0,
                    },
                    ExecutorEvent::Completed {
                        finish_reason: modelswarm_gateway::FinishReason::Stop,
                    },
                ])))
            }
        }

        let server_identity = InstallationIdentity::from_bytes(&[67u8; 32]);
        let client_identity = InstallationIdentity::from_bytes(&[68u8; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let listener = server.listen("127.0.0.1:0").await.unwrap();
        let addr = listener.bound_addr().to_string();
        let profile = crate::serving::lease_helpers::TEST_PROFILE;
        let client_peer_id = Libp2pTransport::new(&client_identity)
            .unwrap()
            .peer_id()
            .to_string();
        let (policy, token) =
            crate::serving::lease_helpers::policy_and_lease(profile, &client_peer_id);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let served = Arc::new(CountingExecutor {
            served: AtomicUsize::new(0),
        });
        tokio::spawn(serve_sessions(
            listener,
            std::sync::Arc::new(crate::serving::lease_helpers::server_identity()),
            served.clone(),
            profile.into(),
            policy,
            std::sync::Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            rx,
        ));

        let executor = RemoteExecutor::new(
            RemotePeer {
                addr,
                peer_id: server.peer_id().to_string(),
            },
            client_identity,
        );

        async fn run(executor: &RemoteExecutor, profile: &str, token: &str, id: &str) -> String {
            let stream = executor
                .execute(NormalizedRequest {
                    request_id: id.into(),
                    profile_id: profile.into(),
                    capability_token: Some(token.to_string()),
                    messages: vec![NormalizedMessage {
                        role: "user".into(),
                        content: "hi".into(),
                    }],
                    sampling: modelswarm_gateway::Sampling {
                        temperature: 0.0,
                        top_p: 1.0,
                        top_k: 40,
                        seed: None,
                    },
                    max_tokens: 8,
                    deadline_ms: 10_000,
                    stream: true,
                })
                .await
                .expect("execute starts");
            let mut text = String::new();
            futures_util::pin_mut!(stream);
            while let Some(event) = stream.next().await {
                if let ExecutorEvent::TokenDelta { delta, .. } = event {
                    text.push_str(&delta);
                }
            }
            text
        }

        let first = run(&executor, profile, &token, "r1").await;
        // Give the pool a beat to take the returned session.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let pooled = executor.pool.lock().await.is_some();
        let second = run(&executor, profile, &token, "r2").await;

        assert_eq!(first, "answer-0");
        assert_eq!(second, "answer-1");
        assert!(
            pooled,
            "the session returned to the pool after the clean terminal"
        );
        assert_eq!(served.served.load(Ordering::SeqCst), 2);
    }
}

#[cfg(test)]
mod measure_tests {
    use super::*;
    use crate::serving::serve_sessions;
    use futures_util::StreamExt;
    use modelswarm_gateway::{ExecutorError, ExecutorStream, NormalizedMessage, NormalizedRequest};
    use modelswarm_identity::InstallationIdentity;
    use modelswarm_transport::libp2p_backend::Libp2pTransport;
    use std::sync::Arc;
    use std::time::Duration;

    /// F15 end-to-end over REAL loopback QUIC against the real serving
    /// bridge (environment label: loopback-proven): a metrics-attached
    /// RemoteExecutor records the completion distribution
    /// (TTFT/ITL/total, advertised queue alongside the measured
    /// admission-to-first-token), the post-completion idle RTT probe
    /// lands via the serving side's transparent ping answering, and the
    /// pooled session returns to the pool afterwards (connection reuse
    /// preserved).
    #[tokio::test]
    async fn remote_executor_measures_completions_and_rtt_over_quic() {
        struct TwoTokenExecutor;
        #[async_trait::async_trait]
        impl modelswarm_gateway::InferenceExecutor for TwoTokenExecutor {
            async fn execute(
                &self,
                _request: NormalizedRequest,
            ) -> Result<ExecutorStream, ExecutorError> {
                Ok(Box::pin(futures_util::stream::iter(vec![
                    ExecutorEvent::TokenDelta {
                        delta: "a".into(),
                        index: 0,
                    },
                    ExecutorEvent::TokenDelta {
                        delta: "b".into(),
                        index: 1,
                    },
                    ExecutorEvent::Usage {
                        prompt_tokens: 3,
                        completion_tokens: 2,
                        prefill_ms: 1.0,
                        decode_ms: 2.0,
                    },
                    ExecutorEvent::Completed {
                        finish_reason: modelswarm_gateway::FinishReason::Stop,
                    },
                ])))
            }
        }

        let server_identity = InstallationIdentity::from_bytes(&[77u8; 32]);
        let client_identity = InstallationIdentity::from_bytes(&[78u8; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let listener = server.listen("127.0.0.1:0").await.unwrap();
        let server_peer = server.peer_id().to_string();
        let peer = RemotePeer {
            addr: listener.bound_addr().to_string(),
            peer_id: server_peer.clone(),
        };
        let client_peer_id = Libp2pTransport::new(&client_identity)
            .unwrap()
            .peer_id()
            .to_string();
        let profile_id = crate::serving::lease_helpers::TEST_PROFILE;
        let (policy, token) =
            crate::serving::lease_helpers::policy_and_lease(profile_id, &client_peer_id);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_sessions(
            listener,
            std::sync::Arc::new(crate::serving::lease_helpers::server_identity()),
            Arc::new(TwoTokenExecutor),
            profile_id.into(),
            policy,
            Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            rx,
        ));

        let metrics = Arc::new(PeerMetrics::memory(Arc::new(
            modelswarm_telemetry::Telemetry::memory().0,
        )));
        let executor =
            RemoteExecutor::new(peer, client_identity).with_metrics(Arc::clone(&metrics));
        executor.set_advertised_queue_ms(Some(120));

        let stream = executor
            .execute(NormalizedRequest {
                request_id: "req-f15".into(),
                profile_id: profile_id.into(),
                capability_token: Some(token),
                messages: vec![NormalizedMessage {
                    role: "user".into(),
                    content: "hi".into(),
                }],
                sampling: modelswarm_gateway::Sampling {
                    temperature: 0.0,
                    top_p: 1.0,
                    top_k: 40,
                    seed: None,
                },
                max_tokens: 8,
                deadline_ms: 10_000,
                stream: true,
            })
            .await
            .expect("execute starts");
        let mut text = String::new();
        futures_util::pin_mut!(stream);
        while let Some(event) = stream.next().await {
            if let ExecutorEvent::TokenDelta { delta, .. } = event {
                text.push_str(&delta);
            }
        }
        assert_eq!(text, "ab");

        // The completion distribution and the (asynchronous) RTT probe
        // both land; then the session is back in the pool.
        let wait_until = std::time::Instant::now() + Duration::from_secs(5);
        let obs = loop {
            let obs = metrics.observe(&server_peer);
            if obs.rtt_ewma_ms.is_some() {
                break obs;
            }
            assert!(
                std::time::Instant::now() < wait_until,
                "post-completion RTT probe did not land within 5 s"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };

        assert!(obs.rtt_ewma_ms.unwrap() > 0.0, "loopback rtt positive");
        assert!(obs.rtt_jitter_ewma_ms.unwrap() >= 0.0);
        assert_eq!(obs.rtt_probe_count, 1);
        assert_eq!(obs.failure_count, 0);

        let profile = obs.profile(profile_id).expect("completion recorded");
        assert!(profile.ttft_ewma_ms.unwrap() > 0.0, "measured ttft");
        assert!(profile.itl_mean_ewma_ms.unwrap() >= 0.0);
        assert!(profile.total_ewma_ms.unwrap() >= profile.ttft_ewma_ms.unwrap());
        assert_eq!(profile.advertised_queue_ms_last, Some(120));
        assert_eq!(profile.completion_count, 1);
        assert_eq!(profile.decode_tokens_per_ms_ewma, Some(1.0)); // 2 tokens / 2 ms
        assert_eq!(profile.prefill_tokens_per_ms_ewma, Some(3.0)); // 3 tokens / 1 ms

        // Connection reuse survives measurement: the probed session is
        // pooled again.
        let pooled = loop {
            if executor.pool.lock().await.is_some() {
                break true;
            }
            assert!(
                std::time::Instant::now() < wait_until,
                "session never returned to the pool after the probe"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert!(pooled);
    }

    /// F15: dial failures are counted (the shadow failure signal), and a
    /// metrics-free executor stays measurement-silent.
    #[tokio::test]
    async fn dial_failures_count_and_unmeasured_executors_stay_silent() {
        let metrics = Arc::new(PeerMetrics::memory(Arc::new(
            modelswarm_telemetry::Telemetry::memory().0,
        )));
        // A REAL PeerId derivation (the placeholder-style base58 string
        // fails PeerId::parse before any dial) with an unreachable
        // address: the dial itself must fail and be counted.
        let dead_peer_id = Libp2pTransport::new(&InstallationIdentity::from_bytes(&[81u8; 32]))
            .unwrap()
            .peer_id()
            .to_string();
        let dead_peer = RemotePeer {
            addr: "/ip4/127.0.0.1/udp/9/udt".into(), // nothing listens here
            peer_id: dead_peer_id,
        };
        let peer_id = dead_peer.peer_id.clone();
        let executor =
            RemoteExecutor::new(dead_peer, InstallationIdentity::from_bytes(&[79u8; 32]))
                .with_metrics(Arc::clone(&metrics));
        let request = NormalizedRequest {
            request_id: "req-dead".into(),
            profile_id: "msp1:dead".into(),
            capability_token: None,
            messages: vec![NormalizedMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
            sampling: modelswarm_gateway::Sampling {
                temperature: 0.0,
                top_p: 1.0,
                top_k: 40,
                seed: None,
            },
            max_tokens: 8,
            deadline_ms: 10_000,
            stream: true,
        };
        assert!(executor.execute(request).await.is_err());
        assert_eq!(metrics.observe(&peer_id).failure_count, 1);

        // Without metrics attached, nothing is recorded anywhere.
        let silent = Arc::new(PeerMetrics::memory(Arc::new(
            modelswarm_telemetry::Telemetry::memory().0,
        )));
        let silent_exec = RemoteExecutor::new(
            RemotePeer {
                addr: "/ip4/127.0.0.1/udp/9/udt".into(),
                peer_id: Libp2pTransport::new(&InstallationIdentity::from_bytes(&[82u8; 32]))
                    .unwrap()
                    .peer_id()
                    .to_string(),
            },
            InstallationIdentity::from_bytes(&[80u8; 32]),
        );
        let request = NormalizedRequest {
            request_id: "req-silent".into(),
            profile_id: "msp1:dead".into(),
            capability_token: None,
            messages: vec![NormalizedMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
            sampling: modelswarm_gateway::Sampling {
                temperature: 0.0,
                top_p: 1.0,
                top_k: 40,
                seed: None,
            },
            max_tokens: 8,
            deadline_ms: 10_000,
            stream: true,
        };
        assert!(silent_exec.execute(request).await.is_err());
        assert!(silent.observe_all().is_empty());
    }
}

#[cfg(test)]
mod shadow_tests {
    use super::*;
    use crate::serving::serve_sessions;
    use futures_util::StreamExt;
    use modelswarm_gateway::{
        ExecutorError, ExecutorStream, NormalizedMessage, NormalizedRequest, Sampling,
    };
    use modelswarm_identity::InstallationIdentity;
    use modelswarm_scheduler::shadow::{
        self, QueueDiscountPolicy, RosterFacts, ShadowCandidateInput,
    };
    use modelswarm_transport::libp2p_backend::Libp2pTransport;
    use std::sync::Arc;
    use std::time::Duration;

    /// Two tokens + a Usage frame (deterministic rates: prefill 3 tok/ms,
    /// decode 1 tok/ms), counting invocations so the test can prove the
    /// SHADOW never caused a dial.
    struct CountingTwoTokenExecutor {
        served: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl modelswarm_gateway::InferenceExecutor for CountingTwoTokenExecutor {
        async fn execute(
            &self,
            _request: NormalizedRequest,
        ) -> Result<ExecutorStream, ExecutorError> {
            self.served
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Box::pin(futures_util::stream::iter(vec![
                ExecutorEvent::TokenDelta {
                    delta: "a".into(),
                    index: 0,
                },
                ExecutorEvent::TokenDelta {
                    delta: "b".into(),
                    index: 1,
                },
                ExecutorEvent::Usage {
                    prompt_tokens: 3,
                    completion_tokens: 2,
                    prefill_ms: 1.0,
                    decode_ms: 2.0,
                },
                ExecutorEvent::Completed {
                    finish_reason: modelswarm_gateway::FinishReason::Stop,
                },
            ])))
        }
    }

    fn request(profile_id: &str, token: &str) -> NormalizedRequest {
        NormalizedRequest {
            request_id: "req-shadow".into(),
            profile_id: profile_id.into(),
            capability_token: Some(token.to_string()),
            messages: vec![NormalizedMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
            sampling: Sampling {
                temperature: 0.0,
                top_p: 1.0,
                top_k: 40,
                seed: None,
            },
            max_tokens: 8,
            deadline_ms: 10_000,
            stream: true,
        }
    }

    /// Shadow-planner wiring over the REAL serving bridge (F15 pattern;
    /// environment label: loopback-proven). Two serving peers come up in
    /// PRODUCTION roster order — `first` (never measured) then `fast`
    /// (measured via one real completion + the idle RTT probe). Production
    /// semantics pick first-found; the shadow planner must pick the
    /// measured-fast peer, record the divergence, and NEVER dial anything
    /// on its own behalf (`first`'s served counter must stay 0).
    #[tokio::test]
    async fn shadow_planner_diverges_from_first_found_over_quic() {
        // The PRODUCTION profile shape end-to-end: ADR-011 derived id
        // (valid for the lease gate; the shadow's profile-id adapter
        // carries it into the frozen selector).
        let profile_id = crate::serving::lease_helpers::TEST_PROFILE;

        let transport_first =
            Libp2pTransport::new(&InstallationIdentity::from_bytes(&[91u8; 32])).unwrap();
        let transport_fast =
            Libp2pTransport::new(&InstallationIdentity::from_bytes(&[92u8; 32])).unwrap();
        let listener_first = transport_first.listen("127.0.0.1:0").await.unwrap();
        let listener_fast = transport_fast.listen("127.0.0.1:0").await.unwrap();
        let first_peer = transport_first.peer_id().to_string();
        let fast_peer = transport_fast.peer_id().to_string();
        let first_addr = listener_first.bound_addr().to_string();
        let fast_addr = listener_fast.bound_addr().to_string();
        // The roster dialability filter (app.rs) matches on this suffix —
        // pin the contract the shadow inputs rely on.
        assert!(first_addr.ends_with("quic-v1"));
        assert!(fast_addr.ends_with("quic-v1"));

        let client_identity = InstallationIdentity::from_bytes(&[93u8; 32]);
        let client_peer_id = Libp2pTransport::new(&client_identity)
            .unwrap()
            .peer_id()
            .to_string();
        // One independent (policy, token) pair per serving side (the
        // first-found side is never dialed — its token goes unused).
        let (policy_first, _token_first) =
            crate::serving::lease_helpers::policy_and_lease(profile_id, &client_peer_id);
        let (policy_fast, token_fast) =
            crate::serving::lease_helpers::policy_and_lease(profile_id, &client_peer_id);
        let first_executor = Arc::new(CountingTwoTokenExecutor {
            served: std::sync::atomic::AtomicUsize::new(0),
        });
        let (_tx_a, rx_a) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_sessions(
            listener_first,
            std::sync::Arc::new(crate::serving::lease_helpers::server_identity()),
            first_executor.clone(),
            profile_id.into(),
            policy_first,
            Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            rx_a,
        ));
        let (_tx_b, rx_b) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_sessions(
            listener_fast,
            std::sync::Arc::new(crate::serving::lease_helpers::server_identity()),
            Arc::new(CountingTwoTokenExecutor {
                served: std::sync::atomic::AtomicUsize::new(0),
            }),
            profile_id.into(),
            policy_fast,
            Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            rx_b,
        ));

        // ONE real completion against the fast peer (production would
        // have picked FIRST here — roster order; we dial fast directly to
        // create the measurement asymmetry the shadow must detect).
        let metrics = Arc::new(PeerMetrics::memory(Arc::new(
            modelswarm_telemetry::Telemetry::memory().0,
        )));
        let executor = RemoteExecutor::new(
            RemotePeer {
                addr: fast_addr,
                peer_id: fast_peer.clone(),
            },
            client_identity,
        )
        .with_metrics(Arc::clone(&metrics));
        executor.set_advertised_queue_ms(Some(120));
        let stream = executor
            .execute(request(profile_id, &token_fast))
            .await
            .expect("execute starts");
        let mut text = String::new();
        futures_util::pin_mut!(stream);
        while let Some(event) = stream.next().await {
            if let ExecutorEvent::TokenDelta { delta, .. } = event {
                text.push_str(&delta);
            }
        }
        assert_eq!(text, "ab");

        // The F15 idle RTT probe lands after the clean completion.
        let wait_until = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if metrics.observe(&fast_peer).rtt_ewma_ms.is_some() {
                break;
            }
            assert!(
                std::time::Instant::now() < wait_until,
                "post-completion RTT probe did not land within 5 s"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Shadow inputs in production roster order: FIRST is first-found
        // and advertises no queue; FAST advertises 120 ms.
        let roster = |peer: &str, queue: u64| ShadowCandidateInput {
            roster: RosterFacts {
                peer_id: peer.to_string(),
                free_slots: 1,
                advertised_queue_ms: Some(queue),
                capacity_class: Some("gpu_mid".into()),
                has_direct_quic_addr: true,
            },
            observed: metrics.observe(peer),
        };
        let inputs = vec![roster(&first_peer, 0), roster(&fast_peer, 120)];
        let env = shadow::EnvPolicy {
            policy: QueueDiscountPolicy::DEFAULT,
            env_overrides: 0,
            warnings: Vec::new(),
        };
        let decision = shadow::shadow_decision(
            &inputs,
            &client_peer_id,
            profile_id,
            Some(&first_peer), // what first-found production picks
            2,
            8,
            &env,
        );

        // The divergence the shadow exists to surface.
        assert_eq!(decision.pick.as_deref(), Some(fast_peer.as_str()));
        assert_eq!(
            decision.production_pick.as_deref(),
            Some(first_peer.as_str())
        );
        assert_eq!(decision.agree, Some(false));
        assert_eq!(decision.candidate_count, 2);
        assert_eq!(decision.measured_count, 1);
        assert_eq!(decision.label, "shadow-no-action");

        // Ranking: the measured peer first with a finite, queue-charged
        // prediction; the cold peer last with NO prediction (not a fake
        // alphabetical one).
        assert_eq!(decision.ranked[0].peer_id, fast_peer);
        let predicted = decision.ranked[0].predicted_ms.expect("finite prediction");
        assert!(
            predicted > 120.0 && predicted < 400.0,
            "queue must be charged and loopback rates must keep it small: {predicted}"
        );
        // Discount record: advertised 120 dominates the small measured
        // estimate (advertised only ever penalizes), and the measured
        // estimate exists (measured dominates when it would be larger).
        assert!((decision.ranked[0].effective_queue_ms - 120.0).abs() < 1e-6);
        assert!(decision.ranked[0].measured_queue_estimate_ms.is_some());
        assert!(decision.ranked[0].measured);
        assert_eq!(decision.ranked[1].peer_id, first_peer);
        assert_eq!(decision.ranked[1].predicted_ms, None);
        assert!(!decision.ranked[1].measured);

        // The shadow NEVER acts: the first-found peer was never dialed by
        // the planner (only the explicit completion above moved bytes).
        assert_eq!(
            first_executor
                .served
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "shadow planning must not dial anyone"
        );
        // And the serialized record is telemetry-safe (finite numbers).
        let json = serde_json::to_string(&decision).expect("serializes");
        assert!(json.contains("\"predicted_ms\":null"));
        assert!(!json.contains("infinity") && !json.contains("NaN"));
    }
}

#[cfg(test)]
mod relay_fallback_tests {
    use super::*;
    use crate::serving::{serve_sessions_relayed, RelaySlot};
    use futures_util::StreamExt;
    use modelswarm_gateway::{ExecutorError, ExecutorStream, NormalizedRequest};
    use modelswarm_identity::InstallationIdentity;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// The relay binary's raised limits (crates/modelswarm-relay
    /// relay_config): stream-carrying — no duration/byte caps. This is
    /// the relay DOUBLE the transport crate's F2B suite uses: the exact
    /// rust-libp2p stack the modelswarm-relay binary hosts, in-process
    /// on an ephemeral loopback QUIC port.
    fn raised_relay_config() -> libp2p::relay::Config {
        libp2p::relay::Config {
            max_reservations: 4096,
            max_reservations_per_peer: 8,
            max_circuits: 4096,
            max_circuits_per_peer: 128,
            max_circuit_duration: Duration::from_secs(u32::MAX as u64),
            max_circuit_bytes: u64::MAX,
            ..libp2p::relay::Config::default()
        }
    }

    /// Spawns the relay double; returns its `/p2p/`-suffixed address and a
    /// live circuit counter.
    async fn spawn_relay_double(
        config: libp2p::relay::Config,
    ) -> (libp2p::Multiaddr, Arc<AtomicUsize>) {
        use libp2p::swarm::NetworkBehaviour;

        #[derive(NetworkBehaviour)]
        struct RelayOnly {
            relay: libp2p::relay::Behaviour,
        }

        let key = libp2p::identity::Keypair::generate_ed25519();
        let relay_peer_id = libp2p::PeerId::from(key.public());
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_quic()
            .with_behaviour(|key| RelayOnly {
                relay: libp2p::relay::Behaviour::new(key.public().to_peer_id(), config),
            })
            .expect("relay double behaviour builds")
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(300)))
            .build();
        swarm
            .behaviour_mut()
            .relay
            .set_status(Some(libp2p::relay::Status::Enable));
        swarm
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();

        let bound = loop {
            match swarm.select_next_some().await {
                libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => break address,
                _ => continue,
            }
        };
        swarm.add_external_address(bound.clone());
        let addr = bound.with(libp2p::multiaddr::Protocol::P2p(relay_peer_id));

        let circuits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&circuits);
        tokio::spawn(async move {
            loop {
                if let libp2p::swarm::SwarmEvent::Behaviour(RelayOnlyEvent::Relay(
                    libp2p::relay::Event::CircuitReqAccepted { .. },
                )) = swarm.select_next_some().await
                {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        (addr, circuits)
    }

    /// A BLACKHOLED direct candidate: a UDP socket is bound (so no sibling
    /// test can take the port) but never answers — the loopback stand-in
    /// for the owner's cross-NAT failure mode. The returned socket must
    /// stay alive for the blackhole to hold.
    fn blackholed_direct_addr() -> (String, std::net::UdpSocket) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        (format!("/ip4/127.0.0.1/udp/{port}/quic-v1"), socket)
    }

    struct TwoTokenExecutor;
    #[async_trait::async_trait]
    impl modelswarm_gateway::InferenceExecutor for TwoTokenExecutor {
        async fn execute(
            &self,
            _request: NormalizedRequest,
        ) -> Result<ExecutorStream, ExecutorError> {
            Ok(Box::pin(futures_util::stream::iter(vec![
                ExecutorEvent::TokenDelta {
                    delta: "a".into(),
                    index: 0,
                },
                ExecutorEvent::TokenDelta {
                    delta: "b".into(),
                    index: 1,
                },
                ExecutorEvent::Completed {
                    finish_reason: modelswarm_gateway::FinishReason::Stop,
                },
            ])))
        }
    }

    fn request(profile: &str, token: &str) -> NormalizedRequest {
        NormalizedRequest {
            request_id: format!("req-f2b-{}", modelswarm_identity::new_nonce()),
            profile_id: profile.into(),
            capability_token: Some(token.to_string()),
            messages: vec![modelswarm_gateway::NormalizedMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
            sampling: modelswarm_gateway::Sampling {
                temperature: 0.0,
                top_p: 1.0,
                top_k: 40,
                seed: None,
            },
            max_tokens: 8,
            deadline_ms: 60_000,
            stream: true,
        }
    }

    async fn collect(stream: ExecutorStream) -> String {
        let mut text = String::new();
        futures_util::pin_mut!(stream);
        while let Some(event) = stream.next().await {
            if let ExecutorEvent::TokenDelta { delta, .. } = event {
                text.push_str(&delta);
            }
        }
        text
    }

    /// F2B requester+serving proof (the owner's live blocker, simulated):
    /// the peer's PRIMARY advertised direct address is a cross-NAT
    /// blackhole; its advertised candidate list also carries the circuit
    /// address it reserved on the relay. The RemoteExecutor's direct phase
    /// burns its SHORT budget, the relay phase wins, the serving bridge
    /// (admitting the relayed circuit through the RelaySlot) serves, and
    /// the honesty surfaces are exact: the pooled path is labeled
    /// `Relayed`, the failed direct attempt is reported per-attempt
    /// (`net.failure`/stage=dial counted, kind=direct in the report) even
    /// though the dial SUCCEEDED via the relay.
    #[tokio::test]
    async fn direct_blackhole_falls_back_to_relay_through_the_serving_bridge() {
        let server_identity = InstallationIdentity::from_bytes(&[111u8; 32]);
        let client_identity = InstallationIdentity::from_bytes(&[112u8; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let server_peer = server.peer_id().to_string();

        let (relay_addr, circuits) = spawn_relay_double(raised_relay_config()).await;
        let reservation = server
            .reserve_relay(&relay_addr.to_string(), Duration::from_secs(10))
            .await
            .expect("serving peer reserves on the relay");
        let circuit = reservation.circuit_addr();

        // The serving bridge: direct listener (unused by this client) PLUS
        // the relay slot — the composed F2B serving shape.
        let listener = server.listen("127.0.0.1:0").await.unwrap();
        let slot = RelaySlot::empty();
        assert!(
            slot.circuit_addr().await.is_none(),
            "empty slot advertises nothing"
        );
        slot.install(reservation).await;
        assert_eq!(
            slot.circuit_addr().await.as_deref(),
            Some(circuit.as_str()),
            "the installed reservation's circuit addr is exposed"
        );
        assert!(slot.holds_live().await);

        let profile = crate::serving::lease_helpers::TEST_PROFILE;
        let client_peer_id = Libp2pTransport::new(&client_identity)
            .unwrap()
            .peer_id()
            .to_string();
        let (policy, token) =
            crate::serving::lease_helpers::policy_and_lease(profile, &client_peer_id);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_sessions_relayed(
            listener,
            slot,
            std::sync::Arc::new(crate::serving::lease_helpers::server_identity()),
            Arc::new(TwoTokenExecutor),
            profile.into(),
            policy,
            Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            rx,
        ));

        // The requester: blackhole primary + the peer's advertised circuit
        // candidate (exactly what the tracker `addresses` list carries).
        let (direct, _blackhole) = blackholed_direct_addr();
        let metrics = Arc::new(PeerMetrics::memory(Arc::new(
            modelswarm_telemetry::Telemetry::memory().0,
        )));
        let executor = RemoteExecutor::new(
            RemotePeer {
                addr: direct,
                peer_id: server_peer.clone(),
            },
            client_identity,
        )
        .with_metrics(Arc::clone(&metrics));
        executor.set_candidate_addrs(vec![circuit.clone()]);

        let text = collect(
            executor
                .execute(request(profile, &token))
                .await
                .expect("the direct blackhole must not kill the dial: the relay candidate serves"),
        )
        .await;
        assert_eq!(text, "ab");
        assert_eq!(
            circuits.load(Ordering::SeqCst),
            1,
            "exactly one relayed circuit served the request"
        );

        // Honesty surfaces.
        assert!(
            matches!(executor.pooled_dial_path(), Some(DialPath::Relayed { .. })),
            "the winning path must be labeled relayed: {:?}",
            executor.pooled_dial_path()
        );
        let attempts = executor.last_dial_attempts();
        assert_eq!(attempts.len(), 1, "one failed direct attempt, reported");
        assert_eq!(attempts[0].kind, "direct");
        assert_eq!(attempts[0].addr, executor_primary_blackhole(&executor));
        assert_eq!(
            metrics.observe(&server_peer).failure_count,
            1,
            "the failed direct attempt counts one net.failure/stage=dial row"
        );
    }

    /// The executor's primary address (test seam for the report shape).
    fn executor_primary_blackhole(executor: &RemoteExecutor) -> String {
        executor.peer.addr.clone()
    }

    /// F2B: a RELAY-ONLY peer (its sole advertised address is the circuit)
    /// is dialable — the circuit addr as the PRIMARY candidate works, no
    /// direct phase runs at all, and no per-attempt failure is recorded.
    #[tokio::test]
    async fn relay_only_peer_is_dialable_as_the_primary_candidate() {
        let server_identity = InstallationIdentity::from_bytes(&[113u8; 32]);
        let client_identity = InstallationIdentity::from_bytes(&[114u8; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let server_peer = server.peer_id().to_string();

        let (relay_addr, _circuits) = spawn_relay_double(raised_relay_config()).await;
        let reservation = server
            .reserve_relay(&relay_addr.to_string(), Duration::from_secs(10))
            .await
            .expect("reservation");
        let circuit = reservation.circuit_addr();

        let listener = server.listen("127.0.0.1:0").await.unwrap();
        let slot = RelaySlot::empty();
        slot.install(reservation).await;
        let profile = crate::serving::lease_helpers::TEST_PROFILE;
        let client_peer_id = Libp2pTransport::new(&client_identity)
            .unwrap()
            .peer_id()
            .to_string();
        let (policy, token) =
            crate::serving::lease_helpers::policy_and_lease(profile, &client_peer_id);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_sessions_relayed(
            listener,
            slot,
            std::sync::Arc::new(crate::serving::lease_helpers::server_identity()),
            Arc::new(TwoTokenExecutor),
            profile.into(),
            policy,
            Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            rx,
        ));

        let metrics = Arc::new(PeerMetrics::memory(Arc::new(
            modelswarm_telemetry::Telemetry::memory().0,
        )));
        let executor = RemoteExecutor::new(
            RemotePeer {
                addr: circuit,
                peer_id: server_peer.clone(),
            },
            client_identity,
        )
        .with_metrics(Arc::clone(&metrics));

        let text = collect(executor.execute(request(profile, &token)).await.expect(
            "a relay-only peer's circuit address must be dialable as the primary candidate",
        ))
        .await;
        assert_eq!(text, "ab");
        assert!(matches!(
            executor.pooled_dial_path(),
            Some(DialPath::Relayed { .. })
        ));
        assert!(
            executor.last_dial_attempts().is_empty(),
            "no direct phase ran: no attempts, no failures"
        );
        assert_eq!(metrics.observe(&server_peer).failure_count, 0);
    }

    /// The candidate-refresh seam: the primary address is deduplicated out
    /// of the additional candidates (one dial per address, advertised
    /// order otherwise preserved).
    #[test]
    fn candidate_addrs_dedup_the_primary() {
        let executor = RemoteExecutor::new(
            RemotePeer {
                addr: "/ip4/10.1.1.5/udp/4001/quic-v1".into(),
                peer_id: "peer".into(),
            },
            InstallationIdentity::from_bytes(&[115u8; 32]),
        );
        executor.set_candidate_addrs(vec![
            "/ip4/10.1.1.5/udp/4001/quic-v1".into(), // duplicate of primary
            "/ip4/10.2.2.6/udp/4002/quic-v1/p2p/relayx/p2p-circuit".into(),
        ]);
        let candidates = executor
            .candidate_addrs
            .lock()
            .expect("candidate addr lock")
            .clone();
        assert_eq!(
            candidates,
            vec!["/ip4/10.2.2.6/udp/4002/quic-v1/p2p/relayx/p2p-circuit".to_string()]
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serving::serve_sessions;
    use futures_util::StreamExt;
    use modelswarm_gateway::{ExecutorError, ExecutorStream, NormalizedRequest};
    use modelswarm_identity::InstallationIdentity;
    use modelswarm_transport::libp2p_backend::Libp2pTransport;
    use std::sync::Arc;

    /// F1 same-host proof: RemoteExecutor dials a serving peer over real
    /// QUIC and re-emits its frames as gateway executor events — the
    /// exact path a requesting gateway will drive.
    #[tokio::test]
    async fn remote_executor_streams_from_serving_peer() {
        struct FixedExecutor;
        #[async_trait::async_trait]
        impl modelswarm_gateway::InferenceExecutor for FixedExecutor {
            async fn execute(
                &self,
                _request: NormalizedRequest,
            ) -> Result<ExecutorStream, ExecutorError> {
                Ok(Box::pin(futures_util::stream::iter(vec![
                    modelswarm_gateway::ExecutorEvent::TokenDelta {
                        delta: "remote ".into(),
                        index: 0,
                    },
                    modelswarm_gateway::ExecutorEvent::TokenDelta {
                        delta: "answer".into(),
                        index: 1,
                    },
                    modelswarm_gateway::ExecutorEvent::Completed {
                        finish_reason: modelswarm_gateway::FinishReason::Stop,
                    },
                ])))
            }
        }

        let server_identity = InstallationIdentity::from_bytes(&[27u8; 32]);
        let client_identity = InstallationIdentity::from_bytes(&[28u8; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let listener = server.listen("127.0.0.1:0").await.unwrap();

        let peer = RemotePeer {
            addr: listener.bound_addr().to_string(),
            peer_id: server.peer_id().to_string(),
        };
        let client_peer_id = Libp2pTransport::new(&client_identity)
            .unwrap()
            .peer_id()
            .to_string();
        let (policy, token) = crate::serving::lease_helpers::policy_and_lease(
            crate::serving::lease_helpers::TEST_PROFILE,
            &client_peer_id,
        );
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_sessions(
            listener,
            std::sync::Arc::new(crate::serving::lease_helpers::server_identity()),
            Arc::new(FixedExecutor),
            crate::serving::lease_helpers::TEST_PROFILE.into(),
            policy,
            std::sync::Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            shutdown_rx,
        ));

        let executor = RemoteExecutor::new(peer, client_identity);
        let stream = executor
            .execute(NormalizedRequest {
                request_id: "req-f1".into(),
                profile_id: crate::serving::lease_helpers::TEST_PROFILE.into(),
                capability_token: Some(token),
                messages: vec![modelswarm_gateway::NormalizedMessage {
                    role: "user".into(),
                    content: "hi".into(),
                }],
                sampling: modelswarm_gateway::Sampling {
                    temperature: 0.0,
                    top_p: 1.0,
                    top_k: 40,
                    seed: None,
                },
                max_tokens: 8,
                deadline_ms: 10_000,
                stream: true,
            })
            .await
            .expect("remote execute starts");

        let mut text = String::new();
        let mut finish = String::new();
        futures_util::pin_mut!(stream);
        while let Some(event) = stream.next().await {
            match event {
                ExecutorEvent::TokenDelta { delta, .. } => text.push_str(&delta),
                ExecutorEvent::Completed { finish_reason } => {
                    finish = format!("{finish_reason:?}");
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }
        assert_eq!(text, "remote answer");
        assert_eq!(finish, "Stop");
    }
}

#[cfg(test)]
mod b3_receipt_roundtrip {
    // ADR-030 B3 (requester half) — the full receipt round-trip over a real
    // loopback QUIC session: the server's Completed carries the phase-1
    // receipt, the executor's stream tail counter-signs it with the
    // requester's identity, sends the best-effort `receipt_ack`, and stashes
    // the final object for the accounting POST. The serving loop must
    // SURVIVE the ack frame (a pooled follow-up request still completes —
    // the pre-B3 loop would have ended the session with `bad_frame`), and
    // the serving side's telemetry must show the ack landed.
    use super::*;
    use crate::serving::{lease_helpers, serve_sessions};
    use futures_util::stream;
    use futures_util::StreamExt;
    use modelswarm_gateway::{NormalizedMessage, NormalizedRequest, Sampling};
    use std::sync::Arc;
    use std::time::Duration;

    struct FixedExecutor;
    #[async_trait::async_trait]
    impl modelswarm_gateway::InferenceExecutor for FixedExecutor {
        async fn execute(
            &self,
            _request: NormalizedRequest,
        ) -> Result<ExecutorStream, ExecutorError> {
            Ok(Box::pin(stream::iter(vec![
                ExecutorEvent::Accepted {
                    queue_position: 0,
                    eta_ms: 0,
                },
                ExecutorEvent::TokenDelta {
                    delta: "hi".into(),
                    index: 0,
                },
                ExecutorEvent::Usage {
                    prompt_tokens: 1,
                    completion_tokens: 1,
                    prefill_ms: 1.0,
                    decode_ms: 1.0,
                },
                ExecutorEvent::Completed {
                    finish_reason: modelswarm_gateway::FinishReason::Stop,
                },
            ])))
        }
    }

    fn request(profile: &str, token: String, id: &str) -> NormalizedRequest {
        NormalizedRequest {
            request_id: id.into(),
            profile_id: profile.into(),
            capability_token: Some(token),
            messages: vec![NormalizedMessage {
                role: "user".into(),
                content: "hi".into(),
            }],
            sampling: Sampling {
                temperature: 0.0,
                top_p: 1.0,
                top_k: 40,
                seed: None,
            },
            max_tokens: 8,
            deadline_ms: 10_000,
            stream: true,
        }
    }

    #[tokio::test]
    async fn b3_receipt_counted_signed_acked_and_session_survives() {
        let server_identity = lease_helpers::server_identity();
        let client_identity = InstallationIdentity::from_bytes(&[0xB3; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let listener = server.listen("127.0.0.1:0").await.unwrap();
        let bound = listener.bound_addr().to_string();
        let server_peer = server.peer_id().to_string();
        let (policy, token) = lease_helpers::policy_and_lease_for(
            lease_helpers::TEST_PROFILE,
            &client_identity.peer_id(),
            &client_identity.installation_id(),
        );
        let (telemetry, sink) = modelswarm_telemetry::Telemetry::memory();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_sessions(
            listener,
            Arc::new(server_identity.clone()),
            Arc::new(FixedExecutor),
            lease_helpers::TEST_PROFILE.into(),
            policy,
            Arc::new(telemetry),
            shutdown_rx,
        ));

        let remote = RemoteExecutor::new(
            RemotePeer {
                addr: bound,
                peer_id: server_peer,
            },
            client_identity.clone(),
        );

        // Turn 1: completed remotely, receipt stashed + counter-signed.
        let mut events = remote
            .execute(request(
                lease_helpers::TEST_PROFILE,
                token.clone(),
                "b3-turn-1",
            ))
            .await
            .expect("first execute");
        let mut completed = false;
        while let Some(ev) = events.next().await {
            if matches!(ev, ExecutorEvent::Completed { .. }) {
                completed = true;
            }
        }
        assert!(completed, "turn 1 completed remotely");

        let wire = remote.take_last_receipt().expect("receipt stashed");
        assert!(!wire.server_signature.is_empty(), "phase-1 sig present");
        assert!(
            !wire.requester_signature.is_empty(),
            "phase-2 (requester) sig present"
        );
        assert!(
            remote.take_last_receipt().is_none(),
            "taking clears the slot"
        );
        assert_eq!(wire.request_id, "b3-turn-1");

        // The final digest reproduces through the spec layer, and BOTH
        // signatures verify against the signing identities' keys.
        let receipt = crate::receipt_wire::wire_to_receipt(&wire).expect("wire -> spec");
        let server_vk = ed25519_dalek::SigningKey::from_bytes(&[0xA7; 32]).verifying_key();
        let client_vk = ed25519_dalek::SigningKey::from_bytes(&[0xB3; 32]).verifying_key();
        receipt
            .verify_signatures(&server_vk, &client_vk)
            .expect("both signatures verify");
        let digest = crate::receipt_wire::final_digest(&wire).expect("final digest");
        assert_eq!(digest, receipt.receipt_digest().expect("spec digest"));

        // Turn 2 on the SAME pooled session: the receipt_ack frame must
        // not have ended the serving loop (pre-B3 that frame was a
        // `bad_frame` session end).
        let mut events = remote
            .execute(request(lease_helpers::TEST_PROFILE, token, "b3-turn-2"))
            .await
            .expect("second execute (pooled session survived the ack)");
        let mut completed2 = false;
        while let Some(ev) = events.next().await {
            if matches!(ev, ExecutorEvent::Completed { .. }) {
                completed2 = true;
            }
        }
        assert!(completed2, "turn 2 completed on the reused session");
        assert_eq!(
            remote
                .take_last_receipt()
                .expect("turn-2 receipt")
                .request_id,
            "b3-turn-2"
        );

        // The serving side saw the ack land (telemetry row; the serving
        // task is concurrent, so poll briefly).
        let saw_ack = {
            let sink = sink.clone();
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if sink
                        .snapshot()
                        .iter()
                        .any(|row| row.contains("\"event\":\"receipt.acked\""))
                    {
                        return true;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .unwrap_or(false)
        };
        assert!(saw_ack, "serving side logged receipt.acked");

        shutdown_tx.send(true).ok();
    }
}
