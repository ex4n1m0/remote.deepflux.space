//! F0(3) serving bridge: inbound framed sessions → local executor →
//! outbound token frames (Phase F0; see docs/reviews/phase-f-research).
//!
//! The listener hands us authenticated sessions (the QUIC handshake
//! verifies the remote's libp2p PeerId = the ADR-020 derivation). For
//! each session we read one `InferenceRequest`, check the hub-signed
//! lease gate (ADR-026, at session open and per request), clamp
//! requester-supplied limits (msp-v1 §6.4), drive the node's
//! [`InferenceExecutor`] (the same executor the local gateway uses —
//! ADR-025 ChatML templating applies), and stream
//! `TokenDelta`/`Usage`/`Completed` frames back.
//!
//! F2B (ADR-014, 2026-10-15): serving is no longer listener-only. A
//! [`RelayReservation`] on a configured relay (owned through the
//! replaceable [`RelaySlot`]) admits RELAYED circuits — requesters behind
//! NAT dial `<relay>/p2p-circuit/p2p/<us>` — into the SAME admission- and
//! lease-gated loop. [`ServingInbox`] fans the direct listener and the
//! relay slot into one bounded session channel so an accepted session is
//! never lost to select-cancellation.
//!
//! Privacy: peer-supplied frame payloads are never logged or echoed —
//! diagnostics carry variant names and stable codes only (AGENTS.md
//! rule 5). Admission control (session cap, per-peer cap, request-id
//! dedup) is prototype-grade hostile-peer resistance per
//! docs/threat-model.md §4.2.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use modelswarm_gateway::{
    ExecutorEvent, InferenceExecutor, NormalizedMessage, NormalizedRequest, DEADLINE_MS_MAX,
    DEADLINE_MS_MIN, DEFAULT_MAX_OUTPUT_TOKENS, MAX_PROMPT_BYTES,
};
use modelswarm_telemetry::Telemetry;
use modelswarm_transport::libp2p_backend::{Libp2pListener, Libp2pSession};
use modelswarm_transport::message::{
    Accepted, ChatMessage, Completed, StreamError, TokenDelta, Usage, WireMessage,
};
use modelswarm_transport::relay_client::RelayReservation;
use modelswarm_transport::TransportError;

const IO_DEADLINE: Duration = Duration::from_secs(30);
/// Serving-source poll cadence (the direct listener and the relay slot
/// both wake at this period when idle).
const SERVE_POLL: Duration = Duration::from_secs(1);

/// ADR-043 §1: the queue admission deadline (msp-v1 §6.4) — a session that
/// waits longer than this for a serving slot is refused `overloaded` with
/// reason `queue_deadline` instead of waiting forever.
const QUEUE_ADMISSION_DEADLINE: Duration = Duration::from_secs(10);
/// ADR-043 §1: bounded wait-queue capacity; a session arriving at a FULL
/// queue is refused immediately (today's `session_limit` behavior).
const FAIR_QUEUE_CAPACITY: usize = 16;
/// How long a freshly accepted connection may take to send its first
/// `InferenceRequest` before the pre-admission read gives up (the request
/// carries the lease token the fair queue needs, so the read happens
/// BEFORE a slot is taken — ADR-043 §2 design note).
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);

/// The serving side's relay reservation slot (F2B): a replaceable handle
/// a supervisor task owns and [`ServingInbox`] polls. Installing a new
/// reservation drops the previous one — its driver aborts, which the
/// relay reads as a released lease (honest cleanup, no leak).
#[derive(Clone)]
pub struct RelaySlot {
    inner: Arc<tokio::sync::Mutex<Option<RelayReservation>>>,
}

impl RelaySlot {
    /// No reservation held — direct-only serving (the pre-F2B behavior).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Installs `reservation`, replacing (and releasing) any previous one.
    pub async fn install(&self, reservation: RelayReservation) {
        *self.inner.lock().await = Some(reservation);
    }

    /// Whether a reservation is held AND believed live (honest: a
    /// relay-side drop is only observed on the next renewal or traffic —
    /// the transport's own liveness signal).
    pub async fn holds_live(&self) -> bool {
        self.inner
            .lock()
            .await
            .as_ref()
            .is_some_and(RelayReservation::alive)
    }

    /// The held reservation's advertised circuit address
    /// (`<relay>/p2p-circuit/p2p/<own peer id>`), `None` while none is
    /// held or the held one reads dead.
    pub async fn circuit_addr(&self) -> Option<String> {
        self.inner
            .lock()
            .await
            .as_ref()
            .filter(|reservation| reservation.alive())
            .map(RelayReservation::circuit_addr)
    }
}

/// ONE receiving end for ALL serving sources (F2B): the direct listener
/// and the relay slot each get a forwarder task; accepted sessions land
/// in one bounded channel. A session accepted by either source is
/// buffered and never dropped by select-cancellation (cancelling a raw
/// `accept` future mid-completion would kill the connection — the same
/// class of bug as the 2026-10-09 LAN pass-1 shutdown race).
pub struct ServingInbox {
    rx: tokio::sync::mpsc::Receiver<Libp2pSession>,
}

impl ServingInbox {
    /// Fans `listener` and `relay` into one inbox. Both forwarder tasks
    /// stop when the inbox (its receiver) is dropped.
    #[must_use]
    pub fn new(mut listener: Libp2pListener, relay: RelaySlot) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel::<Libp2pSession>(16);
        // Direct-listener forwarder: owns the listener end-to-end.
        let listener_tx = tx.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept(SERVE_POLL).await {
                    Ok(session) => {
                        if listener_tx.send(session).await.is_err() {
                            break; // inbox dropped: stop serving
                        }
                    }
                    Err(TransportError::Closed) => break,
                    Err(_) => {}
                }
            }
        });
        // Relay forwarder: polls the (replaceable) reservation slot. A
        // dead reservation reads `Closed` — sleep and re-poll (the
        // supervisor replaces it); never spin.
        let relay_tx = tx.clone();
        tokio::spawn(async move {
            loop {
                let session = {
                    let mut guard = relay.inner.lock().await;
                    match guard.as_mut() {
                        Some(reservation) => reservation.accept(SERVE_POLL).await.ok(),
                        None => None,
                    }
                }; // lock released before any channel backpressure
                match session {
                    Some(session) => {
                        if relay_tx.send(session).await.is_err() {
                            break; // inbox dropped: stop serving
                        }
                    }
                    None => tokio::time::sleep(SERVE_POLL).await,
                }
            }
        });
        Self { rx }
    }

    /// Accepts the next session from any source. Same contract as
    /// [`Libp2pListener::accept`]: deadline expiry is a poll timeout
    /// (`Err(Timeout)`), a dead inbox is `Err(Closed)`.
    pub async fn recv(&mut self, deadline: Duration) -> Result<Libp2pSession, TransportError> {
        match tokio::time::timeout(deadline, self.rx.recv()).await {
            Ok(Some(session)) => Ok(session),
            Ok(None) => Err(TransportError::Closed),
            Err(_) => Err(TransportError::Timeout),
        }
    }
}

/// Serves accepted sessions until `shutdown` flips to true OR its watch
/// sender is dropped (no owner left to signal stop ⇒ stop serving). Callers
/// that want serving to continue MUST hold the sender for the bridge's
/// lifetime. Never panics on a bad session: malformed input becomes a
/// `StreamError` frame, then the session closes.
pub async fn serve_sessions(
    listener: Libp2pListener,
    identity: std::sync::Arc<modelswarm_identity::InstallationIdentity>,
    executor: Arc<dyn InferenceExecutor>,
    profile_id: String,
    lease_policy: LeasePolicy,
    telemetry: Arc<Telemetry>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    serve_sessions_relayed(
        listener,
        RelaySlot::empty(),
        identity,
        executor,
        profile_id,
        lease_policy,
        telemetry,
        shutdown,
    )
    .await
}

/// F2B (ADR-014): the serving bridge with a relay reservation slot —
/// sessions from the DIRECT listener and from RELAYED circuits (peers
/// behind NAT that reserved nothing themselves but dial us through the
/// relay we reserved on) land in the same admission- and lease-gated
/// loop. Identical to [`serve_sessions`] when the slot is empty.
#[allow(clippy::too_many_arguments)]
pub async fn serve_sessions_relayed(
    listener: Libp2pListener,
    relay: RelaySlot,
    identity: std::sync::Arc<modelswarm_identity::InstallationIdentity>,
    executor: Arc<dyn InferenceExecutor>,
    profile_id: String,
    lease_policy: LeasePolicy,
    telemetry: Arc<Telemetry>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    serve_inbox(
        ServingInbox::new(listener, relay),
        identity,
        executor,
        profile_id,
        lease_policy,
        telemetry,
        shutdown,
    )
    .await
}

/// The F0(3)/F2B serving loop over a [`ServingInbox`].
async fn serve_inbox(
    mut inbox: ServingInbox,
    identity: std::sync::Arc<modelswarm_identity::InstallationIdentity>,
    executor: Arc<dyn InferenceExecutor>,
    profile_id: String,
    lease_policy: LeasePolicy,
    telemetry: Arc<Telemetry>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let admission = Admission::defaults();
    loop {
        let session = tokio::select! {
            // watch::changed() fires immediately for the unseen INITIAL
            // value — only an actual true flip stops serving. A CLOSED
            // channel (every Sender dropped) must ALSO stop serving: a
            // closed channel makes changed() permanently Ready, and a
            // permanently-ready branch cancels the in-flight `accept` on
            // (nearly) every poll — dropping the listener's mid-handshake
            // QUIC upgrade, which quinn then application-closes as
            // transport error 0xC while the connection is unconfirmed.
            // The dialer sees exactly "aborted by peer: the application
            // or application protocol caused the connection to be closed
            // during the handshake" (the 2026-10-09 LAN pass-1 bug). With
            // no Sender left, nobody can ever signal stop, so stop now,
            // visibly, instead of silently killing every fresh connection.
            changed = shutdown.changed() => match changed {
                Err(_) => {
                    telemetry.warn(
                        "serving.stopped",
                        &[("reason", "shutdown_sender_dropped")],
                    );
                    return;
                }
                Ok(()) => {
                    if *shutdown.borrow() {
                        return;
                    }
                    continue;
                }
            },
            accepted = inbox.recv(Duration::from_secs(1)) => match accepted {
                Ok(s) => s,
                Err(_) => continue, // timeout/accept miss: keep serving
            },
        };
        let peer_id = session.remote_peer_id().to_string();
        let executor = Arc::clone(&executor);
        let profile = profile_id.clone();
        let policy = lease_policy.clone();
        let session_admission = admission.clone();
        let session_telemetry = Arc::clone(&telemetry);
        let session_identity = Arc::clone(&identity);
        tokio::spawn(async move {
            let identity = session_identity;
            let mut session = session;
            // ADR-043 §2: the queue weight lives INSIDE the lease token
            // carried by the first InferenceRequest, so the first frame is
            // read BEFORE a serving slot is taken; only then does the
            // session admit (immediately, or via the bounded WFQ wait
            // queue). A non-request first frame (defensive) takes the base
            // weight — the full LeasePolicy check inside serve_one_seeded
            // is unchanged.
            let first = match session.recv(FIRST_FRAME_TIMEOUT).await {
                Ok(frame) => frame,
                Err(_) => {
                    session_telemetry.warn("serving.first_frame_timeout", &[("peer", &peer_id)]);
                    return;
                }
            };
            let queue_weight = match &first {
                WireMessage::InferenceRequest(r) => {
                    modelswarm_eligibility::EligibilityLease::from_wire(&r.capability_token)
                        .map(|lease| lease.queue_weight)
                        .unwrap_or(1)
                }
                _ => 1,
            };
            let (guard, waited_at) = match session_admission
                .admit_session_fair(&peer_id, queue_weight, QUEUE_ADMISSION_DEADLINE)
                .await
            {
                Ok(v) => v,
                Err(reason) => {
                    session_telemetry
                        .warn("serving.refused", &[("peer", &peer_id), ("reason", reason)]);
                    let mut session = session;
                    send_error(&mut session, "overloaded", reason).await;
                    return;
                }
            };
            let _session_slot = guard;
            // ADR-043 §3: the §6.3 `accepted` emission, un-deferred from
            // ADR-028 — ONLY for sessions that actually waited, so the
            // frame sequence of an uncontended stream is unchanged (old
            // peers never see the new variant in normal operation).
            if let (Some(position), WireMessage::InferenceRequest(r)) = (waited_at, &first) {
                let accepted = WireMessage::Accepted(Accepted {
                    request_id: r.request_id.clone(),
                    queue_position: position,
                    eta_ms: 0,
                });
                let mut session = session;
                let _ = session.send(&accepted, IO_DEADLINE).await;
                session_telemetry.info(
                    "serving.accepted_after_wait",
                    &[("peer", &peer_id), ("weight", &queue_weight.to_string())],
                );
                if let Err(code) = serve_one_seeded(
                    session,
                    identity,
                    executor,
                    profile,
                    &policy,
                    &session_admission,
                    &session_telemetry,
                    Some(first),
                )
                .await
                {
                    session_telemetry.warn("serving.session_ended", &[("code", code.as_str())]);
                }
                return;
            }
            if let Err(code) = serve_one_seeded(
                session,
                identity,
                executor,
                profile,
                &policy,
                &session_admission,
                &session_telemetry,
                Some(first),
            )
            .await
            {
                // `code` is a stable reason code by construction — never
                // peer-supplied payload text.
                session_telemetry.warn("serving.session_ended", &[("code", code.as_str())]);
            }
        });
    }
}

/// Wire-request limits (msp-v1 §6.4): the serving peer clamps
/// requester-supplied values exactly like the local gateway does, so a
/// lease-holder cannot pin the engine with a 49-day deadline or an
/// unbounded token budget. Returns `(deadline_ms, max_tokens)` and a
/// rejection code when the prompt itself exceeds the byte cap.
pub(crate) fn clamp_wire_request(
    deadline_ms: u32,
    max_tokens: u32,
    prompt_bytes: usize,
) -> Result<(u32, u32), &'static str> {
    if prompt_bytes > MAX_PROMPT_BYTES {
        return Err("payload_too_large");
    }
    let deadline_ms = deadline_ms.clamp(DEADLINE_MS_MIN, DEADLINE_MS_MAX);
    let max_tokens = max_tokens.clamp(1, DEFAULT_MAX_OUTPUT_TOKENS);
    Ok((deadline_ms, max_tokens))
}

/// Variant name only — peer-supplied payloads must never reach logs or
/// error echoes (privacy rule 5; a hostile peer writes arbitrary text
/// into Debug output otherwise).
fn wire_kind(m: &WireMessage) -> &'static str {
    match m {
        WireMessage::Handshake(_) => "Handshake",
        WireMessage::HandshakeAck(_) => "HandshakeAck",
        WireMessage::InferenceRequest(_) => "InferenceRequest",
        WireMessage::TokenDelta(_) => "TokenDelta",
        WireMessage::Usage(_) => "Usage",
        WireMessage::StreamError(_) => "StreamError",
        WireMessage::ReceiptAck(_) => "ReceiptAck",
        WireMessage::Accepted(_) => "Accepted",
        WireMessage::Cancelled(_) => "Cancelled",
        WireMessage::Completed(_) => "Completed",
        WireMessage::Cancel(_) => "Cancel",
        WireMessage::Control(_) => "Control",
    }
}

/// Executor error → stable code for the wire and logs (no payload text).
fn executor_error_code(e: &modelswarm_gateway::ExecutorError) -> String {
    use modelswarm_gateway::ExecutorError;
    match e {
        ExecutorError::NoPeer => "no_peer".into(),
        ExecutorError::Retryable { .. } => "executor_retryable".into(),
        ExecutorError::Fatal { code } => code.clone(),
    }
}

/// Serving admission control: bounded concurrent sessions, a per-peer
/// session cap, and a bounded request-id dedup window (threat model
/// §4.2: a captured request frame must not replay into fresh inference
/// for the lease's lifetime).
#[derive(Clone)]
pub struct Admission {
    inner: Arc<std::sync::Mutex<AdmissionState>>,
    max_sessions: usize,
    max_sessions_per_peer: usize,
}

struct AdmissionState {
    sessions: usize,
    per_peer: HashMap<String, usize>,
    seen_requests: HashMap<(String, String), Instant>,
    /// ADR-043: WFQ service state — the per-peer virtual finish advances
    /// by `1 / weight` per admission (so under sustained demand a
    /// weight-4 peer is served ~4× as often), and `virtual_clock` (the
    /// last admitted finish) levels newcomers so an idle returner never
    /// jumps a fresh queue nor is penalized for old history.
    virtual_finish: HashMap<String, f64>,
    virtual_clock: f64,
    /// ADR-043: the bounded wait queue, FIFO-ordered on arrival. WFQ
    /// chooses WHICH waiter a freed slot goes to, not the arrival order.
    waiters: VecDeque<Waiter>,
}

/// One session waiting for a serving slot (ADR-043). `wake` is this
/// waiter's private notifier — the release path wakes exactly the WFQ
/// winner, never the herd.
struct Waiter {
    /// WFQ virtual finish time (monotonic, per-peer advance).
    finish: f64,
    wake: Arc<tokio::sync::Notify>,
}

/// RAII session slot — releasing on drop keeps the count correct on every
/// exit path (panic, error return, client vanish).
pub struct SessionGuard {
    admission: Admission,
    peer_id: String,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.admission.release_session(&self.peer_id);
    }
}

impl Admission {
    /// Defaults sized for the prototype swarm: 8 concurrent sessions
    /// total, 2 per peer.
    pub fn defaults() -> Self {
        Self::new(8, 2)
    }

    pub fn new(max_sessions: usize, max_sessions_per_peer: usize) -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(AdmissionState {
                sessions: 0,
                per_peer: HashMap::new(),
                seen_requests: HashMap::new(),
                virtual_finish: HashMap::new(),
                virtual_clock: 0.0,
                waiters: VecDeque::new(),
            })),
            max_sessions,
            max_sessions_per_peer,
        }
    }

    pub fn admit_session(&self, peer_id: &str) -> Result<SessionGuard, &'static str> {
        let mut state = self.inner.lock().expect("admission lock");
        // ADR-043: a non-empty wait queue blocks side-door admission — a
        // fresh session must take its place in line (admit_session_fair),
        // otherwise newcomers would starve every queued waiter.
        if !state.waiters.is_empty() {
            return Err("session_limit");
        }
        if state.sessions >= self.max_sessions {
            return Err("session_limit");
        }
        if state.per_peer.get(peer_id).copied().unwrap_or(0) >= self.max_sessions_per_peer {
            return Err("per_peer_session_limit");
        }
        state.sessions += 1;
        *state.per_peer.entry(peer_id.to_string()).or_insert(0) += 1;
        Ok(SessionGuard {
            admission: self.clone(),
            peer_id: peer_id.to_string(),
        })
    }

    /// ADR-043 §2: admit, or wait in the bounded DRR fair queue until a
    /// slot frees or `deadline` elapses. `weight` is the session's
    /// hub-signed queue weight (1 / 2 / 4; the unverified token parse
    /// defaults to base 1 — the full `LeasePolicy` check still runs after
    /// admission, exactly as before).
    ///
    /// Returns the slot guard plus the position the request held when
    /// scheduled (`Some` only when it actually waited — the caller emits
    /// the §6.3 `accepted` frame for waited sessions only, keeping the
    /// uncontended frame sequence unchanged).
    pub async fn admit_session_fair(
        &self,
        peer_id: &str,
        weight: u8,
        deadline: Duration,
    ) -> Result<(SessionGuard, Option<u32>), &'static str> {
        let mut queued_ahead: Option<u32> = None;
        let mut my_wake: Option<Arc<tokio::sync::Notify>> = None;
        let deadline_at = Instant::now() + deadline;
        loop {
            {
                let mut state = self.inner.lock().expect("admission lock");
                if state.per_peer.get(peer_id).copied().unwrap_or(0) >= self.max_sessions_per_peer {
                    return Err("per_peer_session_limit");
                }
                if state.sessions < self.max_sessions && state.waiters.is_empty() {
                    // Fast path: nobody waiting, slot free.
                    state.sessions += 1;
                    *state.per_peer.entry(peer_id.to_string()).or_insert(0) += 1;
                    return Ok((
                        SessionGuard {
                            admission: self.clone(),
                            peer_id: peer_id.to_string(),
                        },
                        queued_ahead,
                    ));
                }
                if state.waiters.len() >= FAIR_QUEUE_CAPACITY {
                    return Err("session_limit");
                }
                match &mut my_wake {
                    None => {
                        // First contended pass: enqueue (WFQ-stamped).
                        let (position, waiter) = enqueue_waiter(&mut state, peer_id, weight);
                        queued_ahead = Some(position);
                        my_wake = Some(Arc::clone(&waiter.wake));
                        state.waiters.push_back(waiter);
                    }
                    Some(current) => {
                        // Re-check after a wake or deadline retry: if we are
                        // no longer queued, the release path already chose
                        // us (it removes the winner BEFORE notifying); take
                        // the slot it reserved.
                        if !state.waiters.iter().any(|w| Arc::ptr_eq(&w.wake, current)) {
                            if state.sessions < self.max_sessions {
                                state.sessions += 1;
                                *state.per_peer.entry(peer_id.to_string()).or_insert(0) += 1;
                                return Ok((
                                    SessionGuard {
                                        admission: self.clone(),
                                        peer_id: peer_id.to_string(),
                                    },
                                    queued_ahead,
                                ));
                            }
                            // Slot vanished anyway (a stale wake lost the
                            // race): re-enqueue at the back with a fresh
                            // handle so the release path can target us.
                            let (position, waiter) = enqueue_waiter(&mut state, peer_id, weight);
                            queued_ahead = Some(position);
                            my_wake = Some(Arc::clone(&waiter.wake));
                            state.waiters.push_back(waiter);
                        }
                    }
                }
            }
            let wake = my_wake.as_ref().expect("enqueued");
            let remaining = deadline_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                // Deadline: leave the queue honestly before refusing.
                let mut state = self.inner.lock().expect("admission lock");
                if let Some(idx) = state
                    .waiters
                    .iter()
                    .position(|w| Arc::ptr_eq(&w.wake, wake))
                {
                    state.waiters.remove(idx);
                }
                return Err("queue_deadline");
            }
            let notified = wake.notified();
            tokio::select! {
                _ = notified => continue,
                _ = tokio::time::sleep(remaining) => continue,
            }
        }
    }

    fn release_session(&self, peer_id: &str) {
        let winner_wake = {
            let mut state = self.inner.lock().expect("admission lock");
            state.sessions = state.sessions.saturating_sub(1);
            if let Some(count) = state.per_peer.get_mut(peer_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.per_peer.remove(peer_id);
                }
            }
            // ADR-043 §2: a freed slot goes to the DRR winner, not the
            // next arrival. The winner is REMOVED from the queue before it
            // is notified (its post-wake recheck takes the slot); its
            // deficit resets so a heavyweight cannot monopolize forever.
            if state.sessions < self.max_sessions {
                pick_fair_winner(&mut state).map(|w| w.wake)
            } else {
                None
            }
        };
        if let Some(wake) = winner_wake {
            wake.notify_one();
        }
    }

    /// `true` when `(peer, request_id)` is fresh; `false` = duplicate
    /// within the replay window (reject as a replay).
    pub fn check_request_fresh(&self, peer_id: &str, request_id: &str) -> bool {
        const WINDOW: Duration = Duration::from_secs(600);
        const HARD_CAP: usize = 8192;
        let mut state = self.inner.lock().expect("admission lock");
        if state.seen_requests.len() > HARD_CAP {
            state.seen_requests.retain(|_, at| at.elapsed() < WINDOW);
        }
        let key = (peer_id.to_string(), request_id.to_string());
        let now = Instant::now();
        match state.seen_requests.get(&key) {
            Some(at) if at.elapsed() < WINDOW => false,
            Some(_) | None => {
                state.seen_requests.insert(key, now);
                true
            }
        }
    }
}

/// ADR-043 §2 pick step (WFQ): the freed slot goes to the waiter with the
/// SMALLEST virtual finish time (FIFO among exact ties — arrival order in
/// the VecDeque). Finish times are stamped at enqueue (`enqueue_waiter`)
/// and advance per-peer by `1 / weight` per admission, so a weight-4
/// contributor beats a simultaneously-waiting weight-1 peer (0.25 steps
/// vs 1.0), under sustained demand is served ~4× as often, and a lone
/// lightweight is still admitted the moment it is the only waiter —
/// contributor-priority, never starvation. Per-peer history is capped so
/// the map cannot grow unbounded.
fn pick_fair_winner(state: &mut AdmissionState) -> Option<Waiter> {
    let mut best: Option<usize> = None;
    for (idx, w) in state.waiters.iter().enumerate() {
        let finish = best
            .and_then(|b| state.waiters.get(b))
            .map(|bw| bw.finish)
            .unwrap_or(f64::INFINITY);
        if w.finish < finish {
            best = Some(idx);
        }
    }
    let winner = best.and_then(|idx| state.waiters.remove(idx));
    if let Some(w) = &winner {
        state.virtual_clock = state.virtual_clock.max(w.finish);
    }
    if state.virtual_finish.len() > 4096 {
        // Prototype-scale safety valve: service history is best-effort.
        state.virtual_finish.clear();
    }
    winner
}

/// ADR-043 §2 stamp step: the waiter's WFQ virtual finish = max(the
/// peer's previous finish, the virtual clock) + `1 / weight`. Weight 1
/// advances a full step per admission; weight 4 a quarter step — exactly
/// the 4:1 service ratio the hub-signed `queue_weight` encodes.
fn enqueue_waiter(state: &mut AdmissionState, peer_id: &str, weight: u8) -> (u32, Waiter) {
    let position = state.waiters.len() as u32;
    let base = state
        .virtual_finish
        .get(peer_id)
        .copied()
        .unwrap_or(0.0)
        .max(state.virtual_clock);
    let finish = base + 1.0 / f64::from(weight.max(1));
    state.virtual_finish.insert(peer_id.to_string(), finish);
    let wake = Arc::new(tokio::sync::Notify::new());
    (position, Waiter { finish, wake })
}

/// The msp-v1 per-session loop, optionally seeded with an already-read
/// first frame: the composed demux (`verifydrafts::composed`) classifies a
/// session by its FIRST frame and hands it here pre-read, and the
/// ADR-043 fair-queue path pre-reads the first frame to extract the
/// lease-carried queue weight BEFORE admission — so the frame is never
/// decoded twice. `None` (no pre-read) reads the first frame below.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_one_seeded(
    mut session: Libp2pSession,
    identity: std::sync::Arc<modelswarm_identity::InstallationIdentity>,
    executor: Arc<dyn InferenceExecutor>,
    profile_id: String,
    lease_policy: &LeasePolicy,
    admission: &Admission,
    telemetry: &Telemetry,
    first: Option<WireMessage>,
) -> Result<(), String> {
    let peer_id = session.remote_peer_id().to_string();
    // One QUIC session, many sequential requests (connection reuse): the
    // loop waits for the next request until the client closes. The
    // between-requests wait is generous (chat gaps); a recv error ends the
    // session and the client re-dials self-healingly.
    const BETWEEN_REQUESTS: Duration = Duration::from_secs(300);
    let mut seeded = first;
    // ADR-030 B3: the request this session last served — the receipt_ack
    // arm below matches against it (a stale/mismatched ack is ignored).
    let mut last_request_id: Option<String> = None;
    loop {
        let frame = match seeded.take() {
            Some(frame) => frame,
            None => match session.recv(BETWEEN_REQUESTS).await {
                Ok(msg) => msg,
                Err(e) => {
                    // Transport errors are our own diagnostics text; the peer
                    // sees the code, the log keeps the detail short.
                    send_error(&mut session, "bad_frame", "frame receive failed").await;
                    linger(&mut session).await;
                    return Err(format!("recv: {e}"));
                }
            },
        };
        let request = match frame {
            // ADR-030 B3 / msp-v1 §6 `receipt_ack`: the requester's
            // best-effort confirmation it received + counter-signed the
            // receipt this session's last completion carried. Never a
            // session error, never new state — a matching id is visible
            // in telemetry, anything else is swallowed (the accounting
            // POST to the tracker is the durable act, not this frame).
            WireMessage::ReceiptAck(ack) => {
                if Some(ack.request_id.as_str()) == last_request_id.as_deref() {
                    telemetry.info(
                        "receipt.acked",
                        &[
                            ("peer", peer_id.as_str()),
                            ("request", ack.request_id.as_str()),
                        ],
                    );
                }
                continue;
            }
            WireMessage::InferenceRequest(r) => r,
            other => {
                // Variant name only — the payload is peer-controlled text.
                let code = format!("expected InferenceRequest, got {}", wire_kind(&other));
                send_error(
                    &mut session,
                    "bad_frame",
                    "expected an InferenceRequest frame",
                )
                .await;
                linger(&mut session).await;
                return Err(code);
            }
        };
        last_request_id = Some(request.request_id.clone());
        if request.profile_id != profile_id {
            send_error(
                &mut session,
                "profile_mismatch",
                "this node serves another profile",
            )
            .await;
            linger(&mut session).await;
            return Err("profile_mismatch".into());
        }

        // Replay protection: a repeated (peer, request_id) is rejected —
        // each replay would otherwise re-execute inference on the lease.
        if !admission.check_request_fresh(&peer_id, &request.request_id) {
            send_error(
                &mut session,
                "replayed_request",
                "request id already served",
            )
            .await;
            linger(&mut session).await;
            return Err("replayed_request".into());
        }

        // ADR-030 B2: the request's wall-clock start (receipt
        // started_at/endpoint_seconds) + the requester's installation
        // from the lease this gate is about to validate.
        let request_started = time::OffsetDateTime::now_utc();
        let requester_installation =
            modelswarm_eligibility::EligibilityLease::from_wire(&request.capability_token)
                .map(|lease| lease.installation_id)
                .unwrap_or_default();
        // F3: the hub-signed lease gate. The remote's PeerId comes from the
        // QUIC handshake, so a lease issued to anyone else is worthless here.
        if let Err(why) = lease_policy.check(
            &request.capability_token,
            &profile_id,
            &session.remote_peer_id().to_string(),
        ) {
            send_error(&mut session, "invalid_lease", "lease check failed").await;
            linger(&mut session).await;
            return Err(format!("invalid_lease: {why}"));
        }

        // §6.4 clamps — wire values are attacker-controlled even with a
        // valid lease; the local gateway applies the same table.
        let prompt_bytes: usize = request.messages.iter().map(|m| m.content.len()).sum();
        let (deadline_ms, max_tokens) =
            match clamp_wire_request(request.deadline_ms, request.max_tokens, prompt_bytes) {
                Ok(v) => v,
                Err(code) => {
                    send_error(&mut session, code, "prompt exceeds the byte cap").await;
                    linger(&mut session).await;
                    return Err(code.into());
                }
            };
        if deadline_ms != request.deadline_ms || max_tokens != request.max_tokens {
            telemetry.info(
                "serving.clamped",
                &[
                    ("peer", peer_id.as_str()),
                    (
                        "deadline_ms",
                        &format!("{}->{}", request.deadline_ms, deadline_ms),
                    ),
                    (
                        "max_tokens",
                        &format!("{}->{}", request.max_tokens, max_tokens),
                    ),
                ],
            );
        }

        let normalized = NormalizedRequest {
            request_id: request.request_id.clone(),
            profile_id: request.profile_id.clone(),
            capability_token: Some(request.capability_token.clone()),
            messages: request
                .messages
                .into_iter()
                .map(|m: ChatMessage| NormalizedMessage {
                    role: m.role,
                    content: m.content,
                })
                .collect(),
            sampling: modelswarm_gateway::Sampling {
                temperature: request.sampling.temperature as f32,
                top_p: request.sampling.top_p as f32,
                top_k: request.sampling.top_k,
                seed: request.sampling.seed,
            },
            max_tokens,
            deadline_ms,
            stream: true,
        };

        // ADR-039 (telemetry gap fix): remember the last Usage counts of
        // THIS request so `Completed` can log a counts-only
        // `serving.completed` — a cleanly-served swarm turn previously
        // left NO trace on the serving peer (only errored sessions
        // logged; the F2B record note). Counts only, never content.
        let mut last_usage: Option<(u32, u32, u32, u32)> = None;
        let mut events = match executor.execute(normalized).await {
            Ok(stream) => stream,
            Err(e) => {
                let code = executor_error_code(&e);
                send_error(&mut session, "executor_error", &code).await;
                linger(&mut session).await;
                return Err(format!("executor_error: {code}"));
            }
        };
        while let Some(event) = events.next().await {
            let frame = match event {
                ExecutorEvent::Accepted { .. } => continue,
                ExecutorEvent::TokenDelta { delta, index } => WireMessage::TokenDelta(TokenDelta {
                    request_id: request.request_id.clone(),
                    delta,
                    index,
                }),
                ExecutorEvent::Usage {
                    prompt_tokens,
                    completion_tokens,
                    prefill_ms,
                    decode_ms,
                } => {
                    last_usage = Some((
                        prompt_tokens,
                        completion_tokens,
                        prefill_ms as u32,
                        decode_ms as u32,
                    ));
                    WireMessage::Usage(Usage {
                        prompt_tokens,
                        completion_tokens,
                        prefill_ms: prefill_ms as u32,
                        decode_ms: decode_ms as u32,
                    })
                }
                ExecutorEvent::Completed { finish_reason } => {
                    let finish_reason_str = format!("{finish_reason:?}").to_lowercase();
                    // The clean-completion trace (ADR-039): counts only —
                    // peer id and token/timing counters, never content.
                    let (completion_tokens, prefill_ms, decode_ms) = match last_usage {
                        Some((_, ct, pf, dc)) => (ct.to_string(), pf.to_string(), dc.to_string()),
                        None => ("0".to_string(), "0".to_string(), "0".to_string()),
                    };
                    telemetry.info(
                        "serving.completed",
                        &[
                            ("peer", peer_id.as_str()),
                            ("completion_tokens", completion_tokens.as_str()),
                            ("prefill_ms", prefill_ms.as_str()),
                            ("decode_ms", decode_ms.as_str()),
                        ],
                    );
                    // ADR-030 B2: attach the phase-1-signed work
                    // receipt. Honest values only: single-mode path,
                    // preset unspecified until ADR-029 negotiation rides
                    // the wire. Construction failure (never for these
                    // inputs) degrades to a receipt-less Completed — the
                    // accounting simply doesn't happen, nothing breaks.
                    let (pt, ct, pf, dc) = last_usage.unwrap_or((0, 0, 0, 0));
                    let job_receipt = crate::receipt_wire::build_server_receipt(
                        &crate::receipt_wire::ReceiptContext {
                            request_id: &request.request_id,
                            profile_id: &profile_id,
                            requester: modelswarm_eligibility::receipt_v2::ReceiptPeer {
                                peer_id: peer_id.clone(),
                                installation_id: requester_installation.clone(),
                                role: "requester".into(),
                            },
                            server_identity: &identity,
                            started_at: request_started,
                            ended_at: time::OffsetDateTime::now_utc(),
                            finish_reason: &finish_reason_str,
                            accepted_tokens: ct,
                            verified_tokens: ct,
                            prompt_tokens: pt,
                            prefill_ms: pf,
                            decode_ms: dc,
                            deadline_ms,
                            max_tokens,
                        },
                    )
                    .ok();
                    WireMessage::Completed(Completed {
                        request_id: request.request_id.clone(),
                        finish_reason: finish_reason_str.clone(),
                        job_receipt,
                    })
                }
                ExecutorEvent::Error {
                    code, retryable, ..
                } => {
                    send_error(&mut session, &code, &format!("retryable={retryable}")).await;
                    linger(&mut session).await;
                    return Err(code);
                }
            };
            if session.send(&frame, IO_DEADLINE).await.is_err() {
                return Err("client vanished mid-stream".into());
            }
        }
    } // loop: await the next request on this session
}

/// Give the requester a moment to drain the last frame before the
/// session drops (see the post-completion linger note).
async fn linger(session: &mut Libp2pSession) {
    let _ = tokio::time::timeout(Duration::from_secs(1), session.recv(IO_DEADLINE)).await;
}

/// Sends a best-effort `StreamError` frame (the composed demux reuses this
/// for its admission refusals — the only msp-v1 frame that exists for
/// them).
pub(crate) async fn send_error(session: &mut Libp2pSession, code: &str, detail: &str) {
    let _ = session
        .send(
            &WireMessage::StreamError(StreamError {
                request_id: String::new(),
                code: code.to_string(),
                message: detail.chars().take(200).collect(),
                retryable_peer_hint: false,
            }),
            IO_DEADLINE,
        )
        .await;
}

// ---- F3: lease verification at session open (ADR-026) ----------------------
//
// A serving peer admits a session only when the request carries a
// hub-signed EligibilityLease in `capability_token` that (1) verifies
// against the pinned hub key, (2) names THIS node's profile, (3) grants
// can_consume with slots, and (4) is bound to the remote's
// QUIC-authenticated PeerId — a lease stolen from another peer is
// worthless. This closes the F0 TODO: serving is no longer
// protocol-speaking-anyone.

/// RFC 3339 "now" (shared by the gate and external verifiers).
pub fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339 formats")
}

/// The pinned hub signing key (protocol/keys/hub-public.hex) — the same
/// key the tracker's catalog envelopes are verified against.
const HUB_PUBLIC_KEY_HEX: &str = include_str!("../../../protocol/keys/hub-public.hex");

#[derive(Clone)]
pub struct LeasePolicy {
    hub_pubkey: ed25519_dalek::VerifyingKey,
}

impl LeasePolicy {
    /// Production policy: the pinned hub key.
    pub fn production() -> Self {
        Self::from_hex(HUB_PUBLIC_KEY_HEX.trim()).expect("pinned hub key parses")
    }

    /// Test policy over an arbitrary key (hex of 32 bytes).
    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str).map_err(|e| format!("hub key hex: {e}"))?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(
            &bytes[..32]
                .try_into()
                .map_err(|_| "hub key must be 32 bytes".to_string())?,
        )
        .map_err(|e| format!("hub key: {e}"))?;
        Ok(Self { hub_pubkey: key })
    }

    /// The pinned hub verifying key (for verification by other layers).
    pub fn hub_key(&self) -> &ed25519_dalek::VerifyingKey {
        &self.hub_pubkey
    }

    /// Full admission check for one inbound request.
    pub fn check(
        &self,
        capability_token: &str,
        served_profile: &str,
        remote_peer_id: &str,
    ) -> Result<(), String> {
        if capability_token.is_empty() || capability_token.starts_with("f0-unverified") {
            return Err("no lease presented".into());
        }
        let lease = modelswarm_eligibility::EligibilityLease::from_wire(capability_token)
            .map_err(|e| format!("bad lease: {e}"))?;
        let now = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| format!("clock: {e}"))?;
        lease
            .verify(&self.hub_pubkey, &now)
            .map_err(|e| format!("lease invalid: {e}"))?;
        if lease.model_profile_id != served_profile {
            return Err(format!(
                "lease is for another profile: {}",
                lease.model_profile_id
            ));
        }
        if !lease.can_consume || lease.slots == 0 {
            return Err("lease grants no consume right".into());
        }
        if lease.peer_id != remote_peer_id {
            return Err("lease is not bound to this peer".into());
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod lease_helpers {
    use super::LeasePolicy;
    use ed25519_dalek::SigningKey;
    use modelswarm_eligibility::{CapacityClass, EligibilityLease};

    /// Direct gate round-trip: helper-issued lease passes check for its
    /// own peer, fails for any other binding.
    #[test]
    fn gate_accepts_own_and_rejects_foreign_binding() {
        let (policy, token) = policy_and_lease(TEST_PROFILE, "peer-x");
        policy
            .check(&token, TEST_PROFILE, "peer-x")
            .expect("own lease verifies");
        let err = policy.check(&token, TEST_PROFILE, "peer-y").unwrap_err();
        assert!(err.contains("not bound"), "got: {err}");
        let err = policy.check("", TEST_PROFILE, "peer-x").unwrap_err();
        assert!(err.contains("no lease"));
    }

    /// A profile id that passes the ADR-011 format check in tests.
    /// A deterministic serving identity for tests (stable seed; peer id
    /// + installation id derive from it).
    pub fn server_identity() -> modelswarm_identity::InstallationIdentity {
        modelswarm_identity::InstallationIdentity::from_bytes(&[0xA7; 32])
    }

    pub const TEST_PROFILE: &str =
        "msp1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn rfc3339(plus_secs: i64) -> String {
        time::OffsetDateTime::now_utc()
            .saturating_add(time::Duration::seconds(plus_secs))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    }

    /// Issues a consume lease for (profile, peer) under a fresh test hub
    /// key; returns (policy over that key, wire token).
    pub fn policy_and_lease(profile: &str, peer_id: &str) -> (LeasePolicy, String) {
        policy_and_lease_for(profile, peer_id, "test-installation")
    }

    /// ADR-030 B3: the lease names the REQUESTER's real installation
    /// (production shape — the tracker leases to the installation, and
    /// the requester-side countersign refuses receipts whose requester
    /// peer names any other installation).
    pub fn policy_and_lease_for(
        profile: &str,
        peer_id: &str,
        installation_id: &str,
    ) -> (LeasePolicy, String) {
        let signing = SigningKey::generate(&mut rand_core::OsRng);
        let lease = EligibilityLease::issue(
            peer_id,
            installation_id,
            profile,
            rfc3339(-60),
            rfc3339(300),
            rfc3339(360),
            true,
            true,
            1,
            CapacityClass::GpuMid,
            1,
            "test-challenge",
            "test-nonce",
            1,
            &signing,
        );
        let token = lease.to_wire();
        let policy =
            LeasePolicy::from_hex(&hex::encode(signing.verifying_key().to_bytes())).unwrap();
        (policy, token)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    /// F0(4) same-host proof: the full serving-bridge round trip over real
    /// QUIC — dial, InferenceRequest in, TokenDelta/Usage/Completed out.
    #[tokio::test]
    async fn serving_bridge_round_trips_over_quic() {
        use super::serve_sessions;
        use futures_util::stream;
        use modelswarm_gateway::{
            ExecutorError, ExecutorEvent, ExecutorStream, FinishReason, InferenceExecutor,
            NormalizedRequest,
        };
        use modelswarm_identity::InstallationIdentity;
        use modelswarm_transport::libp2p_backend::Libp2pTransport;
        use modelswarm_transport::message::{
            ChatMessage, InferenceRequest, Sampling as WireSampling, WireMessage,
        };
        use std::time::Duration;

        struct FixedExecutor;
        #[async_trait::async_trait]
        impl InferenceExecutor for FixedExecutor {
            async fn execute(
                &self,
                request: NormalizedRequest,
            ) -> Result<ExecutorStream, ExecutorError> {
                assert_eq!(request.messages.len(), 1);
                assert_eq!(request.messages[0].role, "user");
                Ok(Box::pin(stream::iter(vec![
                    ExecutorEvent::Accepted {
                        queue_position: 0,
                        eta_ms: 0,
                    },
                    ExecutorEvent::TokenDelta {
                        delta: "Hello ".into(),
                        index: 0,
                    },
                    ExecutorEvent::TokenDelta {
                        delta: "swarm".into(),
                        index: 1,
                    },
                    ExecutorEvent::Usage {
                        prompt_tokens: 3,
                        completion_tokens: 2,
                        prefill_ms: 1.0,
                        decode_ms: 2.0,
                    },
                    ExecutorEvent::Completed {
                        finish_reason: FinishReason::Stop,
                    },
                ])))
            }
        }

        let server_identity = InstallationIdentity::from_bytes(&[7u8; 32]);
        let client_identity = InstallationIdentity::from_bytes(&[8u8; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let client = Libp2pTransport::new(&client_identity).unwrap();
        let listener = server.listen("127.0.0.1:0").await.unwrap();

        let bound = listener.bound_addr().clone();
        let expected_server_peer = server.peer_id();
        let (policy, token) = super::lease_helpers::policy_and_lease(
            super::lease_helpers::TEST_PROFILE,
            &client.peer_id().to_string(),
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_sessions(
            listener,
            std::sync::Arc::new(super::lease_helpers::server_identity()),
            Arc::new(FixedExecutor),
            super::lease_helpers::TEST_PROFILE.into(),
            policy,
            std::sync::Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            shutdown_rx,
        ));

        let dial_addr = bound.to_string();
        let mut session = client
            .dial(
                dial_addr.as_str(),
                &expected_server_peer,
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        session
            .send(
                &WireMessage::InferenceRequest(InferenceRequest {
                    request_id: "req-1".into(),
                    profile_id: super::lease_helpers::TEST_PROFILE.into(),
                    capability_token: token,
                    messages: vec![ChatMessage {
                        role: "user".into(),
                        content: "hi".into(),
                    }],
                    sampling: WireSampling {
                        temperature: 0.0,
                        top_p: 1.0,
                        top_k: 40,
                        seed: None,
                    },
                    max_tokens: 8,
                    deadline_ms: 10_000,
                    stream: true,
                }),
                Duration::from_secs(5),
            )
            .await
            .unwrap();

        let mut deltas = String::new();
        let mut saw_usage = false;
        let mut finish = String::new();
        for _ in 0..4 {
            match session.recv(Duration::from_secs(10)).await.unwrap() {
                WireMessage::TokenDelta(d) => deltas.push_str(&d.delta),
                WireMessage::Usage(_) => saw_usage = true,
                WireMessage::Completed(c) => finish = c.finish_reason,
                other => panic!("unexpected frame: {other:?}"),
            }
        }
        assert_eq!(deltas, "Hello swarm");
        assert!(saw_usage);
        assert_eq!(finish, "stop");
        shutdown_tx.send(true).ok();
    }

    /// 2026-10-09 LAN pass-1 bug (regression pin): dropping the shutdown
    /// watch SENDER must terminate the serving task — never spin with a
    /// permanently-ready `changed()` branch cancelling in-flight accepts
    /// (each cancellation dropped a mid-handshake QUIC upgrade; quinn then
    /// application-closed the unconfirmed connection as transport error
    /// 0xC, surfacing on the dialer as "libp2p stream open: aborted by
    /// peer: ... during the handshake"). The pre-fix task never exited,
    /// so a resolving JoinHandle is the pin.
    #[tokio::test]
    async fn serve_sessions_stops_when_shutdown_sender_drops() {
        use super::serve_sessions;
        use modelswarm_gateway::{ExecutorError, ExecutorStream, NormalizedRequest};
        use modelswarm_identity::InstallationIdentity;
        use modelswarm_transport::libp2p_backend::Libp2pTransport;
        use std::time::Duration;

        struct NeverExecutor;
        #[async_trait::async_trait]
        impl modelswarm_gateway::InferenceExecutor for NeverExecutor {
            async fn execute(
                &self,
                _request: NormalizedRequest,
            ) -> Result<ExecutorStream, ExecutorError> {
                unreachable!("no request is ever accepted in this test")
            }
        }

        let server_identity = InstallationIdentity::from_bytes(&[67u8; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let listener = server.listen("127.0.0.1:0").await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let serving = tokio::spawn(serve_sessions(
            listener,
            std::sync::Arc::new(super::lease_helpers::server_identity()),
            Arc::new(NeverExecutor),
            super::lease_helpers::TEST_PROFILE.into(),
            super::LeasePolicy::production(),
            std::sync::Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            shutdown_rx,
        ));
        // Drop the last sender: no owner can ever signal stop — the
        // bridge must stop serving on its own, promptly.
        drop(shutdown_tx);
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("serve_sessions exits when the shutdown sender drops")
            .expect("serve_sessions task did not panic");
    }

    /// The honest-refusal path (wrong profile → StreamError frame, then
    /// close). Previously flaky: the connection close raced the error
    /// frame — fixed by the post-error linger; kept as a regression pin.
    #[tokio::test]
    async fn serving_bridge_refuses_foreign_profile() {
        use super::serve_sessions;
        use modelswarm_gateway::{ExecutorError, ExecutorStream, NormalizedRequest};
        use modelswarm_identity::InstallationIdentity;
        use modelswarm_transport::libp2p_backend::Libp2pTransport;
        use modelswarm_transport::message::{
            ChatMessage, InferenceRequest, Sampling as WireSampling, WireMessage,
        };
        use std::time::Duration;

        struct NeverExecutor;
        #[async_trait::async_trait]
        impl modelswarm_gateway::InferenceExecutor for NeverExecutor {
            async fn execute(
                &self,
                _request: NormalizedRequest,
            ) -> Result<ExecutorStream, ExecutorError> {
                unreachable!("wrong-profile requests never reach the executor")
            }
        }

        let server_identity = InstallationIdentity::from_bytes(&[17u8; 32]);
        let client_identity = InstallationIdentity::from_bytes(&[18u8; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let client = Libp2pTransport::new(&client_identity).unwrap();
        let listener = server.listen("127.0.0.1:0").await.unwrap();
        let bound = listener.bound_addr().to_string();
        let expected = server.peer_id();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_sessions(
            listener,
            std::sync::Arc::new(super::lease_helpers::server_identity()),
            Arc::new(NeverExecutor),
            super::lease_helpers::TEST_PROFILE.into(),
            super::LeasePolicy::production(),
            std::sync::Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            shutdown_rx,
        ));

        let mut session = client
            .dial(bound.as_str(), &expected, Duration::from_secs(10))
            .await
            .unwrap();
        session
            .send(
                &WireMessage::InferenceRequest(InferenceRequest {
                    request_id: "req-x".into(),
                    profile_id: "msp1:OTHER".into(),
                    capability_token: "f0-unverified".into(),
                    messages: vec![ChatMessage {
                        role: "user".into(),
                        content: "hi".into(),
                    }],
                    sampling: WireSampling {
                        temperature: 0.0,
                        top_p: 1.0,
                        top_k: 40,
                        seed: None,
                    },
                    max_tokens: 8,
                    deadline_ms: 10_000,
                    stream: true,
                }),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        match session.recv(Duration::from_secs(10)).await.unwrap() {
            WireMessage::StreamError(e) => assert_eq!(e.code, "profile_mismatch"),
            other => panic!("expected StreamError, got {other:?}"),
        }
    }

    /// F3 gate: a valid profile request WITHOUT a lease is refused with
    /// invalid_lease — and never reaches the executor.
    #[tokio::test]
    async fn serving_bridge_refuses_leaseless_requests() {
        use super::serve_sessions;
        use modelswarm_gateway::{ExecutorError, ExecutorStream, NormalizedRequest};
        use modelswarm_identity::InstallationIdentity;
        use modelswarm_transport::libp2p_backend::Libp2pTransport;
        use modelswarm_transport::message::{
            ChatMessage, InferenceRequest, Sampling as WireSampling, WireMessage,
        };
        use std::time::Duration;

        struct NeverExecutor;
        #[async_trait::async_trait]
        impl modelswarm_gateway::InferenceExecutor for NeverExecutor {
            async fn execute(
                &self,
                _request: NormalizedRequest,
            ) -> Result<ExecutorStream, ExecutorError> {
                unreachable!("leaseless requests never reach the executor")
            }
        }

        let server_identity = InstallationIdentity::from_bytes(&[47u8; 32]);
        let client_identity = InstallationIdentity::from_bytes(&[48u8; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let client = Libp2pTransport::new(&client_identity).unwrap();
        let listener = server.listen("127.0.0.1:0").await.unwrap();
        let bound = listener.bound_addr().to_string();
        let expected = server.peer_id();
        // Policy over a TEST hub key; the request presents NO lease at all.
        let (policy, _unused) = super::lease_helpers::policy_and_lease(
            super::lease_helpers::TEST_PROFILE,
            &client.peer_id().to_string(),
        );
        let (_tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_sessions(
            listener,
            std::sync::Arc::new(super::lease_helpers::server_identity()),
            Arc::new(NeverExecutor),
            super::lease_helpers::TEST_PROFILE.into(),
            policy,
            std::sync::Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            rx,
        ));

        let mut session = client
            .dial(bound.as_str(), &expected, Duration::from_secs(10))
            .await
            .unwrap();
        session
            .send(
                &WireMessage::InferenceRequest(InferenceRequest {
                    request_id: "req-nolease".into(),
                    profile_id: super::lease_helpers::TEST_PROFILE.into(),
                    capability_token: String::new(),
                    messages: vec![ChatMessage {
                        role: "user".into(),
                        content: "hi".into(),
                    }],
                    sampling: WireSampling {
                        temperature: 0.0,
                        top_p: 1.0,
                        top_k: 40,
                        seed: None,
                    },
                    max_tokens: 8,
                    deadline_ms: 10_000,
                    stream: true,
                }),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        match session.recv(Duration::from_secs(10)).await.unwrap() {
            WireMessage::StreamError(e) => assert_eq!(e.code, "invalid_lease"),
            other => panic!("expected StreamError, got {other:?}"),
        }
    }

    /// F3 gate: a VALID lease bound to a DIFFERENT peer is refused — the
    /// QUIC-authenticated PeerId binding makes stolen leases worthless.
    #[tokio::test]
    async fn serving_bridge_refuses_foreign_peer_lease() {
        use super::serve_sessions;
        use modelswarm_gateway::{ExecutorError, ExecutorStream, NormalizedRequest};
        use modelswarm_identity::InstallationIdentity;
        use modelswarm_transport::libp2p_backend::Libp2pTransport;
        use modelswarm_transport::message::{
            ChatMessage, InferenceRequest, Sampling as WireSampling, WireMessage,
        };
        use std::time::Duration;

        struct NeverExecutor;
        #[async_trait::async_trait]
        impl modelswarm_gateway::InferenceExecutor for NeverExecutor {
            async fn execute(
                &self,
                _request: NormalizedRequest,
            ) -> Result<ExecutorStream, ExecutorError> {
                unreachable!("foreign-lease requests never reach the executor")
            }
        }

        let server_identity = InstallationIdentity::from_bytes(&[57u8; 32]);
        let client_identity = InstallationIdentity::from_bytes(&[58u8; 32]);
        let server = Libp2pTransport::new(&server_identity).unwrap();
        let client = Libp2pTransport::new(&client_identity).unwrap();
        let listener = server.listen("127.0.0.1:0").await.unwrap();
        let bound = listener.bound_addr().to_string();
        let expected = server.peer_id();
        // Lease issued to SOMEONE ELSE (a third identity), signed by the
        // same hub key the policy verifies with — signature valid, binding
        // wrong.
        let stranger = Libp2pTransport::new(&InstallationIdentity::from_bytes(&[59u8; 32]))
            .unwrap()
            .peer_id()
            .to_string();
        let (policy, stranger_token) =
            super::lease_helpers::policy_and_lease(super::lease_helpers::TEST_PROFILE, &stranger);
        let (_tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(serve_sessions(
            listener,
            std::sync::Arc::new(super::lease_helpers::server_identity()),
            Arc::new(NeverExecutor),
            super::lease_helpers::TEST_PROFILE.into(),
            policy,
            std::sync::Arc::new(modelswarm_telemetry::Telemetry::memory().0),
            rx,
        ));

        let mut session = client
            .dial(bound.as_str(), &expected, Duration::from_secs(10))
            .await
            .unwrap();
        session
            .send(
                &WireMessage::InferenceRequest(InferenceRequest {
                    request_id: "req-stolen".into(),
                    profile_id: super::lease_helpers::TEST_PROFILE.into(),
                    capability_token: stranger_token,
                    messages: vec![ChatMessage {
                        role: "user".into(),
                        content: "hi".into(),
                    }],
                    sampling: WireSampling {
                        temperature: 0.0,
                        top_p: 1.0,
                        top_k: 40,
                        seed: None,
                    },
                    max_tokens: 8,
                    deadline_ms: 10_000,
                    stream: true,
                }),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        match session.recv(Duration::from_secs(10)).await.unwrap() {
            WireMessage::StreamError(e) => {
                assert_eq!(e.code, "invalid_lease");
                // The wire message is static by policy (no lease internals
                // cross the wire); the specific reason stays in node logs.
                assert_eq!(e.message, "lease check failed");
            }
            other => panic!("expected StreamError, got {other:?}"),
        }
    }

    #[test]
    fn serving_module_wires_wire_shapes() {
        use modelswarm_transport::message::Completed;
        assert_eq!(
            Completed {
                request_id: "r".into(),
                finish_reason: "stop".into(),
                job_receipt: None,
            }
            .finish_reason,
            "stop"
        );
    }

    /// §6.4 clamps on the wire path: a lease-holder sending a 49-day
    /// deadline or an unbounded token budget gets the same table the
    /// local gateway applies; an oversized prompt is rejected outright.
    #[test]
    fn wire_limits_clamp_like_the_gateway() {
        use modelswarm_gateway::{
            DEADLINE_MS_MAX, DEADLINE_MS_MIN, DEFAULT_MAX_OUTPUT_TOKENS, MAX_PROMPT_BYTES,
        };
        let (d, t) = super::clamp_wire_request(u32::MAX, u32::MAX, 100).unwrap();
        assert_eq!(d, DEADLINE_MS_MAX);
        assert_eq!(t, DEFAULT_MAX_OUTPUT_TOKENS);
        let (d, t) = super::clamp_wire_request(0, 0, 100).unwrap();
        assert_eq!(d, DEADLINE_MS_MIN);
        assert_eq!(t, 1);
        let (d, t) = super::clamp_wire_request(30_000, 64, 100).unwrap();
        assert_eq!((d, t), (30_000, 64));
        assert_eq!(
            super::clamp_wire_request(30_000, 64, MAX_PROMPT_BYTES + 1),
            Err("payload_too_large")
        );
    }

    #[test]
    fn admission_caps_sessions_and_replays() {
        let adm = super::Admission::new(2, 1);
        let a = adm.admit_session("peer-a").expect("first session admitted");
        assert!(adm.admit_session("peer-a").is_err(), "per-peer cap");
        let b = adm.admit_session("peer-b").expect("second peer admitted");
        assert!(adm.admit_session("peer-c").is_err(), "total cap");
        drop(a);
        drop(b);
        assert!(
            adm.admit_session("peer-c").is_ok(),
            "slots released on drop"
        );
        // request-id dedup: fresh once, replay rejected, other peer fresh.
        assert!(adm.check_request_fresh("peer-a", "req-1"));
        assert!(!adm.check_request_fresh("peer-a", "req-1"));
        assert!(adm.check_request_fresh("peer-b", "req-1"));
    }

    /// ADR-043 §2: when a weight-4 contributor and a weight-1 peer wait
    /// in the SAME contention episode, the contributor is admitted first
    /// (quarter-step finish vs full-step); and a lightweight that waits
    /// ALONE is admitted the moment a slot frees — contributor priority
    /// without starvation.
    #[tokio::test]
    async fn adr043_fair_queue_prefers_the_contributor() {
        let adm = super::Admission::new(1, 8);
        for round in 0..10 {
            let holder = adm.admit_session(&format!("holder-{round}")).expect("slot");
            let light = {
                let adm = adm.clone();
                tokio::spawn(async move {
                    adm.admit_session_fair("light", 1, std::time::Duration::from_secs(5))
                        .await
                })
            };
            let heavy = {
                let adm = adm.clone();
                tokio::spawn(async move {
                    adm.admit_session_fair("heavy", 4, std::time::Duration::from_secs(5))
                        .await
                })
            };
            // Let both settle into the queue before freeing the slot.
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            drop(holder);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            // The contributor must be the admitted one in every round.
            assert!(
                !light.is_finished(),
                "round {round}: the weight-1 peer must still be waiting"
            );
            assert!(
                heavy.is_finished(),
                "round {round}: the weight-4 contributor must be admitted"
            );
            light.abort();
            if let Ok(Ok((guard, _))) = heavy.await {
                drop(guard);
            }
            // Let the aborted lightweight's queue entry clear (its future
            // drops on abort; give the runtime a beat).
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Starvation guard: alone in the queue, the lightweight is
        // admitted promptly after a release.
        let holder = adm.admit_session("holder-final").expect("slot");
        let light = {
            let adm = adm.clone();
            tokio::spawn(async move {
                adm.admit_session_fair("light", 1, std::time::Duration::from_secs(5))
                    .await
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        drop(holder);
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), light).await;
        assert!(
            matches!(outcome, Ok(Ok(Ok(_)))),
            "a lone lightweight waiter is admitted after a release"
        );
    }

    /// ADR-043 §1: a waiter past the §6.4 queue admission deadline is
    /// refused `queue_deadline` and leaves the queue honestly.
    #[tokio::test]
    async fn adr043_queue_deadline_expires() {
        let adm = super::Admission::new(1, 2);
        let _holder = adm.admit_session("holder").expect("slot");
        let result = adm
            .admit_session_fair("waiter", 1, std::time::Duration::from_millis(80))
            .await;
        assert_eq!(result.err(), Some("queue_deadline"));
        // Slot frees afterwards: normal admission works again (the expired
        // waiter is not stuck in the queue).
        drop(_holder);
        assert!(adm.admit_session("fresh").is_ok());
    }

    /// ADR-043 §1: the wait queue is bounded — beyond 16 waiters, the
    /// refusal is today's immediate `session_limit`.
    #[tokio::test]
    async fn adr043_queue_capacity_is_bounded() {
        let adm = super::Admission::new(1, 32);
        let _holder = adm.admit_session("holder").expect("slot");
        let mut waiters = Vec::new();
        for i in 0..16 {
            let a = adm.clone();
            waiters.push(tokio::spawn(async move {
                a.admit_session_fair(&format!("w{i}"), 1, std::time::Duration::from_secs(5))
                    .await
            }));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let overflow = adm
            .admit_session_fair("w16", 1, std::time::Duration::from_millis(50))
            .await;
        assert_eq!(overflow.err(), Some("session_limit"));
        for w in waiters {
            w.abort();
        }
    }

    /// ADR-043 §3: the `accepted` frame's wire shape — externally tagged,
    /// snake_case, additive variant (old peers keep parsing everything
    /// else; golden-shape pin for the requester-side mapping).
    #[test]
    fn adr043_accepted_wire_shape() {
        let frame = modelswarm_transport::message::WireMessage::Accepted(
            modelswarm_transport::message::Accepted {
                request_id: "r-1".into(),
                queue_position: 0,
                eta_ms: 0,
            },
        );
        let json = serde_json::to_value(&frame).expect("serializes");
        assert_eq!(
            json,
            serde_json::json!({"accepted": {
                "request_id": "r-1",
                "queue_position": 0,
                "eta_ms": 0,
            }})
        );
        let back: modelswarm_transport::message::WireMessage =
            serde_json::from_value(json).expect("round-trips");
        assert_eq!(back, frame);
    }
}
