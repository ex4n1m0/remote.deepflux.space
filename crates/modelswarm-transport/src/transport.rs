//! `SignedFrameTransport`: the ADR-018 Phase C–E backend.
//!
//! Tokio TCP + length-prefixed JSON frames. The handshake is Ed25519-signed
//! and verified against the expected peer key; subsequent messages travel
//! inside the established session (msp-v1 §6.1 flow staging — the ack and
//! stream events are integrity-protected by the session, not individually
//! signed; full per-message authentication arrives with libp2p+Noise at
//! Phase F).
//!
//! Honesty guard (ADR-018): [`SignedFrameTransport::listen`] refuses any
//! bind address except `127.0.0.1` or `::1` with
//! [`TransportError::NonLoopbackDenied`]. The backend provides integrity and
//! authentication, not confidentiality, and must never listen beyond
//! loopback.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use modelswarm_identity::{rfc3339_now, within_window, REPLAY_WINDOW_SECS};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;

use crate::error::{invalid_data, TransportError};
use crate::frame;
use crate::handshake::verify_handshake;
use crate::message::{Control, Handshake, HandshakeAck, WireMessage, MSP_PROTOCOL_VERSION};

/// Bounded outbound queue depth (frames). A slow peer fills TCP buffers,
/// then this channel, then senders wait — memory stays bounded.
pub const SEND_CHANNEL_CAPACITY: usize = 16;
/// Bounded inbound queue depth (frames) between the reader task and
/// [`Session::recv`].
pub const RECV_CHANNEL_CAPACITY: usize = 16;
/// Deadline used by [`Session::request_cancel`], which has no per-call
/// deadline parameter.
pub const CANCEL_DEADLINE: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Pre-serialized frame payload queued for the writer task.
struct OutboundItem {
    payload: Vec<u8>,
    /// Completed by the writer task once the frame hit the socket. Dropped
    /// without send when the writer dies first (surfaced as `Closed`).
    ack: oneshot::Sender<Result<(), TransportError>>,
}

/// One decoded inbound frame: a typed [`WireMessage`] or, when the payload is
/// valid JSON but not a typed message, the raw passthrough value delivered to
/// [`Session::recv_json`] (extension namespaces, ADR-018 amended staging).
enum InboundFrame {
    Typed(Box<WireMessage>),
    Raw(Value),
}

#[derive(Debug, Default)]
struct SessionState {
    closed: AtomicBool,
    /// First fatal error observed by the reader/writer task; surfaced once
    /// to the next caller, then the session reads as `Closed`.
    terminal: Mutex<Option<TransportError>>,
}

impl SessionState {
    fn record(&self, err: TransportError) {
        let mut slot = self.terminal.lock().expect("terminal lock poisoned");
        if slot.is_none() {
            *slot = Some(err);
        }
    }

    fn take_terminal(&self) -> Option<TransportError> {
        self.terminal.lock().expect("terminal lock poisoned").take()
    }
}

/// An authenticated, framed, deadline-aware session over one TCP connection.
///
/// All async methods take `&mut self` (a session has one logical owner);
/// [`close`](Session::close) takes `&self` and is idempotent.
///
/// Deadline policy: a send/recv whose deadline elapses returns
/// [`TransportError::Timeout`] **and closes the session** — a missed deadline
/// is treated as peer failure, never as a reason to hang. Later calls return
/// [`TransportError::Closed`].
#[derive(Debug)]
pub struct Session {
    outbound: mpsc::Sender<OutboundItem>,
    inbound: mpsc::Receiver<InboundFrame>,
    /// Typed frames intercepted by [`Session::recv_json`] while waiting for a
    /// raw passthrough frame (delivered by the next [`Session::recv`]).
    stashed_typed: VecDeque<WireMessage>,
    /// Raw passthrough frames intercepted by [`Session::recv`] while waiting
    /// for a typed message (delivered by the next [`Session::recv_json`]).
    stashed_raw: VecDeque<Value>,
    shutdown: watch::Sender<bool>,
    state: Arc<SessionState>,
}

fn spawn_session(stream: TcpStream) -> Session {
    let _ = stream.set_nodelay(true);
    let (read_half, write_half) = stream.into_split();

    let (outbound_tx, outbound_rx) = mpsc::channel::<OutboundItem>(SEND_CHANNEL_CAPACITY);
    let (inbound_tx, inbound_rx) = mpsc::channel::<InboundFrame>(RECV_CHANNEL_CAPACITY);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let state = Arc::new(SessionState::default());

    // Writer task: drains the bounded outbound channel to the socket. A
    // blocked write is unbounded only until close() drops its future via the
    // shutdown arm; caller-side deadlines bound the observable wait. Write
    // failures are delivered to the awaiting sender via the ack; the reader
    // task's terminal error (the connection is broken for it too) covers
    // callers that never see the ack. Payloads arrive pre-serialized
    // (typed WireMessage or raw JSON passthrough) — encode errors surface at
    // the send call site instead.
    {
        let mut shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut writer = write_half;
            let mut queue = outbound_rx;
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => break,
                    item = queue.recv() => {
                        let Some(item) = item else { break };
                        let result = frame::write_frame_raw(&mut writer, &item.payload)
                            .await
                            .map_err(TransportError::from);
                        let fatal = result.is_err();
                        let _ = item.ack.send(result);
                        if fatal {
                            break;
                        }
                    }
                }
            }
        });
    }

    // Reader task: frames off the socket into the bounded inbound channel.
    // Payloads decode as typed WireMessages when they are one, and as raw
    // JSON values otherwise (the extension-namespace passthrough); only a
    // payload that is not valid JSON at all corrupts the session. Control
    // pings are answered transparently in-band and never reach the
    // application; pongs do (RTT measurement).
    {
        let mut shutdown_rx = shutdown_rx;
        let state = Arc::clone(&state);
        let pong_channel = outbound_tx.clone();
        tokio::spawn(async move {
            let mut reader = read_half;
            let deliver = inbound_tx;
            loop {
                let bytes = tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => break,
                    read = frame::read_frame_raw(&mut reader) => match read {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            state.record(TransportError::from(e));
                            break;
                        }
                    },
                };
                let msg = match serde_json::from_slice::<WireMessage>(&bytes) {
                    Ok(msg) => InboundFrame::Typed(Box::new(msg)),
                    Err(_) => match serde_json::from_slice::<Value>(&bytes) {
                        Ok(value) => InboundFrame::Raw(value),
                        Err(e) => {
                            state.record(TransportError::Io(invalid_data("frame decode", e)));
                            break;
                        }
                    },
                };
                if let InboundFrame::Typed(typed) = &msg {
                    if let WireMessage::Control(control) = typed.as_ref() {
                        if control.kind == Control::PING {
                            let (ack_tx, _ack_rx) = oneshot::channel();
                            let pong = OutboundItem {
                                payload: serde_json::to_vec(&WireMessage::Control(Control::pong(
                                    &control.nonce,
                                )))
                                .expect("control pong serializes"),
                                ack: ack_tx,
                            };
                            if pong_channel.send(pong).await.is_err() {
                                break;
                            }
                            continue;
                        }
                    }
                }
                if deliver.send(msg).await.is_err() {
                    break; // session handle dropped
                }
            }
        });
    }

    Session {
        outbound: outbound_tx,
        inbound: inbound_rx,
        stashed_typed: VecDeque::new(),
        stashed_raw: VecDeque::new(),
        shutdown: shutdown_tx,
        state,
    }
}

impl Session {
    /// Sends one typed message. The deadline bounds both the bounded-channel
    /// wait (backpressure when the peer is slow) and the socket write.
    /// Deadline expiry closes the session.
    pub async fn send(
        &mut self,
        msg: WireMessage,
        deadline: Duration,
    ) -> Result<(), TransportError> {
        self.check_open()?;
        let payload = serde_json::to_vec(&msg)
            .map_err(|e| TransportError::Io(invalid_data("frame encode", e)))?;
        self.send_payload(payload, deadline).await
    }

    /// Sends one raw JSON value as a frame (extension-namespace passthrough).
    ///
    /// ADR-018 amended staging: cooperative extension protocols (e.g. the
    /// Phase-D speculative namespace in `modelswarm-session`) ride the
    /// handshake-authenticated session without being part of the frozen §6
    /// typed surface; state-changing extension messages (commits, receipts)
    /// are additionally signed at the session layer by the extension itself.
    /// The value is framed exactly as serialized — it is NOT wrapped in a
    /// typed [`WireMessage`], so only a peer using [`Session::recv_json`]
    /// can read it.
    pub async fn send_json(&self, value: &Value, deadline: Duration) -> Result<(), TransportError> {
        self.check_open()?;
        let payload = serde_json::to_vec(value)
            .map_err(|e| TransportError::Io(invalid_data("frame encode", e)))?;
        self.send_payload(payload, deadline).await
    }

    /// Shared send path: enqueue the pre-serialized payload, await the writer
    /// ack, apply the deadline policy (expiry closes the session).
    async fn send_payload(
        &self,
        payload: Vec<u8>,
        deadline: Duration,
    ) -> Result<(), TransportError> {
        let (ack_tx, ack_rx) = oneshot::channel();
        let outbound = self.outbound.clone();
        let send_and_write = async move {
            outbound
                .send(OutboundItem {
                    payload,
                    ack: ack_tx,
                })
                .await
                .map_err(|_| TransportError::Closed)?;
            match ack_rx.await {
                Ok(result) => result,
                Err(_) => Err(TransportError::Closed), // writer gone before writing
            }
        };
        match timeout(deadline, send_and_write).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => {
                self.close();
                Err(err)
            }
            Err(_) => {
                self.close();
                Err(TransportError::Timeout)
            }
        }
    }

    /// Receives the next typed application message. Control pongs are
    /// delivered (used by [`Session::measure_rtt`]); control pings never are.
    /// Raw JSON passthrough frames (see [`Session::send_json`]) are stashed
    /// for [`Session::recv_json`] instead of surfacing here. Deadline expiry
    /// closes the session; a dead peer surfaces as its terminal error or
    /// [`TransportError::Closed`].
    pub async fn recv(&mut self, deadline: Duration) -> Result<WireMessage, TransportError> {
        self.check_open()?;
        let wait = async {
            loop {
                if let Some(msg) = self.stashed_typed.pop_front() {
                    return Ok(msg);
                }
                match self.inbound.recv().await {
                    Some(InboundFrame::Typed(msg)) => return Ok(*msg),
                    Some(InboundFrame::Raw(value)) => {
                        self.stashed_raw.push_back(value);
                    }
                    None => {
                        return Err(self.state.take_terminal().unwrap_or(TransportError::Closed))
                    }
                }
            }
        };
        match timeout(deadline, wait).await {
            Ok(result) => result,
            Err(_) => {
                self.close();
                Err(TransportError::Timeout)
            }
        }
    }

    /// Receives the next raw JSON passthrough frame (see [`Session::send_json`]).
    ///
    /// Typed [`WireMessage`] frames that arrive meanwhile are stashed and
    /// delivered by the next [`Session::recv`]. Same deadline policy as
    /// [`Session::recv`]: expiry closes the session; a dead peer surfaces as
    /// its terminal error or [`TransportError::Closed`].
    pub async fn recv_json(&mut self, deadline: Duration) -> Result<Value, TransportError> {
        self.check_open()?;
        let wait = async {
            loop {
                if let Some(value) = self.stashed_raw.pop_front() {
                    return Ok(value);
                }
                match self.inbound.recv().await {
                    Some(InboundFrame::Raw(value)) => return Ok(value),
                    Some(InboundFrame::Typed(msg)) => {
                        self.stashed_typed.push_back(*msg);
                    }
                    None => {
                        return Err(self.state.take_terminal().unwrap_or(TransportError::Closed))
                    }
                }
            }
        };
        match timeout(deadline, wait).await {
            Ok(result) => result,
            Err(_) => {
                self.close();
                Err(TransportError::Timeout)
            }
        }
    }

    /// Forwards an explicit cancellation for `request_id`
    /// (msp-v1 §6.1: cancel, either side, anytime). Uses [`CANCEL_DEADLINE`].
    pub async fn request_cancel(&mut self, request_id: &str) -> Result<(), TransportError> {
        self.send(
            WireMessage::Cancel(crate::message::Cancel {
                request_id: request_id.to_string(),
                reason: "cancelled_by_peer".to_string(),
            }),
            CANCEL_DEADLINE,
        )
        .await
    }

    /// Measures round-trip times with `samples` ping/pong probes
    /// (transport-layer [`WireMessage::Control`]; msp-v1 defines no ping
    /// message). Every probe (enqueue+write+reply) is bounded by `deadline`.
    pub async fn measure_rtt(
        &mut self,
        samples: usize,
        deadline: Duration,
    ) -> Result<Stats, TransportError> {
        let mut durations = Vec::with_capacity(samples);
        for _ in 0..samples {
            let ping = Control::ping();
            let nonce = ping.nonce.clone();
            let started = Instant::now();
            self.send(WireMessage::Control(ping), deadline).await?;
            loop {
                match self.recv(deadline).await? {
                    WireMessage::Control(control)
                        if control.kind == Control::PONG && control.nonce == nonce =>
                    {
                        break;
                    }
                    // Interleaved application traffic is skipped, not lost.
                    _ => continue,
                }
            }
            durations.push(started.elapsed());
        }
        Ok(Stats::from_durations(&durations))
    }

    /// True once closed locally, by deadline expiry, or by peer loss.
    pub fn is_closed(&self) -> bool {
        self.state.closed.load(Ordering::Relaxed)
    }

    /// Closes the session: pending writes are dropped, both halves shut
    /// down, the peer observes EOF. Idempotent.
    pub fn close(&self) {
        self.state.closed.store(true, Ordering::Relaxed);
        let _ = self.shutdown.send(true);
        // Dropping our outbound sender is not enough on its own (&self), but
        // the shutdown signal stops the writer first (biased select), so the
        // channel is abandoned either way.
    }

    fn check_open(&self) -> Result<(), TransportError> {
        if self.is_closed() {
            Err(TransportError::Closed)
        } else {
            Ok(())
        }
    }
}

/// RTT statistics from repeated probes.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Stats {
    pub p50_ms: f64,
    pub p95_ms: f64,
    /// Mean absolute difference between successive samples (RFC 3550-style
    /// jitter estimate).
    pub jitter_ms: f64,
}

impl Stats {
    /// Computes p50/p95 (nearest-rank) and jitter from probe durations, in
    /// original order for the jitter estimate.
    pub fn from_durations(durations: &[Duration]) -> Self {
        if durations.is_empty() {
            return Self {
                p50_ms: 0.0,
                p95_ms: 0.0,
                jitter_ms: 0.0,
            };
        }
        let ms: Vec<f64> = durations
            .iter()
            .map(|d| d.as_secs_f64() * 1_000.0)
            .collect();
        let sorted = {
            let mut s = ms.clone();
            s.sort_by(|a, b| a.total_cmp(b));
            s
        };
        let jitter = if ms.len() > 1 {
            let sum: f64 = ms.windows(2).map(|w| (w[1] - w[0]).abs()).sum();
            sum / (ms.len() - 1) as f64
        } else {
            0.0
        };
        Self {
            p50_ms: percentile(&sorted, 0.50),
            p95_ms: percentile(&sorted, 0.95),
            jitter_ms: jitter,
        }
    }
}

/// Nearest-rank percentile over an ascending-sorted slice.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    debug_assert!((0.0..=1.0).contains(&p));
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (p * sorted.len() as f64).ceil().max(1.0) as usize;
    sorted[(rank - 1).min(sorted.len() - 1)]
}

// ---------------------------------------------------------------------------
// Listener + transport entry points
// ---------------------------------------------------------------------------

/// Loopback-only listener performing the serving side of the §6.1 handshake.
#[derive(Debug)]
pub struct Listener {
    inner: TcpListener,
}

impl Listener {
    /// The bound loopback address (port is concrete even when bound to :0).
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Accepts one RAW TCP connection WITHOUT performing the §6.1 handshake.
    ///
    /// Phase F relay exercise (ADR-014/F13): an intermediary that forwards
    /// frames verbatim between two terminal peers needs byte-level pipes,
    /// not a terminated session. The end-to-end Ed25519 handshake and the
    /// session-layer commit/receipt signatures still authenticate the
    /// terminal peers — the relay is deliberately unauthenticated and cannot
    /// alter, forge, or observe beyond what the length-prefixed frames carry.
    /// The loopback-only bind rule still applies (this listener itself came
    /// from [`SignedFrameTransport::listen`]; the real Circuit-Relay-v2
    /// arrives with the libp2p backend).
    pub async fn accept_raw(&self, deadline: Duration) -> Result<TcpStream, TransportError> {
        let (stream, _peer_addr) = timeout(deadline, self.inner.accept())
            .await
            .map_err(|_| TransportError::Timeout)??;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    /// Accepts one connection and performs the handshake exchange against a
    /// single expected client key. Equivalent to
    /// [`Listener::accept_with`] with a one-key resolver.
    pub async fn accept(
        &self,
        expected_client: &VerifyingKey,
        deadline: Duration,
    ) -> Result<Session, TransportError> {
        let expected = *expected_client;
        self.accept_with(move |_| Some(expected), deadline).await
    }

    /// Accepts one connection and performs the §6.1 handshake exchange:
    ///
    /// 1. read the client `Handshake` frame;
    /// 2. reject with §6.5 `incompatible_protocol` unless the version is
    ///    `"1"`;
    /// 3. reject with `handshake_failed` on a stale `ts` (±120 s window,
    ///    msp-v1 §6.6) or an unknown peer (`resolve` returned no key);
    /// 4. verify the Ed25519 signature and peer-id binding
    ///    ([`verify_handshake`]);
    /// 5. answer `HandshakeAck{ok:true}` (or `ok:false` with the §6.5 code).
    ///
    /// `resolve` maps the *claimed* handshake peer id to the trusted public
    /// key for that peer (the tracker-provided directory in production; the
    /// simulator's known-identity map in tests). Returning `None` rejects.
    pub async fn accept_with<F>(
        &self,
        resolve: F,
        deadline: Duration,
    ) -> Result<Session, TransportError>
    where
        F: Fn(&Handshake) -> Option<VerifyingKey>,
    {
        let (stream, _peer_addr) = timeout(deadline, self.inner.accept())
            .await
            .map_err(|_| TransportError::Timeout)??;
        let mut session = spawn_session(stream);

        let msg = session.recv(deadline).await?;
        let WireMessage::Handshake(handshake) = &msg else {
            return reject_handshake(
                &mut session,
                "handshake_failed",
                "expected a handshake frame",
            )
            .await;
        };
        if handshake.protocol_version != MSP_PROTOCOL_VERSION {
            return reject_handshake(
                &mut session,
                "incompatible_protocol",
                "protocol version must be \"1\"",
            )
            .await;
        }
        if !within_window(&handshake.ts, &rfc3339_now(), REPLAY_WINDOW_SECS) {
            return reject_handshake(
                &mut session,
                "handshake_failed",
                "handshake ts outside the ±120 s window",
            )
            .await;
        }
        let Some(expected_key) = resolve(handshake) else {
            return reject_handshake(&mut session, "handshake_failed", "unknown peer").await;
        };
        if let Err(err) = verify_handshake(&msg, &expected_key) {
            return reject_handshake(
                &mut session,
                "handshake_failed",
                &format!("verification failed: {err}"),
            )
            .await;
        }

        let ack = HandshakeAck {
            ok: true,
            error_code: String::new(),
            queue_position: 0,
            eta_ms: 0,
        };
        session
            .send(WireMessage::HandshakeAck(ack), deadline)
            .await?;
        Ok(session)
    }
}

/// Sends the failure ack (best effort), closes, and returns the error.
async fn reject_handshake(
    session: &mut Session,
    code: &str,
    why: &str,
) -> Result<Session, TransportError> {
    let ack = HandshakeAck {
        ok: false,
        error_code: code.to_string(),
        queue_position: 0,
        eta_ms: 0,
    };
    let _ = session
        .send(WireMessage::HandshakeAck(ack), Duration::from_secs(2))
        .await;
    session.close();
    Err(TransportError::HandshakeFailed(format!("{code}: {why}")))
}

/// The ADR-018 signed-frame transport backend (Phases B–E).
///
/// Integrity and authentication via the signed handshake; **no
/// confidentiality** (no Noise) — hence loopback-only listeners (the honesty
/// guard, tested) and a mandatory libp2p swap at Phase F.
#[derive(Debug, Default, Clone, Copy)]
pub struct SignedFrameTransport;

impl SignedFrameTransport {
    /// Binds `bind` (e.g. `"127.0.0.1:0"`). Refuses any address whose IP is
    /// not `127.0.0.1`/`::1` with [`TransportError::NonLoopbackDenied`] —
    /// the ADR-018 honesty guard, enforced before any socket exists.
    pub async fn listen(bind: &str) -> Result<Listener, TransportError> {
        let addr: SocketAddr = bind
            .parse()
            .map_err(|e| TransportError::Io(invalid_data("invalid bind address", e)))?;
        if !addr.ip().is_loopback() {
            return Err(TransportError::NonLoopbackDenied);
        }
        Ok(Listener {
            inner: TcpListener::bind(addr).await?,
        })
    }

    /// Connects to `addr` and performs the client side of the §6.1 exchange:
    /// sends `handshake`, awaits the ack, fails with
    /// [`TransportError::HandshakeFailed`] carrying the peer's §6.5 code when
    /// the ack is negative.
    ///
    /// The ack itself is unsigned (per the proto schema it carries no
    /// signature field): server authentication in the staged backend rests on
    /// the verified channel/address pairing; the Noise-authenticated binding
    /// arrives with libp2p at Phase F.
    pub async fn connect(
        addr: &str,
        handshake: Handshake,
        deadline: Duration,
    ) -> Result<Session, TransportError> {
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| TransportError::Io(invalid_data("invalid connect address", e)))?;
        let stream = timeout(deadline, TcpStream::connect(addr))
            .await
            .map_err(|_| TransportError::Timeout)??;
        let mut session = spawn_session(stream);
        session
            .send(WireMessage::Handshake(handshake), deadline)
            .await?;
        let ack = session.recv(deadline).await?;
        match ack {
            WireMessage::HandshakeAck(ack) if ack.ok => Ok(session),
            WireMessage::HandshakeAck(ack) => {
                session.close();
                let code = if ack.error_code.is_empty() {
                    "handshake_failed".to_string()
                } else {
                    ack.error_code
                };
                Err(TransportError::HandshakeFailed(code))
            }
            _ => {
                session.close();
                Err(TransportError::HandshakeFailed(
                    "expected a handshake_ack frame".to_string(),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_percentiles_are_nearest_rank() {
        // 1..=10 ms: p50 = 5, p95 = 10 (nearest rank over sorted values).
        let durations: Vec<Duration> = (1..=10).map(Duration::from_millis).collect();
        let stats = Stats::from_durations(&durations);
        assert!((stats.p50_ms - 5.0).abs() < 1e-9);
        assert!((stats.p95_ms - 10.0).abs() < 1e-9);
        assert!(stats.jitter_ms >= 0.0 && stats.jitter_ms.is_finite());
    }

    #[test]
    fn stats_empty_is_zeroed() {
        let stats = Stats::from_durations(&[]);
        assert_eq!(
            stats,
            Stats {
                p50_ms: 0.0,
                p95_ms: 0.0,
                jitter_ms: 0.0
            }
        );
    }

    #[test]
    fn stats_jitter_uses_successive_differences() {
        let durations = [
            Duration::from_millis(10),
            Duration::from_millis(16),
            Duration::from_millis(10),
        ];
        let stats = Stats::from_durations(&durations);
        // |16-10| + |10-16| = 12 over 2 differences = 6 ms.
        assert!((stats.jitter_ms - 6.0).abs() < 1e-9);
    }

    #[tokio::test]
    async fn listen_refuses_non_loopback_before_any_socket() {
        assert!(matches!(
            SignedFrameTransport::listen("0.0.0.0:0").await.unwrap_err(),
            TransportError::NonLoopbackDenied
        ));
        assert!(matches!(
            SignedFrameTransport::listen("192.168.1.10:9000")
                .await
                .unwrap_err(),
            TransportError::NonLoopbackDenied
        ));
        assert!(matches!(
            SignedFrameTransport::listen("[::]:0").await.unwrap_err(),
            TransportError::NonLoopbackDenied
        ));
    }

    #[tokio::test]
    async fn listen_accepts_both_loopback_families() {
        let v4 = SignedFrameTransport::listen("127.0.0.1:0").await.unwrap();
        assert!(v4.local_addr().unwrap().ip().is_loopback());
        let v6 = SignedFrameTransport::listen("[::1]:0").await.unwrap();
        assert!(v6.local_addr().unwrap().ip().is_loopback());
    }
}
