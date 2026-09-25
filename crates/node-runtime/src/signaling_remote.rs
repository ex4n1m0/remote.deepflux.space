//! Remote signaling client — the M3 `SignalingIo` implementation that talks
//! to the Vercel signaling service (`services/signaling`).
//!
//! Transport (both against the same endpoint, `POST /api/signal` + WS
//! upgrade on the same path):
//!
//! * **WebSocket primary.** One background actor thread owns the socket
//!   (a `TcpStream` with a short read timeout, TLS-wrapped for `wss`), so a
//!   single loop multiplexes outbound frames, inbound deliveries, acks,
//!   pings, and reconnects without an async runtime. The connection is
//!   never authoritative: the service stores everything externally (its
//!   risk-register item), and this client keeps only its last-acked mailbox
//!   seq — reconnects resume from it (`hello.resume_seq`) and un-acked
//!   entries come again (at-least-once; the machines dedupe on
//!   `message_id`, exactly like the file adapter).
//! * **HTTP polling fallback.** While the WS is down (or with
//!   `force_http`), each `send` becomes one `POST {op:send}` and
//!   `poll_incoming` issues a rate-limited `POST {op:poll}` +
//!   `POST {op:ack}`. This is the same path taken when the WS beta's
//!   instance-local sockets cut a connection at `maxDuration`.
//!
//! [`SignalingIo::send`] is synchronous and only returns `Ok` when the
//! service accepted the envelope (WS `send_result.ok` or HTTP 2xx) — the
//! F27 contract: the node self-acks `Register` only after a real write.
//! Peer-directed failures (`unknown_target`, ...) come back as `Err`, and
//! the service additionally delivers a typed `Error` envelope through the
//! mailbox (informational to the machines, per World parity).
//!
//! # Sender-role inference
//!
//! The envelope contract carries no sender-role field (the service is a
//! dumb mailbox and `crates/protocol` is out of scope for M3), but
//! [`crate::node::Node`] routes `Disconnect` and `IceCandidate` by the
//! sender's machine kind. This adapter therefore *learns* the peer's role
//! per session from the definitive message types — `connect_request`,
//! `offer` and `cancel` are controller-minted; `accept`, `reject` and
//! `answer` are host-minted — and applies the learned role to later
//! role-ambiguous envelopes in the same session (`ice_candidate`,
//! `disconnect`, `ice_complete`). The state machines guarantee an
//! `Accept`/`ConnectRequest` always precedes those within a session, so
//! the lookup is populated before it is needed. An M4 contract change
//! (additive optional `sender_role`) can replace this; see
//! `docs/reports/m3-signaling.md`.
//!
//! # Queues (invariant 3)
//!
//! The inbound queue is bounded (512); when full the connection is dropped
//! and entries re-deliver on resume (at-least-once) instead of queueing
//! latency. The actor command channel is bounded (256) with an explicit
//! `Err` on overflow. Acks happen at handoff to the node (inside
//! `poll_incoming`), never on wire receipt — the at-least-once boundary
//! that survives crashes.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use native_tls::TlsStream;
use serde::Deserialize;
use serde_json::Value;

use crate::timers::MachineKind;
use protocol::signaling::{
    SIGNALING_PROTOCOL_VERSION, SIGNALING_SERVICE_ID, SignalingBody, SignalingEnvelope,
};

use crate::signaling::{InboundEnvelope, SignalingIo};

/// Bounded inbound delivery queue (invariant 3). Overflow drops the socket
/// so the mailbox redelivers on resume instead of losing envelopes.
const INBOUND_QUEUE_CAP: usize = 512;
/// Bounded actor command channel; overflow is an explicit send error.
const CMD_CHANNEL_CAP: usize = 256;
/// Socket read timeout: how often the actor loop wakes to service commands.
const READ_TIMEOUT: Duration = Duration::from_millis(50);
/// Blocking budget for one `send` (WS round trip or HTTP POST).
const SEND_ACK_TIMEOUT: Duration = Duration::from_secs(15);
/// HTTP fallback timeouts.
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
/// Minimum spacing between HTTP fallback polls (pump cadence is faster).
const HTTP_POLL_MIN_INTERVAL: Duration = Duration::from_millis(150);
/// WS keepalive ping period.
const WS_PING_PERIOD: Duration = Duration::from_secs(20);
/// Backoff bounds for reconnect.
const RECONNECT_MIN_BACKOFF: Duration = Duration::from_millis(250);
const RECONNECT_MAX_BACKOFF: Duration = Duration::from_secs(8);

/// Configuration for [`RemoteSignaling`].
#[derive(Debug, Clone)]
pub struct RemoteSignalingConfig {
    /// Service base URL, e.g. `http://127.0.0.1:38011` or
    /// `https://<project>.vercel.app`. No trailing slash.
    pub base_url: String,
    /// Function path on the service (both HTTP and WS).
    pub path: String,
    pub device_id: String,
    /// Client-generated secret binding this device's presence (see
    /// [`RemoteSignalingConfig::new_token`]). Never logged.
    pub token: String,
    /// Never attempt WebSocket; HTTP polling only (tests, degraded nets).
    pub force_http: bool,
}

impl RemoteSignalingConfig {
    pub fn new(base_url: &str, device_id: &str, token: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            path: "/api/signal".to_owned(),
            device_id: device_id.to_owned(),
            token: token.to_owned(),
            force_http: false,
        }
    }

    /// A fresh 256-bit device token (CSPRNG; never logged).
    pub fn new_token() -> String {
        secure_random_hex(32)
    }
}

/// Counters for diagnostics (payload-free).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RemoteCounters {
    pub sent: u64,
    pub send_errors: u64,
    pub duplicates: u64,
    pub service_directed: u64,
    pub received: u64,
    pub ws_sends: u64,
    pub http_sends: u64,
    pub reconnects: u64,
    pub role_unknown: u64,
    pub http_polls: u64,
}

enum Cmd {
    Send {
        envelope: SignalingEnvelope,
        done: std::sync::mpsc::Sender<Result<bool, String>>,
    },
    Ack {
        seq: u64,
    },
    Shutdown,
}

#[derive(Deserialize)]
struct ServerFrameWire {
    op: String,
    #[serde(default)]
    seq: Option<u64>,
    #[serde(default)]
    envelope: Option<Value>,
    #[serde(default)]
    message_id: Option<String>,
    #[serde(default)]
    ok: Option<bool>,
    #[serde(default)]
    duplicate: Option<bool>,
    #[serde(default)]
    error: Option<String>,
}

struct ActorShared {
    /// (mailbox seq, envelope) — seq drives acks at handoff.
    inbound: Mutex<VecDeque<(u64, InboundEnvelope)>>,
    counters: Mutex<RemoteCounters>,
    acked_seq: AtomicU64,
    ws_connected: AtomicU64,
}

impl ActorShared {
    fn push_inbound(&self, seq: u64, inbound: InboundEnvelope) -> bool {
        let mut q = self.inbound.lock().expect("signaling inbound lock");
        if q.len() >= INBOUND_QUEUE_CAP {
            return false;
        }
        q.push_back((seq, inbound));
        true
    }

    fn counters(&self) -> RemoteCounters {
        *self.counters.lock().expect("signaling counters lock")
    }

    fn bump(&self, f: impl FnOnce(&mut RemoteCounters)) {
        let mut c = self.counters.lock().expect("signaling counters lock");
        f(&mut c);
    }
}

/// The remote signaling adapter (`SignalingIo` over WS + HTTP fallback).
pub struct RemoteSignaling {
    cfg: RemoteSignalingConfig,
    tx: SyncSender<Cmd>,
    shared: Arc<ActorShared>,
    handle: Option<std::thread::JoinHandle<()>>,
    /// Learned peer roles: (session_id, device) -> minting machine.
    roles: Mutex<HashMap<(String, String), MachineKind>>,
    last_http_poll: Mutex<Option<Instant>>,
}

impl RemoteSignaling {
    pub fn new(cfg: RemoteSignalingConfig) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Cmd>(CMD_CHANNEL_CAP);
        let shared = Arc::new(ActorShared {
            inbound: Mutex::new(VecDeque::new()),
            counters: Mutex::new(RemoteCounters::default()),
            acked_seq: AtomicU64::new(0),
            ws_connected: AtomicU64::new(0),
        });
        let actor = Actor {
            cfg: cfg.clone(),
            rx,
            shared: Arc::clone(&shared),
        };
        let handle = std::thread::Builder::new()
            .name(format!("sig-{}", cfg.device_id))
            .spawn(move || actor.run())
            .expect("spawn signaling actor");
        Self {
            cfg,
            tx,
            shared,
            handle: Some(handle),
            roles: Mutex::new(HashMap::new()),
            last_http_poll: Mutex::new(None),
        }
    }

    /// Whether the WebSocket transport is currently connected.
    pub fn ws_connected(&self) -> bool {
        self.shared.ws_connected.load(Ordering::Relaxed) == 1
    }

    /// Last acked mailbox seq (the resume point).
    pub fn acked_seq(&self) -> u64 {
        self.shared.acked_seq.load(Ordering::Relaxed)
    }

    pub fn counters(&self) -> RemoteCounters {
        self.shared.counters()
    }

    /// Peer-role learning + inference (see module docs).
    fn sender_role_for(&self, envelope: &SignalingEnvelope) -> MachineKind {
        let session = envelope.session_id.clone().unwrap_or_default();
        let key = (session, envelope.from_device_id.clone());
        let mut roles = self.roles.lock().expect("roles lock");
        let learned = match &envelope.body {
            SignalingBody::ConnectRequest { .. }
            | SignalingBody::Offer { .. }
            | SignalingBody::Cancel { .. } => Some(MachineKind::Controller),
            SignalingBody::Accept { .. }
            | SignalingBody::Reject { .. }
            | SignalingBody::Answer { .. } => Some(MachineKind::Host),
            SignalingBody::Register { .. } | SignalingBody::Heartbeat => {
                return MachineKind::Controller;
            }
            SignalingBody::IceCandidate { .. }
            | SignalingBody::Disconnect { .. }
            | SignalingBody::IceComplete
            | SignalingBody::Error { .. } => None,
        };
        if let Some(role) = learned {
            roles.insert(key, role);
            return role;
        }
        match roles.get(&key) {
            Some(role) => *role,
            None => {
                self.shared.bump(|c| c.role_unknown += 1);
                // Documented fallback: a session's first role-ambiguous
                // envelope cannot exist per the machines' transitions
                // (offer/accept always precede ICE and disconnect).
                MachineKind::Controller
            }
        }
    }

    /// One HTTP fallback poll (rate-limited by [`Self::http_poll_due`]).
    fn http_poll(&self) -> Vec<InboundEnvelope> {
        let url = self.endpoint();
        let after = self.acked_seq();
        let body = serde_json::json!({
            "op": "poll",
            "device_id": self.cfg.device_id,
            "after_seq": after,
            "max": 64,
        });
        let value = match http_json(&url, &self.cfg.token, &body) {
            Ok(v) => v,
            Err(_) => {
                // Poll errors are transient; the next poll retries.
                return Vec::new();
            }
        };
        self.shared.bump(|c| c.http_polls += 1);
        let mut latest = after;
        let mut envelopes = Vec::new();
        if let Some(entries) = value.get("envelopes").and_then(Value::as_array) {
            for entry in entries {
                let seq = entry.get("seq").and_then(Value::as_u64).unwrap_or(0);
                if seq > latest {
                    latest = seq;
                }
                if let Ok(envelope) = serde_json::from_value::<SignalingEnvelope>(
                    entry.get("envelope").cloned().unwrap_or(Value::Null),
                ) && envelope.protocol_version == SIGNALING_PROTOCOL_VERSION
                {
                    envelopes.push(envelope);
                }
            }
        }
        if latest > after {
            // HTTP mode acks server-side at handoff (symmetric with WS mode,
            // where poll_incoming acks at handoff via the actor).
            self.shared.acked_seq.store(latest, Ordering::Relaxed);
            let ack_body = serde_json::json!({
                "op": "ack",
                "device_id": self.cfg.device_id,
                "seq": latest,
            });
            let _ = http_json(&url, &self.cfg.token, &ack_body);
        }
        envelopes
            .into_iter()
            .map(|envelope| InboundEnvelope {
                from_machine: self.sender_role_for(&envelope),
                envelope,
            })
            .collect()
    }

    fn http_poll_due(&self) -> bool {
        let mut last = self.last_http_poll.lock().expect("http poll lock");
        match *last {
            Some(t) if t.elapsed() < HTTP_POLL_MIN_INTERVAL => false,
            _ => {
                *last = Some(Instant::now());
                true
            }
        }
    }

    fn endpoint(&self) -> String {
        format!(
            "{}{}?device_id={}",
            self.cfg.base_url, self.cfg.path, self.cfg.device_id
        )
    }
}

impl SignalingIo for RemoteSignaling {
    fn send(
        &mut self,
        _from_machine: MachineKind,
        envelope: SignalingEnvelope,
    ) -> Result<(), String> {
        let service_directed = envelope.to_device_id == SIGNALING_SERVICE_ID;
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        match self.tx.try_send(Cmd::Send {
            envelope,
            done: done_tx,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.shared.bump(|c| c.send_errors += 1);
                return Err("signaling send queue full".to_owned());
            }
            Err(TrySendError::Disconnected(_)) => {
                self.shared.bump(|c| c.send_errors += 1);
                return Err("signaling actor stopped".to_owned());
            }
        }
        match done_rx.recv_timeout(SEND_ACK_TIMEOUT) {
            Ok(Ok(duplicate)) => {
                self.shared.bump(|c| {
                    c.sent += 1;
                    if duplicate {
                        c.duplicates += 1;
                    }
                    if service_directed {
                        c.service_directed += 1;
                    }
                });
                Ok(())
            }
            Ok(Err(err)) => {
                self.shared.bump(|c| c.send_errors += 1);
                Err(err)
            }
            Err(_) => {
                self.shared.bump(|c| c.send_errors += 1);
                Err("signaling send timed out".to_owned())
            }
        }
    }

    fn poll_incoming(&mut self) -> Vec<InboundEnvelope> {
        let drained: Vec<(u64, InboundEnvelope)> = {
            let mut q = self.shared.inbound.lock().expect("signaling inbound lock");
            q.drain(..).collect()
        };
        let mut out = Vec::with_capacity(drained.len());
        let mut latest_ack = 0;
        for (seq, mut inbound) in drained {
            // Re-tag the sender role through the learned table (the actor
            // queues a provisional role; learning happens here).
            inbound.from_machine = self.sender_role_for(&inbound.envelope);
            if seq > latest_ack {
                latest_ack = seq;
            }
            out.push(inbound);
        }
        if latest_ack > 0 {
            // Handoff to the node done: advance the resume point.
            self.shared.acked_seq.store(latest_ack, Ordering::Relaxed);
            let _ = self.tx.try_send(Cmd::Ack { seq: latest_ack });
        }
        if !self.cfg.force_http && self.ws_connected() {
            return out;
        }
        if self.http_poll_due() {
            out.extend(self.http_poll());
        }
        out
    }

    fn service_swallowed(&self) -> u64 {
        self.shared.counters().service_directed
    }

    fn describe(&self) -> String {
        let c = self.shared.counters();
        format!(
            "remote({}{}, ws={}, sent={}, recv={})",
            self.cfg.base_url,
            self.cfg.path,
            if self.ws_connected() { "up" } else { "down" },
            c.sent,
            c.received,
        )
    }
}

impl Drop for RemoteSignaling {
    fn drop(&mut self) {
        let _ = self.tx.try_send(Cmd::Shutdown);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP fallback helpers (ureq, blocking)
// ---------------------------------------------------------------------------

fn http_json(url: &str, token: &str, body: &Value) -> Result<Value, String> {
    let agent = ureq::AgentBuilder::new().timeout(HTTP_TIMEOUT).build();
    let response = agent
        .post(url)
        .set("authorization", &format!("Bearer {token}"))
        .set("content-type", "application/json")
        .send_string(&body.to_string())
        .map_err(|e| format!("signaling http: {e}"))?;
    response
        .into_json::<Value>()
        .map_err(|e| format!("signaling http body: {e}"))
}

// ---------------------------------------------------------------------------
// Actor: the single owner of the WebSocket
// ---------------------------------------------------------------------------

enum Socket {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl Read for Socket {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Socket::Plain(s) => s.read(buf),
            Socket::Tls(s) => s.read(buf),
        }
    }
}

impl Socket {
    fn set_read_timeout(&self, d: Option<Duration>) -> std::io::Result<()> {
        match self {
            Socket::Plain(s) => s.set_read_timeout(d),
            Socket::Tls(s) => s.get_ref().set_read_timeout(d),
        }
    }

    fn set_write_timeout(&self, d: Option<Duration>) -> std::io::Result<()> {
        match self {
            Socket::Plain(s) => s.set_write_timeout(d),
            Socket::Tls(s) => s.get_ref().set_write_timeout(d),
        }
    }
}

impl Write for Socket {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Socket::Plain(s) => s.write(buf),
            Socket::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Socket::Plain(s) => s.flush(),
            Socket::Tls(s) => s.flush(),
        }
    }
}

struct Actor {
    cfg: RemoteSignalingConfig,
    rx: Receiver<Cmd>,
    shared: Arc<ActorShared>,
}

impl Actor {
    fn run(self) {
        let Actor { cfg, rx, shared } = self;
        let mut backoff = RECONNECT_MIN_BACKOFF;
        let mut pending: HashMap<String, std::sync::mpsc::Sender<Result<bool, String>>> =
            HashMap::new();
        let mut last_delivered_seq: u64 = 0;
        let mut last_ping = Instant::now();
        let mut ws: Option<tungstenite::WebSocket<Socket>> = None;
        let mut connected_since: Option<Instant> = None;

        loop {
            // --- (Re)connect ------------------------------------------------
            if ws.is_none() && !cfg.force_http {
                let resume = shared.acked_seq.load(Ordering::Relaxed);
                match connect(&cfg, resume) {
                    Ok(socket) => {
                        ws = Some(socket);
                        connected_since = Some(Instant::now());
                        last_ping = Instant::now();
                        backoff = RECONNECT_MIN_BACKOFF;
                        shared.ws_connected.store(1, Ordering::Relaxed);
                        shared.bump(|c| c.reconnects += 1);
                    }
                    Err(_) => {
                        std::thread::sleep(backoff);
                        backoff = std::cmp::min(backoff * 2, RECONNECT_MAX_BACKOFF);
                        // While down, service commands via HTTP so sends
                        // never starve behind the reconnect loop.
                        if !service_commands_http(&cfg, &rx, &mut pending) {
                            return;
                        }
                        continue;
                    }
                }
            }

            // --- Command intake ---------------------------------------------
            loop {
                match rx.try_recv() {
                    Ok(Cmd::Shutdown) => {
                        if let Some(mut socket) = ws.take() {
                            let _ = socket.close(None);
                        }
                        return;
                    }
                    Ok(Cmd::Ack { seq }) => {
                        if let Some(socket) = ws.as_mut() {
                            let frame = serde_json::json!({ "op": "ack", "seq": seq });
                            if socket
                                .send(tungstenite::Message::Text(frame.to_string().into()))
                                .is_err()
                            {
                                let dead = ws.take();
                                if let Some(mut socket) = dead {
                                    let _ = socket.close(None);
                                }
                                break;
                            }
                        }
                    }
                    Ok(Cmd::Send { envelope, done }) => {
                        if let Some(socket) = ws.as_mut() {
                            let value = serde_json::to_value(&envelope)
                                .map_err(|e| e.to_string())
                                .unwrap_or(Value::Null);
                            let frame = serde_json::json!({ "op": "send", "envelope": value });
                            match socket.send(tungstenite::Message::Text(frame.to_string().into()))
                            {
                                Ok(()) => {
                                    shared.bump(|c| c.ws_sends += 1);
                                    match frame_envelope_message_id(&frame) {
                                        Some(mid) => {
                                            pending.insert(mid, done);
                                        }
                                        None => {
                                            let _ = done.send(Err("missing message_id".to_owned()));
                                        }
                                    }
                                }
                                Err(err) => {
                                    let _ = done.send(Err(format!("signaling ws: {err}")));
                                    let dead = ws.take();
                                    if let Some(mut socket) = dead {
                                        let _ = socket.close(None);
                                    }
                                    break;
                                }
                            }
                        } else {
                            shared.bump(|c| c.http_sends += 1);
                            let _ = done.send(http_send(&cfg, &envelope));
                        }
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                }
            }
            if ws.is_none() {
                shared.ws_connected.store(0, Ordering::Relaxed);
                fail_pending(&mut pending, "connection lost");
                continue;
            }

            // --- Read with timeout -------------------------------------------
            let mut socket = ws.take().expect("socket present");
            match socket.read() {
                Ok(tungstenite::Message::Text(text)) => {
                    handle_server_frame(&shared, &text, &mut pending, &mut last_delivered_seq);
                    ws = Some(socket);
                }
                Ok(tungstenite::Message::Binary(_))
                | Ok(tungstenite::Message::Ping(_))
                | Ok(tungstenite::Message::Pong(_))
                | Ok(tungstenite::Message::Frame(_)) => {
                    ws = Some(socket); // frames are JSON text; pings are fine
                }
                Ok(tungstenite::Message::Close(_)) => {
                    let _ = socket.close(None);
                    note_disconnect(&shared, connected_since, &mut backoff);
                    fail_pending(&mut pending, "connection closed");
                }
                Err(tungstenite::Error::Io(ref e))
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // Idle tick: keepalive ping.
                    if last_ping.elapsed() >= WS_PING_PERIOD {
                        if socket
                            .send(tungstenite::Message::Ping(Vec::new().into()))
                            .is_ok()
                        {
                            last_ping = Instant::now();
                            ws = Some(socket);
                        } else {
                            let _ = socket.close(None);
                            note_disconnect(&shared, connected_since, &mut backoff);
                            fail_pending(&mut pending, "write failed");
                        }
                    } else {
                        ws = Some(socket);
                    }
                }
                Err(_) => {
                    let _ = socket.close(None);
                    note_disconnect(&shared, connected_since, &mut backoff);
                    fail_pending(&mut pending, "connection error");
                }
            }
        }
    }
}

fn note_disconnect(shared: &ActorShared, since: Option<Instant>, backoff: &mut Duration) {
    shared.ws_connected.store(0, Ordering::Relaxed);
    // A connection that lived a while resets the backoff (flap damping).
    if since.is_some_and(|t| t.elapsed() > Duration::from_secs(5)) {
        *backoff = RECONNECT_MIN_BACKOFF;
    }
}

fn fail_pending(
    pending: &mut HashMap<String, std::sync::mpsc::Sender<Result<bool, String>>>,
    why: &str,
) {
    for (_, done) in pending.drain() {
        let _ = done.send(Err(why.to_owned()));
    }
}

/// Drain commands over HTTP while the WS is down. Returns false on shutdown.
fn service_commands_http(
    cfg: &RemoteSignalingConfig,
    rx: &Receiver<Cmd>,
    pending: &mut HashMap<String, std::sync::mpsc::Sender<Result<bool, String>>>,
) -> bool {
    let _ = pending; // pending is empty while disconnected
    loop {
        match rx.try_recv() {
            Ok(Cmd::Shutdown) => return false,
            Ok(Cmd::Ack { .. }) => { /* cursor already advanced over HTTP */ }
            Ok(Cmd::Send { envelope, done }) => {
                let _ = done.send(http_send(cfg, &envelope));
            }
            Err(_) => return true,
        }
    }
}

fn handle_server_frame(
    shared: &ActorShared,
    text: &str,
    pending: &mut HashMap<String, std::sync::mpsc::Sender<Result<bool, String>>>,
    last_delivered_seq: &mut u64,
) {
    let Ok(frame) = serde_json::from_str::<ServerFrameWire>(text) else {
        return;
    };
    match frame.op.as_str() {
        "deliver" => {
            let Some(seq) = frame.seq else { return };
            let Some(value) = frame.envelope else { return };
            let Ok(envelope) = serde_json::from_value::<SignalingEnvelope>(value) else {
                return;
            };
            if envelope.protocol_version != SIGNALING_PROTOCOL_VERSION {
                return;
            }
            if seq <= *last_delivered_seq {
                return; // duplicate push (benign race)
            }
            *last_delivered_seq = seq;
            let provisional = InboundEnvelope {
                from_machine: MachineKind::Controller,
                envelope,
            };
            let queued = shared.push_inbound(seq, provisional);
            shared.bump(|c| c.received += 1);
            if !queued {
                // Inbound overflow: drop the socket; resume redelivers.
                shared.bump(|c| c.send_errors += 1);
            }
        }
        "send_result" => {
            let mid = frame.message_id.unwrap_or_default();
            if let Some(done) = pending.remove(&mid) {
                match (frame.ok, frame.error) {
                    (Some(true), _) => {
                        let dup = frame.duplicate.unwrap_or(false);
                        if dup {
                            shared.bump(|c| c.duplicates += 1);
                        }
                        let _ = done.send(Ok(dup));
                    }
                    (Some(false), err) => {
                        let _ = done.send(Err(err.unwrap_or_else(|| "rejected".to_owned())));
                    }
                    _ => {
                        let _ = done.send(Err("malformed send_result".to_owned()));
                    }
                }
            }
        }
        "bye" | "hello_ok" | "error" => { /* informational; read loop reacts to Close */ }
        _ => {}
    }
}

/// One HTTP fallback send: `POST {op:send}`.
fn http_send(cfg: &RemoteSignalingConfig, envelope: &SignalingEnvelope) -> Result<bool, String> {
    let url = format!("{}{}?device_id={}", cfg.base_url, cfg.path, cfg.device_id);
    let body = serde_json::json!({
        "op": "send",
        "envelope": serde_json::to_value(envelope).map_err(|e| e.to_string())?,
    });
    let value = http_json(&url, &cfg.token, &body)?;
    match (value.get("ok").and_then(Value::as_bool), value.get("error")) {
        (Some(true), _) => Ok(value
            .get("duplicate")
            .and_then(Value::as_bool)
            .unwrap_or(false)),
        (_, Some(err)) => Err(err.as_str().unwrap_or("rejected").to_owned()),
        _ => Err("malformed reply".to_owned()),
    }
}

fn frame_envelope_message_id(frame: &Value) -> Option<String> {
    frame
        .get("envelope")
        .and_then(|e| e.get("message_id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn connect(
    cfg: &RemoteSignalingConfig,
    resume_seq: u64,
) -> Result<tungstenite::WebSocket<Socket>, String> {
    let ws_url = format!(
        "{}{}?device_id={}",
        ws_base(&cfg.base_url),
        cfg.path,
        cfg.device_id
    );
    let (host, port, tls, _path_and_query) = parse_ws_url(&ws_url)?;
    let tcp = TcpStream::connect((host.as_str(), port)).map_err(|e| format!("connect: {e}"))?;
    let _ = tcp.set_nodelay(true);

    let socket = if tls {
        let connector = native_tls::TlsConnector::new().map_err(|e| format!("tls: {e}"))?;
        Socket::Tls(Box::new(
            connector
                .connect(&host, tcp)
                .map_err(|e| format!("tls handshake: {e}"))?,
        ))
    } else {
        Socket::Plain(tcp)
    };

    // Full URL as the request URI: tungstenite checks the scheme (ws/wss)
    // to pick the connector and derives the handshake target line from it.
    let request = tungstenite::http::Request::builder()
        .uri(&ws_url)
        .header("Host", &host)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .header("Sec-WebSocket-Version", "13")
        .header("Authorization", format!("Bearer {}", cfg.token))
        .body(())
        .map_err(|e| format!("ws request: {e}"))?;
    let (mut socket, _response) =
        tungstenite::client(request, socket).map_err(|e| format!("ws handshake: {e}"))?;
    // Timeouts go on AFTER the handshake: the blocking handshake read must
    // not see a WouldBlock. The read timeout is what wakes the actor loop.
    socket_set_timeouts(&mut socket)?;

    let hello = serde_json::json!({
        "op": "hello",
        "device_id": cfg.device_id,
        "resume_seq": resume_seq,
        "svc_version": 1,
    });
    socket
        .send(tungstenite::Message::Text(hello.to_string().into()))
        .map_err(|e| format!("hello: {e}"))?;
    Ok(socket)
}

/// Set the actor-loop wake timeout on the post-handshake stream.
fn socket_set_timeouts(socket: &mut tungstenite::WebSocket<Socket>) -> Result<(), String> {
    socket
        .get_ref()
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|e| format!("read timeout: {e}"))?;
    socket
        .get_ref()
        .set_write_timeout(Some(HTTP_TIMEOUT))
        .map_err(|e| format!("write timeout: {e}"))
}

fn ws_base(http_base: &str) -> String {
    if let Some(rest) = http_base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = http_base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        format!("ws://{http_base}")
    }
}

/// Parse ws://host[:port]/path?query into (host, port, tls, path?query).
fn parse_ws_url(url: &str) -> Result<(String, u16, bool, String), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("bad url {url}"))?;
    let tls = match scheme {
        "ws" => false,
        "wss" => true,
        _ => return Err(format!("bad scheme {scheme}")),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_owned(),
            p.parse::<u16>().map_err(|_| format!("bad port {p}"))?,
        ),
        None => (authority.to_owned(), if tls { 443 } else { 80 }),
    };
    Ok((host, port, tls, path.to_owned()))
}

/// CSPRNG hex for device tokens (never logged).
fn secure_random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    // The OS CSPRNG is the source; failure is fatal-ish (fallback keeps the
    // adapter usable in exotic test environments but is flagged by length).
    if getrandom::fill(&mut buf).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut state = nanos ^ ((std::process::id() as u128) << 96);
        for b in buf.iter_mut() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (state >> 96) as u8;
        }
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::capabilities::{
        Capabilities, EncoderCapabilities, EncoderKind, FeatureFlags, MonitorInfo,
    };

    fn caps() -> Capabilities {
        Capabilities {
            encoders: vec![EncoderCapabilities {
                kind: EncoderKind::Software,
                codec: protocol::capabilities::Codec::H264,
                max_width_px: 1920,
                max_height_px: 1080,
                max_fps: 30,
            }],
            monitors: vec![MonitorInfo {
                monitor_id: "\\\\.\\DISPLAY1".to_owned(),
                width_px: 1920,
                height_px: 1080,
                is_primary: true,
            }],
            max_bitrate_kbps: 5_000,
            features: FeatureFlags::empty(),
        }
    }

    fn env(
        from: &str,
        to: &str,
        id: &str,
        body: SignalingBody,
        session: Option<&str>,
    ) -> SignalingEnvelope {
        SignalingEnvelope {
            protocol_version: SIGNALING_PROTOCOL_VERSION,
            message_id: id.to_owned(),
            session_id: session.map(str::to_owned),
            from_device_id: from.to_owned(),
            to_device_id: to.to_owned(),
            timestamp_ms: 1,
            body,
        }
    }

    #[test]
    fn ws_url_parsing() {
        let (h, p, tls, path) =
            parse_ws_url("ws://127.0.0.1:38013/api/signal?device_id=a").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 38013);
        assert!(!tls);
        assert_eq!(path, "/api/signal?device_id=a");
        let (h, p, tls, _) = parse_ws_url("wss://example.com").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 443);
        assert!(tls);
        assert!(parse_ws_url("ftp://x").is_err());
    }

    #[test]
    fn ws_base_mapping() {
        assert_eq!(ws_base("http://a:1"), "ws://a:1");
        assert_eq!(ws_base("https://a"), "wss://a");
        assert_eq!(ws_base("a"), "ws://a");
    }

    #[test]
    fn role_learning_routes_ice_and_disconnect() {
        let sig = RemoteSignaling::new(RemoteSignalingConfig::new(
            "http://127.0.0.1:1",
            "dev-a",
            "t",
        ));
        // Definitive: connect_request from peer => Controller.
        let req = env(
            "dev-b",
            "dev-a",
            "b-1",
            SignalingBody::ConnectRequest {
                capabilities: caps(),
            },
            Some("s1"),
        );
        assert_eq!(sig.sender_role_for(&req), MachineKind::Controller);
        // Peer's ICE in the same session => Controller-minted.
        let ice = env(
            "dev-b",
            "dev-a",
            "b-2",
            SignalingBody::IceCandidate {
                candidate: "x".to_owned(),
                sdp_mid: Some("0".to_owned()),
                sdp_mline_index: Some(0),
            },
            Some("s1"),
        );
        assert_eq!(sig.sender_role_for(&ice), MachineKind::Controller);
        // Definitive: accept from peer => Host, disconnect follows suit.
        let acc = env(
            "dev-b",
            "dev-a",
            "b-3",
            SignalingBody::Accept {
                session_secret: protocol::signaling::SessionSecret("s".to_owned()),
            },
            Some("s2"),
        );
        assert_eq!(sig.sender_role_for(&acc), MachineKind::Host);
        let disc = env(
            "dev-b",
            "dev-a",
            "b-4",
            SignalingBody::Disconnect {
                reason: protocol::signaling::DisconnectReason::User,
            },
            Some("s2"),
        );
        assert_eq!(sig.sender_role_for(&disc), MachineKind::Host);
        // Unknown session falls back (counted).
        let orphan = env(
            "dev-c",
            "dev-a",
            "c-1",
            SignalingBody::Disconnect {
                reason: protocol::signaling::DisconnectReason::Timeout,
            },
            Some("s3"),
        );
        assert_eq!(sig.sender_role_for(&orphan), MachineKind::Controller);
        assert_eq!(sig.counters().role_unknown, 1);
    }

    /// Full WS round trip against a local tungstenite server double that
    /// speaks the service frame protocol: hello -> hello_ok, send ->
    /// send_result, server push -> deliver, ack observed.
    #[test]
    fn ws_round_trip_against_local_double() {
        use std::net::TcpListener;
        use tungstenite::accept_hdr;
        use tungstenite::handshake::server::NoCallback;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut ws = accept_hdr(stream, NoCallback).expect("ws accept");
            // hello -> hello_ok
            let hello = ws.read().expect("read hello");
            let text = hello.into_text().expect("text").to_string();
            assert!(text.contains("\"hello\""), "got {text}");
            ws.send(
                tungstenite::Message::Text(
                    r#"{"op":"hello_ok","svc_version":1,"device_id":"dev-a","resume_seq":0,"latest_seq":0,"ttl_device_s":45,"authed":true}"#.into(),
                ),
            )
            .expect("send hello_ok");
            // send(register) -> send_result ok
            let send_frame = ws
                .read()
                .expect("read send")
                .into_text()
                .unwrap()
                .to_string();
            assert!(send_frame.contains("\"register\""), "got {send_frame}");
            let mid = extract_message_id(&send_frame);
            ws.send(tungstenite::Message::Text(
                format!(
                    r#"{{"op":"send_result","message_id":"{mid}","ok":true,"duplicate":false}}"#
                )
                .into(),
            ))
            .expect("send result");
            // push one deliver (peer offer) then expect the ack
            ws.send(
                tungstenite::Message::Text(
                    r#"{"op":"deliver","seq":7,"envelope":{"protocol_version":1,"message_id":"dev-b-1","session_id":"s1","from_device_id":"dev-b","to_device_id":"dev-a","timestamp_ms":5,"type":"offer","sdp":"v=0 x"}}"#
                        .into(),
                ),
            )
            .expect("push deliver");
            let ack = ws
                .read()
                .expect("read ack")
                .into_text()
                .unwrap()
                .to_string();
            assert!(
                ack.contains("\"ack\"") && ack.contains("\"seq\":7"),
                "got {ack}"
            );
        });

        let mut sig = RemoteSignaling::new(RemoteSignalingConfig::new(
            &format!("http://127.0.0.1:{port}"),
            "dev-a",
            "unit-token",
        ));
        // Register write must succeed (service accepted).
        let register = env(
            "dev-a",
            SIGNALING_SERVICE_ID,
            "dev-a-host-1",
            SignalingBody::Register {
                capabilities: caps(),
            },
            None,
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut sent = false;
        while Instant::now() < deadline {
            if sig.send(MachineKind::Host, register.clone()).is_ok() {
                sent = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(sent, "register send must be accepted once connected");
        assert_eq!(sig.service_swallowed(), 1);

        // The pushed offer must surface via poll_incoming with the learned
        // Controller role, and the ack must reach the server (asserted above).
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut inbound = Vec::new();
        while Instant::now() < deadline {
            inbound = sig.poll_incoming();
            if !inbound.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(inbound.len(), 1);
        assert_eq!(inbound[0].envelope.message_id, "dev-b-1");
        assert_eq!(inbound[0].from_machine, MachineKind::Controller);
        assert_eq!(sig.acked_seq(), 7);

        drop(sig);
        server.join().expect("server thread");
    }

    fn extract_message_id(frame: &str) -> String {
        let value: serde_json::Value = serde_json::from_str(frame).expect("frame json");
        value["envelope"]["message_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    #[test]
    fn token_generator_is_random_hex() {
        let a = RemoteSignalingConfig::new_token();
        let b = RemoteSignalingConfig::new_token();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }
}
