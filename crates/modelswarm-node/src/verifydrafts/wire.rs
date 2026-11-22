//! The transport port for the VerifyDrafts family (feature `verifydrafts`).
//!
//! ADR-032's frames are bare JSON objects riding the ADR-018 amended
//! staging — raw-JSON passthrough frames over a handshake-authenticated
//! session — and the remote PeerId must be TRANSPORT-authenticated (msp-v1
//! §6.6; security review RC-1). This module defines that surface as the
//! [`VerifyDraftsWire`] port plus two concrete implementations:
//!
//! - [`StagedVerifyWire`] over the staged TCP backend
//!   ([`modelswarm_transport::SignedFrameTransport`]) — the CI venue with
//!   the staged §6.1 handshake;
//! - [`QuicVerifyWire`] over the REAL libp2p QUIC backend
//!   ([`modelswarm_transport::libp2p_backend::Libp2pSession`]) — the
//!   production venue. The 2026-10-12 transport passthrough
//!   (`Libp2pSession::send_json`/`recv_json`, same stash discipline as the
//!   staged `Session`) closed the light-up handoff's G1 gap, and the QUIC
//!   handshake authenticates the remote PeerId cryptographically (the
//!   staged adapter's address/key pinning was the staging approximation of
//!   exactly that binding).
//!
//! The staged adapter owns one pump task per session: `recv_json` on the
//! staged `Session` closes the session on deadline expiry, which would make
//! WAIT_COMMIT expiry polling (RC-5(b)) destructive. The pump isolates the
//! session behind channels, so a caller-side `recv` timeout is a pure
//! wake-up — the session stays open and no frame is lost (`mpsc` recv is
//! cancel-safe, and the pump's `select!` never drops a completed arm).
//!
//! The QUIC adapter needs NO pump: a `Libp2pSession` recv timeout is
//! non-destructive by construction (the backend keeps mid-frame bytes in a
//! session-owned buffer, so a cancelled recv resumes the same frame), and
//! the port's recv/send deadlines map straight through.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::timeout;

use modelswarm_identity::{peer_id_for, InstallationIdentity};
use modelswarm_transport::ed25519_dalek::VerifyingKey;
use modelswarm_transport::libp2p_backend::{
    Libp2pListener, Libp2pSession, Libp2pTransport, PeerId,
};
use modelswarm_transport::{Handshake, Listener, Session, SignedFrameTransport, TransportError};

/// Bounded channel depth between the pump and the caller (frames).
const CHANNEL_CAPACITY: usize = 32;

/// The pump's own recv deadline: effectively "never" — a staged-backend
/// recv timeout CLOSES the session, and the pump must not be the one to
/// enforce caller deadlines (the caller's wake-ups live on the channel).
const PUMP_RECV_IDLE: Duration = Duration::from_secs(60 * 60 * 24 * 7);

/// Error surface of the port — caller deadlines never kill the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The caller's deadline elapsed (a wake-up; the session is untouched).
    Timeout,
    /// The session is gone (peer closed, transport failure, pump exited).
    Closed,
    /// Transport-level I/O failure; the string is a short local label,
    /// never peer-supplied payload text.
    Io(String),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Timeout => write!(f, "deadline elapsed (session unaffected)"),
            WireError::Closed => write!(f, "session closed"),
            WireError::Io(why) => write!(f, "transport io failure: {why}"),
        }
    }
}

impl std::error::Error for WireError {}

/// The family's transport port: bare JSON frames over an authenticated
/// session, with the remote PeerId as authenticated by the transport
/// itself (RC-1: never peer-supplied).
#[async_trait]
pub trait VerifyDraftsWire: Send {
    /// Sends one family frame (serialized exactly as given — the staged
    /// backend frames the raw JSON without a typed envelope).
    async fn send_json(&mut self, value: &Value, deadline: Duration) -> Result<(), WireError>;

    /// Receives the next family frame. A timeout is a WAKE-UP, not a
    /// session failure — implementations MUST keep the session open so the
    /// serve loop can poll the WAIT_COMMIT bound (RC-5(b)).
    async fn recv_json(&mut self, deadline: Duration) -> Result<Value, WireError>;

    /// The transport-authenticated remote PeerId (ADR-020 `12D3Koo…` form).
    fn remote_peer_id(&self) -> &str;
}

fn wire_error_of(e: TransportError) -> WireError {
    match e {
        TransportError::Timeout => WireError::Timeout,
        TransportError::Closed => WireError::Closed,
        other => WireError::Io(other.to_string()),
    }
}

/// Staged-backend adapter: one pump task owning the [`Session`], exposing
/// channel-based send/recv plus the authenticated remote PeerId.
pub struct StagedVerifyWire {
    outbound: mpsc::Sender<Value>,
    inbound: mpsc::Receiver<Result<Value, WireError>>,
    peer_id: String,
}

impl StagedVerifyWire {
    /// Wraps an already-authenticated staged session (server side: from
    /// [`Listener::accept_with`]; client side: from
    /// [`SignedFrameTransport::connect`]). `peer_id` MUST be the
    /// authenticated remote identity, not a claim out of a payload.
    pub fn over_session(session: Session, peer_id: String) -> Self {
        let (out_tx, mut out_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (in_tx, in_rx) = mpsc::channel(CHANNEL_CAPACITY);
        tokio::spawn(async move {
            let mut session = session;
            loop {
                // `biased` with the inbound arm first: an inbound frame that
                // is ready is always taken before an outbound send runs, so
                // no received frame is ever dropped in favor of a send. The
                // losing arm's future was last polled Pending, and both
                // channel recv futures are cancel-safe — nothing is lost.
                tokio::select! {
                    biased;
                    inbound = session.recv_json(PUMP_RECV_IDLE) => {
                        let mapped = inbound.map_err(wire_error_of);
                        let terminal = mapped.is_err();
                        if in_tx.send(mapped).await.is_err() {
                            break; // caller gone
                        }
                        if terminal {
                            break; // session is dead; surfacing once is enough
                        }
                    }
                    outbound = out_rx.recv() => {
                        match outbound {
                            Some(value) => {
                                if session
                                    .send_json(&value, super::FAMILY_IO_DEADLINE)
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            None => break, // caller dropped the wire handle
                        }
                    }
                }
            }
        });
        Self {
            outbound: out_tx,
            inbound: in_rx,
            peer_id,
        }
    }
}

#[async_trait]
impl VerifyDraftsWire for StagedVerifyWire {
    async fn send_json(&mut self, value: &Value, deadline: Duration) -> Result<(), WireError> {
        match timeout(deadline, self.outbound.send(value.clone())).await {
            Ok(Ok(())) => Ok(()),
            // Pump gone: the session died with it.
            Ok(Err(_send_failed)) => Err(WireError::Closed),
            // Cancel-safe channel send: on timeout the frame was never
            // enqueued — the session is unaffected.
            Err(_elapsed) => Err(WireError::Timeout),
        }
    }

    async fn recv_json(&mut self, deadline: Duration) -> Result<Value, WireError> {
        match timeout(deadline, self.inbound.recv()).await {
            Ok(Some(result)) => result,
            Ok(None) => Err(WireError::Closed),
            Err(_elapsed) => Err(WireError::Timeout),
        }
    }

    fn remote_peer_id(&self) -> &str {
        &self.peer_id
    }
}

/// Accepts one cooperative session on `listener`, resolving the client's
/// claimed handshake PeerId against `trusted_peers` (the peer directory;
/// the tracker roster in production, a fixed map in tests).
///
/// `Listener::accept_with` verifies the handshake signature under the
/// resolved key AND pins `peer_id`/`installation_id` to that key
/// (`verify_handshake`), so the PeerId captured here is authenticated —
/// this is the staged-backend equivalent of the QUIC-authenticated remote
/// PeerId.
pub async fn accept_staged(
    listener: &Listener,
    trusted_peers: &HashMap<String, VerifyingKey>,
    deadline: Duration,
) -> Result<StagedVerifyWire, TransportError> {
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&captured);
    let trusted = trusted_peers.clone();
    let session = listener
        .accept_with(
            move |handshake: &Handshake| {
                if let Ok(mut slot) = seen.lock() {
                    *slot = Some(handshake.peer_id.clone());
                }
                trusted.get(&handshake.peer_id).cloned()
            },
            deadline,
        )
        .await?;
    let peer_id = captured
        .lock()
        .ok()
        .and_then(|mut slot| slot.take())
        .ok_or_else(|| {
            TransportError::HandshakeFailed("handshake peer id not captured".to_string())
        })?;
    Ok(StagedVerifyWire::over_session(session, peer_id))
}

/// Dials a cooperative peer on the staged backend and returns the wire with
/// the pinned server PeerId.
///
/// Honest staging note (the backend's own doc): the server's ack is
/// unsigned — server authentication rests on the verified channel/address
/// pairing; the cryptographic PeerId binding arrives with the libp2p QUIC
/// backend. Callers pin `expected_server` and the reported PeerId is that
/// pinned derivation, never a payload claim.
pub async fn dial_staged(
    addr: &str,
    identity: &InstallationIdentity,
    profile_id: &str,
    expected_server: &VerifyingKey,
    deadline: Duration,
) -> Result<StagedVerifyWire, TransportError> {
    let handshake = Handshake::build(
        identity,
        profile_id,
        "modelswarm-node",
        env!("CARGO_PKG_VERSION"),
    );
    let session = SignedFrameTransport::connect(addr, handshake, deadline).await?;
    Ok(StagedVerifyWire::over_session(
        session,
        peer_id_for(&expected_server.to_bytes()),
    ))
}

// ---------------------------------------------------------------------------
// QUIC venue (the production transport; the light-up handoff's G1 follow-up)
// ---------------------------------------------------------------------------

/// How long the wire's graceful teardown waits for the peer to drain the
/// last frame before the underlying session drops (the msp-v1 bridge's
/// `linger` bound; see [`Libp2pSession::close_graceful`]).
const GRACEFUL_CLOSE_DRAIN: Duration = Duration::from_secs(1);

/// QUIC adapter over [`Libp2pSession`]: the family's raw-JSON frames ride the
/// libp2p backend's passthrough directly, and the remote PeerId is the
/// QUIC-TLS-authenticated identity (ADR-020 derivation) — RC-1's
/// transport-authenticated PeerId by construction, not a payload claim and
/// not a resolver-directory approximation.
///
/// No pump task: a `Libp2pSession` recv timeout is a non-destructive
/// wake-up (mid-frame bytes survive cancellation in the session's own
/// buffer), so the serve loop can poll WAIT_COMMIT bounds straight through
/// this adapter — the property the staged adapter needs its pump for.
///
/// Teardown is graceful BY CONSTRUCTION: dropping the wire FINs the stream
/// and gives the peer a bounded drain window (spawned; see [`Drop`]), so a
/// caller's last sent frame — e.g. the client's final `PrefixCommit` or the
/// server's `SessionReject` — is delivered before the connection closes.
/// A bare quinn drop would send CONNECTION_CLOSE immediately and could
/// overtake queued frames (the race the transport's
/// [`Libp2pSession::close_graceful`] exists for).
pub struct QuicVerifyWire {
    session: Option<Libp2pSession>,
    peer_id: String,
}

impl QuicVerifyWire {
    /// Wraps an accepted or dialled libp2p session; `remote_peer_id()` is
    /// the QUIC-authenticated remote for the session's whole lifetime.
    pub fn over_session(session: Libp2pSession) -> Self {
        Self {
            peer_id: session.remote_peer_id().to_string(),
            session: Some(session),
        }
    }

    fn session(&mut self) -> &mut Libp2pSession {
        self.session
            .as_mut()
            .expect("the session is present until drop")
    }
}

impl Drop for QuicVerifyWire {
    fn drop(&mut self) {
        let Some(mut session) = self.session.take() else {
            return;
        };
        // Outside a runtime a graceful drain is impossible; the drop then
        // keeps the plain (abrupt) semantics.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                session.close_graceful(GRACEFUL_CLOSE_DRAIN).await;
            });
        }
    }
}

#[async_trait]
impl VerifyDraftsWire for QuicVerifyWire {
    async fn send_json(&mut self, value: &Value, deadline: Duration) -> Result<(), WireError> {
        self.session()
            .send_json(value, deadline)
            .await
            .map_err(wire_error_of)
    }

    async fn recv_json(&mut self, deadline: Duration) -> Result<Value, WireError> {
        self.session()
            .recv_json(deadline)
            .await
            .map_err(wire_error_of)
    }

    fn remote_peer_id(&self) -> &str {
        &self.peer_id
    }
}

/// Accepts one cooperative session on a libp2p QUIC listener. There is no
/// resolver directory to consult: the QUIC handshake itself authenticates
/// the remote PeerId, which [`QuicVerifyWire`] reports and the serve loop
/// pins the coordinator key from.
pub async fn accept_quic(
    listener: &mut Libp2pListener,
    deadline: Duration,
) -> Result<QuicVerifyWire, TransportError> {
    Ok(QuicVerifyWire::over_session(
        listener.accept(deadline).await?,
    ))
}

/// Hands one already-read frame back to a serve loop pre-read: the first
/// `recv_json` returns [`Self::first`], everything after delegates to the
/// wrapped wire. The composed daemon's demux and the session-open lease
/// gate read frames straight off the session (to classify and gate BEFORE
/// any engine work); this wrapper then feeds the winning frame to the
/// venue-agnostic serve loop — never decoded twice, never dropped.
pub struct PrefacedWire<W> {
    first: Option<Value>,
    inner: W,
}

impl<W> PrefacedWire<W> {
    /// Wraps `inner`, replaying `first` on the next `recv_json`.
    pub fn new(inner: W, first: Option<Value>) -> Self {
        Self { first, inner }
    }
}

#[async_trait]
impl<W: VerifyDraftsWire> VerifyDraftsWire for PrefacedWire<W> {
    async fn send_json(&mut self, value: &Value, deadline: Duration) -> Result<(), WireError> {
        self.inner.send_json(value, deadline).await
    }

    async fn recv_json(&mut self, deadline: Duration) -> Result<Value, WireError> {
        match self.first.take() {
            Some(value) => Ok(value),
            None => self.inner.recv_json(deadline).await,
        }
    }

    fn remote_peer_id(&self) -> &str {
        self.inner.remote_peer_id()
    }
}

/// Dials a cooperative peer over QUIC. The connected PeerId is verified
/// against the pinned server key's ADR-020 derivation (an impostor fails
/// the binding inside `dial`), and the returned wire reports that pinned
/// derivation — never a payload claim.
pub async fn dial_quic(
    addr: &str,
    identity: &InstallationIdentity,
    expected_server: &VerifyingKey,
    deadline: Duration,
) -> Result<QuicVerifyWire, TransportError> {
    let transport = Libp2pTransport::new(identity)?;
    let expected: PeerId = peer_id_for(&expected_server.to_bytes())
        .parse()
        .map_err(|e| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("expected server key does not derive a valid peer id: {e}"),
            ))
        })?;
    Ok(QuicVerifyWire::over_session(
        transport.dial(addr, &expected, deadline).await?,
    ))
}
