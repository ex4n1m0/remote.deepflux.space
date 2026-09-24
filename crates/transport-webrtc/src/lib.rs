//! # `transport-webrtc` — direct peer transport behind the `Transport` trait
//!
//! Platform boundary for the WebRTC data plane (invariant 7; ADR-002). All
//! `webrtc-rs` types, SDP plumbing, ICE/STUN handling, RTP packetization, and
//! RTCP feedback stay inside this crate. The rest of the system sees only
//! [`Transport`] and [`TransportEvent`]. TURN is forbidden in MVP (invariant
//! 4): no TURN servers may be configured, and relayed candidate types must be
//! rejected at the configuration layer.
//!
//! Channel layout mirrors `protocol::wire`:
//! `control` (ordered/reliable), `input-fast` (unordered, maxRetransmits 0),
//! `input-reliable` (ordered/reliable), `cursor` (latest-state).
//!
//! M0 pins the trait shape with a poll-based API (deterministic, mockable,
//! no async runtime dependency). M2 (RD-006/007/008) provides the `webrtc-rs`
//! implementation; it may add async plumbing *inside* the crate but the
//! public surface must remain runtime-agnostic. The libwebrtc fallback swap
//! (source plan frozen decision) replaces this crate's implementation while
//! preserving the trait — see ADR-002 for the seam mechanics.

use protocol::wire::WireMessage;

/// Data-channel selectors. Exactly the four channels from the source plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Control,
    InputFast,
    InputReliable,
    Cursor,
}

/// Events surfaced by the transport to the node runtime. The runtime
/// translates these into `session::HostEvent`/`ControllerEvent` and pipeline
/// control — the transport never talks to the state machines directly.
#[derive(Debug)]
pub enum TransportEvent {
    /// A data-channel message arrived. Already version-checked by the
    /// transport; unknown versions surface as `ProtocolError`.
    Message(Channel, WireMessage),
    /// All channels are open and media may flow (maps to `DataChannelOpen`).
    ChannelsOpen,
    /// Peer connection state changed (connected/disconnected/failed).
    ConnectionStateChanged(ConnectionState),
    /// SDP offer/answer produced locally (in response to `compose_offer` /
    /// `compose_answer` from the session machines).
    LocalAnswer { sdp: String },
    /// ICE selected a new candidate pair, or a candidate trickled in
    /// (forwarded over signaling by the runtime). `sdp_mid` is the JSEP
    /// string mid (protocol version 1, QA F9).
    IceCandidate {
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
    },
    /// Transport-level failure (ICE dead, DTLS error, protocol violation).
    /// The runtime maps this to `TransportFailed`.
    Failed { reason: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    New,
    Connecting,
    Connected,
    Disconnected,
    Failed,
    Closed,
}

#[derive(Debug)]
pub struct TransportError(pub String);

impl core::fmt::Display for TransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "transport failed: {}", self.0)
    }
}

impl std::error::Error for TransportError {}

/// Narrow boundary over the direct peer connection.
///
/// Send-side backpressure (invariant 3): every internal channel queue is
/// bounded; when `input-fast`/`cursor` are full, the newest message replaces
/// the queued one. Reliable channels return an error rather than growing.
pub trait Transport: Send {
    /// Create the local SDP offer (controller role). Raises
    /// `TransportEvent::LocalAnswer`-style plumbing in M2; M0 keeps the
    /// method so the trait shape is complete.
    fn compose_offer(&mut self) -> Result<String, TransportError>;

    /// Accept a remote offer and produce the local answer (host role).
    fn compose_answer(&mut self, offer_sdp: &str) -> Result<String, TransportError>;

    /// Apply the remote answer (controller role).
    fn apply_answer(&mut self, answer_sdp: &str) -> Result<(), TransportError>;

    /// Feed a trickled remote candidate (both roles). `sdp_mid` is the JSEP
    /// string mid (protocol version 1, QA F9).
    fn add_remote_candidate(
        &mut self,
        candidate: &str,
        sdp_mid: Option<&str>,
        sdp_mline_index: Option<u16>,
    ) -> Result<(), TransportError>;

    /// Send one binary message on a channel. `bytes` is the output of
    /// `protocol::wire::encode`.
    fn send(&mut self, channel: Channel, bytes: &[u8]) -> Result<(), TransportError>;

    /// Drain pending events. Poll-based on purpose: keeps the M0 contract
    /// deterministic and unit-testable with a mock implementation.
    fn poll(&mut self) -> Option<TransportEvent>;

    /// Tear down the peer connection and all channels.
    fn close(&mut self);
}

// ---------------------------------------------------------------------------
// M2 implementation slot (RD-006, RD-007, RD-008): webrtc-rs-backed
// `WebrtcTransport` and a `MockTransport` for deterministic tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::wire::{ButtonState, InputEvent};

    /// QA F3: the transport event surface carries `WireMessage`s; logging a
    /// `TransportEvent` at debug level must not print input payloads.
    /// `InputEvent`'s manual `Debug` provides the redaction; this test pins
    /// it end-to-end through the wrapper.
    #[test]
    fn transport_event_debug_redacts_input_payloads() {
        let event = TransportEvent::Message(
            Channel::InputReliable,
            WireMessage::Input(InputEvent::Key {
                seq: 10,
                scan_code: 0x1E,
                extended: true,
                state: ButtonState::Pressed,
            }),
        );
        let formatted = format!("{event:?}");
        assert!(
            !formatted.contains("30") && !formatted.contains("0x1e"),
            "TransportEvent Debug leaked key content: {formatted}"
        );
        assert!(
            formatted.contains("<redacted>"),
            "expected redaction: {formatted}"
        );
        // Channel identity and event kind remain diagnosable.
        assert!(formatted.contains("InputReliable"));
        assert!(formatted.contains("Message"));
    }
}
