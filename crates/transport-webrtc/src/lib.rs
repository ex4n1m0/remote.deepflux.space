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
//! `input-reliable` (ordered/reliable), `cursor` (latest-state: unordered,
//! maxRetransmits 0).
//!
//! M0 pinned the trait shape with a poll-based API (deterministic, mockable,
//! no async runtime dependency). The M2 implementation ([`WebrtcTransport`],
//! RD-006/007/008) runs tokio *inside* the crate; every trait method is a
//! bounded-wait bridge into that private runtime, so the public surface stays
//! callable from any executor. The libwebrtc fallback swap (source plan frozen
//! decision) replaces this crate's implementation while preserving the trait —
//! see ADR-002 for the seam mechanics.
//!
//! ## M2 trait extension (documented rationale)
//!
//! The M0 trait carried data-channel messages only. Video is an RTP track,
//! not messages (invariant 1), so M2 adds the video carriage ([`VideoFrame`],
//! [`ReceivedFrame`], `send_video`/`poll_video`), the frame-id marker surface
//! ([`FRAME_ID_EXTENSION_URI`], per ADR-002's open item: the host stamps the
//! 64-bit capture-assigned `frame_id` on every RTP packet via the header
//! extension; the controller reads it to join its `FrameTiming` records), and
//! a stats snapshot for the diagnostics `LinkSample` path. All additions have
//! default implementations so existing implementors (test doubles in other
//! crates) compile unchanged — this is the additive trait change ADR-002
//! pre-declared for the first M2 transport patch.

use protocol::wire::WireMessage;

/// RTP header-extension URI carrying the 64-bit host-assigned `frame_id`
/// (ADR-002 "Frame-id carriage"; the perf-counter schema joins host and
/// controller `FrameTiming` halves on this value).
pub const FRAME_ID_EXTENSION_URI: &str = "urn:rd:frame-id";

/// Data-channel selectors. Exactly the four channels from the source plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Control,
    InputFast,
    InputReliable,
    Cursor,
}

impl Channel {
    /// Wire label; also the SCTP data-channel label negotiated on the wire.
    pub fn label(self) -> &'static str {
        match self {
            Channel::Control => "control",
            Channel::InputFast => "input-fast",
            Channel::InputReliable => "input-reliable",
            Channel::Cursor => "cursor",
        }
    }

    /// Delivery policy of this channel (ADR-002 decision 4).
    pub fn is_lossy(self) -> bool {
        matches!(self, Channel::InputFast | Channel::Cursor)
    }
}

/// One encoded video frame handed to the transport for the RTP path.
///
/// Mirrors the `codec-windows::EncodedPacket` handoff shape (Annex-B access
/// unit, no RTP packetization) plus the `frame_id` the host assigned at
/// capture — the value the RTP header extension carries per packet.
#[derive(Debug, Clone)]
pub struct VideoFrame {
    /// Host-assigned at capture; carried per RTP packet in the
    /// `urn:rd:frame-id` header extension.
    pub frame_id: u64,
    /// Capture timestamp on the host monotonic clock. Mapped to the 90 kHz
    /// RTP clock by the packetizer.
    pub timestamp_ns: u64,
    pub is_keyframe: bool,
    /// Annex-B H.264 access unit (start-code delimited NAL units).
    pub bytes: Vec<u8>,
}

/// A depacketized video frame surfaced to the controller.
#[derive(Debug, Clone)]
pub struct ReceivedFrame {
    /// Read from the `urn:rd:frame-id` RTP header extension. `None` when the
    /// sending side did not stamp one (extension not negotiated yet).
    pub frame_id: Option<u64>,
    /// RTP timestamp of the frame's first packet, 90 kHz units.
    pub rtp_timestamp: u32,
    /// Best-effort IDR/SPS detection from the depacketized NAL types.
    pub is_keyframe: bool,
    /// Annex-B H.264 access unit.
    pub bytes: Vec<u8>,
    /// Packets of this frame the depacketizer detected as missing (sequence
    /// gap between consecutive packets of the same frame).
    pub missing_packets: u32,
    /// M2 QA F31: when the engine received this frame's FIRST packet — the
    /// true arrival point the perf schema's `recv_ns` wants, instead of the
    /// runtime's poll-drain time. Same `Instant` domain as
    /// `TransportStats`'s bitrate window. `None` only for hand-built test
    /// frames that never crossed the engine.
    pub recv_instant: Option<std::time::Instant>,
}

/// The selected ICE candidate pair, described without SDP secrets
/// (addresses and types only — never ufrag/password; invariant 6).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectedIcePair {
    pub local_address: String,
    pub remote_address: String,
    /// Host / Srflx / Relay / Prflx of the local candidate.
    pub local_candidate_type: String,
    pub remote_candidate_type: String,
    pub nominated: bool,
}

/// Transport statistics snapshot mapped from the W3C stats report into the
/// diagnostics `LinkSample` fields (plus counters the schema tracks
/// elsewhere). Bitrates are computed over the interval since the previous
/// `stats()` call.
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    pub rtt_ms: Option<f64>,
    pub send_bitrate_kbps: Option<f64>,
    pub recv_bitrate_kbps: Option<f64>,
    /// Lost / (lost + received) on the inbound RTP stream, percent.
    pub loss_percent: Option<f64>,
    /// RFC 3550 interarrival jitter of the inbound stream, milliseconds.
    pub jitter_ms: Option<f64>,
    pub selected_pair: Option<SelectedIcePair>,
    /// True if the selected pair uses a relayed candidate. With the MVP
    /// no-TURN configuration this can only indicate a bug (invariant 4).
    pub relay_in_use: bool,
    /// Lifetime RTP counters.
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    /// Video-path counters (transport-level).
    pub frames_sent: u64,
    pub frames_received: u64,
    /// Receive-side frames dropped by the bounded newest-wins video queue
    /// (invariant 3 evidence) plus frames aborted mid-assembly by loss.
    pub frames_dropped: u64,
    /// Channel-queue counters (invariant 3 evidence; mapped to
    /// `diagnostics::QueueKind::Channel*` by the caller).
    pub channel_queue: ChannelQueues,
    /// Events dropped by the bounded event-drain queue (oldest-first) when
    /// the runtime polls slower than messages arrive. Nonzero on a lossless
    /// link means the consuming loop is the bottleneck, not the network.
    pub events_dropped: u64,
    // --- M5 additions (congestion + netem; all `None`/0 when inactive). ---
    /// Sender-side bandwidth estimate from the configured congestion
    /// controller (M5: `Gcc` over TWCC feedback), bits per second. `None`
    /// when the transport was built without congestion control.
    pub available_bandwidth_bps: Option<u64>,
    /// Receiver-reported fraction lost for the OUTBOUND stream (RTCP RR via
    /// `remote-inbound-rtp` stats), percent — the media-path loss signal a
    /// sender-side congestion policy reacts to. `None` until the first
    /// receiver report arrives.
    pub remote_loss_percent: Option<f64>,
    /// RTT implied by the most recent receiver report (media path),
    /// milliseconds. `None` until the first RR.
    pub remote_rtt_ms: Option<f64>,
    /// Sender-side loss-derived state of the estimator (delay vs loss
    /// halves), for diagnostics. `None` without congestion control.
    pub congestion_stats: Option<CongestionStats>,
    /// Netem shaper queue (invariant 3: bounded, counted). `None` when no
    /// shaper is configured.
    pub netem_queue: Option<NetemQueueStats>,
}

/// Sender-side congestion estimator snapshot (M5).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CongestionStats {
    /// Delay-based half of the estimate, bps.
    pub delay_based_bps: Option<u64>,
    /// Loss-based half of the estimate, bps.
    pub loss_based_bps: Option<u64>,
    /// Remote-reported loss fraction over the estimator's window (0..=1).
    pub packet_loss: Option<f64>,
    /// RTT implied by the most recent feedback, milliseconds.
    pub rtt_ms: Option<f64>,
    /// How many times the estimate has changed since transport creation.
    pub updates: u64,
}

/// Netem shaper queue gauges (the M5 matrix's shaped link; invariant 3
/// evidence — the shaper's queue is bounded and its overflow is counted).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetemQueueStats {
    pub depth: u32,
    pub capacity: u32,
    /// Packets dropped by the shaper: injected loss, blackhole, and
    /// queue-overflow (bandwidth step-downs) combined.
    pub dropped: u64,
    /// Packets released to the wire so far.
    pub delivered: u64,
    /// M6 soak F74a: highest pre-shaper queue depth observed (the
    /// high-water of `depth`). 0 when nothing was ever queued.
    pub high_water: u32,
    /// M6 soak F74a: the explicit due-heap cap (F69). Packets above it
    /// are dropped newest-first and counted in `dropped`.
    pub heap_capacity: u32,
    /// M6 soak F74a: highest due-heap occupancy observed (F69 evidence —
    /// the heap's share of the shaper's bounded buffering).
    pub heap_high_water: u32,
}

/// Per-channel send-queue gauges (depth/capacity plus cumulative counters).
#[derive(Debug, Clone, Copy, Default)]
pub struct ChannelQueues {
    /// (depth, capacity) per channel, in the order of [`Channel`] variants
    /// documented in [`CHANNEL_LABELS`].
    pub depth: [u32; 4],
    pub capacity: [u32; 4],
    pub high_water: [u32; 4],
    /// Messages dropped because the bounded queue was full.
    pub dropped: [u64; 4],
    /// Newest-wins overwrites (`input-fast`, `cursor`).
    pub replaced: [u64; 4],
    /// Cumulative enqueues per channel since transport creation (M2 QA
    /// F32): a poller comparing consecutive snapshots detects activity
    /// between polls and can sample on change per the perf schema's
    /// channel-queue cadence rule.
    pub enqueued: [u64; 4],
    /// Cumulative dequeues (handed to SCTP) per channel.
    pub dequeued: [u64; 4],
    /// M6 soak F74b: depth-trail overflows per channel (F63): entries the
    /// bounded per-slot trail dropped oldest-first because more depth
    /// changes accumulated between drains than the trail holds. Zero in
    /// healthy runs; growth means the consumer drains the trail slower
    /// than the queues change depth.
    pub trail_overflow: [u64; 4],
}

/// One depth-change entry from a channel queue's bounded trail (M6 QA
/// F63): the queue's depth at the instant it changed, on the transport's
/// uptime clock. See [`Transport::take_channel_depth_trail`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelDepthSample {
    /// Which channel's queue changed depth.
    pub channel: Channel,
    /// Transport uptime at the change, ns (anchor via
    /// [`Transport::uptime_ns`]).
    pub at_uptime_ns: u64,
    /// The new depth.
    pub depth: u32,
}

/// Channel labels in the fixed order used by [`ChannelQueues`] arrays.
pub const CHANNEL_LABELS: [&str; 4] = ["control", "input-fast", "input-reliable", "cursor"];

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
    /// One data channel reached the open state. Order of these events is the
    /// SCTP/DCEP establishment order — the channel-open ordering evidence
    /// for the M2 rig.
    ChannelOpened(Channel),
    /// Peer connection state changed (connected/disconnected/failed).
    ConnectionStateChanged(ConnectionState),
    /// SDP answer produced locally (host role, after `compose_answer`).
    /// SDP bodies must never be logged (invariant 6).
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
    /// Create the local SDP offer (controller role).
    fn compose_offer(&mut self) -> Result<String, TransportError>;

    /// Accept a remote offer and produce the local answer (host role).
    fn compose_answer(&mut self, offer_sdp: &str) -> Result<String, TransportError>;

    /// Apply the remote answer (controller role).
    fn apply_answer(&mut self, answer_sdp: &str) -> Result<(), TransportError>;

    /// Feed a trickled remote candidate (both roles). `sdp_mid` is the JSEP
    /// string mid (protocol version 1, QA F9). Duplicate delivery must be a
    /// no-op (signaling idempotency contract).
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

    // --- M2 additive extension (see module docs for rationale). ---
    ///
    /// Send one encoded video frame on the RTP track: RFC 6184
    /// packetization, 90 kHz timestamps from `timestamp_ns`, and the
    /// `frame_id` header extension on every packet (ADR-002).
    fn send_video(&mut self, _frame: VideoFrame) -> Result<(), TransportError> {
        Err(TransportError("transport does not carry video".into()))
    }

    /// Drain one depacketized received video frame (newest-wins bounded
    /// queue; drops oldest when the consumer is slower than the sender).
    fn poll_video(&mut self) -> Option<ReceivedFrame> {
        None
    }

    /// Snapshot transport statistics (RTT/bitrate/loss/jitter, selected ICE
    /// pair, invariant-3 queue counters). Bitrate needs two calls some
    /// interval apart; the first call returns `None` bitrates.
    fn stats(&mut self) -> Result<TransportStats, TransportError> {
        Err(TransportError("transport provides no stats".into()))
    }

    /// Cheap channel-queue gauge snapshot WITHOUT the full `stats()` work
    /// (no stats-report walk, no async bridge in the webrtc-rs engine) so
    /// a runtime loop can poll it every few milliseconds and satisfy the
    /// perf schema's channel-queue rule: sample on every change plus at
    /// ≥1 Hz (M2 QA F32). `None` when the transport tracks no such
    /// queues.
    fn channel_queue_gauges(&mut self) -> Option<ChannelQueues> {
        None
    }

    /// Drain the channel depth-change trail recorded INSIDE the bounded
    /// queues (M6 QA F63): one entry per depth change, stamped on the
    /// transport's monotonic uptime clock ([`Transport::uptime_ns`]).
    ///
    /// Why a trail and not faster polling: an enqueue→pump-drain burst
    /// routinely completes inside a single poll interval (the M5 matrix
    /// polled at ~2–5 ms and still recorded `depth: 0` on every sample
    /// while `high_water` hit 30/32 — the burst lived and died between
    /// polls). The trail is bounded (per-slot ring; overflow drops oldest
    /// and is counted), so draining it every loop iteration turns those
    /// bursts into real samples at their true depth.
    fn take_channel_depth_trail(&mut self) -> Vec<ChannelDepthSample> {
        Vec::new()
    }

    /// The transport's monotonic uptime in nanoseconds — the clock the
    /// depth-trail entries are stamped on. Consumers anchor trail
    /// timestamps onto their own session clock by differencing against a
    /// fresh `uptime_ns()` reading.
    fn uptime_ns(&self) -> u64 {
        0
    }

    /// Request an ICE restart on the next offer/answer round (network-change
    /// recovery entry point; full re-signaling is owned by the session
    /// layer). Spike: wired to the peer connection's `restart_ice`.
    fn restart_ice(&mut self) -> Result<(), TransportError> {
        Err(TransportError("transport cannot restart ice".into()))
    }

    /// Tear down the peer connection and all channels.
    fn close(&mut self);
}

// ---------------------------------------------------------------------------
// M2 implementation (RD-006, RD-007, RD-008): webrtc-rs-backed
// `WebrtcTransport`. Deterministic application-layer loss/reorder injection
// for the rig lives in `chaos`.
// ---------------------------------------------------------------------------

pub mod chaos;
pub mod engine;
pub mod rtp;

pub use engine::{
    CongestionOptions, DEFAULT_STUN_SERVERS, NetemHandle, WebrtcTransport, WebrtcTransportOptions,
    WebrtcTransportRole,
};

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

    #[test]
    fn channel_labels_match_wire_channel_names() {
        assert_eq!(Channel::Control.label(), "control");
        assert_eq!(Channel::InputFast.label(), "input-fast");
        assert_eq!(Channel::InputReliable.label(), "input-reliable");
        assert_eq!(Channel::Cursor.label(), "cursor");
        assert_eq!(
            CHANNEL_LABELS,
            ["control", "input-fast", "input-reliable", "cursor"]
        );
        assert!(Channel::InputFast.is_lossy());
        assert!(Channel::Cursor.is_lossy());
        assert!(!Channel::Control.is_lossy());
        assert!(!Channel::InputReliable.is_lossy());
    }
}
