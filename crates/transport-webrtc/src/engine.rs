//! `WebrtcTransport` — the `webrtc`-0.21 (rtc-core) implementation of the
//! [`Transport`] trait (RD-006/007/008 spike).
//!
//! Architecture (ADR-002 decision 2): the poll-based trait stays
//! runtime-agnostic; this implementation owns a private tokio runtime and
//! bridges every trait method into it with a bounded wait. Nothing async
//! leaks past this crate's public API.
//!
//! Queue/bounds map (invariant 3):
//!
//! | Queue                           | Bound | Overflow policy           |
//! |---------------------------------|-------|---------------------------|
//! | event drain                     | 256   | drop oldest (counted)     |
//! | `control`/`input-reliable` send | 256   | `Err` (never grow)        |
//! | `input-fast` send               | 32    | drop oldest (newest wins) |
//! | `cursor` send                   | 8     | drop oldest (newest wins) |
//! | received-video frames           | 4     | drop oldest (counted)     |
//! | remote-candidate dedupe set     | 128   | clear (re-add lazily)     |
//!
//! TURN is never configured (invariant 4); a gathered `relay` candidate is
//! surfaced as a transport failure rather than used.

use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::BytesMut;
use rtc::interceptor::{BandwidthEstimator as _, EstimatorStats, Gcc, PacerBuilder, Slot};
use rtc::media_stream::MediaStreamTrack;
use rtc::rtp::Packet as RtpPacket;
use rtc::rtp::extension::HeaderExtension;
use rtc::rtp::header::Header as RtpHeader;
use rtc::rtp_transceiver::rtp_sender::{
    RTCRtpCodecParameters, RTCRtpCodingParameters, RTCRtpEncodingParameters,
    RTCRtpHeaderExtensionCapability, RtpCodecKind,
};
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use rtc::statistics::stats::ice_candidate_pair::RTCStatsIceCandidatePairState;
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::error::Error as WrError;
use webrtc::media_stream::track_local::TrackLocal;
use webrtc::media_stream::track_local::static_rtp::TrackLocalStaticRTP;
use webrtc::media_stream::track_remote::{TrackRemote, TrackRemoteEvent};
use webrtc::peer_connection::{
    CongestionFeedback, MediaEngine, PeerConnection, PeerConnectionBuilder,
    PeerConnectionEventHandler, RTCConfigurationBuilder, RTCIceCandidateInit, RTCIceCandidateType,
    RTCIceServer, RTCPeerConnectionIceEvent, RTCPeerConnectionState, RTCSessionDescription,
    RTCStatsReportEntry, Registry, SettingEngineBuilder, StatsSelector,
    configure_congestion_control, register_default_interceptors,
};
use webrtc::runtime::TokioRuntime;

use crate::chaos::{Netem, NetemProfile, PacketVerdict};
use crate::rtp::{
    DEFAULT_MTU, FrameAssembler, FrameIdExt, is_keyframe_annexb, packetize_access_unit,
    parse_frame_id_ext, rtp_timestamp_from_ns,
};
use crate::{
    Channel, ChannelQueues, CongestionStats, ConnectionState, FRAME_ID_EXTENSION_URI,
    NetemQueueStats, ReceivedFrame, SelectedIcePair, Transport, TransportError, TransportEvent,
    TransportStats, VideoFrame,
};

/// Upper bound for any trait-method bridge into the private runtime.
const BRIDGE_TIMEOUT: Duration = Duration::from_secs(15);
/// Bound for teardown paths (must not hang the caller on close).
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

const EVENT_QUEUE_CAPACITY: usize = 256;
const VIDEO_QUEUE_CAPACITY: usize = 4;
const RELIABLE_QUEUE_CAPACITY: usize = 256;
const FAST_QUEUE_CAPACITY: usize = 32;
const CURSOR_QUEUE_CAPACITY: usize = 8;
const CANDIDATE_DEDUPE_CAPACITY: usize = 128;

/// SCTP send-buffer limit for data channels — webrtc-rs' built-in send
/// backpressure (`try_send` then fails with `ErrSendBufferFull`).
const DATA_CHANNEL_SEND_BUFFER_LIMIT: usize = 256 * 1024;

/// Bound of the netem shaper's packet queue (M5 matrix): ~360 KiB of
/// shaped video. Deliberately NOT a deep buffer: a delay-line shaper
/// delivers at input rate until the queue FILLS, so the queue depth IS the
/// bottleneck's buffer. At 1024 packets the 20→2 Mbps step-down took
/// ~20 s to saturate (measured run 1: receiver saw 3.0 Mbps straight
/// through the 2 Mbps phase — pure bufferbloat, phase over before the
/// drop); 300 packets (~1.4 s at 2 Mbps) overflows within seconds,
/// producing the queue-overflow loss a real shallow-buffered bottleneck
/// shows (counted, invariant 3).
const NETEM_QUEUE_CAPACITY: usize = 300;

/// The product's STUN configuration (M5, RD-013): two independent public
/// servers so one being unreachable does not degrade gathering to
/// host-candidates-only. TURN stays forbidden (invariant 4) — these URLs
/// are validated to `stun:`/`stuns:` scheme only, and a relayed candidate
/// is surfaced as a transport failure, never used.
pub const DEFAULT_STUN_SERVERS: [&str; 2] = [
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
];

/// Tuning of the sender-side congestion controller (M5). The estimate is
/// `rtc`'s GCC (delay-gradient + loss based) over TWCC feedback; the
/// encoder-facing *policy* on top of it lives in `node-runtime::congestion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CongestionOptions {
    /// Estimate start, bps. Deliberately below the Balanced encode target:
    /// a path that cannot carry the start rate is discovered by probing
    /// down, not by congesting it first (rtc's own example rationale).
    pub initial_bps: u64,
    pub min_bps: u64,
    pub max_bps: u64,
}

impl Default for CongestionOptions {
    fn default() -> Self {
        Self {
            initial_bps: 4_000_000,
            min_bps: 300_000,
            max_bps: 12_000_000,
        }
    }
}

/// Construction options (M5). The zero value is exactly the pre-M5
/// transport: no ICE servers, loopback-only sockets, no congestion
/// estimator, no shaper — existing tests keep their meaning.
#[derive(Debug, Clone, Default)]
pub struct WebrtcTransportOptions {
    /// STUN server URLs (`stun:`/`stuns:` only). TURN/relay URLs are a
    /// typed construction error (invariant 4 enforced at the config layer).
    pub ice_servers: Vec<String>,
    /// Bind UDP sockets to all interfaces (WAN path) instead of loopback
    /// only (test/rig path). Needed for srflx gathering to leave the
    /// machine.
    pub bind_all_interfaces: bool,
    /// Sender-side congestion estimator (host role only; ignored for the
    /// controller, which sends no media).
    pub congestion: Option<CongestionOptions>,
    /// Shape the outgoing RTP path (M5 matrix / chaos testing).
    pub video_netem: Option<NetemProfile>,
}

impl WebrtcTransportOptions {
    /// The product (WAN) configuration: public STUN, all-interface sockets,
    /// congestion estimator on, no shaping.
    pub fn wan() -> Self {
        Self {
            ice_servers: DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
            bind_all_interfaces: true,
            congestion: Some(CongestionOptions::default()),
            video_netem: None,
        }
    }

    fn validate(&self) -> Result<(), TransportError> {
        for url in &self.ice_servers {
            let scheme = url
                .split(':')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            match scheme.as_str() {
                "stun" | "stuns" => {}
                "turn" | "turns" => {
                    return Err(TransportError(format!(
                        "TURN server configured ({url:?}): relay is forbidden in MVP (invariant 4)"
                    )));
                }
                other => {
                    return Err(TransportError(format!(
                        "unsupported ICE server scheme {other:?} in {url:?}"
                    )));
                }
            }
        }
        if let Some(congestion) = &self.congestion
            && !(congestion.min_bps <= congestion.initial_bps
                && congestion.initial_bps <= congestion.max_bps)
        {
            return Err(TransportError(format!(
                "congestion tuning must satisfy min<=initial<=max (got {}..{}..{})",
                congestion.min_bps, congestion.initial_bps, congestion.max_bps
            )));
        }
        Ok(())
    }
}

/// Which SDP role this peer plays. The controller offers (the M0 trait's
/// `compose_offer` is the controller role); the host answers and sends video.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebrtcTransportRole {
    Controller,
    Host,
}

/// Bridge a future onto `runtime` with a bounded wait. The output crosses a
/// thread boundary (std mpsc), so it must be `Send`. On timeout the future
/// keeps running inside the runtime — the caller just stops waiting.
fn bridge<T, F>(
    runtime: &Arc<tokio::runtime::Runtime>,
    closing: &AtomicBool,
    timeout: Duration,
    label: &str,
    fut: F,
) -> Result<T, String>
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    if closing.load(Ordering::Acquire) {
        return Err(format!("{label}: transport is closing"));
    }
    let (tx, rx) = std::sync::mpsc::sync_channel::<T>(1);
    runtime.spawn(async move {
        // Send fails only if the caller already timed out; the future still
        // runs to completion so the runtime stays consistent.
        let _ = tx.send(fut.await);
    });
    rx.recv_timeout(timeout)
        .map_err(|_| format!("{label} timed out after {timeout:?}"))
}

/// Role-independent shared state reachable from webrtc-rs event handlers.
struct Shared {
    closing: AtomicBool,
    events: StdMutex<VecDeque<TransportEvent>>,
    video_rx: StdMutex<VecDeque<ReceivedFrame>>,
    events_overflow: AtomicU64,
    frames_dropped: AtomicU64,
    frames_sent: AtomicU64,
    frames_received: AtomicU64,
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    /// Channel bitmask of opened channels (bit = Channel index).
    opened_mask: AtomicU8,
    channels_open_emitted: AtomicBool,
    /// Duplicate-signaling dedupe (candidate strings).
    seen_candidates: StdMutex<HashSet<String>>,
    /// Inputs for bitrate deltas between `stats()` calls:
    /// (instant, sent_bytes, recv_bytes).
    last_bitrate_sample: StdMutex<Option<(Instant, u64, u64)>>,
}

impl Shared {
    fn new() -> Self {
        Self {
            closing: AtomicBool::new(false),
            events: StdMutex::new(VecDeque::with_capacity(EVENT_QUEUE_CAPACITY)),
            video_rx: StdMutex::new(VecDeque::with_capacity(VIDEO_QUEUE_CAPACITY)),
            events_overflow: AtomicU64::new(0),
            frames_dropped: AtomicU64::new(0),
            frames_sent: AtomicU64::new(0),
            frames_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            opened_mask: AtomicU8::new(0),
            channels_open_emitted: AtomicBool::new(false),
            seen_candidates: StdMutex::new(HashSet::new()),
            last_bitrate_sample: StdMutex::new(None),
        }
    }

    fn push_event(&self, event: TransportEvent) {
        let mut events = self.events.lock().expect("event queue poisoned");
        if events.len() >= EVENT_QUEUE_CAPACITY {
            events.pop_front();
            self.events_overflow.fetch_add(1, Ordering::Relaxed);
        }
        events.push_back(event);
    }

    fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Acquire)
    }

    /// True exactly once: when the last of the four channels has opened.
    fn mark_channel_opened(&self, channel: Channel) -> bool {
        let bit = 1u8 << (channel as u8);
        let mask = self.opened_mask.fetch_or(bit, Ordering::AcqRel) | bit;
        mask == 0b1111 && !self.channels_open_emitted.swap(true, Ordering::AcqRel)
    }
}

/// One data channel's bounded send queue plus its webrtc-rs handle.
struct ChannelSlot {
    channel: Channel,
    lossy: bool,
    capacity: usize,
    queue: StdMutex<VecDeque<Vec<u8>>>,
    high_water: AtomicU32,
    dropped: AtomicU64,
    replaced: AtomicU64,
    /// Cumulative activity counters (F32 change detection).
    enqueued: AtomicU64,
    dequeued: AtomicU64,
    dc: tokio::sync::Mutex<Option<Arc<dyn DataChannel>>>,
    notify: Arc<tokio::sync::Notify>,
}

impl ChannelSlot {
    fn new(channel: Channel) -> Self {
        let (capacity, lossy) = match channel {
            Channel::Control | Channel::InputReliable => (RELIABLE_QUEUE_CAPACITY, false),
            Channel::InputFast => (FAST_QUEUE_CAPACITY, true),
            Channel::Cursor => (CURSOR_QUEUE_CAPACITY, true),
        };
        Self {
            channel,
            lossy,
            capacity,
            queue: StdMutex::new(VecDeque::new()),
            high_water: AtomicU32::new(0),
            dropped: AtomicU64::new(0),
            replaced: AtomicU64::new(0),
            enqueued: AtomicU64::new(0),
            dequeued: AtomicU64::new(0),
            dc: tokio::sync::Mutex::new(None),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Enqueue per the channel's policy: reliable → `Err` when full; lossy →
    /// drop oldest so the newest message wins (invariant 3).
    fn enqueue(&self, bytes: Vec<u8>) -> Result<(), TransportError> {
        let mut queue = self.queue.lock().expect("channel queue poisoned");
        if queue.len() >= self.capacity {
            if self.lossy {
                queue.pop_front();
                self.replaced.fetch_add(1, Ordering::Relaxed);
            } else {
                drop(queue);
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return Err(TransportError(format!(
                    "{} send queue full (capacity {})",
                    self.channel.label(),
                    self.capacity
                )));
            }
        }
        queue.push_back(bytes);
        let depth = queue.len() as u32;
        drop(queue);
        self.enqueued.fetch_add(1, Ordering::Relaxed);
        self.high_water.fetch_max(depth, Ordering::Relaxed);
        self.notify.notify_one();
        Ok(())
    }

    fn gauges(&self) -> (u32, u32, u32, u64, u64) {
        let queue = self.queue.lock().expect("channel queue poisoned");
        (
            queue.len() as u32,
            self.capacity as u32,
            self.high_water.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
            self.replaced.load(Ordering::Relaxed),
        )
    }

    /// Bridge-free snapshot for the F32 per-change polling path.
    fn quick_gauges(&self) -> ChannelQueues {
        let mut out = ChannelQueues::default();
        out.depth[self.channel as usize] =
            self.queue.lock().expect("channel queue poisoned").len() as u32;
        out.capacity[self.channel as usize] = self.capacity as u32;
        out.high_water[self.channel as usize] = self.high_water.load(Ordering::Relaxed);
        out.dropped[self.channel as usize] = self.dropped.load(Ordering::Relaxed);
        out.replaced[self.channel as usize] = self.replaced.load(Ordering::Relaxed);
        out.enqueued[self.channel as usize] = self.enqueued.load(Ordering::Relaxed);
        out.dequeued[self.channel as usize] = self.dequeued.load(Ordering::Relaxed);
        out
    }
}

/// The four channel slots, shared between engine and event handler.
#[derive(Clone)]
struct Channels {
    slots: Arc<[Arc<ChannelSlot>; 4]>,
}

impl Channels {
    fn new() -> Self {
        Self {
            slots: Arc::new([
                Arc::new(ChannelSlot::new(Channel::Control)),
                Arc::new(ChannelSlot::new(Channel::InputFast)),
                Arc::new(ChannelSlot::new(Channel::InputReliable)),
                Arc::new(ChannelSlot::new(Channel::Cursor)),
            ]),
        }
    }

    fn slot(&self, channel: Channel) -> &Arc<ChannelSlot> {
        &self.slots[channel as usize]
    }

    fn for_label(&self, label: &str) -> Option<&Arc<ChannelSlot>> {
        self.slots.iter().find(|s| s.channel.label() == label)
    }
}

/// Host-side RTP send state.
struct VideoSend {
    track: Arc<TrackLocalStaticRTP>,
    seq: AtomicU16,
    payload_type: AtomicU8,
    ssrc: AtomicU32,
}

// ---------------------------------------------------------------------------
// M5: congestion estimator publication + netem shaper
// ---------------------------------------------------------------------------

/// Non-async-readable projection of the sender-side GCC estimate. The
/// estimator itself lives on the private runtime (called by the congestion
/// interceptor); this is what `stats()` reads.
#[derive(Debug, Default)]
struct CongestionPublish {
    target_bps: AtomicU64,
    stats: StdMutex<EstimatorStats>,
    updates: AtomicU64,
}

impl CongestionPublish {
    fn snapshot(&self) -> (Option<u64>, CongestionStats) {
        let stats = *self.stats.lock().expect("gcc stats poisoned");
        let conv = |v: Option<f64>| v.filter(|v| v.is_finite() && *v >= 0.0).map(|v| v as u64);
        (
            Some(self.target_bps.load(Ordering::Relaxed)),
            CongestionStats {
                delay_based_bps: conv(stats.delay_based_bitrate),
                loss_based_bps: conv(stats.loss_based_bitrate),
                packet_loss: stats.packet_loss,
                rtt_ms: stats.round_trip_time.map(|d| d.as_secs_f64() * 1000.0),
                updates: self.updates.load(Ordering::Relaxed),
            },
        )
    }
}

/// `rtc`'s ReportingEstimator pattern: delegate to `Gcc`, publish every
/// target change to atomics so the poll-based trait never has to touch the
/// runtime to read the estimate.
struct ReportingGcc {
    inner: Gcc,
    publish: Arc<CongestionPublish>,
}

impl ReportingGcc {
    fn new(options: CongestionOptions, publish: Arc<CongestionPublish>) -> Self {
        Self {
            inner: Gcc::new(
                options.initial_bps as f64,
                options.min_bps as f64,
                options.max_bps as f64,
            ),
            publish,
        }
    }

    fn publish(&self) {
        self.publish.target_bps.store(
            self.inner.target_bitrate().max(0.0) as u64,
            Ordering::Relaxed,
        );
        *self.publish.stats.lock().expect("gcc stats poisoned") = self.inner.stats();
        self.publish.updates.fetch_add(1, Ordering::Relaxed);
    }
}

impl rtc::interceptor::BandwidthEstimator for ReportingGcc {
    fn on_reports(&mut self, now: Instant, reports: &[rtc::interceptor::PacketReport]) {
        self.inner.on_reports(now, reports);
        self.publish();
    }

    fn target_bitrate(&self) -> f64 {
        self.inner.target_bitrate()
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.inner.handle_timeout(now);
        self.publish();
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.inner.poll_timeout()
    }

    fn stats(&self) -> EstimatorStats {
        self.inner.stats()
    }
}

/// Shared netem state between the trait side (enqueue + verdicts) and the
/// runtime shaper task (delayed writes).
struct NetemShared {
    netem: StdMutex<Netem>,
    gauges: Arc<NetemGauges>,
}

#[derive(Default)]
struct NetemGauges {
    queued: AtomicU64,
    written: AtomicU64,
    dropped: AtomicU64,
    /// Shaper queue capacity (the mpsc channel bound).
    capacity: u32,
}

impl NetemGauges {
    fn stats(&self) -> NetemQueueStats {
        let queued = self.queued.load(Ordering::Relaxed);
        let written = self.written.load(Ordering::Relaxed);
        NetemQueueStats {
            depth: queued.saturating_sub(written).min(u64::from(u32::MAX)) as u32,
            capacity: self.capacity,
            dropped: self.dropped.load(Ordering::Relaxed),
            delivered: written,
        }
    }
}

/// Handle for mid-run profile changes (matrix step-down schedules). The
/// shaper picks the new profile up on the next packet.
#[derive(Clone)]
pub struct NetemHandle {
    shared: Arc<NetemShared>,
}

impl NetemHandle {
    /// Replace the shaping profile (loss/delay/rate/blackhole).
    pub fn set_profile(&self, profile: NetemProfile) {
        self.shared
            .netem
            .lock()
            .expect("netem poisoned")
            .set_profile(profile);
    }

    /// Current gauges (bounded-queue evidence).
    pub fn stats(&self) -> NetemQueueStats {
        self.shared.gauges.stats()
    }
}

/// One shaped outbound packet in the due-queue. `Ord` is inverted on
/// purpose so the `BinaryHeap` (a max-heap) pops the earliest due first.
struct ShapedPacket {
    packet: RtpPacket,
    frame_id: u64,
    due: Instant,
}

#[derive(PartialEq, Eq)]
struct DuePacket {
    due: Instant,
    seq: u64,
    frame_id: u64,
    packet: RtpPacket,
}

impl Ord for DuePacket {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse (due, seq): earliest first.
        other
            .due
            .cmp(&self.due)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

impl PartialOrd for DuePacket {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The shaper task: writes due packets to the track in due order. The
/// queue is the bounded channel plus this heap; on transport close the
/// closing flag stops the loop and the pending heap is dropped.
async fn netem_shaper_loop(
    mut rx: tokio::sync::mpsc::Receiver<ShapedPacket>,
    video: Arc<VideoSend>,
    shared: Arc<Shared>,
    gauges: Arc<NetemGauges>,
) {
    let mut heap: std::collections::BinaryHeap<DuePacket> = std::collections::BinaryHeap::new();
    let mut seq = 0u64;
    loop {
        if shared.is_closing() {
            return;
        }
        // Next due instant, if any. tokio's clock is std's Instant on this
        // platform, but the type is distinct — convert at the boundary.
        let next_due = heap
            .peek()
            .map(|top| tokio::time::Instant::from_std(top.due));
        let recv = match next_due {
            Some(due) => tokio::time::timeout_at(due, rx.recv()).await,
            None => Ok(rx.recv().await),
        };
        match recv {
            Ok(Some(shaped)) => {
                gauges.queued.fetch_add(1, Ordering::Relaxed);
                seq += 1;
                heap.push(DuePacket {
                    due: shaped.due,
                    seq,
                    frame_id: shaped.frame_id,
                    packet: shaped.packet,
                });
            }
            Ok(None) => {
                // Sender gone (transport dropped): drain what is due, then stop.
                while let Some(top) = heap.pop() {
                    write_shaped(&video, top.frame_id, top.packet, &shared, &gauges).await;
                }
                return;
            }
            Err(_) => {
                // Timeout reached: everything whose due instant has passed
                // is written now, in due order.
                while let Some(top) = heap.peek() {
                    let due = top.due;
                    if due > Instant::now() {
                        break;
                    }
                    let top = heap.pop().expect("peek checked");
                    write_shaped(&video, top.frame_id, top.packet, &shared, &gauges).await;
                }
            }
        }
        // Also flush anything already due after an enqueue.
        while heap.peek().is_some_and(|top| top.due <= Instant::now()) {
            let top = heap.pop().expect("peek checked");
            write_shaped(&video, top.frame_id, top.packet, &shared, &gauges).await;
        }
    }
}

/// Write one shaped packet (frame-id extension rebuilt; single shaper task
/// ⇒ single writer).
async fn write_shaped(
    video: &Arc<VideoSend>,
    frame_id: u64,
    packet: RtpPacket,
    shared: &Arc<Shared>,
    gauges: &Arc<NetemGauges>,
) {
    let extensions = [HeaderExtension::Custom {
        uri: Cow::Borrowed(FRAME_ID_EXTENSION_URI),
        extension: Box::new(FrameIdExt { frame_id }),
    }];
    if video
        .track
        .write_rtp_with_extensions(packet, &extensions)
        .await
        .is_ok()
    {
        shared.packets_sent.fetch_add(1, Ordering::Relaxed);
    }
    gauges.written.fetch_add(1, Ordering::Relaxed);
}

/// The transport. `Send` (trait requirement) but deliberately not `Sync`:
/// the trait takes `&mut self`.
pub struct WebrtcTransport {
    role: WebrtcTransportRole,
    runtime: Arc<tokio::runtime::Runtime>,
    pc: StdMutex<Option<Arc<dyn PeerConnection>>>,
    video: StdMutex<Option<Arc<VideoSend>>>,
    channels: Channels,
    shared: Arc<Shared>,
    /// Negotiated `urn:rd:frame-id` extension id on the receive side,
    /// shared with the event handler (0 = not negotiated → received frames
    /// carry `frame_id: None`, the documented ADR-002 fallback).
    rx_frame_ext_id: Arc<AtomicU8>,
    /// M5: sender-side GCC estimate publication (`None` when built without
    /// congestion control).
    congestion: Option<Arc<CongestionPublish>>,
    /// M5: netem shaper state (`None` when built without shaping).
    netem: Option<Arc<NetemShared>>,
    /// Sender side of the bounded shaper queue (kept for `send_video`).
    netem_tx: Option<tokio::sync::mpsc::Sender<ShapedPacket>>,
    /// Receiver side, consumed by the shaper task at `compose_answer`.
    netem_rx: Option<tokio::sync::mpsc::Receiver<ShapedPacket>>,
    closed: AtomicBool,
}

impl Drop for WebrtcTransport {
    fn drop(&mut self) {
        self.shutdown(Duration::from_secs(2));
    }
}

impl WebrtcTransport {
    /// Build a transport for `role` with the pre-M5 defaults: no ICE
    /// servers (loopback), loopback-only UDP sockets, no congestion
    /// estimator, no shaper.
    pub fn new(role: WebrtcTransportRole) -> Result<Self, TransportError> {
        Self::with_options(role, WebrtcTransportOptions::default())
    }

    /// Build a transport with explicit options (M5). See
    /// [`WebrtcTransportOptions`] and [`WebrtcTransportOptions::wan`] for
    /// the product configuration (public STUN, all-interface sockets,
    /// sender-side GCC).
    pub fn with_options(
        role: WebrtcTransportRole,
        options: WebrtcTransportOptions,
    ) -> Result<Self, TransportError> {
        options.validate()?;
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("rd-transport")
                .enable_all()
                .build()
                .map_err(|e| TransportError(format!("runtime start failed: {e}")))?,
        );

        let mut media = MediaEngine::default();
        let h264 = RTCRtpCodecParameters {
            rtp_codec: rtc::rtp_transceiver::rtp_sender::RTCRtpCodec {
                mime_type: "video/H264".to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line:
                    "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
                        .to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type: 102,
        };
        media
            .register_codec(h264, RtpCodecKind::Video)
            .map_err(|e| TransportError(format!("codec registration failed: {e}")))?;
        media
            .register_header_extension(
                RTCRtpHeaderExtensionCapability {
                    uri: FRAME_ID_EXTENSION_URI.to_owned(),
                },
                RtpCodecKind::Video,
                None,
            )
            .map_err(|e| TransportError(format!("header extension registration failed: {e}")))?;

        // M5: sender-side congestion control on the media-sending role.
        // `configure_congestion_control` places send history + pacer + TWCC
        // and registers the transport-cc feedback/extension the remote
        // needs; `register_default_interceptors` adds NACK/RR/SR on top
        // (the rtc example's blessed order — slots are unique, so the
        // receiver TWCC is not doubled).
        let (congestion, registry) = match (role, options.congestion) {
            (WebrtcTransportRole::Host, Some(tuning)) => {
                let publish = Arc::new(CongestionPublish::default());
                let reporting = ReportingGcc::new(tuning, Arc::clone(&publish));
                let base = configure_congestion_control(
                    Registry::new(),
                    reporting,
                    CongestionFeedback::Twcc,
                    &mut media,
                )
                .map_err(|e| TransportError(format!("congestion setup failed: {e}")))?;
                // `configure_congestion_control` builds its pacer at the
                // 1 Mbps library default, and the estimator only re-rates
                // the pacer when its target *changes* — a healthy path
                // (target constant) would pace at 1 Mbps forever
                // (measured: 974 kbps delivered vs a 3.6 Mbps encoder).
                // Replace the slot with a pacer starting at our initial
                // rate (`Registry::with` replaces, not stacks).
                let initial = tuning.initial_bps as f64;
                let base = base.with(
                    Slot::Pacer,
                    PacerBuilder::new().with_target_bitrate(initial).build(),
                );
                (Some(publish), base)
            }
            _ => (None, Registry::new()),
        };
        let registry = register_default_interceptors(registry, &mut media)
            .map_err(|e| TransportError(format!("interceptor setup failed: {e}")))?;

        let setting_engine = SettingEngineBuilder::new()
            .with_multicast_dns_mode(rtc::ice::mdns::MulticastDnsMode::Disabled)
            .build();

        // ICE servers: public STUN only. TURN URLs were rejected above at
        // the configuration layer (invariant 4); a relayed candidate that
        // somehow still appears is surfaced as a failure in the handler.
        let config = RTCConfigurationBuilder::new()
            .with_ice_servers(
                options
                    .ice_servers
                    .iter()
                    .map(|url| RTCIceServer {
                        urls: vec![url.clone()],
                        ..Default::default()
                    })
                    .collect(),
            )
            .build();

        let shared = Arc::new(Shared::new());
        let channels = Channels::new();
        let rx_frame_ext_id = Arc::new(AtomicU8::new(0));

        // M5 netem: bounded shaper queue, deterministic per-transport seed
        // (reproducible matrix cells; xorshift just needs nonzero).
        static NETEM_SEED: AtomicU64 = AtomicU64::new(0x5EED_0000);
        let seed = NETEM_SEED.fetch_add(0x9E37, Ordering::Relaxed) | 1;
        let (netem, netem_tx, netem_rx) = match options.video_netem {
            Some(profile) => {
                let (tx, rx) = tokio::sync::mpsc::channel(NETEM_QUEUE_CAPACITY);
                let gauges = Arc::new(NetemGauges {
                    capacity: NETEM_QUEUE_CAPACITY as u32,
                    ..Default::default()
                });
                let state = Arc::new(NetemShared {
                    netem: StdMutex::new(Netem::new(seed, profile)),
                    gauges,
                });
                (Some(state), Some(tx), Some(rx))
            }
            None => (None, None, None),
        };

        let handler = TransportHandler {
            shared: Arc::clone(&shared),
            channels: channels.clone(),
            rx_frame_ext_id: Arc::clone(&rx_frame_ext_id),
        };

        let udp_addrs = if options.bind_all_interfaces {
            vec!["0.0.0.0:0".to_owned()]
        } else {
            vec!["127.0.0.1:0".to_owned()]
        };

        let closing_probe = Arc::new(AtomicBool::new(false));
        let pc: Arc<dyn PeerConnection> = bridge(
            &runtime,
            &closing_probe,
            BRIDGE_TIMEOUT,
            "peer connection build",
            async move {
                let pc = PeerConnectionBuilder::new()
                    .with_configuration(config)
                    .with_media_engine(media)
                    .with_interceptor_registry(registry)
                    .with_setting_engine(setting_engine)
                    .with_handler(Arc::new(handler))
                    .with_runtime(Arc::new(TokioRuntime) as Arc<dyn webrtc::runtime::Runtime>)
                    .with_udp_addrs(udp_addrs)
                    .with_data_channel_send_buffer_limit(DATA_CHANNEL_SEND_BUFFER_LIMIT)
                    .build()
                    .await
                    .map_err(|e| format!("{e}"))?;
                Ok(Arc::from(pc) as Arc<dyn PeerConnection>)
            },
        )
        .and_then(|inner| inner)
        .map_err(|e| TransportError(format!("peer connection build failed: {e}")))?;

        let transport = Self {
            role,
            runtime: Arc::clone(&runtime),
            pc: StdMutex::new(None),
            video: StdMutex::new(None),
            channels: channels.clone(),
            shared,
            rx_frame_ext_id,
            congestion,
            netem,
            netem_tx,
            netem_rx,
            closed: AtomicBool::new(false),
        };

        // Role setup on the built connection.
        let setup_channels = channels.clone();
        let setup_shared = Arc::clone(&transport.shared);
        let setup_pc = Arc::clone(&pc);
        let setup_role = role;
        bridge(
            &runtime,
            &transport.shared.closing,
            BRIDGE_TIMEOUT,
            "role setup",
            async move {
                if matches!(setup_role, WebrtcTransportRole::Controller) {
                    // Offerer: announce the four data channels in fixed
                    // creation order (→ fixed SCTP ids → deterministic
                    // open order) and a recvonly video transceiver.
                    for slot in setup_channels.slots.iter() {
                        let init = RTCDataChannelInit {
                            ordered: !slot.lossy,
                            max_retransmits: if slot.lossy { Some(0) } else { None },
                            ..Default::default()
                        };
                        let dc = setup_pc
                            .create_data_channel(slot.channel.label(), Some(init))
                            .await
                            .map_err(|e| format!("create_data_channel: {e}"))?;
                        attach_data_channel(Arc::clone(&setup_shared), Arc::clone(slot), dc).await;
                    }
                    setup_pc
                        .add_transceiver_from_kind(
                            RtpCodecKind::Video,
                            Some(RTCRtpTransceiverInit {
                                direction: RTCRtpTransceiverDirection::Recvonly,
                                streams: vec![],
                                send_encodings: vec![],
                            }),
                        )
                        .await
                        .map_err(|e| format!("add_transceiver: {e}"))?;
                }
                Ok::<(), String>(())
            },
        )
        .and_then(|inner| inner)
        .map_err(|e| TransportError(format!("role setup failed: {e}")))?;

        *transport.pc.lock().expect("pc poisoned") = Some(pc);
        Ok(transport)
    }

    /// Which SDP role this transport was built for (diagnostics/tests).
    pub fn role(&self) -> WebrtcTransportRole {
        self.role
    }

    /// Handle for mid-run netem profile changes (M5 matrix). `None` when
    /// the transport was built without shaping.
    pub fn netem_handle(&self) -> Option<NetemHandle> {
        self.netem.as_ref().map(|shared| NetemHandle {
            shared: Arc::clone(shared),
        })
    }

    /// Replace the shaping profile (convenience over [`Self::netem_handle`]).
    pub fn set_netem(&self, profile: NetemProfile) {
        if let Some(handle) = self.netem_handle() {
            handle.set_profile(profile);
        }
    }

    fn bridge<T, F>(&self, label: &str, fut: F) -> Result<T, String>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        bridge(
            &self.runtime,
            &self.shared.closing,
            BRIDGE_TIMEOUT,
            label,
            fut,
        )
    }

    fn require_pc(&self) -> Result<Arc<dyn PeerConnection>, TransportError> {
        self.pc
            .lock()
            .expect("pc poisoned")
            .clone()
            .ok_or_else(|| TransportError("peer connection not built".into()))
    }

    /// Teardown: mark closing (pumps and receive loops observe it), close
    /// the peer connection with a short bound, then stop the runtime.
    fn shutdown(&mut self, runtime_timeout: Duration) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.shared.closing.store(true, Ordering::Release);
        for slot in self.channels.slots.iter() {
            slot.notify.notify_waiters();
        }
        if let Some(pc) = self.pc.lock().expect("pc poisoned").clone() {
            let _ = bridge(
                &self.runtime,
                &AtomicBool::new(false), // closing is set; bypass the guard
                CLOSE_TIMEOUT,
                "close",
                async move {
                    let _ = pc.close().await;
                },
            );
        }
        // Consume the runtime (only this transport holds it) and stop it
        // with a bound; remaining pump/receive tasks are cancelled.
        if let Ok(runtime) = Arc::try_unwrap(Arc::clone(&self.runtime)) {
            runtime.shutdown_timeout(runtime_timeout);
        }
    }
}

/// Attach a freshly available data channel: store the handle and spawn the
/// receive-poll loop plus the bounded send pump. Idempotent per channel.
async fn attach_data_channel(
    shared: Arc<Shared>,
    slot: Arc<ChannelSlot>,
    dc: Arc<dyn DataChannel>,
) {
    {
        let mut guard = slot.dc.lock().await;
        if guard.is_some() {
            return; // already attached (duplicate on_data_channel)
        }
        *guard = Some(Arc::clone(&dc));
    }

    // Receive loop: drain channel events. Messages decode through
    // `protocol::wire`; input payloads are never logged (invariant 6).
    let shared_rx = Arc::clone(&shared);
    let channel = slot.channel;
    let dc_rx = Arc::clone(&dc);
    tokio::spawn(async move {
        loop {
            if shared_rx.is_closing() {
                break;
            }
            let Some(event) = dc_rx.poll().await else {
                break;
            };
            match event {
                DataChannelEvent::OnOpen => {
                    shared_rx.push_event(TransportEvent::ChannelOpened(channel));
                    if shared_rx.mark_channel_opened(channel) {
                        shared_rx.push_event(TransportEvent::ChannelsOpen);
                    }
                }
                DataChannelEvent::OnMessage(msg) => {
                    if msg.is_string {
                        shared_rx.push_event(TransportEvent::Failed {
                            reason: format!(
                                "text frame on {} channel (binary wire expected)",
                                channel.label()
                            ),
                        });
                        continue;
                    }
                    match protocol::wire::decode(&msg.data) {
                        Ok(message) => {
                            shared_rx.push_event(TransportEvent::Message(channel, message))
                        }
                        // `DecodeError`'s Display is payload-free.
                        Err(err) => shared_rx.push_event(TransportEvent::Failed {
                            reason: format!("wire decode on {}: {err}", channel.label()),
                        }),
                    }
                }
                DataChannelEvent::OnClose | DataChannelEvent::OnClosing => break,
                DataChannelEvent::OnError => {
                    shared_rx.push_event(TransportEvent::Failed {
                        reason: format!("data channel error on {}", channel.label()),
                    });
                }
                DataChannelEvent::OnBufferedAmountLow | DataChannelEvent::OnBufferedAmountHigh => {}
                _ => {}
            }
        }
    });

    // Send pump: drain the bounded queue into the SCTP channel with
    // backpressure — `try_send` fails fast on a full SCTP buffer, and the
    // message returns to the queue front until capacity frees.
    let slot_pump = Arc::clone(&slot);
    let shared_tx = Arc::clone(&shared);
    let dc_tx = Arc::clone(&dc);
    tokio::spawn(async move {
        loop {
            if shared_tx.is_closing() {
                break;
            }
            loop {
                let next = {
                    let mut guard = slot_pump.queue.lock().expect("channel queue poisoned");
                    guard.pop_front()
                };
                let Some(bytes) = next else { break };
                slot_pump.dequeued.fetch_add(1, Ordering::Relaxed);
                match dc_tx.try_send(BytesMut::from(&bytes[..])).await {
                    Ok(()) => {}
                    Err(WrError::ErrSendBufferFull) => {
                        {
                            let mut guard = slot_pump.queue.lock().expect("channel queue poisoned");
                            guard.push_front(bytes);
                        }
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                    Err(_) => return, // channel closed: pump exits
                }
            }
            // Wake on new queue items, with a periodic liveness re-check so
            // a missed notification cannot stall the pump.
            let _ =
                tokio::time::timeout(Duration::from_millis(50), slot_pump.notify.notified()).await;
        }
    });
}

/// webrtc-rs event handler → `TransportEvent`s, channel/track attach.
struct TransportHandler {
    shared: Arc<Shared>,
    channels: Channels,
    rx_frame_ext_id: Arc<AtomicU8>,
}

#[async_trait]
impl PeerConnectionEventHandler for TransportHandler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        // Invariant 4: relayed candidates are rejected, not signaled. With
        // no TURN configured this is a should-never-happen guard.
        if event.candidate.typ == RTCIceCandidateType::Relay {
            self.shared.push_event(TransportEvent::Failed {
                reason: "relayed ICE candidate gathered (TURN is forbidden in MVP)".to_owned(),
            });
            return;
        }
        let Ok(init) = event.candidate.to_json() else {
            return;
        };
        // `to_json` fills placeholder mids; transport them as absent.
        let mid = match init.sdp_mid.as_deref() {
            None | Some("") => None,
            Some(mid) => Some(mid.to_owned()),
        };
        self.shared.push_event(TransportEvent::IceCandidate {
            candidate: init.candidate,
            sdp_mid: mid,
            sdp_mline_index: init.sdp_mline_index,
        });
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        let mapped = match state {
            RTCPeerConnectionState::New => ConnectionState::New,
            RTCPeerConnectionState::Connecting => ConnectionState::Connecting,
            RTCPeerConnectionState::Connected => ConnectionState::Connected,
            RTCPeerConnectionState::Disconnected => ConnectionState::Disconnected,
            RTCPeerConnectionState::Failed => ConnectionState::Failed,
            RTCPeerConnectionState::Closed => ConnectionState::Closed,
            _ => ConnectionState::Connecting,
        };
        self.shared
            .push_event(TransportEvent::ConnectionStateChanged(mapped));
        if mapped == ConnectionState::Failed {
            self.shared.push_event(TransportEvent::Failed {
                reason: "peer connection failed".to_owned(),
            });
        }
    }

    async fn on_data_channel(&self, dc: Arc<dyn DataChannel>) {
        let Ok(label) = dc.label().await else {
            return;
        };
        let Some(slot) = self.channels.for_label(&label) else {
            self.shared.push_event(TransportEvent::Failed {
                reason: format!("unexpected data channel label {label:?}"),
            });
            return;
        };
        attach_data_channel(Arc::clone(&self.shared), Arc::clone(slot), dc).await;
    }

    async fn on_track(&self, track: Arc<dyn TrackRemote>) {
        let shared = Arc::clone(&self.shared);
        let ext_id = Arc::clone(&self.rx_frame_ext_id);
        tokio::spawn(async move {
            video_receive_loop(shared, ext_id, track).await;
        });
    }
}

/// Receive loop for the remote video track: depacketize, carry the
/// `urn:rd:frame-id` extension, abort on mid-frame sequence gaps, push
/// complete frames into the bounded newest-wins queue.
async fn video_receive_loop(
    shared: Arc<Shared>,
    ext_id: Arc<AtomicU8>,
    track: Arc<dyn TrackRemote>,
) {
    let mut assembler = FrameAssembler::new();
    let mut last_seq: Option<u16> = None;
    // Per-frame state.
    let mut frame_id: Option<u64> = None;
    let mut frame_ts: u32 = 0;
    let mut missing: u32 = 0;
    // F31: first-packet arrival stamp for the in-flight frame.
    let mut frame_recv: Option<Instant> = None;
    // Set after in-frame loss: discard the damaged frame's remainder.
    let mut skipping_to_marker = false;

    while let Some(event) = track.poll().await {
        if shared.is_closing() {
            break;
        }
        let TrackRemoteEvent::OnRtpPacket(pkt) = &event else {
            continue;
        };
        shared.packets_received.fetch_add(1, Ordering::Relaxed);
        let seq = pkt.header.sequence_number;

        if let Some(last) = last_seq
            && seq != last.wrapping_add(1)
        {
            let gap = seq.wrapping_sub(last.wrapping_add(1)) as u32;
            if skipping_to_marker {
                missing = missing.saturating_add(gap);
            } else if assembler.has_partial() {
                // Mid-frame hole: abort the partial assembly and skip
                // the damaged frame's remainder up to its marker.
                assembler.abort_partial();
                shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
                skipping_to_marker = true;
                frame_id = None;
                frame_recv = None;
                missing = 0;
            }
            // A gap with no partial assembly is a sender-side drop —
            // normal under the bounded send queue, not an error here.
        }
        last_seq = Some(seq);

        if skipping_to_marker {
            if pkt.header.marker {
                skipping_to_marker = false;
            }
            continue;
        }

        if frame_id.is_none() {
            let id = ext_id.load(Ordering::Acquire);
            if id != 0 {
                frame_id = pkt
                    .header
                    .get_extension(id)
                    .and_then(|payload| parse_frame_id_ext(&payload));
            }
            frame_ts = pkt.header.timestamp;
            if frame_recv.is_none() {
                frame_recv = Some(Instant::now());
            }
        }

        match assembler.push(&pkt.payload, pkt.header.marker) {
            Ok(Some(access_unit)) => {
                let frame = ReceivedFrame {
                    frame_id,
                    rtp_timestamp: frame_ts,
                    is_keyframe: is_keyframe_annexb(&access_unit),
                    bytes: access_unit,
                    missing_packets: missing,
                    recv_instant: frame_recv,
                };
                let mut queue = shared.video_rx.lock().expect("video queue poisoned");
                if queue.len() >= VIDEO_QUEUE_CAPACITY {
                    queue.pop_front();
                    shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
                }
                queue.push_back(frame);
                shared.frames_received.fetch_add(1, Ordering::Relaxed);
                drop(queue);
                frame_id = None;
                frame_recv = None;
                missing = 0;
            }
            Ok(None) => {}
            Err(_) => {
                // Malformed payload: same recovery path as loss.
                assembler.abort_partial();
                shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
                skipping_to_marker = true;
                frame_id = None;
                frame_recv = None;
                missing = 0;
            }
        }
    }
}

impl Transport for WebrtcTransport {
    fn compose_offer(&mut self) -> Result<String, TransportError> {
        let pc = self.require_pc()?;
        let sdp: Result<Result<String, String>, String> =
            self.bridge("compose_offer", async move {
                let offer = pc.create_offer(None).await.map_err(|e| format!("{e}"))?;
                pc.set_local_description(offer.clone())
                    .await
                    .map_err(|e| format!("{e}"))?;
                Ok(offer.sdp)
            });
        sdp.and_then(|inner| inner)
            .map_err(|e| TransportError(format!("compose_offer failed: {e}")))
    }

    fn compose_answer(&mut self, offer_sdp: &str) -> Result<String, TransportError> {
        let pc = self.require_pc()?;
        let offer = RTCSessionDescription::offer(offer_sdp.to_owned())
            .map_err(|e| TransportError(format!("invalid offer: {e}")))?;
        let result: Result<(String, Arc<VideoSend>), String> = self
            .bridge("compose_answer", async move {
                pc.set_remote_description(offer)
                    .await
                    .map_err(|e| format!("{e}"))?;

                // Host sends video: bind a static RTP track to the offer's
                // video m-line (recvonly from the controller's view).
                let ssrc = session_ssrc();
                let track = Arc::new(TrackLocalStaticRTP::new(MediaStreamTrack::new(
                    "rd-video-stream".to_owned(),
                    "rd-video-track".to_owned(),
                    "rd-video".to_owned(),
                    RtpCodecKind::Video,
                    vec![RTCRtpEncodingParameters {
                        rtp_coding_parameters: RTCRtpCodingParameters {
                            ssrc: Some(ssrc),
                            ..Default::default()
                        },
                        ..Default::default()
                    }],
                )));
                let sender = pc
                    .add_track(Arc::clone(&track) as Arc<dyn TrackLocal>)
                    .await
                    .map_err(|e| format!("add_track: {e}"))?;

                let answer = pc.create_answer(None).await.map_err(|e| format!("{e}"))?;
                pc.set_local_description(answer.clone())
                    .await
                    .map_err(|e| format!("{e}"))?;

                // Resolve the negotiated payload type — webrtc-rs requires
                // outgoing RTP packets to carry it.
                let params = sender
                    .get_parameters()
                    .await
                    .map_err(|e| format!("get_parameters: {e}"))?;
                let payload_type = params
                    .rtp_parameters
                    .codecs
                    .iter()
                    .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case("video/h264"))
                    .map(|c| c.payload_type)
                    .ok_or_else(|| "no negotiated H264 payload type".to_owned())?;

                Ok((
                    answer.sdp,
                    Arc::new(VideoSend {
                        track,
                        seq: AtomicU16::new(0),
                        payload_type: AtomicU8::new(payload_type),
                        ssrc: AtomicU32::new(ssrc),
                    }),
                ))
            })
            .and_then(|inner| inner);
        let (sdp, video) =
            result.map_err(|e| TransportError(format!("compose_answer failed: {e}")))?;
        // M5: arm the netem shaper task now that the video track exists.
        if let (Some(rx), Some(shared_netem)) = (self.netem_rx.take(), self.netem.as_ref()) {
            let gauges = Arc::clone(&shared_netem.gauges);
            self.runtime.spawn(netem_shaper_loop(
                rx,
                Arc::clone(&video),
                Arc::clone(&self.shared),
                gauges,
            ));
        }
        *self.video.lock().expect("video poisoned") = Some(video);
        self.shared
            .push_event(TransportEvent::LocalAnswer { sdp: sdp.clone() });
        Ok(sdp)
    }

    fn apply_answer(&mut self, answer_sdp: &str) -> Result<(), TransportError> {
        let pc = self.require_pc()?;
        let answer = RTCSessionDescription::answer(answer_sdp.to_owned())
            .map_err(|e| TransportError(format!("invalid answer: {e}")))?;
        let rx_cell = Arc::clone(&self.rx_frame_ext_id);
        let result: Result<Result<u8, String>, String> = self.bridge("apply_answer", async move {
            pc.set_remote_description(answer)
                .await
                .map_err(|e| format!("{e}"))?;
            // Resolve the receive-side `urn:rd:frame-id` extension id from
            // the negotiated SDP. The remote answer is authoritative; fall
            // back to our own offer (ids survive when the answerer accepts
            // the extension, which both MediaEngines registered). The
            // transceivers' `get_parameters().header_extensions` did not
            // expose the URI at this stage in webrtc 0.21.0 — recorded as
            // an API-risk finding.
            let mut found = 0u8;
            if let Some(remote) = pc.remote_description().await {
                found = find_extmap_id(&remote.sdp).unwrap_or(0);
            }
            if found == 0
                && let Some(local) = pc.local_description().await
            {
                found = find_extmap_id(&local.sdp).unwrap_or(0);
            }
            Ok(found)
        });
        let id = result
            .and_then(|inner| inner)
            .map_err(|e| TransportError(format!("apply_answer failed: {e}")))?;
        rx_cell.store(id, Ordering::Release);
        Ok(())
    }

    fn add_remote_candidate(
        &mut self,
        candidate: &str,
        sdp_mid: Option<&str>,
        sdp_mline_index: Option<u16>,
    ) -> Result<(), TransportError> {
        if candidate.trim().is_empty() {
            return Err(TransportError("empty ICE candidate".into()));
        }
        // Duplicate-signaling contract: re-delivery is a no-op.
        {
            let mut seen = self.shared.seen_candidates.lock().expect("dedupe poisoned");
            if !seen.insert(candidate.to_owned()) {
                return Ok(());
            }
            if seen.len() > CANDIDATE_DEDUPE_CAPACITY {
                seen.clear();
                seen.insert(candidate.to_owned());
            }
        }
        let pc = self.require_pc()?;
        let init = RTCIceCandidateInit {
            candidate: candidate.to_owned(),
            sdp_mid: sdp_mid.map(str::to_owned),
            sdp_mline_index,
            username_fragment: None,
            url: None,
        };
        let result: Result<Result<(), String>, String> = self
            .bridge("add_remote_candidate", async move {
                pc.add_ice_candidate(init).await.map_err(|e| format!("{e}"))
            });
        // A candidate the ICE agent rejects at this stage is a typed error,
        // never a panic (ICE-failure test path).
        result
            .and_then(|inner| inner)
            .map_err(|e| TransportError(format!("add_remote_candidate failed: {e}")))
    }

    fn send(&mut self, channel: Channel, bytes: &[u8]) -> Result<(), TransportError> {
        self.channels.slot(channel).enqueue(bytes.to_vec())
    }

    fn poll(&mut self) -> Option<TransportEvent> {
        self.shared
            .events
            .lock()
            .expect("event queue poisoned")
            .pop_front()
    }

    fn send_video(&mut self, frame: VideoFrame) -> Result<(), TransportError> {
        let video = self
            .video
            .lock()
            .expect("video poisoned")
            .clone()
            .ok_or_else(|| TransportError("video track not established (host role only)".into()))?;
        let payloads = packetize_access_unit(&frame.bytes, DEFAULT_MTU)?;
        let payload_type = video.payload_type.load(Ordering::Relaxed);
        let ssrc = video.ssrc.load(Ordering::Relaxed);
        let timestamp = rtp_timestamp_from_ns(frame.timestamp_ns);
        let frame_id = frame.frame_id;

        // M5 netem path: per-packet verdicts on the caller thread (the
        // Netem decision state is a plain mutex, deterministic), the actual
        // RTP write happens in the shaper task at each packet's due time.
        // The channel is bounded; overflow drops the incoming packet and
        // counts it (queue-overflow loss, invariant 3 evidence).
        if let (Some(state), Some(tx)) = (self.netem.as_ref(), self.netem_tx.as_ref()) {
            let count = payloads.len();
            let now = Instant::now();
            let now_ms = netem_now_ms(now);
            let mut dropped = 0u64;
            for (index, payload) in payloads.into_iter().enumerate() {
                let seq = video.seq.fetch_add(1, Ordering::Relaxed);
                let packet = RtpPacket {
                    header: RtpHeader {
                        version: 2,
                        marker: index + 1 == count,
                        payload_type,
                        sequence_number: seq,
                        timestamp,
                        ssrc,
                        ..Default::default()
                    },
                    payload,
                };
                let verdict = state
                    .netem
                    .lock()
                    .expect("netem poisoned")
                    .verdict(now_ms, DEFAULT_MTU);
                match verdict {
                    PacketVerdict::Drop => dropped += 1,
                    PacketVerdict::Deliver { delay_ms } => {
                        if tx
                            .try_send(ShapedPacket {
                                packet,
                                frame_id,
                                due: now + Duration::from_millis(delay_ms),
                            })
                            .is_err()
                        {
                            dropped += 1; // queue overflow
                        }
                    }
                }
            }
            if dropped > 0 {
                state.gauges.dropped.fetch_add(dropped, Ordering::Relaxed);
            }
            self.shared.frames_sent.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        let shared = Arc::clone(&self.shared);
        self.bridge("send_video", async move {
            let extensions = [HeaderExtension::Custom {
                uri: Cow::Borrowed(FRAME_ID_EXTENSION_URI),
                extension: Box::new(FrameIdExt { frame_id }),
            }];
            let count = payloads.len();
            for (index, payload) in payloads.into_iter().enumerate() {
                let seq = video.seq.fetch_add(1, Ordering::Relaxed);
                let header = RtpHeader {
                    version: 2,
                    marker: index + 1 == count,
                    payload_type,
                    sequence_number: seq,
                    timestamp,
                    ssrc,
                    ..Default::default()
                };
                let packet = RtpPacket { header, payload };
                video
                    .track
                    .write_rtp_with_extensions(packet, &extensions)
                    .await
                    .map_err(|e| format!("write_rtp: {e}"))?;
                shared.packets_sent.fetch_add(1, Ordering::Relaxed);
            }
            shared.frames_sent.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .and_then(|inner| inner)
        .map_err(|e| TransportError(format!("send_video failed: {e}")))
    }

    fn poll_video(&mut self) -> Option<ReceivedFrame> {
        self.shared
            .video_rx
            .lock()
            .expect("video queue poisoned")
            .pop_front()
    }

    fn stats(&mut self) -> Result<TransportStats, TransportError> {
        let pc = self.require_pc()?;
        type Snapshot = (
            Option<f64>,
            Option<(u64, u64, i64, f64)>,
            Option<(u64, u64)>,
            Option<(f64, f64)>,
            Option<SelectedIcePair>,
            bool,
        );
        let snapshot: Result<Snapshot, String> = self
            .bridge("stats", async move {
                let report = pc.get_stats(Instant::now(), StatsSelector::None).await;
                let mut rtt = None;
                let mut inbound = None;
                let mut outbound = None;
                // M5: remote-inbound-rtp = the receiver's RTCP RR projection
                // of OUR outbound stream (fraction lost + RR RTT).
                let mut remote_inbound = None;
                let mut pair_ids: Option<(String, String, bool)> = None;
                let mut relay = false;

                for entry in report.iter() {
                    match entry {
                        RTCStatsReportEntry::IceCandidatePair(p) => {
                            let usable = p.state == RTCStatsIceCandidatePairState::Succeeded
                                || (p.nominated
                                    && p.state != RTCStatsIceCandidatePairState::Failed);
                            if usable && pair_ids.is_none() {
                                rtt = Some(p.current_round_trip_time * 1000.0);
                                pair_ids = Some((
                                    p.local_candidate_id.clone(),
                                    p.remote_candidate_id.clone(),
                                    p.nominated,
                                ));
                            }
                        }
                        RTCStatsReportEntry::InboundRtp(i) => {
                            inbound = Some((
                                i.bytes_received,
                                i.received_rtp_stream_stats.packets_received,
                                i.received_rtp_stream_stats.packets_lost,
                                i.received_rtp_stream_stats.jitter,
                            ));
                        }
                        RTCStatsReportEntry::OutboundRtp(o) => {
                            outbound = Some((
                                o.sent_rtp_stream_stats.bytes_sent,
                                o.sent_rtp_stream_stats.packets_sent,
                            ));
                        }
                        RTCStatsReportEntry::RemoteInboundRtp(r) => {
                            remote_inbound = Some((r.fraction_lost, r.round_trip_time));
                        }
                        _ => {}
                    }
                }

                // Resolve the selected pair's addresses/types from the
                // candidate entries (addresses only — no SDP secrets).
                let selected = pair_ids.and_then(|(local_id, remote_id, nominated)| {
                    let mut local = None;
                    let mut remote = None;
                    for entry in report.iter() {
                        let (RTCStatsReportEntry::LocalCandidate(c)
                        | RTCStatsReportEntry::RemoteCandidate(c)) = entry
                        else {
                            continue;
                        };
                        let endpoint = (
                            format!("{}:{}", c.address.clone().unwrap_or_default(), c.port),
                            candidate_type_name(c.candidate_type),
                        );
                        if c.candidate_type == RTCIceCandidateType::Relay {
                            relay = true;
                        }
                        // Report entry ids carry a type prefix
                        // (`RTCLocalIceCandidate_candidate:...`) while the pair
                        // references the bare candidate id — match by suffix.
                        if c.stats.id.ends_with(&local_id) {
                            local = Some(endpoint.clone());
                        }
                        if c.stats.id.ends_with(&remote_id) {
                            remote = Some(endpoint);
                        }
                    }
                    let (local, remote) = (local?, remote?);
                    Some(SelectedIcePair {
                        local_address: local.0,
                        local_candidate_type: local.1,
                        remote_address: remote.0,
                        remote_candidate_type: remote.1,
                        nominated,
                    })
                });
                Ok((rtt, inbound, outbound, remote_inbound, selected, relay))
            })
            .and_then(|inner| inner);
        let (rtt, inbound, outbound, remote_inbound, selected, relay) =
            snapshot.map_err(|e| TransportError(format!("stats failed: {e}")))?;

        // Bitrate over the interval since the previous stats() call.
        let now = Instant::now();
        let (mut send_kbps, mut recv_kbps) = (None, None);
        {
            let mut last = self
                .shared
                .last_bitrate_sample
                .lock()
                .expect("bitrate sample poisoned");
            if let Some((at, prev_sent, prev_recv)) = *last {
                let elapsed = now.duration_since(at).as_secs_f64().max(0.001);
                if let Some((bytes, _)) = outbound {
                    send_kbps =
                        Some(bytes.saturating_sub(prev_sent) as f64 * 8.0 / 1000.0 / elapsed);
                }
                if let Some((bytes, _, _, _)) = inbound {
                    recv_kbps =
                        Some(bytes.saturating_sub(prev_recv) as f64 * 8.0 / 1000.0 / elapsed);
                }
            }
            *last = Some((
                now,
                outbound.map(|(b, _)| b).unwrap_or(0),
                inbound.map(|(b, _, _, _)| b).unwrap_or(0),
            ));
        }

        let mut channel_queue = ChannelQueues::default();
        for (index, slot) in self.channels.slots.iter().enumerate() {
            let (depth, capacity, high_water, dropped, replaced) = slot.gauges();
            channel_queue.depth[index] = depth;
            channel_queue.capacity[index] = capacity;
            channel_queue.high_water[index] = high_water;
            channel_queue.dropped[index] = dropped;
            channel_queue.replaced[index] = replaced;
            channel_queue.enqueued[index] = slot.enqueued.load(Ordering::Relaxed);
            channel_queue.dequeued[index] = slot.dequeued.load(Ordering::Relaxed);
        }

        let loss_percent = inbound.map(|(_, received, lost, _)| {
            let total = received as f64 + lost.max(0) as f64;
            if total > 0.0 {
                lost.max(0) as f64 * 100.0 / total
            } else {
                0.0
            }
        });

        let (available_bandwidth_bps, congestion_stats) = self
            .congestion
            .as_ref()
            .map(|publish| publish.snapshot())
            .unwrap_or((None, CongestionStats::default()));
        let (remote_loss_percent, remote_rtt_ms) = match remote_inbound {
            Some((fraction_lost, rtt_secs)) => (
                Some(fraction_lost.clamp(0.0, 1.0) * 100.0),
                Some(rtt_secs.max(0.0) * 1000.0),
            ),
            None => (None, None),
        };

        Ok(TransportStats {
            rtt_ms: rtt,
            send_bitrate_kbps: send_kbps,
            recv_bitrate_kbps: recv_kbps,
            loss_percent,
            jitter_ms: inbound.map(|(_, _, _, jitter)| jitter * 1000.0),
            selected_pair: selected,
            relay_in_use: relay,
            packets_sent: self.shared.packets_sent.load(Ordering::Relaxed),
            packets_received: self.shared.packets_received.load(Ordering::Relaxed),
            packets_lost: inbound
                .map(|(_, _, lost, _)| lost.max(0) as u64)
                .unwrap_or(0),
            frames_sent: self.shared.frames_sent.load(Ordering::Relaxed),
            frames_received: self.shared.frames_received.load(Ordering::Relaxed),
            frames_dropped: self.shared.frames_dropped.load(Ordering::Relaxed),
            channel_queue,
            events_dropped: self.shared.events_overflow.load(Ordering::Relaxed),
            available_bandwidth_bps,
            remote_loss_percent,
            remote_rtt_ms,
            congestion_stats: if self.congestion.is_some() {
                Some(congestion_stats)
            } else {
                None
            },
            netem_queue: self.netem.as_ref().map(|state| state.gauges.stats()),
        })
    }

    fn channel_queue_gauges(&mut self) -> Option<ChannelQueues> {
        // No async bridge: locks only, safe at a few-ms polling cadence.
        let mut merged = ChannelQueues::default();
        for slot in self.channels.slots.iter() {
            let quick = slot.quick_gauges();
            let index = slot.channel as usize;
            merged.depth[index] = quick.depth[index];
            merged.capacity[index] = quick.capacity[index];
            merged.high_water[index] = quick.high_water[index];
            merged.dropped[index] = quick.dropped[index];
            merged.replaced[index] = quick.replaced[index];
            merged.enqueued[index] = quick.enqueued[index];
            merged.dequeued[index] = quick.dequeued[index];
        }
        Some(merged)
    }

    fn restart_ice(&mut self) -> Result<(), TransportError> {
        let pc = self.require_pc()?;
        let result: Result<Result<(), String>, String> = self.bridge("restart_ice", async move {
            pc.restart_ice().await.map_err(|e| format!("{e}"))
        });
        result
            .and_then(|inner| inner)
            .map_err(|e| TransportError(format!("restart_ice failed: {e}")))
    }

    fn close(&mut self) {
        self.shutdown(CLOSE_TIMEOUT);
    }
}

/// Stable per-session SSRC derived from time + a process counter (no
/// randomness dependency; uniqueness within a session is what RTP needs).
fn session_ssrc() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let hash = nanos
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(count.wrapping_mul(0xBF58_476D_1CE4_E5B9));
    (hash >> 32) as u32 | 1
}

/// Deterministic millisecond feed for the netem verdicts (process uptime).
fn netem_now_ms(now: Instant) -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    now.saturating_duration_since(*start).as_millis() as u64
}

/// Find the negotiated extmap id for `FRAME_ID_EXTENSION_URI` in an SDP
/// text (`a=extmap:<id>[/<direction>] <uri>`). The SDP is parsed, never
/// logged (invariant 6).
fn find_extmap_id(sdp: &str) -> Option<u8> {
    for line in sdp.lines() {
        let Some(rest) = line.trim().strip_prefix("a=extmap:") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let Some(id_token) = parts.next() else {
            continue;
        };
        let Some(uri) = parts.next() else { continue };
        if uri == FRAME_ID_EXTENSION_URI {
            let id = id_token.split('/').next()?;
            return id.parse::<u8>().ok();
        }
    }
    None
}

fn candidate_type_name(t: RTCIceCandidateType) -> String {
    match t {
        RTCIceCandidateType::Host => "host".to_owned(),
        RTCIceCandidateType::Srflx => "srflx".to_owned(),
        RTCIceCandidateType::Prflx => "prflx".to_owned(),
        RTCIceCandidateType::Relay => "relay".to_owned(),
        _ => "unknown".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Invariant 3 at the queue layer: reliable channels reject with a
    /// typed error when the bounded queue is full, and the drop is counted;
    /// lossy channels evict the oldest message instead (newest wins).
    #[test]
    fn channel_slot_queue_policies() {
        let reliable = ChannelSlot::new(Channel::InputReliable);
        for i in 0..RELIABLE_QUEUE_CAPACITY {
            reliable.enqueue(vec![i as u8]).expect("within capacity");
        }
        let err = reliable.enqueue(vec![0xFF]).expect_err("must reject");
        assert!(err.0.contains("input-reliable send queue full"), "{err:?}");
        let (_, capacity, high_water, dropped, _) = reliable.gauges();
        assert_eq!(capacity as usize, RELIABLE_QUEUE_CAPACITY);
        assert_eq!(high_water as usize, RELIABLE_QUEUE_CAPACITY);
        assert_eq!(dropped, 1);

        let lossy = ChannelSlot::new(Channel::InputFast);
        for i in 0..(FAST_QUEUE_CAPACITY + 10) {
            lossy.enqueue(vec![i as u8]).expect("lossy never rejects");
        }
        let (depth, _, _, dropped, replaced) = lossy.gauges();
        assert_eq!(depth as usize, FAST_QUEUE_CAPACITY);
        assert_eq!(dropped, 0, "lossy drops are replacements, not errors");
        assert_eq!(replaced, 10, "newest-wins evictions are counted");
        // The queue holds the newest messages.
        let queue = lossy.queue.lock().expect("queue poisoned");
        assert_eq!(queue.front(), Some(&vec![10u8]));
    }

    /// SDP extmap scanning: the receive-side frame-id id resolution path.
    #[test]
    fn find_extmap_id_parses_negotiated_lines() {
        let sdp = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 102\r\na=extmap:3 urn:ietf:params:rtp-hdrext:toffset\r\na=extmap:1/recvonly urn:rd:frame-id\r\na=extmap:4 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n";
        assert_eq!(
            find_extmap_id(sdp),
            Some(1),
            "direction suffix must not break parsing"
        );
        assert_eq!(find_extmap_id("a=extmap:7 something-else\r\n"), None);
        assert_eq!(find_extmap_id(""), None);
    }

    /// The bridge guard: a closing transport refuses new work typed, not by
    /// hanging.
    #[test]
    fn bridge_refuses_when_closing() {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime"),
        );
        let closing = AtomicBool::new(true);
        let result: Result<Result<(), String>, String> =
            bridge(&runtime, &closing, BRIDGE_TIMEOUT, "test", async {
                Ok::<(), String>(())
            });
        assert!(result.unwrap_err().contains("closing"));
    }
}
