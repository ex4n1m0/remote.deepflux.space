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
    MediaEngine, PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler,
    RTCConfigurationBuilder, RTCIceCandidateInit, RTCIceCandidateType, RTCPeerConnectionIceEvent,
    RTCPeerConnectionState, RTCSessionDescription, RTCStatsReportEntry, Registry,
    SettingEngineBuilder, StatsSelector, register_default_interceptors,
};
use webrtc::runtime::TokioRuntime;

use crate::rtp::{
    DEFAULT_MTU, FrameAssembler, FrameIdExt, is_keyframe_annexb, packetize_access_unit,
    parse_frame_id_ext, rtp_timestamp_from_ns,
};
use crate::{
    Channel, ChannelQueues, ConnectionState, FRAME_ID_EXTENSION_URI, ReceivedFrame,
    SelectedIcePair, Transport, TransportError, TransportEvent, TransportStats, VideoFrame,
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
    closed: AtomicBool,
}

impl Drop for WebrtcTransport {
    fn drop(&mut self) {
        self.shutdown(Duration::from_secs(2));
    }
}

impl WebrtcTransport {
    /// Build a transport for `role`: private runtime + webrtc-rs peer
    /// connection with no ICE servers (no STUN in the loopback spike, TURN
    /// forbidden by invariant 4), mDNS disabled so host candidates carry
    /// real addresses, loopback-only UDP sockets, default interceptors
    /// (RTCP reports + NACK), exactly one H.264 codec, and the
    /// `urn:rd:frame-id` header extension registered for negotiation.
    pub fn new(role: WebrtcTransportRole) -> Result<Self, TransportError> {
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
        let registry = register_default_interceptors(Registry::new(), &mut media)
            .map_err(|e| TransportError(format!("interceptor setup failed: {e}")))?;

        let setting_engine = SettingEngineBuilder::new()
            .with_multicast_dns_mode(rtc::ice::mdns::MulticastDnsMode::Disabled)
            .build();

        // Deliberately no `with_ice_servers`: zero ICE servers (invariant 4).
        let config = RTCConfigurationBuilder::new().build();

        let shared = Arc::new(Shared::new());
        let channels = Channels::new();
        let rx_frame_ext_id = Arc::new(AtomicU8::new(0));

        let handler = TransportHandler {
            shared: Arc::clone(&shared),
            channels: channels.clone(),
            rx_frame_ext_id: Arc::clone(&rx_frame_ext_id),
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
                    .with_udp_addrs(vec!["127.0.0.1:0".to_owned()])
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
        }

        match assembler.push(&pkt.payload, pkt.header.marker) {
            Ok(Some(access_unit)) => {
                let frame = ReceivedFrame {
                    frame_id,
                    rtp_timestamp: frame_ts,
                    is_keyframe: is_keyframe_annexb(&access_unit),
                    bytes: access_unit,
                    missing_packets: missing,
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
                missing = 0;
            }
            Ok(None) => {}
            Err(_) => {
                // Malformed payload: same recovery path as loss.
                assembler.abort_partial();
                shared.frames_dropped.fetch_add(1, Ordering::Relaxed);
                skipping_to_marker = true;
                frame_id = None;
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
            Option<SelectedIcePair>,
            bool,
        );
        let snapshot: Result<Snapshot, String> = self
            .bridge("stats", async move {
                let report = pc.get_stats(Instant::now(), StatsSelector::None).await;
                let mut rtt = None;
                let mut inbound = None;
                let mut outbound = None;
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
                Ok((rtt, inbound, outbound, selected, relay))
            })
            .and_then(|inner| inner);
        let (rtt, inbound, outbound, selected, relay) =
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
        }

        let loss_percent = inbound.map(|(_, received, lost, _)| {
            let total = received as f64 + lost.max(0) as f64;
            if total > 0.0 {
                lost.max(0) as f64 * 100.0 / total
            } else {
                0.0
            }
        });

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
        })
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
