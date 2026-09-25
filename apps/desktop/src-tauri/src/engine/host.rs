//! Host pipeline: DXGI capture → MF H.264 encode (M4 product adaptation
//! of the `m2_rig` composition). Differences from the rig:
//!
//! * the monitor to duplicate is runtime-switchable (`SelectMonitor`) — the
//!   capture thread swaps the duplication when the wanted monitor changes
//!   and forces a keyframe (new content),
//! * the encoder configuration comes from the quality preset
//!   (`engine::quality`), and a preset change rebuilds the stage,
//! * every queue still samples per `docs/perf-counter-schema.md` through a
//!   tee sink (JSONL report + UI aggregation).

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use capture_windows::{CaptureError, CaptureSource, DxgiCapture};
use codec_windows::{EncodeInput, VideoEncoder as _};
use diagnostics::{PerfSink, QueueKind};
use frame_surface::GpuDevice;
use node_runtime::Clock as _;
use node_runtime::clock::MonotonicClock;
use node_runtime::metrics::{ClockFn, DropPolicy, FrameQueue, LatestSlot, SessionSlot};
use node_runtime::pacing::FramePacer;
use protocol::wire::CursorMessage;

use super::pool::CodecPool;
use super::quality::QualityPlan;

pub struct CapItem {
    pub frame_id: u64,
    pub capture_ns: u64,
    pub surface: frame_surface::FrameSurface,
}

pub struct WireItem {
    pub packet: codec_windows::EncodedPacket,
    pub capture_ns: u64,
    pub encode_submit_ns: u64,
    pub encode_done_ns: u64,
}

#[derive(Default)]
pub struct HostPipeCounters {
    pub captured: AtomicU64,
    pub encoded: AtomicU64,
    pub cursor_only: AtomicU64,
    pub encode_deferred: AtomicU64,
    pub keyframes: AtomicU64,
    pub keyframe_forced: AtomicU64,
    pub cursor_positions: AtomicU64,
    pub device_lost: AtomicU64,
    pub capture_reinit: AtomicU64,
    pub monitor_switches: AtomicU64,
    pub display_changed: AtomicU64,
    pub encode_errors: AtomicU64,
}

/// Host-stage runtime control shared with the engine loop.
pub struct HostCtl {
    /// Monitor the user selected (engine sets; capture thread applies).
    pub want_monitor: Mutex<String>,
    /// Monitor currently duplicated (capture thread updates).
    pub active_monitor: Mutex<String>,
    /// Keyframe request flag (controller PLI, monitor switch, session start).
    pub force_keyframe: Arc<AtomicBool>,
    /// Capture thread saw a display change (engine refreshes the input
    /// sink's display metrics once per edge).
    pub display_changed_edge: AtomicBool,
}

impl HostCtl {
    pub fn new(monitor: &str) -> Self {
        Self {
            want_monitor: Mutex::new(monitor.to_owned()),
            active_monitor: Mutex::new(monitor.to_owned()),
            force_keyframe: Arc::new(AtomicBool::new(false)),
            display_changed_edge: AtomicBool::new(false),
        }
    }

    pub fn select_monitor(&self, monitor: &str) {
        *self.want_monitor.lock().expect("want monitor") = monitor.to_owned();
    }

    pub fn active_monitor(&self) -> String {
        self.active_monitor.lock().expect("active monitor").clone()
    }
}

fn stamp_with(cap: &mut DxgiCapture, clock: &Arc<MonotonicClock>) {
    let clock = Arc::clone(clock);
    cap.set_clock(Box::new(move || clock.now_ns()));
}

/// One live host capture→encode pipeline (rebuilt per session and per
/// quality-preset change).
pub struct HostPipeline {
    pub q_cap_enc: Arc<FrameQueue<CapItem>>,
    pub q_enc_send: Arc<FrameQueue<WireItem>>,
    pub cursor_slot: Arc<LatestSlot<CursorMessage>>,
    capture_stop: Arc<AtomicBool>,
    joins: Vec<std::thread::JoinHandle<()>>,
    pub counters: Arc<HostPipeCounters>,
    pub ctl: Arc<HostCtl>,
    /// Encoder description for diagnostics (set by the encode thread).
    pub encoder_describe: Arc<Mutex<Option<String>>>,
}

impl HostPipeline {
    /// `make_sink` produces one schema-exact `PerfSink` per bounded queue
    /// (the engine tees JSONL + UI aggregation).
    pub fn start(
        device: GpuDevice,
        codec_pool: &CodecPool,
        plan: &QualityPlan,
        monitor: &str,
        mut make_sink: impl FnMut() -> Box<dyn PerfSink>,
        session: Arc<SessionSlot>,
        clock: Arc<MonotonicClock>,
    ) -> Result<Self, String> {
        let force_keyframe = Arc::new(AtomicBool::new(true)); // session start ⇒ IDR
        let ctl = Arc::new(HostCtl::new(monitor));
        let clock_fn: ClockFn = {
            let clock = Arc::clone(&clock);
            Arc::new(move || clock.now_ns())
        };
        let q_cap_enc = Arc::new(FrameQueue::new(
            QueueKind::CaptureToEncode,
            1,
            DropPolicy::NewestWins,
            make_sink(),
            Arc::clone(&session),
            Arc::clone(&clock_fn),
        ));
        let q_enc_send = Arc::new(FrameQueue::new(
            QueueKind::EncodeToSend,
            1,
            DropPolicy::NewestWins,
            make_sink(),
            session,
            clock_fn,
        ));
        let cursor_slot = Arc::new(LatestSlot::new());
        let counters = Arc::new(HostPipeCounters::default());
        let capture_stop = Arc::new(AtomicBool::new(false));
        let encoder_describe = Arc::new(Mutex::new(None));
        let mut joins = Vec::new();

        // ---- capture thread ----
        {
            let stop = Arc::clone(&capture_stop);
            let q = Arc::clone(&q_cap_enc);
            let cursor_slot = Arc::clone(&cursor_slot);
            let counters = Arc::clone(&counters);
            let device = device.clone();
            let capture_pool = Arc::clone(&codec_pool.capture);
            let ctl = Arc::clone(&ctl);
            let force = Arc::clone(&force_keyframe);
            let clock = Arc::clone(&clock);
            let fps = plan.fps;
            joins.push(
                std::thread::Builder::new()
                    .name("capture".into())
                    .spawn(move || {
                        frame_surface::attach_thread_to_input_desktop().expect("input desktop");
                        let mut cap = match capture_pool.lock().expect("capture pool").take() {
                            Some(cap) => cap,
                            None => match DxgiCapture::new(device.clone(), &ctl.active_monitor()) {
                                Ok(cap) => cap,
                                Err(err) => {
                                    eprintln!("[host] capture init failed: {err}");
                                    q.close();
                                    return;
                                }
                            },
                        };
                        stamp_with(&mut cap, &clock);
                        eprintln!(
                            "[host] capture: {} at {:?}",
                            cap.monitor_id(),
                            cap.dimensions()
                        );
                        let mut pacer = FramePacer::new(fps);
                        pacer.start();
                        while !stop.load(Ordering::Acquire) {
                            pacer.wait();
                            // Monitor switch (SelectMonitor): swap the
                            // duplication, force a keyframe.
                            let want = ctl.want_monitor.lock().expect("want monitor").clone();
                            let active = ctl.active_monitor();
                            if want != active {
                                match DxgiCapture::new(device.clone(), &want) {
                                    Ok(mut new_cap) => {
                                        stamp_with(&mut new_cap, &clock);
                                        cap = new_cap;
                                        *ctl.want_monitor.lock().expect("want monitor") =
                                            want.clone();
                                        *ctl.active_monitor.lock().expect("active monitor") = want;
                                        force.store(true, Ordering::Release);
                                        counters.monitor_switches.fetch_add(1, Ordering::Relaxed);
                                        eprintln!(
                                            "[host] monitor switched: {} at {:?}",
                                            cap.monitor_id(),
                                            cap.dimensions()
                                        );
                                    }
                                    Err(err) => {
                                        eprintln!("[host] monitor switch to {want} failed: {err}");
                                        // Revert the request; keep duplicating `active`.
                                        *ctl.want_monitor.lock().expect("want monitor") = active;
                                    }
                                }
                            }
                            let budget = pacer.period();
                            match cap.next_frame(budget) {
                                Ok(Some(frame)) => {
                                    if let Some(cursor) = frame.cursor {
                                        if matches!(cursor, CursorMessage::Position { .. }) {
                                            counters
                                                .cursor_positions
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        cursor_slot.put(cursor);
                                    }
                                    if frame.metadata.only_cursor_update {
                                        counters.cursor_only.fetch_add(1, Ordering::Relaxed);
                                        continue;
                                    }
                                    counters.captured.fetch_add(1, Ordering::Relaxed);
                                    let _ = q.push(CapItem {
                                        frame_id: frame.frame_id,
                                        capture_ns: frame.timestamp_ns,
                                        surface: frame.surface,
                                    });
                                }
                                Ok(None) => {}
                                Err(CaptureError::AccessLost(_)) => {
                                    counters.capture_reinit.fetch_add(1, Ordering::Relaxed);
                                    std::thread::sleep(Duration::from_millis(100));
                                    let _ = cap.reinit();
                                }
                                Err(CaptureError::AccessDenied(detail)) => {
                                    eprintln!(
                                        "[host] capture denied (lock screen/protected): {detail}"
                                    );
                                    std::thread::sleep(Duration::from_millis(500));
                                }
                                Err(CaptureError::DisplayChanged(detail)) => {
                                    counters.capture_reinit.fetch_add(1, Ordering::Relaxed);
                                    counters.display_changed.fetch_add(1, Ordering::Relaxed);
                                    ctl.display_changed_edge.store(true, Ordering::Release);
                                    eprintln!("[host] display changed: {detail}");
                                    std::thread::sleep(Duration::from_millis(200));
                                    let monitor = ctl.active_monitor();
                                    match DxgiCapture::new(device.clone(), &monitor)
                                        .or_else(|_| DxgiCapture::new(device.clone(), "primary"))
                                    {
                                        Ok(mut new_cap) => {
                                            stamp_with(&mut new_cap, &clock);
                                            cap = new_cap;
                                        }
                                        Err(e) => eprintln!("[host] re-duplicate failed: {e}"),
                                    }
                                }
                                Err(CaptureError::DeviceLost(detail)) => {
                                    eprintln!("[host] capture DEVICE LOST: {detail}");
                                    counters.device_lost.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                                Err(e) => {
                                    eprintln!("[host] capture error: {e}");
                                    std::thread::sleep(Duration::from_millis(100));
                                }
                            }
                        }
                        *capture_pool.lock().expect("capture pool") = Some(cap);
                        q.close();
                    })
                    .expect("spawn capture"),
            );
        }

        // ---- encode thread ----
        {
            let q_in = Arc::clone(&q_cap_enc);
            let q_out = Arc::clone(&q_enc_send);
            let counters = Arc::clone(&counters);
            let force = Arc::clone(&force_keyframe);
            let clock = Arc::clone(&clock);
            let encoder_pool = Arc::clone(&codec_pool.encoder);
            let device = device.clone();
            let enc_cfg = plan.encoder_config();
            let describe_slot = Arc::clone(&encoder_describe);
            joins.push(
                std::thread::Builder::new()
                    .name("encode".into())
                    .spawn(move || {
                        let mut encoder = match encoder_pool.lock().expect("encoder pool").take() {
                            Some(encoder) => encoder,
                            None => match codec_windows::MfEncoder::new(device, enc_cfg) {
                                Ok(encoder) => encoder,
                                Err(e) => {
                                    eprintln!("[host] encoder init failed: {e}");
                                    q_out.close();
                                    return;
                                }
                            },
                        };
                        *describe_slot.lock().expect("describe") = Some(encoder.describe());
                        eprintln!("[host] encoder: {}", encoder.describe());
                        loop {
                            let Some(item) = q_in.pop(Duration::from_millis(100)) else {
                                if !q_in.is_open() {
                                    break;
                                }
                                continue;
                            };
                            let submit_ns = clock.now_ns();
                            let input = EncodeInput {
                                frame_id: item.frame_id,
                                timestamp_ns: item.capture_ns,
                                surface: item.surface,
                            };
                            let force = force.swap(false, Ordering::AcqRel);
                            if force {
                                counters.keyframe_forced.fetch_add(1, Ordering::Relaxed);
                            }
                            match encoder.encode(input, force) {
                                Ok(mut packet) => {
                                    packet.timestamp_ns = item.capture_ns;
                                    counters.encoded.fetch_add(1, Ordering::Relaxed);
                                    if packet.is_keyframe {
                                        counters.keyframes.fetch_add(1, Ordering::Relaxed);
                                    }
                                    let done_ns = clock.now_ns();
                                    let _ = q_out.push(WireItem {
                                        packet,
                                        capture_ns: item.capture_ns,
                                        encode_submit_ns: submit_ns,
                                        encode_done_ns: done_ns,
                                    });
                                }
                                Err(codec_windows::CodecError::Timeout(_)) => {
                                    counters.encode_deferred.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(codec_windows::CodecError::DeviceLost(d)) => {
                                    eprintln!("[host] encode DEVICE LOST: {d}");
                                    counters.device_lost.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }
                                Err(e) => {
                                    counters.encode_errors.fetch_add(1, Ordering::Relaxed);
                                    eprintln!("[host] encode error: {e}");
                                }
                            }
                        }
                        *encoder_pool.lock().expect("encoder pool") = Some(encoder);
                        q_out.close();
                    })
                    .expect("spawn encode"),
            );
        }

        Ok(Self {
            q_cap_enc,
            q_enc_send,
            cursor_slot,
            capture_stop,
            joins,
            counters,
            ctl,
            encoder_describe,
        })
    }

    pub fn stop(mut self) {
        self.capture_stop.store(true, Ordering::Release);
        self.q_cap_enc.close();
        self.q_enc_send.close();
        for join in self.joins.drain(..) {
            let _ = join.join();
        }
    }
}
