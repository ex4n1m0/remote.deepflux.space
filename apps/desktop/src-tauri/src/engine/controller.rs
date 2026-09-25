//! Controller pipeline: RTP receive → MF decode → native viewer present
//! (M4 product adaptation of the `m2_rig` composition). Differences from
//! the rig:
//!
//! * the present thread drives a [`ViewerWindow`] — the `render-windows`
//!   presenter subclassed for input capture, scale mode, and fullscreen —
//!   so the controller's keyboard/mouse route onto the wire through the
//!   same input path the rig used, and focus loss emits
//!   `AllKeysUp{FocusLost}`,
//! * cursor positions overlay locally (the cursor channel's purpose);
//! * queues still sample per the perf-counter schema through a tee sink.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use codec_windows::VideoDecoder as _;
use diagnostics::{CounterRecord, FrameTiming, Origin, PerfSink, QueueKind};
use frame_surface::GpuDevice;
use node_runtime::Clock as _;
use node_runtime::clock::MonotonicClock;
use node_runtime::metrics::{ClockFn, DropPolicy, FrameQueue, LatestSlot, SessionSlot};
use protocol::wire::CursorMessage;
use render_windows::{CursorOverlay, RenderFrame};
use transport_webrtc::ReceivedFrame;

use super::pool::CodecPool;
use super::viewer::{ViewerCtl, ViewerWindow};

pub struct RecvItem {
    pub frame: ReceivedFrame,
    pub recv_ns: u64,
}

pub struct DecItem {
    pub frame_id: u64,
    pub recv_ns: u64,
    pub decode_done_ns: u64,
    pub decoded: codec_windows::DecodedFrame,
}

#[derive(Default)]
pub struct ControllerPipeCounters {
    pub received: AtomicU64,
    pub decoded: AtomicU64,
    pub presented: AtomicU64,
    pub decode_errors: AtomicU64,
    pub idr_gate_drops: AtomicU64,
    pub keyframe_requests: AtomicU64,
    pub frames_missing_packets: AtomicU64,
    pub frame_id_gaps: AtomicU64,
    pub frames_without_frame_id: AtomicU64,
    pub device_lost: AtomicU64,
    pub window_closed: AtomicBool,
    pub cursor_positions: AtomicU64,
}

/// One live controller decode→present pipeline (rebuilt per session).
pub struct ControllerPipeline {
    pub q_recv_dec: Arc<FrameQueue<RecvItem>>,
    pub q_dec_pres: Arc<FrameQueue<DecItem>>,
    joins: Vec<std::thread::JoinHandle<()>>,
    pub reset_decoder: Arc<AtomicBool>,
    pub keyframe_needed: Arc<AtomicBool>,
    pub counters: Arc<ControllerPipeCounters>,
    /// Viewer control shared with the engine loop (input drain, scale,
    /// fullscreen). Set once the present thread created the window.
    pub viewer_ctl: Arc<ViewerCtl>,
    /// The viewer's HWND once created (diagnostics/E2E only; 0 before).
    pub viewer_hwnd: Arc<AtomicU64>,
    /// Latest cursor state from the `cursor` channel (engine loop fills;
    /// present thread overlays).
    pub cursor_slot: Arc<LatestSlot<CursorMessage>>,
}

impl ControllerPipeline {
    /// `make_sink` produces one `PerfSink` per bounded queue;
    /// `present_sink` goes to the present thread (FrameTiming records).
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        device: GpuDevice,
        codec_pool: &CodecPool,
        mut make_sink: impl FnMut() -> Box<dyn PerfSink>,
        present_sink: Box<dyn PerfSink + Send>,
        session: Arc<SessionSlot>,
        clock: Arc<MonotonicClock>,
        viewer_title: &str,
        viewer_width: i32,
        viewer_height: i32,
        initial_scale: render_windows::ScaleMode,
    ) -> Result<Self, String> {
        let session_for_present = Arc::clone(&session);
        let decoder_pool = Arc::clone(&codec_pool.decoder);
        let clock_fn: ClockFn = {
            let clock = Arc::clone(&clock);
            Arc::new(move || clock.now_ns())
        };
        let q_recv_dec = Arc::new(FrameQueue::new(
            QueueKind::RecvToDecode,
            2,
            // Bounded, drop-oldest (schema table): the stale frame drops
            // and surfaces as a frame-id gap → keyframe request.
            DropPolicy::NewestWins,
            make_sink(),
            Arc::clone(&session),
            Arc::clone(&clock_fn),
        ));
        let q_dec_pres = Arc::new(FrameQueue::new(
            QueueKind::DecodeToPresent,
            1,
            DropPolicy::NewestWins,
            make_sink(),
            session,
            clock_fn,
        ));
        let reset_decoder = Arc::new(AtomicBool::new(false));
        let keyframe_needed = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(ControllerPipeCounters::default());
        let viewer_ctl = Arc::new(ViewerCtl::new(initial_scale));
        let viewer_hwnd = Arc::new(AtomicU64::new(0));
        let cursor_slot = Arc::new(LatestSlot::new());
        let mut joins = Vec::new();

        // ---- decode thread ----
        {
            let q_in = Arc::clone(&q_recv_dec);
            let q_out = Arc::clone(&q_dec_pres);
            let counters = Arc::clone(&counters);
            let reset = Arc::clone(&reset_decoder);
            let keyframe_needed = Arc::clone(&keyframe_needed);
            let clock = Arc::clone(&clock);
            let device = device.clone();
            joins.push(
                std::thread::Builder::new()
                    .name("decode".into())
                    .spawn(move || {
                        let mut decoder = match decoder_pool.lock().expect("decoder pool").take() {
                            Some(mut decoder) => {
                                let _ = decoder.reset();
                                decoder
                            }
                            None => codec_windows::MfDecoder::new(
                                device,
                                codec_windows::MfDecoderConfig { use_gpu: true },
                            )
                            .expect("decoder"),
                        };
                        eprintln!("[controller] decoder: {}", decoder.describe());
                        let mut last_frame_id: Option<u64> = None;
                        loop {
                            let Some(item) = q_in.pop(Duration::from_millis(100)) else {
                                if !q_in.is_open() {
                                    break;
                                }
                                continue;
                            };
                            let RecvItem { frame, recv_ns } = item;
                            let frame_id = frame.frame_id;
                            match frame_id {
                                Some(id) => {
                                    if last_frame_id.is_some_and(|last| id != last + 1) {
                                        counters.frame_id_gaps.fetch_add(1, Ordering::Relaxed);
                                        reset.store(true, Ordering::Release);
                                        keyframe_needed.store(true, Ordering::Release);
                                    }
                                    last_frame_id = Some(id);
                                }
                                None => {
                                    counters
                                        .frames_without_frame_id
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            if frame.missing_packets > 0 {
                                counters
                                    .frames_missing_packets
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            if reset.swap(false, Ordering::AcqRel) {
                                let _ = decoder.reset();
                            }
                            // 90 kHz RTP clock → ns (join keys only).
                            let timestamp_ns = u64::from(frame.rtp_timestamp) * 1_000_000 / 90_000;
                            match decoder.decode(
                                &frame.bytes,
                                frame_id.unwrap_or(u64::MAX),
                                timestamp_ns,
                            ) {
                                Ok(decoded) => {
                                    counters.decoded.fetch_add(1, Ordering::Relaxed);
                                    let done_ns = clock.now_ns();
                                    let _ = q_out.push(DecItem {
                                        frame_id: frame_id.unwrap_or(u64::MAX),
                                        recv_ns,
                                        decode_done_ns: done_ns,
                                        decoded,
                                    });
                                }
                                Err(codec_windows::CodecError::DroppedAfterReset(_)) => {
                                    counters.idr_gate_drops.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(codec_windows::CodecError::DeviceLost(d)) => {
                                    eprintln!("[controller] decode DEVICE LOST: {d}");
                                    counters.device_lost.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(e) => {
                                    counters.decode_errors.fetch_add(1, Ordering::Relaxed);
                                    eprintln!("[controller] decode error: {e}");
                                }
                            }
                        }
                        *decoder_pool.lock().expect("decoder pool") = Some(decoder);
                        q_out.close();
                    })
                    .expect("spawn decode"),
            );
        }

        // ---- present thread (owns the native viewer window) ----
        {
            let q = Arc::clone(&q_dec_pres);
            let counters = Arc::clone(&counters);
            let clock = Arc::clone(&clock);
            let device = device.clone();
            let mut sink = present_sink;
            let session = Arc::clone(&session_for_present);
            let viewer_ctl = Arc::clone(&viewer_ctl);
            let viewer_hwnd = Arc::clone(&viewer_hwnd);
            let cursor_slot = Arc::clone(&cursor_slot);
            let title = viewer_title.to_owned();
            joins.push(
                std::thread::Builder::new()
                    .name("present".into())
                    .spawn(move || {
                        frame_surface::attach_thread_to_input_desktop().expect("input desktop");
                        let Ok(mut viewer) = ViewerWindow::create(
                            &device,
                            &title,
                            viewer_width,
                            viewer_height,
                            Arc::clone(&viewer_ctl),
                        ) else {
                            eprintln!("[controller] viewer window creation failed");
                            counters.window_closed.store(true, Ordering::Release);
                            return;
                        };
                        viewer_hwnd.store(viewer.hwnd().0 as usize as u64, Ordering::Release);
                        let mut cursor_overlay: Option<CursorOverlay> = None;
                        loop {
                            let item = q.pop(Duration::from_millis(20));
                            if item.is_none() && !q.is_open() {
                                break;
                            }
                            // Cursor channel: latest position overlays
                            // locally (shape compositing is polish; counted).
                            while let Some(cursor) = cursor_slot.take() {
                                match cursor {
                                    CursorMessage::Position { x, y, .. } => {
                                        counters.cursor_positions.fetch_add(1, Ordering::Relaxed);
                                        cursor_overlay = Some(CursorOverlay {
                                            x_norm: x,
                                            y_norm: y,
                                            shape_id: 0,
                                        });
                                    }
                                    CursorMessage::Shape { .. } | CursorMessage::Hide => {
                                        cursor_overlay = None;
                                    }
                                }
                            }
                            let Some(item) = item else {
                                if !viewer.pump_and_present(None) {
                                    counters.window_closed.store(true, Ordering::Release);
                                    break;
                                }
                                continue;
                            };
                            let rf = RenderFrame {
                                frame_id: item.frame_id,
                                timestamp_ns: item.decoded.timestamp_ns,
                                width_px: item.decoded.width,
                                height_px: item.decoded.height,
                                surface: item.decoded.surface,
                            };
                            viewer.set_cursor(cursor_overlay);
                            if !viewer.pump_and_present(Some(&rf)) {
                                counters.window_closed.store(true, Ordering::Release);
                                break;
                            }
                            counters.presented.fetch_add(1, Ordering::Relaxed);
                            let present_ns = clock.now_ns();
                            sink.record(CounterRecord::FrameTiming(FrameTiming {
                                session_id: session.get(),
                                origin: Origin::Controller,
                                frame_id: item.frame_id,
                                capture_ns: None,
                                encode_submit_ns: None,
                                encode_done_ns: None,
                                send_ns: None,
                                recv_ns: Some(item.recv_ns),
                                decode_done_ns: Some(item.decode_done_ns),
                                present_ns: Some(present_ns),
                            }));
                        }
                    })
                    .expect("spawn present"),
            );
        }

        Ok(Self {
            q_recv_dec,
            q_dec_pres,
            joins,
            reset_decoder,
            keyframe_needed,
            counters,
            viewer_ctl,
            viewer_hwnd,
            cursor_slot,
        })
    }

    pub fn stop(mut self) {
        self.q_recv_dec.close();
        self.q_dec_pres.close();
        for join in self.joins.drain(..) {
            let _ = join.join();
        }
    }
}
