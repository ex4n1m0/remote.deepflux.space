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
    /// M5 congestion: live `ICodecAPI` bitrate reconfigurations (CR-1 —
    /// never a rebuild on this machine's encoders), internal rebuilds,
    /// failed attempts, and pacer fps retargets.
    pub reconfig_live: AtomicU64,
    pub reconfig_rebuilt: AtomicU64,
    pub reconfig_errors: AtomicU64,
    pub fps_retargets: AtomicU64,
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
    /// M5 congestion slots: the engine loop writes a wanted bitrate (live
    /// reconfigure) / fps cap; the owning thread applies it on its next
    /// iteration. One pending slot each, newest wins (bounded).
    pub want_params: Arc<Mutex<Option<codec_windows::EncoderParams>>>,
    pub want_fps: Arc<Mutex<Option<u32>>>,
    /// F71 typed pipeline death: set once by the capture or encode thread
    /// when the pipeline hit an irrecoverable failure (capture dead /
    /// device lost / error budget exhausted). The engine loop polls this
    /// every iteration and ends the session — a frozen `Connected` stream
    /// must be impossible.
    pub fatal: Arc<AtomicBool>,
    /// The typed reason accompanying `fatal` (diagnostics + the session's
    /// end cause).
    pub fatal_reason: Mutex<Option<String>>,
}

impl HostCtl {
    pub fn new(monitor: &str) -> Self {
        Self {
            want_monitor: Mutex::new(monitor.to_owned()),
            active_monitor: Mutex::new(monitor.to_owned()),
            force_keyframe: Arc::new(AtomicBool::new(false)),
            display_changed_edge: AtomicBool::new(false),
            want_params: Arc::new(Mutex::new(None)),
            want_fps: Arc::new(Mutex::new(None)),
            fatal: Arc::new(AtomicBool::new(false)),
            fatal_reason: Mutex::new(None),
        }
    }

    pub fn select_monitor(&self, monitor: &str) {
        *self.want_monitor.lock().expect("want monitor") = monitor.to_owned();
    }

    pub fn active_monitor(&self) -> String {
        self.active_monitor.lock().expect("active monitor").clone()
    }

    /// F71: mark the pipeline dead (idempotent; first reason wins).
    fn mark_fatal(&self, reason: String) {
        let mut slot = self.fatal_reason.lock().expect("fatal reason");
        if slot.is_none() {
            *slot = Some(reason);
        }
        self.fatal.store(true, Ordering::Release);
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
                                    // F71: a pipeline that never produced a
                                    // frame must end the session too (the
                                    // old path exited silently — freeze).
                                    eprintln!("[host] capture init failed: {err}");
                                    ctl.mark_fatal(format!("capture init failed: {err}"));
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
                        // F71: bounded budget for non-AccessLost capture
                        // errors (the recovery policy's retry/death
                        // decision drives it; reset on any success).
                        let mut err_attempts = 0u32;
                        while !stop.load(Ordering::Acquire) {
                            // M5: apply a congestion fps retarget (if any).
                            if let Some(next_fps) = ctl.want_fps.lock().expect("want fps").take()
                                && next_fps != pacer.fps()
                            {
                                eprintln!(
                                    "[host] congestion: fps cap {} -> {}",
                                    pacer.fps(),
                                    next_fps
                                );
                                pacer.retarget(next_fps);
                                counters.fps_retargets.fetch_add(1, Ordering::Relaxed);
                            }
                            pacer.wait();
                            // Monitor switch (SelectMonitor): swap the
                            // duplication, force a keyframe.
                            let want = ctl.want_monitor.lock().expect("want monitor").clone();
                            let active = ctl.active_monitor();
                            if want != active {
                                // DDA: the driver refuses `DuplicateOutput`
                                // on an output that already holds a live
                                // duplication in this process (E_INVALIDARG)
                                // — release the old one before constructing
                                // the replacement (same-output switches
                                // included; M6 e2e regression).
                                cap.release_duplication();
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
                                        // Best-effort restore of the old
                                        // output (bounded reinit policy).
                                        if let Err(e) = cap.reinit()
                                            && e.is_fatal()
                                        {
                                            ctl.mark_fatal(format!("capture dead: {e}"));
                                            break;
                                        }
                                    }
                                }
                            }
                            let budget = pacer.period();
                            match cap.next_frame(budget) {
                                Ok(Some(frame)) => {
                                    err_attempts = 0;
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
                                    // F71: reinit is transactional inside
                                    // capture-windows (bounded retries with
                                    // backoff, then typed death). A fatal
                                    // result must END THE SESSION — the M6
                                    // soak froze 14.7 min through the old
                                    // `let _ = cap.reinit()` discard.
                                    if let Err(e) = cap.reinit() {
                                        eprintln!("[host] capture reinit failed: {e}");
                                        if e.is_fatal() {
                                            ctl.mark_fatal(format!("capture dead: {e}"));
                                            break;
                                        }
                                    }
                                }
                                Err(CaptureError::AccessDenied(detail)) => {
                                    // Secure desktop (lock screen/UAC):
                                    // documented-unsupported but expected to
                                    // clear when the user returns — poll,
                                    // never convert into capture death.
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
                                    // F71: the re-duplicate fallback is
                                    // bounded by the same recovery policy —
                                    // a topology change that outlives the
                                    // budget kills the pipeline loudly.
                                    // Release-first (DDA refuses a second
                                    // duplication on the same output).
                                    cap.release_duplication();
                                    match DxgiCapture::new(device.clone(), &ctl.active_monitor())
                                        .or_else(|_| DxgiCapture::new(device.clone(), "primary"))
                                    {
                                        Ok(mut new_cap) => {
                                            stamp_with(&mut new_cap, &clock);
                                            cap = new_cap;
                                            err_attempts = 0;
                                            force.store(true, Ordering::Release);
                                        }
                                        Err(e) => {
                                            err_attempts += 1;
                                            let wait =
                                                match capture_windows::recovery::recovery_decision(
                                                    &e,
                                                    err_attempts - 1,
                                                ) {
                                                    capture_windows::RecoveryDecision::Retry {
                                                        delay,
                                                        ..
                                                    } => delay,
                                                    capture_windows::RecoveryDecision::Die {
                                                        reason,
                                                    } => {
                                                        let reason = format!(
                                                            "display change unrecoverable: {reason}"
                                                        );
                                                        eprintln!("[host] {reason}");
                                                        ctl.mark_fatal(reason);
                                                        break;
                                                    }
                                                };
                                            eprintln!("[host] re-duplicate failed: {e}");
                                            std::thread::sleep(wait);
                                        }
                                    }
                                }
                                Err(CaptureError::DeviceLost(detail)) => {
                                    eprintln!("[host] capture DEVICE LOST: {detail}");
                                    counters.device_lost.fetch_add(1, Ordering::Relaxed);
                                    ctl.mark_fatal(format!("capture device lost: {detail}"));
                                    break;
                                }
                                Err(e) => {
                                    // F71: unknown errors are budgeted, not
                                    // retried forever (the old catch-all
                                    // slept 100 ms eternally, freezing the
                                    // stream while `Connected`).
                                    err_attempts += 1;
                                    let wait = match capture_windows::recovery::recovery_decision(
                                        &e,
                                        err_attempts - 1,
                                    ) {
                                        capture_windows::RecoveryDecision::Retry {
                                            delay, ..
                                        } => delay,
                                        capture_windows::RecoveryDecision::Die { reason } => {
                                            let reason = format!(
                                                "capture errors exhausted budget: {reason}"
                                            );
                                            eprintln!("[host] {reason}");
                                            ctl.mark_fatal(reason);
                                            break;
                                        }
                                    };
                                    eprintln!("[host] capture error: {e}");
                                    std::thread::sleep(wait);
                                }
                            }
                        }
                        // A dead capture must not return to the pool — the
                        // next session would start already dead.
                        if !cap.is_dead() {
                            *capture_pool.lock().expect("capture pool") = Some(cap);
                        }
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
            let ctl = Arc::clone(&ctl);
            joins.push(
                std::thread::Builder::new()
                    .name("encode".into())
                    .spawn(move || {
                        let mut encoder = match encoder_pool.lock().expect("encoder pool").take() {
                            Some(mut encoder) => {
                                // MF threading: this thread is the MFT's
                                // home for the session (pool handoff).
                                encoder.adopt_thread();
                                encoder
                            }
                            None => match codec_windows::MfEncoder::new(device, enc_cfg) {
                                Ok(encoder) => encoder,
                                Err(e) => {
                                    // F71: same session-ending rule as
                                    // capture init failure.
                                    eprintln!("[host] encoder init failed: {e}");
                                    ctl.mark_fatal(format!("encoder init failed: {e}"));
                                    q_out.close();
                                    return;
                                }
                            },
                        };
                        *describe_slot.lock().expect("describe") = Some(encoder.describe());
                        eprintln!("[host] encoder: {}", encoder.describe());
                        loop {
                            // M5: apply a congestion bitrate step LIVE via
                            // `reconfigure` (CR-1: bitrate changes never
                            // rebuild the MFT — the rebuild leak is priced
                            // out of the adaptation path).
                            if let Some(params) =
                                ctl.want_params.lock().expect("want params").take()
                            {
                                match encoder.reconfigure(&params) {
                                    Ok(codec_windows::ReconfigureOutcome::Live { .. }) => {
                                        counters.reconfig_live.fetch_add(1, Ordering::Relaxed);
                                        if let Some(bps) = params.bitrate_bps {
                                            eprintln!(
                                                "[host] congestion: bitrate -> {bps} bps (live)"
                                            );
                                        }
                                    }
                                    Ok(codec_windows::ReconfigureOutcome::Rebuilt { reason }) => {
                                        counters.reconfig_rebuilt.fetch_add(1, Ordering::Relaxed);
                                        eprintln!(
                                            "[host] congestion: reconfigure rebuilt ({reason})"
                                        );
                                    }
                                    Ok(codec_windows::ReconfigureOutcome::Noop) => {}
                                    Err(e) => {
                                        counters.reconfig_errors.fetch_add(1, Ordering::Relaxed);
                                        eprintln!("[host] congestion: reconfigure failed: {e}");
                                    }
                                }
                            }
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
                                    // F71: an encode-side device loss is the
                                    // same session-ending class as capture
                                    // death — without this the encode thread
                                    // would exit quietly and the session
                                    // would freeze `Connected`.
                                    ctl.mark_fatal(format!("encoder device lost: {d}"));
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
