//! `local-loop` — the M1 gate binary (RD-004 + RD-005): capture -> encode
//! -> decode -> render in ONE process, with per-stage timestamps and
//! queue-depth sampling per `docs/perf-counter-schema.md`.
//!
//! Thread model (the M2 architecture in miniature):
//!
//! ```text
//! capture thread -> [capture_to_encode, cap 1 newest-wins]
//! encode  thread -> [encode_to_send,   cap 1 newest-wins]
//! send    thread -> [recv_to_decode,   cap 2 reject]     (models the wire)
//! decode  thread -> [decode_to_present,cap 1 newest-wins]
//! present thread (owns the window)
//! ```
//!
//! The send->recv hop is the network boundary stand-in: `send_ns` is
//! stamped when the sender hands the packet off, `recv_ns` when the
//! decode thread takes it. All queues emit `QueueSample` on every depth
//! change (F5). The host half of `FrameTiming` is emitted when `send_ns`
//! is filled, the controller half when `present_ns` is filled (pinned
//! emission timing).
//!
//! All five threads share one session clock (`SessionClock`, cloned) so
//! stage timestamps are directly subtractable — the one-clock same-process
//! property that makes the `capture_to_present` stage meaningful here.
//!
//! Usage:
//!   cargo run --release -p capture-windows --example local_loop -- \
//!       [--duration-secs 1800] [--monitor primary] [--bitrate 8000] \
//!       [--fps-cap 0] [--encoder auto|hw|sw] [--decoder dxva|cpu] \
//!       [--encode-size 1920x1080] [--scale fit|1:1] [--no-stimulus]

#[path = "loop_common/mod.rs"]
mod loop_common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use diagnostics::{CounterRecord, FrameTiming, LinkSample, Origin, PerfSink, QueueKind};
use loop_common::{
    DropPolicy, FrameQueue, JsonlReport, SESSION_ID, SessionClock, Summary, human_summary,
    parse_args, spawn_resource_sampler, spawn_stimulus, summarize,
};

use capture_windows::{CaptureError, CaptureSource, DxgiCapture};
use codec_windows::{
    CodecError, DecodedFrame, EncodeInput, EncodedPacket, MfDecoder, MfDecoderConfig, MfEncoder,
    MfEncoderConfig, MfEncoderPreference, MfRuntime, VideoDecoder, VideoEncoder,
};
use frame_surface::{FrameSurface, GpuDevice, attach_thread_to_input_desktop};
use render_windows::{
    D3D11Renderer, FrameRenderer, PresenterWindow, RenderFrame, ScaleMode, WindowConfig,
};

/// Items on the capture->encode queue.
struct CapItem {
    frame_id: u64,
    capture_ns: u64,
    surface: FrameSurface,
}

/// Items on the encode->send and recv->decode queues. The packet bytes are
/// the modeled wire payload; diagnostics carry ids/timestamps only
/// (invariant 1).
struct WireItem {
    packet: EncodedPacket,
    capture_ns: u64,
    encode_submit_ns: u64,
    encode_done_ns: u64,
}

/// Items on the decode->present queue.
struct DecItem {
    frame_id: u64,
    recv_ns: u64,
    decode_done_ns: u64,
    decoded: DecodedFrame,
}

fn main() {
    let usage = "local-loop [--duration-secs N] [--monitor M] [--bitrate kbps] [--fps-cap N] \
                 [--encoder auto|hw|sw] [--decoder dxva|cpu] [--encode-size WxH] \
                 [--window-size WxH] [--scale fit|1:1] [--no-stimulus] [--report-stem NAME]";
    let args = parse_args(&std::env::args().skip(1).collect::<Vec<_>>(), usage);

    let clock = SessionClock::new();
    let stop = Arc::new(AtomicBool::new(false));

    // ---- Report sink (F6: file sink, no in-memory truncation) ----
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root");
    let report_dir = repo_root.join("docs/reports/data");
    let stem = args
        .report_stem
        .clone()
        .unwrap_or_else(|| format!("m1-local-loop-{}", date_string()));
    let report = JsonlReport::create(&report_dir, &stem).expect("create report");
    eprintln!("report: {}", report.path.display());

    // ---- Stimulus (guaranteed 60 Hz desktop updates during soaks) ----
    let stimulus = if args.stimulus {
        Some(spawn_stimulus(Arc::clone(&stop)))
    } else {
        None
    };

    // ---- Shared device + MF runtime ----
    let _mf = MfRuntime::new().expect("MFStartup");
    let device = GpuDevice::create_hardware().expect("hardware D3D11 device");
    eprintln!(
        "device: {}",
        device.adapter_description().unwrap_or_default()
    );

    // ---- Queues (invariant 3) ----
    let q_cap_enc = Arc::new(FrameQueue::<CapItem>::new(
        QueueKind::CaptureToEncode,
        1,
        DropPolicy::NewestWins,
        Box::new(report.sink_handle(clock.clone())),
        clock.clone(),
    ));
    let q_enc_send = Arc::new(FrameQueue::<WireItem>::new(
        QueueKind::EncodeToSend,
        1,
        DropPolicy::NewestWins,
        Box::new(report.sink_handle(clock.clone())),
        clock.clone(),
    ));
    let q_recv_dec = Arc::new(FrameQueue::<WireItem>::new(
        QueueKind::RecvToDecode,
        2,
        DropPolicy::Reject,
        Box::new(report.sink_handle(clock.clone())),
        clock.clone(),
    ));
    let q_dec_pres = Arc::new(FrameQueue::<DecItem>::new(
        QueueKind::DecodeToPresent,
        1,
        DropPolicy::NewestWins,
        Box::new(report.sink_handle(clock.clone())),
        clock.clone(),
    ));

    // ---- Codec (constructed on the main thread, moved into its stage) ----
    let preference = match args.encoder.as_str() {
        "hw" => MfEncoderPreference::Hardware,
        "sw" => MfEncoderPreference::Software,
        _ => MfEncoderPreference::Auto,
    };
    let fps = if args.fps_cap > 0 { args.fps_cap } else { 60 };
    let enc_cfg = MfEncoderConfig {
        width: args.encode_w & !1, // H.264 needs even dimensions
        height: args.encode_h & !1,
        fps,
        bitrate_bps: args.bitrate_kbps.saturating_mul(1000),
        gop_size: fps * 2, // ~2 s keyframe interval
        preference,
    };
    let mut encoder = MfEncoder::new(device.clone(), enc_cfg).expect("encoder");
    eprintln!(
        "encoder: {} (force-keyframe supported: {})",
        encoder.describe(),
        encoder.force_keyframe_supported()
    );
    let mut decoder = MfDecoder::new(
        device.clone(),
        MfDecoderConfig {
            use_gpu: args.decoder != "cpu",
        },
    )
    .expect("decoder");
    eprintln!("decoder: {}", decoder.describe());
    let encoder_desc = encoder.describe();
    let decoder_desc = decoder.describe();

    // ---- Stage counters ----
    let frames_captured = Arc::new(AtomicU64::new(0));
    let frames_encoded = Arc::new(AtomicU64::new(0));
    let frames_decoded = Arc::new(AtomicU64::new(0));
    let frames_presented = Arc::new(AtomicU64::new(0));
    let cursor_only = Arc::new(AtomicU64::new(0));
    let encode_deferred = Arc::new(AtomicU64::new(0));
    let bytes_sent = Arc::new(AtomicU64::new(0));
    let keyframes = Arc::new(AtomicU64::new(0));
    let idr_drops = Arc::new(AtomicU64::new(0));

    // F16: CPU-copy baselines so the run reports measured deltas.
    let readbacks0 = frame_surface::readback_count();
    let uploads0 = frame_surface::upload_count();

    let deadline = Instant::now() + Duration::from_secs(args.duration_secs);
    let fps_cap = args.fps_cap;

    // ---- Resource sampler (>= 1 Hz) ----
    let resource = spawn_resource_sampler(
        Box::new(report.sink_handle(clock.clone())),
        clock.clone(),
        Arc::clone(&stop),
    );

    // ---- Capture thread ----
    let capture_join = {
        let stop = Arc::clone(&stop);
        let q = Arc::clone(&q_cap_enc);
        let frames_captured = Arc::clone(&frames_captured);
        let cursor_only = Arc::clone(&cursor_only);
        let clock = clock.clone();
        let device = device.clone();
        let monitor_arg = args.monitor.clone();
        std::thread::Builder::new()
            .name("capture".into())
            .spawn(move || {
                attach_thread_to_input_desktop().expect("input desktop");
                let mut cap = DxgiCapture::new(device.clone(), &monitor_arg).expect("duplicate");
                // F17: capture_ns is stamped at AcquireNextFrame-return on
                // the loop's session clock.
                let stamp_clock = clock.clone();
                cap.set_clock(Box::new(move || stamp_clock.ns()));
                eprintln!(
                    "capture: {} at {}x{}",
                    cap.monitor_id(),
                    cap.dimensions().0,
                    cap.dimensions().1
                );
                let mut denied_backoff = 0u32;
                let mut last_capture = Instant::now() - Duration::from_secs(1);
                while !stop.load(Ordering::Acquire) {
                    if fps_cap > 0 {
                        let interval = Duration::from_secs_f64(1.0 / fps_cap as f64);
                        let elapsed = last_capture.elapsed();
                        if elapsed < interval {
                            std::thread::sleep(interval - elapsed);
                        }
                    }
                    last_capture = Instant::now();
                    match cap.next_frame(Duration::from_millis(50)) {
                        Ok(Some(frame)) => {
                            if frame.metadata.only_cursor_update {
                                cursor_only.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            frames_captured.fetch_add(1, Ordering::Relaxed);
                            // Schema pin: stamped at AcquireNextFrame
                            // return inside `DxgiCapture::next_frame`.
                            let capture_ns = frame.timestamp_ns;
                            let _ = q.push(CapItem {
                                frame_id: frame.frame_id,
                                capture_ns,
                                surface: frame.surface,
                            });
                        }
                        Ok(None) => {}
                        Err(CaptureError::AccessLost(_)) => {
                            eprintln!("capture: access lost; re-duplicating");
                            std::thread::sleep(Duration::from_millis(100));
                            let _ = cap.reinit();
                        }
                        Err(CaptureError::AccessDenied(_)) => {
                            denied_backoff = (denied_backoff + 1).min(20);
                            eprintln!(
                                "capture: access denied (lock screen/protected content); backoff {} ms",
                                denied_backoff * 100
                            );
                            std::thread::sleep(Duration::from_millis(100 * denied_backoff as u64));
                        }
                        Err(CaptureError::DisplayChanged(detail)) => {
                            eprintln!("capture: display changed ({detail}); re-selecting");
                            std::thread::sleep(Duration::from_millis(200));
                            match DxgiCapture::new(device.clone(), "primary") {
                                Ok(new_cap) => cap = new_cap,
                                Err(e) => eprintln!("capture re-select failed: {e}"),
                            }
                        }
                        Err(CaptureError::DeviceLost(detail)) => {
                            eprintln!("capture: FATAL device lost: {detail}");
                            stop.store(true, Ordering::Release);
                            break;
                        }
                        Err(e) => {
                            eprintln!("capture error: {e}");
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
                q.close();
            })
            .expect("spawn capture")
    };

    // ---- Encode thread ----
    let encode_join = {
        let stop = Arc::clone(&stop);
        let q_in = Arc::clone(&q_cap_enc);
        let q_out = Arc::clone(&q_enc_send);
        let frames_encoded = Arc::clone(&frames_encoded);
        let encode_deferred = Arc::clone(&encode_deferred);
        let keyframes = Arc::clone(&keyframes);
        let clock = clock.clone();
        std::thread::Builder::new()
            .name("encode".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let Some(item) = q_in.pop(Duration::from_millis(100)) else {
                        continue;
                    };
                    let submit_ns = clock.ns();
                    let input = EncodeInput {
                        frame_id: item.frame_id,
                        timestamp_ns: item.capture_ns,
                        surface: item.surface,
                    };
                    match encoder.encode(input, false) {
                        Ok(mut packet) => {
                            packet.timestamp_ns = item.capture_ns;
                            frames_encoded.fetch_add(1, Ordering::Relaxed);
                            if packet.is_keyframe {
                                keyframes.fetch_add(1, Ordering::Relaxed);
                            }
                            let done_ns = clock.ns();
                            let _ = q_out.push(WireItem {
                                packet,
                                capture_ns: item.capture_ns,
                                encode_submit_ns: submit_ns,
                                encode_done_ns: done_ns,
                            });
                        }
                        Err(CodecError::Timeout(_)) => {
                            // Software-encoder depth-1 deferral: the output
                            // surfaces on the next submit (documented M1
                            // behavior); counted, not fatal.
                            encode_deferred.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(CodecError::DeviceLost(d)) => {
                            eprintln!("encode: FATAL device lost: {d}");
                            stop.store(true, Ordering::Release);
                            break;
                        }
                        Err(e) => eprintln!("encode error: {e}"),
                    }
                }
                q_out.close();
            })
            .expect("spawn encode")
    };

    // ---- Send thread (models the transport boundary) ----
    let send_join = {
        let stop = Arc::clone(&stop);
        let q_in = Arc::clone(&q_enc_send);
        let q_out = Arc::clone(&q_recv_dec);
        let bytes_sent = Arc::clone(&bytes_sent);
        let mut sink = report.sink_handle(clock.clone());
        let clock = clock.clone();
        let mut last_link = Instant::now() - Duration::from_secs(1);
        let mut window_bytes = 0u64;
        std::thread::Builder::new()
            .name("send".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let Some(item) = q_in.pop(Duration::from_millis(100)) else {
                        continue;
                    };
                    let send_ns = clock.ns();
                    bytes_sent.fetch_add(item.packet.bytes.len() as u64, Ordering::Relaxed);
                    window_bytes += item.packet.bytes.len() as u64;
                    // Host half: emitted exactly when send_ns is filled.
                    sink.record(CounterRecord::FrameTiming(FrameTiming {
                        session_id: SESSION_ID.to_string(),
                        origin: Origin::Host,
                        frame_id: item.packet.frame_id,
                        capture_ns: Some(item.capture_ns),
                        encode_submit_ns: Some(item.encode_submit_ns),
                        encode_done_ns: Some(item.encode_done_ns),
                        send_ns: Some(send_ns),
                        recv_ns: None,
                        decode_done_ns: None,
                        present_ns: None,
                    }));
                    // Loopback wire: zero propagation delay; the queue in
                    // front of the decoder is where backlog would show.
                    if q_out.push(item).is_err() {
                        // recv queue rejected: modeled packet loss under
                        // backpressure (counted by the queue's `dropped`).
                    }
                    if last_link.elapsed() >= Duration::from_secs(1) {
                        let kbps = (window_bytes * 8) / 1000;
                        window_bytes = 0;
                        last_link = Instant::now();
                        sink.record(CounterRecord::LinkSample(LinkSample {
                            session_id: SESSION_ID.to_string(),
                            send_bitrate_kbps: Some(kbps as u32),
                            recv_bitrate_kbps: Some(kbps as u32),
                            rtt_ms: Some(0.0), // in-process wire stand-in
                            loss_percent: Some(0.0),
                            at_ns: clock.ns(),
                        }));
                    }
                }
                q_out.close();
            })
            .expect("spawn send")
    };

    // ---- Decode thread ----
    let decode_join = {
        let stop = Arc::clone(&stop);
        let q_in = Arc::clone(&q_recv_dec);
        let q_out = Arc::clone(&q_dec_pres);
        let frames_decoded = Arc::clone(&frames_decoded);
        let idr_drops = Arc::clone(&idr_drops);
        let clock = clock.clone();
        std::thread::Builder::new()
            .name("decode".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    let Some(item) = q_in.pop(Duration::from_millis(100)) else {
                        continue;
                    };
                    let recv_ns = clock.ns();
                    match decoder.decode(
                        &item.packet.bytes,
                        item.packet.frame_id,
                        item.packet.timestamp_ns,
                    ) {
                        Ok(decoded) => {
                            frames_decoded.fetch_add(1, Ordering::Relaxed);
                            let done_ns = clock.ns();
                            let _ = q_out.push(DecItem {
                                frame_id: item.packet.frame_id,
                                recv_ns,
                                decode_done_ns: done_ns,
                                decoded,
                            });
                        }
                        Err(CodecError::Timeout(_)) => {}
                        // F18: expected after a loss reset — packets are
                        // dropped until the next IDR; counted, not an
                        // error.
                        Err(CodecError::DroppedAfterReset(_)) => {
                            idr_drops.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => eprintln!("decode error: {e}"),
                    }
                }
                q_out.close();
            })
            .expect("spawn decode")
    };

    // ---- Present thread (owns the window) ----
    let present_join = {
        let stop = Arc::clone(&stop);
        let q = Arc::clone(&q_dec_pres);
        let frames_presented = Arc::clone(&frames_presented);
        let mut sink = report.sink_handle(clock.clone());
        let clock = clock.clone();
        let scale = if args.scale == "1:1" {
            ScaleMode::OneToOne
        } else {
            ScaleMode::Fit
        };
        let window_w = args.window_w;
        let window_h = args.window_h;
        let device = device.clone();
        std::thread::Builder::new()
            .name("present".into())
            .spawn(move || {
                attach_thread_to_input_desktop().expect("input desktop");
                let mut window = PresenterWindow::create(&WindowConfig {
                    title: "M1 local-loop".into(),
                    width: window_w,
                    height: window_h,
                })
                .expect("window");
                let mut renderer = D3D11Renderer::new(
                    device,
                    window.hwnd(),
                    window_w.max(1) as u32,
                    window_h.max(1) as u32,
                )
                .expect("renderer");
                renderer.set_scale_mode(scale);
                while !stop.load(Ordering::Acquire) {
                    if !window.pump() {
                        eprintln!("present: window closed; stopping");
                        stop.store(true, Ordering::Release);
                        break;
                    }
                    let Some(item) = q.pop(Duration::from_millis(20)) else {
                        continue;
                    };
                    let rf = RenderFrame {
                        frame_id: item.frame_id,
                        timestamp_ns: item.decoded.timestamp_ns,
                        width_px: item.decoded.width,
                        height_px: item.decoded.height,
                        surface: item.decoded.surface,
                    };
                    if let Err(e) = renderer.present(&rf) {
                        eprintln!("present: FATAL {e}");
                        stop.store(true, Ordering::Release);
                        break;
                    }
                    let present_ns = clock.ns();
                    frames_presented.fetch_add(1, Ordering::Relaxed);
                    // Controller half: emitted exactly when present_ns is
                    // filled (pinned emission timing).
                    sink.record(CounterRecord::FrameTiming(FrameTiming {
                        session_id: SESSION_ID.to_string(),
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
            .expect("spawn present")
    };

    // ---- Wait for the deadline (or an early fatal) ----
    while Instant::now() < deadline {
        if stop.load(Ordering::Acquire) {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    stop.store(true, Ordering::Release);
    let _ = capture_join.join();
    let _ = encode_join.join();
    let _ = send_join.join();
    let _ = decode_join.join();
    let _ = present_join.join();
    let _ = resource.join();
    if let Some(t) = stimulus {
        let _ = t.join();
    }

    // ---- Close the report and summarize (F6) ----
    let (path, records, backpressure) = report.close();
    let mut summary = summarize(&path, 60);
    summary.keyframes = keyframes.load(Ordering::Relaxed);
    summary.encoded_bytes = bytes_sent.load(Ordering::Relaxed);
    summary.backpressure_events = backpressure;
    summary.readbacks = frame_surface::readback_count() - readbacks0;
    summary.uploads = frame_surface::upload_count() - uploads0;

    let text = human_summary(&summary, &encoder_desc, &decoder_desc);
    println!("{text}");
    eprintln!(
        "counters: captured {} encoded {} (deferred {}) decoded {} presented {} cursor-only {} keyframes {} wire {:.2} MiB stimulus-ticks {} cpu-copies(readback/upload) {}/{} idr-gate-drops {}",
        frames_captured.load(Ordering::Relaxed),
        frames_encoded.load(Ordering::Relaxed),
        encode_deferred.load(Ordering::Relaxed),
        frames_decoded.load(Ordering::Relaxed),
        frames_presented.load(Ordering::Relaxed),
        cursor_only.load(Ordering::Relaxed),
        keyframes.load(Ordering::Relaxed),
        bytes_sent.load(Ordering::Relaxed) as f64 / (1 << 20) as f64,
        loop_common::stimulus_ticks(),
        summary.readbacks,
        summary.uploads,
        idr_drops.load(Ordering::Relaxed),
    );
    eprintln!(
        "report: {} ({} records, {} sink-backpressure events)",
        path.display(),
        records,
        backpressure
    );

    let summary_path = path.with_extension("summary.json");
    write_summary_json(&summary_path, &summary, &encoder_desc, &decoder_desc);
    eprintln!("summary: {}", summary_path.display());
}

/// Civil date from the Unix epoch (no chrono dependency): Howard
/// Hinnant's days-to-civil algorithm.
fn date_string() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (now / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}")
}

fn write_summary_json(
    path: &std::path::Path,
    summary: &Summary,
    encoder_desc: &str,
    decoder_desc: &str,
) {
    use serde_json::json;
    let stages: serde_json::Value = summary
        .stages
        .iter()
        .map(|(name, s)| {
            (
                *name,
                json!({
                    "p50_ms": s.p50_ns as f64 / 1e6,
                    "p95_ms": s.p95_ns as f64 / 1e6,
                    "p99_ms": s.p99_ns as f64 / 1e6,
                    "max_ms": s.max_ns as f64 / 1e6,
                    "count": s.count,
                }),
            )
        })
        .map(|(k, v)| (k.to_string(), v))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();
    let queues: serde_json::Value = summary
        .queue_stats
        .iter()
        .map(|(kind, hw, cap, dropped, replaced)| {
            (
                format!("{kind:?}"),
                json!({ "high_water": hw, "capacity": cap, "dropped": dropped, "replaced": replaced }),
            )
        })
        .map(|(k, v)| (k.to_string(), v))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();
    let doc = json!({
        "encoder": encoder_desc,
        "decoder": decoder_desc,
        "frames": { "host": summary.frames_host, "presented": summary.frames_presented },
        "keyframes": summary.keyframes,
        "wire_bytes": summary.encoded_bytes,
        "run_secs": summary.run_secs,
        "warmup_secs": summary.warmup_secs,
        "stages": stages,
        "queues": queues,
        "resource": {
            "cpu_percent_min_max": summary.resource_cpu_min_max,
            "working_set_bytes_min_max": summary.resource_ws_min_max,
        },
        "unstable_windows": summary
            .unstable_windows
            .iter()
            .map(|(w, r)| json!({ "window": w, "reason": r }))
            .collect::<Vec<_>>(),
        "sink_backpressure_events": summary.backpressure_events,
        "cpu_copies": { "readbacks": summary.readbacks, "uploads": summary.uploads },
        "session_id": SESSION_ID,
    });
    let _ = std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap_or_default());
}
