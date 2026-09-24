//! `capture-preview` — validate DXGI capture with no codec (RD-004).
//!
//! Renders the captured desktop into a local window (which itself lives
//! on the captured desktop, so the classic mirror effect keeps content
//! changing; move the mouse for updates). Prints capture counters.
//!
//! Usage:
//!   cargo run -p capture-windows --example capture_preview -- \
//!       [--monitor primary] [--duration-secs 30] [--window-size 1280x720]

#[path = "loop_common/mod.rs"]
mod loop_common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use loop_common::{SessionClock, parse_args};

use capture_windows::{CaptureSource, DxgiCapture};
use frame_surface::{GpuDevice, attach_thread_to_input_desktop};
use render_windows::{
    D3D11Renderer, FrameRenderer, PresenterWindow, RenderFrame, ScaleMode, WindowConfig,
};

fn main() {
    let usage = "capture-preview [--monitor <id|index|primary>] [--duration-secs N] \
                 [--window-size WxH] [--scale fit|1:1]";
    let args = parse_args(&std::env::args().skip(1).collect::<Vec<_>>(), usage);

    let stop = Arc::new(AtomicBool::new(false));
    let clock = SessionClock::new();

    // One device for capture and presentation (M1 handoff decision).
    let device = GpuDevice::create_hardware().expect("hardware D3D11 device");
    println!(
        "device: {}",
        device.adapter_description().unwrap_or_default()
    );

    // Present thread owns the window + renderer.
    let present_stop = Arc::clone(&stop);
    let window_w = args.window_w;
    let window_h = args.window_h;
    let scale = if args.scale == "1:1" {
        ScaleMode::OneToOne
    } else {
        ScaleMode::Fit
    };
    let monitor_arg = args.monitor.clone();

    let capture_stats = Arc::new((AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0))); // frames, cursor-only, dirty rects
    let stats_capture = Arc::clone(&capture_stats);

    let present = std::thread::Builder::new()
        .name("present".into())
        .spawn(move || {
            attach_thread_to_input_desktop().expect("input desktop");
            let mut window = PresenterWindow::create(&WindowConfig {
                title: "M1 capture-preview".into(),
                width: window_w,
                height: window_h,
            })
            .expect("window");
            let mut renderer = D3D11Renderer::new(
                device.clone(),
                window.hwnd(),
                window_w.max(1) as u32,
                window_h.max(1) as u32,
            )
            .expect("renderer");
            renderer.set_scale_mode(scale);

            let (frames, cursor_only, dirty) = &*stats_capture;
            let mut cap = cap_take(&device, &monitor_arg);
            while !present_stop.load(Ordering::Acquire) {
                if !window.pump() {
                    break;
                }
                if window.resized {
                    let (w, h) = window.client_size();
                    let _ = renderer.resize(w.max(1) as u32, h.max(1) as u32);
                }
                // Capture and present on the same thread: the preview has
                // no queues to measure; next_frame paces at desktop rate.
                match cap.next_frame(Duration::from_millis(50)) {
                    Ok(Some(frame)) => {
                        if frame.metadata.only_cursor_update {
                            cursor_only.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        frames.fetch_add(1, Ordering::Relaxed);
                        dirty.fetch_add(frame.metadata.dirty_rects.len() as u64, Ordering::Relaxed);
                        let rf = RenderFrame {
                            frame_id: frame.frame_id,
                            timestamp_ns: frame.timestamp_ns,
                            width_px: frame.width_px,
                            height_px: frame.height_px,
                            surface: frame.surface,
                        };
                        if let Err(e) = renderer.present(&rf) {
                            eprintln!("present error: {e}");
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(capture_windows::CaptureError::AccessLost(_)) => {
                        eprintln!("capture: access lost, reinit");
                        let _ = cap.reinit();
                    }
                    Err(e) => {
                        eprintln!("capture error: {e}");
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
            }
        })
        .expect("spawn present");

    while clock.start.elapsed() < Duration::from_secs(args.duration_secs) {
        if present.is_finished() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    stop.store(true, Ordering::Release);
    let _ = present.join();

    let (frames, cursor_only, dirty) = &*capture_stats;
    let secs = args.duration_secs.max(1);
    println!(
        "capture-preview: {} frames ({:.1} fps), {} cursor-only, {} dirty rects total",
        frames.load(Ordering::Relaxed),
        frames.load(Ordering::Relaxed) as f64 / secs as f64,
        cursor_only.load(Ordering::Relaxed),
        dirty.load(Ordering::Relaxed),
    );
}

fn cap_take(device: &GpuDevice, monitor: &str) -> DxgiCapture {
    // Rebuilt after fatal capture errors in the caller loop.
    loop {
        match DxgiCapture::new(device.clone(), monitor) {
            Ok(cap) => return cap,
            Err(e) => {
                eprintln!("capture init error: {e}; retrying");
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}
