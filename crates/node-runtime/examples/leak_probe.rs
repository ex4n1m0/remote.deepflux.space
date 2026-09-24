//! `leak_probe` — F26 diagnosis: isolate which per-session component
//! retains memory across create/drop cycles (reconnect-path leak).
//!
//! Each phase loops one component N times and prints working set, private
//! bytes, thread count, and handle count after every iteration. Flat lines
//! exonerate a component; monotonic growth convicts it.
//!
//! ```text
//! cargo run --release -p node-runtime --example leak_probe -- --iters 12
//! ```
//!
//! Phases: `transport` (WebrtcTransport create/close), `capture`
//! (DxgiCapture), `encoder` (MfEncoder + one encode), `decoder` (MfDecoder),
//! `render` (PresenterWindow + D3D11Renderer), `all` (default: every phase).

use std::time::Duration;

use capture_windows::{CaptureSource, DxgiCapture};
use codec_windows::{
    MfDecoder, MfDecoderConfig, MfEncoder, MfEncoderConfig, MfEncoderPreference, VideoDecoder as _,
    VideoEncoder as _,
};
use frame_surface::{FrameSurface, GpuDevice, SurfaceFormat, attach_thread_to_input_desktop};
use render_windows::{
    D3D11Renderer, FrameRenderer as _, PresenterWindow, RenderFrame, WindowConfig,
};
use transport_webrtc::{Transport as _, WebrtcTransport, WebrtcTransportRole};

#[derive(Default, Clone, Copy)]
struct Snap {
    ws: u64,
    private: u64,
    threads: u32,
    handles: u32,
}

fn snapshot() -> Snap {
    unsafe {
        use windows::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
        let mut counters = PROCESS_MEMORY_COUNTERS_EX::default();
        let cb = size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
        let mut handles = 0u32;
        let _ = GetProcessHandleCount(GetCurrentProcess(), &mut handles);
        let ok = GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters as *mut _
                as *mut windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS,
            cb,
        );
        let (ws, private) = if ok.is_ok() {
            (counters.WorkingSetSize as u64, counters.PrivateUsage as u64)
        } else {
            (0, 0)
        };
        // Thread count via toolhelp snapshot.
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        };
        let mut threads = 0u32;
        if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            let mut entry = THREADENTRY32 {
                dwSize: size_of::<THREADENTRY32>() as u32,
                ..Default::default()
            };
            if Thread32First(snap, &mut entry).is_ok() {
                loop {
                    if entry.th32OwnerProcessID == std::process::id() {
                        threads += 1;
                    }
                    if Thread32Next(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snap);
        }
        Snap {
            ws,
            private,
            threads,
            handles,
        }
    }
}

fn mib(v: u64) -> f64 {
    v as f64 / (1 << 20) as f64
}

fn report(tag: &str, i: usize, s: Snap) {
    println!(
        "{tag:<10} iter {i:>2}: ws {:+7.1} MiB  private {:+7.1} MiB  threads {:>3}  handles {:>5}",
        mib(s.ws),
        mib(s.private),
        s.threads,
        s.handles,
    );
}

fn phase_transport(iters: usize) {
    println!("--- phase: WebrtcTransport create/close ---");
    let base = snapshot();
    report("transport", 0, base);
    for i in 1..=iters {
        let mut t = WebrtcTransport::new(WebrtcTransportRole::Host).expect("transport");
        t.close();
        drop(t);
        std::thread::sleep(Duration::from_millis(250));
        report("transport", i, snapshot());
    }
}

fn phase_capture(iters: usize) {
    println!("--- phase: DxgiCapture create/drop ---");
    let device = GpuDevice::create_hardware().expect("device");
    let base = snapshot();
    report("capture", 0, base);
    for i in 1..=iters {
        let mut cap = DxgiCapture::new(device.clone(), "primary").expect("capture");
        let _ = cap.next_frame(Duration::from_millis(50));
        drop(cap);
        std::thread::sleep(Duration::from_millis(150));
        report("capture", i, snapshot());
    }
}

fn phase_encoder(iters: usize) {
    println!("--- phase: MfEncoder create/encode/drop ---");
    let device = GpuDevice::create_hardware().expect("device");
    let cfg = MfEncoderConfig {
        width: 1920,
        height: 1080,
        fps: 60,
        bitrate_bps: 8_000_000,
        gop_size: 120,
        preference: MfEncoderPreference::Auto,
    };
    let surface = FrameSurface::new(&device, 1920, 1080, SurfaceFormat::Bgra8).expect("surface");
    let base = snapshot();
    report("encoder", 0, base);
    for i in 1..=iters {
        let mut encoder = MfEncoder::new(device.clone(), cfg.clone()).expect("encoder");
        let input = codec_windows::EncodeInput {
            frame_id: i as u64,
            timestamp_ns: (i as u64) * 16_666_666,
            surface: surface.clone(),
        };
        let _ = encoder.encode(input, i == 1);
        drop(encoder);
        std::thread::sleep(Duration::from_millis(150));
        report("encoder", i, snapshot());
    }
}

fn phase_decoder(iters: usize) {
    println!("--- phase: MfDecoder create/drop ---");
    let device = GpuDevice::create_hardware().expect("device");
    let base = snapshot();
    report("decoder", 0, base);
    for i in 1..=iters {
        let mut decoder =
            MfDecoder::new(device.clone(), MfDecoderConfig { use_gpu: true }).expect("decoder");
        let _ = decoder.reset();
        drop(decoder);
        std::thread::sleep(Duration::from_millis(150));
        report("decoder", i, snapshot());
    }
}

fn phase_render(iters: usize) {
    println!("--- phase: PresenterWindow + D3D11Renderer create/drop ---");
    attach_thread_to_input_desktop().expect("desktop");
    let device = GpuDevice::create_hardware().expect("device");
    let surface = FrameSurface::new(&device, 64, 48, SurfaceFormat::Nv12).expect("surface");
    let base = snapshot();
    report("render", 0, base);
    for i in 1..=iters {
        let mut window = PresenterWindow::create(&WindowConfig {
            title: "probe".into(),
            width: 320,
            height: 240,
        })
        .expect("window");
        let mut renderer =
            D3D11Renderer::new(device.clone(), window.hwnd(), 320, 240).expect("renderer");
        window.pump();
        let frame = RenderFrame {
            frame_id: i as u64,
            timestamp_ns: 0,
            width_px: 64,
            height_px: 48,
            surface: surface.clone(),
        };
        let _ = renderer.present(&frame);
        drop(renderer);
        drop(window);
        std::thread::sleep(Duration::from_millis(150));
        report("render", i, snapshot());
    }
}

/// One realistic CONTROLLER session: fresh decoder + window/renderer,
/// decode+present `frames` real encoded frames, drop everything.
fn phase_controller_cycle(iters: usize, frames: usize) {
    println!("--- phase: controller session cycle (decoder+render, {frames} frames) ---");
    attach_thread_to_input_desktop().expect("desktop");
    let device = GpuDevice::create_hardware().expect("device");
    // One process-lifetime encoder produces the test stream (excluded
    // from the measurement target).
    let enc_cfg = MfEncoderConfig {
        width: 1920,
        height: 1080,
        fps: 60,
        bitrate_bps: 8_000_000,
        gop_size: 120,
        preference: MfEncoderPreference::Auto,
    };
    let mut encoder = MfEncoder::new(device.clone(), enc_cfg).expect("encoder");
    let surface = FrameSurface::new(&device, 1920, 1080, SurfaceFormat::Bgra8).expect("surface");
    let base = snapshot();
    report("ctrl-cycle", 0, base);
    for i in 1..=iters {
        let mut packets = Vec::new();
        for f in 0..frames {
            let input = codec_windows::EncodeInput {
                frame_id: (i * frames + f) as u64,
                timestamp_ns: ((i * frames + f) as u64) * 16_666_666,
                surface: surface.clone(),
            };
            if let Ok(packet) = encoder.encode(input, f == 0) {
                packets.push(packet);
            }
        }
        let mut decoder =
            MfDecoder::new(device.clone(), MfDecoderConfig { use_gpu: true }).expect("decoder");
        let mut window = PresenterWindow::create(&WindowConfig {
            title: "probe".into(),
            width: 1280,
            height: 720,
        })
        .expect("window");
        let mut renderer =
            D3D11Renderer::new(device.clone(), window.hwnd(), 1280, 720).expect("renderer");
        for packet in &packets {
            if let Ok(decoded) = decoder.decode(&packet.bytes, packet.frame_id, packet.timestamp_ns)
            {
                let rf = RenderFrame {
                    frame_id: decoded.frame_id,
                    timestamp_ns: decoded.timestamp_ns,
                    width_px: decoded.width,
                    height_px: decoded.height,
                    surface: decoded.surface,
                };
                let _ = renderer.present(&rf);
                window.pump();
            }
        }
        drop(renderer);
        drop(window);
        drop(decoder);
        std::thread::sleep(Duration::from_millis(250));
        report("ctrl-cycle", i, snapshot());
    }
}

fn main() {
    let mut iters = 12usize;
    let mut phase = String::new();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--iters" => {
                iters = args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or(12);
                i += 2;
            }
            "--phase" => {
                phase = args.get(i + 1).cloned().unwrap_or_default();
                i += 2;
            }
            other => {
                eprintln!("unknown arg {other:?}");
                std::process::exit(2);
            }
        }
    }
    // COM on the probing thread (the rig's stage threads get this from
    // their own init paths; the probe touches every component on main).
    unsafe {
        use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx};
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        // S_OK / S_FALSE (already initialized) / RPC_E_CHANGED_MODE all
        // proceed; a genuine failure would surface in the MFT calls.
        let _ = hr;
    }
    let _ = codec_windows::MfRuntime::new().expect("MFStartup");
    match phase.as_str() {
        "transport" => phase_transport(iters),
        "capture" => phase_capture(iters),
        "encoder" => phase_encoder(iters),
        "decoder" => phase_decoder(iters),
        "render" => phase_render(iters),
        "controller-cycle" => phase_controller_cycle(iters, 30),
        _ => {
            phase_transport(iters);
            phase_capture(iters);
            phase_encoder(iters);
            phase_decoder(iters);
            phase_render(iters);
        }
    }
}
