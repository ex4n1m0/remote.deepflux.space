//! `reconfig_probe` — CR-1 memory evidence (M4 QA F56).
//!
//! Two modes, same measurement harness as the node-runtime `leak_probe`:
//!
//! * `--mode rebuild` — the pre-CR-1 behavior: each iteration constructs
//!   a fresh `MfEncoder` (what a quality-preset change used to do).
//! * `--mode reconfigure` — the fix: ONE encoder, each iteration applies
//!   `reconfigure` with alternating bitrate/GOP values and encodes one
//!   frame. Working set / private commit / threads / handles must stay
//!   flat.
//!
//! Usage:
//!   cargo run --release -p codec-windows --example reconfig_probe -- \
//!       [--mode reconfigure|rebuild] [--iters 10] [--encoder hw|sw]

use std::time::Duration;

use codec_windows::{
    EncoderParams, MfEncoder, MfEncoderConfig, MfEncoderPreference, MfRuntime, VideoEncoder,
};

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
                    if !Thread32Next(snap, &mut entry).is_ok() {
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

fn print_delta(tag: &str, i: i32, base: Snap, now: Snap) {
    let ws = (now.ws as f64 - base.ws as f64) / (1 << 20) as f64;
    let private = (now.private as f64 - base.private as f64) / (1 << 20) as f64;
    let threads = now.threads as i32 - base.threads as i32;
    let handles = now.handles as i32 - base.handles as i32;
    println!(
        "{tag:<10} iter {i:>2}: ws {ws:+7.1} MiB  private {private:+7.1} MiB  threads {threads:+3}  handles {handles:+5}"
    );
}

fn parse_args() -> (String, u32, MfEncoderPreference) {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut mode = "reconfigure".to_string();
    let mut iters = 10u32;
    let mut pref = MfEncoderPreference::Hardware;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--mode" => {
                i += 1;
                mode = argv.get(i).cloned().unwrap_or(mode);
            }
            "--iters" => {
                i += 1;
                iters = argv.get(i).and_then(|v| v.parse().ok()).unwrap_or(iters);
            }
            "--encoder" => {
                i += 1;
                pref = match argv.get(i).map(String::as_str) {
                    Some("sw") => MfEncoderPreference::Software,
                    _ => MfEncoderPreference::Hardware,
                };
            }
            other => {
                eprintln!("unknown arg {other:?}");
                std::process::exit(2);
            }
        }
        i += 1;
    }
    (mode, iters, pref)
}

fn main() {
    let (mode, iters, pref) = parse_args();
    let _mf = MfRuntime::new().expect("MFStartup");
    let device = frame_surface::GpuDevice::create_hardware().expect("hardware device");
    let cfg = MfEncoderConfig {
        width: 1920,
        height: 1080,
        fps: 60,
        bitrate_bps: 8_000_000,
        gop_size: 120,
        preference: pref,
    };

    let mut encoder = MfEncoder::new(device.clone(), cfg.clone()).expect("encoder");
    eprintln!("encoder: {}", encoder.describe());
    eprintln!("caps: {}", encoder.reconfig_capabilities().describe());

    let encode_one = |encoder: &mut MfEncoder, frame_id: u64| loop {
        // Rebuild the input each retry: `encode` consumes it even when
        // it defers output (software depth-1 pipeline).
        let surface = frame_surface::FrameSurface::new(
            &encoder.shared_device(),
            cfg.width,
            cfg.height,
            frame_surface::SurfaceFormat::Bgra8,
        )
        .expect("surface");
        let input = codec_windows::EncodeInput {
            frame_id,
            timestamp_ns: 0,
            surface,
        };
        match encoder.encode(input, false) {
            Ok(_) => return,
            Err(codec_windows::CodecError::Timeout(_)) => continue,
            Err(e) => panic!("encode: {e}"),
        }
    };

    let base = snapshot();
    println!(
        "mode {mode}, iters {iters}, base: ws {:.1} MiB private {:.1} MiB threads {} handles {}",
        base.ws as f64 / (1 << 20) as f64,
        base.private as f64 / (1 << 20) as f64,
        base.threads,
        base.handles
    );

    match mode.as_str() {
        "rebuild" => {
            for i in 1..=iters {
                // Pre-CR-1 quality-change behavior: drop and recreate.
                drop(encoder);
                encoder = MfEncoder::new(device.clone(), cfg.clone()).expect("encoder");
                encode_one(&mut encoder, i as u64);
                let now = snapshot();
                print_delta("rebuild", i as i32, base, now);
            }
        }
        "reconfigure" => {
            for i in 1..=iters {
                // CR-1: same encoder, live parameter change + one frame.
                let low = i % 2 == 1;
                encoder
                    .reconfigure(&EncoderParams {
                        bitrate_bps: Some(if low { 6_000_000 } else { 8_000_000 }),
                        gop_size: Some(if low { 90 } else { 120 }),
                        ..Default::default()
                    })
                    .expect("reconfigure");
                encode_one(&mut encoder, i as u64);
                let now = snapshot();
                print_delta("reconfig", i as i32, base, now);
            }
            let (live, rebuilt) = encoder.reconfigure_counters();
            println!("counters: live {live}, rebuilt {rebuilt}");
        }
        "encode-only" => {
            // Control: same loop without any reconfigure — separates
            // encode/allocator growth from reconfigure-path effects.
            for i in 1..=iters {
                encode_one(&mut encoder, i as u64);
                let now = snapshot();
                print_delta("encode", i as i32, base, now);
            }
        }
        other => {
            eprintln!("unknown mode {other:?} (reconfigure|rebuild|encode-only)");
            std::process::exit(2);
        }
    }
    // Let the driver settle before the final reading matters.
    std::thread::sleep(Duration::from_millis(200));
}
