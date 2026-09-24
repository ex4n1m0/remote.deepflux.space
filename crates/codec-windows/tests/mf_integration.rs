//! MF encode/decode integration tests. These need Media Foundation and
//! (for the software path) no display at all; the hardware path needs the
//! real GPU. Run with `cargo test -p codec-windows -- --ignored` on the
//! target machine.

use codec_windows::*;

#[allow(dead_code)]
fn make_nv12_test_input(width: u32, height: u32, seed: u8) -> frame_surface::CpuSurface {
    let mut cpu = frame_surface::CpuSurface::nv12_tight(width, height);
    let (y, uv) = cpu.data.split_at_mut((width * height) as usize);
    for (i, b) in y.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(seed * 3);
    }
    for (i, b) in uv.iter_mut().enumerate() {
        *b = (i as u8)
            .wrapping_mul(13)
            .wrapping_add(seed * 11)
            .clamp(16, 240);
    }
    cpu
}

#[test]
#[ignore = "requires Media Foundation (software path needs no display)"]
fn software_encoder_decoder_round_trip() {
    let _mf = MfRuntime::new().expect("MFStartup");
    // Real GPU (not WARP): the software *encoder* is the fallback under
    // test, but the GPU color converter needs a hardware device — exactly
    // the production fallback configuration (delta D3).
    let device = frame_surface::GpuDevice::create_hardware().expect("hardware device");
    let cfg = MfEncoderConfig {
        width: 320,
        height: 240,
        fps: 30,
        bitrate_bps: 2_000_000,
        gop_size: 60,
        preference: MfEncoderPreference::Software,
    };
    let mut encoder = MfEncoder::new(device.clone(), cfg.clone()).expect("software encoder");
    assert_eq!(encoder.kind(), CodecKind::Software);
    let mut decoder = MfDecoder::new(device.clone(), MfDecoderConfig { use_gpu: false })
        .expect("software decoder");
    assert_eq!(decoder.kind(), CodecKind::Software);

    let readbacks0 = frame_surface::readback_count();
    let uploads0 = frame_surface::upload_count();
    let mut keyframes = 0;
    let mut frames = 0;
    let mut total_bytes = 0u64;
    let bgra = frame_surface::FrameSurface::new(
        &device,
        cfg.width,
        cfg.height,
        frame_surface::SurfaceFormat::Bgra8,
    )
    .expect("bgra surface");
    for seed in 0u8..31 {
        let _ = seed;
        let input = EncodeInput {
            frame_id: seed as u64 + 1,
            timestamp_ns: seed as u64 * 16_000_000,
            surface: bgra.clone(),
        };
        // The software encoder is a depth-1 pipeline: the output for
        // input N surfaces when N+1 is fed (documented M1 behavior).
        match encoder.encode(input, false) {
            Ok(packet) => {
                total_bytes += packet.bytes.len() as u64;
                if packet.is_keyframe {
                    keyframes += 1;
                }
                let frame = decoder
                    .decode(&packet.bytes, packet.frame_id, 0)
                    .expect("decode");
                assert_eq!((frame.width, frame.height), (cfg.width, cfg.height));
                frames += 1;
            }
            Err(CodecError::Timeout(_)) => continue,
            Err(e) => panic!("encode: {e}"),
        }
    }
    // With the low-latency configuration the software encoder is
    // strictly one-in-one-out (measured: 31/31).
    assert_eq!(frames, 31, "expected one output per input");
    // F16: the software path's CPU copies are MEASURED, not inspected —
    // one NV12 readback per encoded frame, one upload per decoded frame.
    assert!(
        frame_surface::readback_count() - readbacks0 >= 31,
        "software encoder must read back every input frame (got {})",
        frame_surface::readback_count() - readbacks0
    );
    assert!(
        frame_surface::upload_count() - uploads0 >= 31,
        "software decoder must upload every output frame (got {})",
        frame_surface::upload_count() - uploads0
    );
    // First frame must be an IDR; with GOP 60 only one keyframe in 30.
    assert!(keyframes >= 1, "expected at least the first-frame IDR");
    eprintln!(
        "software round trip: 30 frames, {keyframes} keyframes, {total_bytes} bytes total (~{} kbps)",
        total_bytes * 8 * 30 / 30 / 1_000
    );
    assert!(total_bytes > 0);
}

#[test]
#[ignore = "requires Media Foundation + real GPU (software codec path)"]
fn decoder_idr_gate_after_reset() {
    // F18: after `reset()` (loss recovery) non-IDR packets must be
    // dropped until the next IDR — decoding mid-GOP after a flush
    // references a broken chain and corrupts the picture.
    let _mf = MfRuntime::new().expect("MFStartup");
    let device = frame_surface::GpuDevice::create_hardware().expect("hardware device");
    let cfg = MfEncoderConfig {
        width: 320,
        height: 240,
        fps: 30,
        bitrate_bps: 2_000_000,
        gop_size: 10, // short GOP so keyframes arrive quickly
        preference: MfEncoderPreference::Software,
    };
    let mut encoder = MfEncoder::new(device.clone(), cfg.clone()).expect("software encoder");
    let mut decoder = MfDecoder::new(device, MfDecoderConfig { use_gpu: false }).expect("decoder");

    let encode = |encoder: &mut MfEncoder, frame_id: u64, force: bool| loop {
        let surface = frame_surface::FrameSurface::new(
            &encoder.shared_device(),
            cfg.width,
            cfg.height,
            frame_surface::SurfaceFormat::Bgra8,
        )
        .expect("surface");
        let input = EncodeInput {
            frame_id,
            timestamp_ns: 0,
            surface,
        };
        match encoder.encode(input, force) {
            Ok(p) => return p,
            // Software depth-1 pipeline: output defers to the next input.
            Err(CodecError::Timeout(_)) => continue,
            Err(e) => panic!("encode: {e}"),
        }
    };

    // Warm up: first frame is an IDR and decodes.
    let idr = encode(&mut encoder, 1, false);
    assert!(idr.is_keyframe, "first frame must be an IDR");
    decoder.decode(&idr.bytes, 1, 0).expect("decode IDR");

    // Non-IDR packet after reset must be dropped by the gate.
    decoder.reset().expect("reset");
    let non_idr = (2u64..14)
        .map(|i| encode(&mut encoder, i, false))
        .find(|p| !p.is_keyframe)
        .expect("a non-IDR packet within the GOP");
    match decoder.decode(&non_idr.bytes, 2, 0) {
        Err(CodecError::DroppedAfterReset(_)) => {}
        other => panic!("expected DroppedAfterReset, got {other:?}"),
    }

    // The next IDR decodes again and clears the gate; a following
    // non-IDR frame decodes normally.
    let idr2 = loop {
        let p = encode(&mut encoder, 99, true);
        if p.is_keyframe {
            break p;
        }
    };
    decoder
        .decode(&idr2.bytes, 3, 0)
        .expect("IDR after reset decodes");
    let after = loop {
        let p = encode(&mut encoder, 100, false);
        if !p.is_keyframe {
            break p;
        }
    };
    decoder
        .decode(&after.bytes, 4, 0)
        .expect("post-IDR frame decodes");
}

#[test]
#[ignore = "requires Media Foundation + real GPU (hardware path)"]
fn hardware_encoder_candidates_reported() {
    let _mf = MfRuntime::new().expect("MFStartup");
    let candidates = describe_encoder_candidates(MfEncoderPreference::Auto);
    for c in &candidates {
        eprintln!("encoder candidate: {c}");
    }
    assert!(
        candidates.iter().any(|c| c.starts_with("sw:")),
        "software encoder must always be enumerated (delta D3)"
    );
}

#[test]
#[ignore = "requires real GPU"]
fn converter_scales_directly() {
    let device = frame_surface::GpuDevice::create_hardware().expect("hw");
    // The real loop's geometry: 4K desktop -> 1080p encode.
    let src =
        frame_surface::FrameSurface::new(&device, 3840, 2160, frame_surface::SurfaceFormat::Bgra8)
            .unwrap();
    let dst =
        frame_surface::FrameSurface::new(&device, 1920, 1080, frame_surface::SurfaceFormat::Nv12)
            .unwrap();
    let device2 = device.clone();
    let mut conv = Nv12Converter::new(device2, 3840, 2160, 1920, 1080).expect("converter 4k");
    let mut times = Vec::new();
    for _ in 0..100 {
        let t = std::time::Instant::now();
        conv.convert(&src, &dst).expect("convert");
        times.push(t.elapsed().as_micros() as u64);
    }
    times.sort();
    eprintln!(
        "convert 4k->1080p x100: p50 {} us, p95 {} us, max {} us",
        times[50], times[95], times[99]
    );
    assert!(times[50] < 5_000, "convert p50 too slow: {} us", times[50]);
}

#[test]
#[ignore = "requires Media Foundation + real GPU + display (full loop on this machine)"]
fn hardware_encoder_scales_on_rebind() {
    let _mf = MfRuntime::new().expect("MFStartup");
    let device = frame_surface::GpuDevice::create_hardware().expect("hw device");
    // Encode at 640x360 while feeding 1280x720 (forces converter rebind
    // + scaling, the local-loop configuration in miniature).
    let cfg = MfEncoderConfig {
        width: 640,
        height: 360,
        fps: 60,
        bitrate_bps: 4_000_000,
        gop_size: 120,
        preference: MfEncoderPreference::Hardware,
    };
    let mut encoder = MfEncoder::new(device.clone(), cfg).expect("encoder");
    let big =
        frame_surface::FrameSurface::new(&device, 1280, 720, frame_surface::SurfaceFormat::Bgra8)
            .expect("surface");
    let input = EncodeInput {
        frame_id: 1,
        timestamp_ns: 0,
        surface: big,
    };
    let packet = encoder.encode(input, false).expect("encode scaled");
    assert!(!packet.bytes.is_empty());
}

#[test]
#[ignore = "requires Media Foundation + real GPU + display (full loop on this machine)"]
fn hardware_encoder_accepts_gpu_input() {
    let _mf = MfRuntime::new().expect("MFStartup");
    let device = frame_surface::GpuDevice::create_hardware().expect("hw device");
    let cfg = MfEncoderConfig {
        width: 640,
        height: 360,
        fps: 60,
        bitrate_bps: 4_000_000,
        gop_size: 120,
        preference: MfEncoderPreference::Hardware,
    };
    let mut encoder = match MfEncoder::new(device.clone(), cfg.clone()) {
        Ok(encoder) => encoder,
        Err(e) => {
            eprintln!("no hardware encoder on this machine: {e}");
            return;
        }
    };
    eprintln!("hardware encoder: {}", encoder.describe());
    let mut decoder =
        MfDecoder::new(device.clone(), MfDecoderConfig { use_gpu: true }).expect("decoder");
    eprintln!("decoder: {}", decoder.describe());

    let readbacks0 = frame_surface::readback_count();
    let uploads0 = frame_surface::upload_count();
    // Feed synthetic BGRA frames through the full path the loop uses:
    // BGRA -> converter (inside encoder) -> NV12 -> encode -> decode.
    let mut bgra = frame_surface::FrameSurface::new(
        &device,
        cfg.width,
        cfg.height,
        frame_surface::SurfaceFormat::Bgra8,
    )
    .expect("bgra");
    let _ = &mut bgra;
    for i in 0..30 {
        let input = EncodeInput {
            frame_id: i as u64 + 1,
            timestamp_ns: i as u64 * 16_000_000,
            surface: bgra.clone(),
        };
        let packet = encoder.encode(input, i == 0).expect("encode");
        let frame = decoder
            .decode(&packet.bytes, i as u64 + 1, 0)
            .expect("decode");
        eprintln!(
            "frame {i}: {}x{} (surface {}x{})",
            frame.width,
            frame.height,
            frame.surface.width(),
            frame.surface.height()
        );
        assert!(
            frame.width == cfg.width && frame.height == cfg.height,
            "decoded {}x{} != {}x{}",
            frame.width,
            frame.height,
            cfg.width,
            cfg.height
        );
    }
    // F16: the hardware path claims zero CPU pixel traffic — assert it.
    assert_eq!(
        frame_surface::readback_count() - readbacks0,
        0,
        "hardware path must not read back pixels"
    );
    assert_eq!(
        frame_surface::upload_count() - uploads0,
        0,
        "DXVA path must not upload pixels"
    );
}
