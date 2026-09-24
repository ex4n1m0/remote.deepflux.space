//! MF H.264 encoder: hardware-first (async MFT) with the inbox software
//! encoder (sync MFT) as a first-class fallback (delta D3).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use windows::Win32::Graphics::Direct3D11::ID3D11Texture2D;
use windows::Win32::Media::MediaFoundation::{
    CODECAPI_AVEncCommonBufferSize, CODECAPI_AVEncCommonMeanBitRate,
    CODECAPI_AVEncCommonRateControlMode, CODECAPI_AVEncMPVDefaultBPictureCount,
    CODECAPI_AVEncMPVGOPSize, CODECAPI_AVEncVideoForceKeyFrame, CODECAPI_AVLowLatencyMode,
    ICodecAPI, IMFActivate, IMFAttributes, IMFMediaBuffer, IMFMediaEventGenerator, IMFSample,
    IMFTransform, METransformHaveOutput, METransformNeedInput, MF_E_TRANSFORM_STREAM_CHANGE,
    MF_EVENT_FLAG_NO_WAIT, MF_LOW_LATENCY, MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE,
    MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE, MF_MT_SUBTYPE, MF_SA_D3D11_AWARE, MF_TRANSFORM_ASYNC,
    MF_TRANSFORM_ASYNC_UNLOCK, MFCreateDXGISurfaceBuffer, MFCreateMemoryBuffer, MFCreateSample,
    MFMediaType_Video, MFSampleExtension_CleanPoint, MFT_CATEGORY_VIDEO_ENCODER,
    MFT_ENUM_ADAPTER_LUID, MFT_ENUM_FLAG, MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SYNCMFT,
    MFT_FRIENDLY_NAME_Attribute, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_MESSAGE_SET_D3D_MANAGER, MFT_OUTPUT_DATA_BUFFER,
    MFT_OUTPUT_STREAM_PROVIDES_SAMPLES, MFT_REGISTER_TYPE_INFO, MFVideoFormat_H264,
    MFVideoFormat_NV12, eAVEncCommonRateControlMode_CBR,
};
use windows::Win32::Media::MediaFoundation::{
    MF_VERSION, MFSTARTUP_NOSOCKET, MFStartup, MFVideoInterlace_Progressive,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::Variant::{VARIANT, VT_BOOL, VT_UI4, VT_UI8, VariantInit};
use windows::core::{IUnknown, Interface};

use frame_surface::{FrameSurface, GpuDevice, readback};

use crate::convert::Nv12Converter;
use crate::{CodecError, CodecKind, EncodeInput, EncodedPacket, VideoEncoder, annex_b_is_keyframe};

/// How many NV12 input textures rotate under the encoder (the async
/// hardware path may hold one while the next is converted).
const NV12_RING: usize = 4;

/// Encoder selection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MfEncoderPreference {
    /// Enumerate hardware MFTs matching the device's adapter; fall back
    /// to the software encoder when none negotiates.
    #[default]
    Auto,
    Hardware,
    Software,
}

/// Low-delay encoder configuration.
#[derive(Debug, Clone)]
pub struct MfEncoderConfig {
    /// Encode resolution (the converter scales the capture into this).
    pub width: u32,
    pub height: u32,
    /// Frame rate for the MF type (drives GOP-in-seconds and the
    /// bitstream's timing info).
    pub fps: u32,
    /// CBR target, bits per second.
    pub bitrate_bps: u32,
    /// GOP length in frames (~2 s at the given fps by convention).
    pub gop_size: u32,
    pub preference: MfEncoderPreference,
}

impl Default for MfEncoderConfig {
    fn default() -> Self {
        Self {
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_bps: 8_000_000,
            gop_size: 120, // ~2 s at 60 fps
            preference: MfEncoderPreference::Auto,
        }
    }
}

/// One enumerated transform candidate.
struct Candidate {
    name: String,
    hardware: bool,
    activate: IMFActivate,
}

unsafe fn enumerate(
    flags: MFT_ENUM_FLAG,
    input_subtype: windows::core::GUID,
    output_subtype: windows::core::GUID,
) -> Vec<Candidate> {
    unsafe {
        let in_info = MFT_REGISTER_TYPE_INFO {
            guidMajorType: MFMediaType_Video,
            guidSubtype: input_subtype,
        };
        let out_info = MFT_REGISTER_TYPE_INFO {
            guidMajorType: MFMediaType_Video,
            guidSubtype: output_subtype,
        };
        let mut activates: *mut Option<IMFActivate> = std::ptr::null_mut();
        let mut count = 0u32;
        let hr = windows::Win32::Media::MediaFoundation::MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            flags,
            Some(&in_info),
            Some(&out_info),
            &mut activates,
            &mut count,
        );
        if hr.is_err() || activates.is_null() {
            return Vec::new();
        }
        let slice = std::slice::from_raw_parts(activates, count as usize);
        let mut out = Vec::new();
        for slot in slice {
            let Some(activate) = slot else { continue };
            let name = activate
                .GetStringLength(&MFT_FRIENDLY_NAME_Attribute)
                .ok()
                .and_then(|len| {
                    let mut buf = vec![0u16; len as usize + 1];
                    activate
                        .GetString(&MFT_FRIENDLY_NAME_Attribute, &mut buf, None)
                        .ok()
                        .map(|_| {
                            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                            String::from_utf16_lossy(&buf[..end])
                        })
                })
                .unwrap_or_else(|| "unnamed MFT".to_string());
            out.push(Candidate {
                name,
                hardware: flags == MFT_ENUM_FLAG_HARDWARE,
                activate: activate.clone(),
            });
        }
        CoTaskMemFree(Some(activates.cast()));
        out
    }
}

/// Input handed to the async worker. The COM sample pointer moves
/// ownership to the worker thread (never touched by the sender after
/// the send) — hence the SendBox wrapper.
struct SubmitInput {
    sample: SendBox<IMFSample>,
    force_keyframe: bool,
}

struct WorkerOutput {
    bytes: Vec<u8>,
    is_keyframe: bool,
}

/// Shared control block between the encode thread and the MFT worker.
struct AsyncShared {
    stop: bool,
    /// Asynchronous MFT credits: incremented by METransformNeedInput,
    /// consumed by ProcessInput.
    need_input: u32,
    have_output: bool,
    error: Option<String>,
}

/// Send-wrapper for COM pointers moved into the worker thread. Safe
/// because *all* calls on these interfaces happen on the worker thread
/// after the handoff.
struct SendBox<T>(T);
unsafe impl<T> Send for SendBox<T> {}

struct AsyncWorker {
    shared: Arc<Mutex<AsyncShared>>,
    submit_tx: SyncSender<SubmitInput>,
    output_rx: Receiver<WorkerOutput>,
    join: Option<std::thread::JoinHandle<()>>,
    dropped_outputs: Arc<AtomicU64>,
}

impl Drop for AsyncWorker {
    fn drop(&mut self) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.stop = true;
        }
        // Drain-block: the worker exits on stop within one poll tick.
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Media Foundation H.264 encoder behind [`VideoEncoder`].
///
/// `Send` safety: the sync backend's MFT is only touched from the thread
/// calling `encode`; the async backend moves *all* MFT calls onto its
/// single worker thread (the encode thread only touches channels). The
/// shared D3D11 device is multithread-protected.
pub struct MfEncoder {
    device: GpuDevice,
    config: MfEncoderConfig,
    kind: CodecKind,
    name: String,
    converter: Nv12Converter,
    nv12_ring: Vec<FrameSurface>,
    ring_next: usize,
    backend: Backend,
    time_100ns: i64,
    bitrate_bps: u32,
    force_keyframe_supported: bool,
    /// Encoded bytes emitted (diagnostics: measured bitrate).
    pub bytes_emitted: u64,
    pub frames_encoded: u64,
}

/// The async-MFT event pump (see `Backend::Async`). Runs entirely on the
/// worker thread: `METransformNeedInput` credits gate `ProcessInput`,
/// `METransformHaveOutput` gates `ProcessOutput`.
fn async_encoder_worker(
    transform: SendBox<IMFTransform>,
    event_gen: SendBox<IMFMediaEventGenerator>,
    codec_api: SendBox<Option<ICodecAPI>>,
    submit_rx: Receiver<SubmitInput>,
    output_tx: SyncSender<WorkerOutput>,
    shared: Arc<Mutex<AsyncShared>>,
    dropped_outputs: Arc<AtomicU64>,
) {
    let SendBox(transform) = transform;
    let SendBox(event_gen) = event_gen;
    let SendBox(codec_api) = codec_api;
    let mut pending: Option<SubmitInput> = None;
    loop {
        let (need_input, _have_output, stop, error) = {
            let s = shared.lock().expect("worker lock");
            (s.need_input, s.have_output, s.stop, s.error.clone())
        };
        if stop {
            break;
        }
        if let Some(err) = error {
            eprintln!("mft-encoder-worker fatal: {err}");
            break;
        }

        if pending.is_none()
            && let Ok(next) = submit_rx.try_recv()
        {
            pending = Some(next);
        }
        if need_input > 0
            && let Some(SubmitInput {
                sample: SendBox(sample),
                force_keyframe,
            }) = pending.take()
        {
            unsafe {
                if force_keyframe && let Some(api) = &codec_api {
                    let _ = set_u32(api, &CODECAPI_AVEncVideoForceKeyFrame, 1);
                }
                let _ = transform.ProcessInput(0, &sample, 0);
            }
            if let Ok(mut s) = shared_guard(&shared) {
                s.need_input = s.need_input.saturating_sub(1);
            }
        }

        // Drain events (non-blocking).
        loop {
            let ev = unsafe { event_gen.GetEvent(MF_EVENT_FLAG_NO_WAIT) };
            let Ok(event) = ev else { break };
            let kind = unsafe { event.GetType() }.unwrap_or(0);
            let mut s = shared.lock().expect("worker lock");
            if kind == METransformNeedInput.0 as u32 {
                s.need_input += 1;
            } else if kind == METransformHaveOutput.0 as u32 {
                s.have_output = true;
            }
            // METransformInputStreamStateChanged / METransformMarker:
            // informational for a fixed-format encode stream.
        }

        let have_output = {
            let s = shared.lock().expect("worker lock");
            s.have_output
        };
        if have_output {
            if let Some(out) = unsafe { extract_output_sync(&transform) } {
                // Bounded (invariant 3): never queue encoded frames; drop
                // the stale one and count it.
                match output_tx.try_send(out) {
                    Err(TrySendError::Full(_)) => {
                        dropped_outputs.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TrySendError::Disconnected(_)) => break,
                    Ok(()) => {}
                }
            }
            if let Ok(mut s) = shared_guard(&shared) {
                s.have_output = false;
            }
        }

        // Idle nap: at 60 fps NeedInput/HaveOutput events dominate; the
        // 200 us poll ceiling adds at most one tick of event latency.
        std::thread::sleep(Duration::from_micros(200));
    }
}

fn shared_guard(
    shared: &Arc<Mutex<AsyncShared>>,
) -> Result<std::sync::MutexGuard<'_, AsyncShared>, ()> {
    shared.lock().map_err(|_| ())
}

unsafe impl Send for MfEncoder {}

enum Backend {
    /// All MFT calls happen on the caller thread (inbox software
    /// encoder). `in_flight` holds the (frame_id, timestamp_ns) of
    /// submitted-but-not-yet-emitted inputs: the software encoder is a
    /// depth-1 pipeline whose output for input N surfaces when N+1 is fed.
    Sync {
        transform: IMFTransform,
        codec_api: Option<ICodecAPI>,
        in_flight: std::collections::VecDeque<(u64, u64)>,
    },
    /// All MFT calls happen on the worker thread (hardware async MFT).
    Async(AsyncWorker),
}

impl MfEncoder {
    /// Build an encoder on `device` (the same shared device as capture —
    /// required for the zero-copy DXGI-buffer input path).
    pub fn new(device: GpuDevice, config: MfEncoderConfig) -> Result<Self, CodecError> {
        let mut candidates: Vec<Candidate> = match config.preference {
            MfEncoderPreference::Hardware | MfEncoderPreference::Auto => unsafe {
                enumerate(
                    MFT_ENUM_FLAG_HARDWARE,
                    MFVideoFormat_NV12,
                    MFVideoFormat_H264,
                )
            },
            MfEncoderPreference::Software => Vec::new(),
        };
        if config.preference != MfEncoderPreference::Hardware {
            let sw = unsafe {
                enumerate(
                    MFT_ENUM_FLAG_SYNCMFT,
                    MFVideoFormat_NV12,
                    MFVideoFormat_H264,
                )
            };
            candidates.extend(sw);
        }

        let mut last_err = String::new();
        for candidate in &candidates {
            match Self::try_build(&device, &config, candidate) {
                Ok(encoder) => return Ok(encoder),
                Err(e) => last_err = format!("{} [{}]: {}", last_err, candidate.name, e),
            }
        }
        Err(CodecError::FormatNegotiation(format!(
            "no usable H.264 encoder MFT (preference {:?}); last errors: {}",
            config.preference, last_err
        )))
    }

    fn try_build(
        device: &GpuDevice,
        config: &MfEncoderConfig,
        candidate: &Candidate,
    ) -> Result<Self, CodecError> {
        unsafe {
            // Hardware MFTs expose MF_TRANSFORM_ASYNC / MF_SA_D3D11_AWARE /
            // MFT_ENUM_ADAPTER_LUID on the *activation object*, not on the
            // transform (which fails IMFAttributes with E_NOINTERFACE).
            let activation_attrs: IMFAttributes = candidate.activate.cast().map_err(|e| {
                CodecError::FormatNegotiation(format!("activate attrs: {}", e.message()))
            })?;
            let is_async = activation_attrs.GetUINT32(&MF_TRANSFORM_ASYNC).unwrap_or(0) == 1;
            let _d3d_aware = activation_attrs.GetUINT32(&MF_SA_D3D11_AWARE).unwrap_or(0) == 1;
            // Adapter affinity: a hardware MFT must run on the device that
            // lives on its own adapter (hybrid laptops: QuickSync on Intel,
            // NVENC on NVIDIA). Mismatched pairs fail at first frame.
            if let (Ok((dev_lo, dev_hi)), Ok(luid)) = (
                device.adapter_luid(),
                activation_attrs.GetUINT64(&MFT_ENUM_ADAPTER_LUID),
            ) {
                let (mft_lo, mft_hi) = (
                    (luid & 0xFFFF_FFFF) as u32 as i32,
                    (luid >> 32) as u32 as i32,
                );
                if (mft_lo, mft_hi) != (dev_lo, dev_hi) {
                    return Err(CodecError::FormatNegotiation(format!(
                        "adapter mismatch (mft {mft_lo}:{mft_hi}, device {dev_lo}:{dev_hi})"
                    )));
                }
            }

            let transform: IMFTransform = candidate
                .activate
                .ActivateObject()
                .map_err(|e| CodecError::FormatNegotiation(e.message().to_string()))?;

            // Async MFTs expose their attribute store via GetAttributes
            // (NOT via QI — hardware MFTs fail that cast). Unlocking is
            // required before any ProcessMessage on an async MFT.
            let transform_attrs: IMFAttributes = transform.GetAttributes().map_err(|e| {
                CodecError::FormatNegotiation(format!("GetAttributes: {}", e.message()))
            })?;

            // Device manager for the hardware (async) path only: the
            // sync/software backend feeds CPU NV12 buffers and a manager
            // would make the MFT expect DXGI-surface inputs instead.
            // Hybrid systems: a hardware MFT on another adapter fails at
            // the LUID check above before reaching here.
            let manager = if is_async {
                Some(make_device_manager(device)?)
            } else {
                None
            };

            let codec_api: Option<ICodecAPI> = transform.cast().ok();
            let mut force_kf_supported = false;
            if let Some(api) = &codec_api {
                if api.IsSupported(&CODECAPI_AVEncVideoForceKeyFrame).is_ok() {
                    force_kf_supported = true;
                }
                // Low-delay settings — set before the output type (the MS
                // encoder applies rate-control caps at type-set time).
                let _ = set_bool(api, &CODECAPI_AVLowLatencyMode, true);
                let _ = set_u32(api, &CODECAPI_AVEncMPVDefaultBPictureCount, 0);
                let _ = set_u32(api, &CODECAPI_AVEncMPVGOPSize, config.gop_size);
                let _ = set_u32(
                    api,
                    &CODECAPI_AVEncCommonRateControlMode,
                    eAVEncCommonRateControlMode_CBR.0 as u32,
                );
                // The MS docs type MeanBitRate/BufferSize as VT_UI4.
                let _ = set_u32(api, &CODECAPI_AVEncCommonMeanBitRate, config.bitrate_bps);
                // The inbox software encoder requires an explicit
                // buffer size in CBR mode; one frame keeps the window
                // at the low-latency minimum.
                let frame_bytes = (config.bitrate_bps / 8).max(1) / config.fps.max(1);
                let _ = set_u32(api, &CODECAPI_AVEncCommonBufferSize, frame_bytes.max(1));
            }

            if is_async {
                transform_attrs
                    .SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)
                    .map_err(|e| {
                        CodecError::FormatNegotiation(format!("async unlock: {}", e.message()))
                    })?;
            }
            if let Some(manager) = &manager {
                let unk: IUnknown = manager
                    .cast()
                    .map_err(|e| CodecError::DeviceLost(e.message()))?;
                transform
                    .ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, unk.as_raw() as usize)
                    .map_err(|e| {
                        CodecError::FormatNegotiation(format!("set D3D manager: {}", e.message()))
                    })?;
            }

            // Output type: H.264 with geometry + rate.
            let out_type = new_media_type()?;
            out_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).ok();
            out_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264).ok();
            out_type
                .SetUINT64(&MF_MT_FRAME_SIZE, pack_size(config.width, config.height))
                .ok();
            out_type
                .SetUINT64(&MF_MT_FRAME_RATE, pack_ratio(config.fps, 1))
                .ok();
            out_type
                .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .ok();
            transform.SetOutputType(0, &out_type, 0).map_err(|e| {
                CodecError::FormatNegotiation(format!("SetOutputType: {}", e.message()))
            })?;

            // Input type: NV12.
            let in_type = new_media_type()?;
            in_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).ok();
            in_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12).ok();
            in_type
                .SetUINT64(&MF_MT_FRAME_SIZE, pack_size(config.width, config.height))
                .ok();
            in_type
                .SetUINT64(&MF_MT_FRAME_RATE, pack_ratio(config.fps, 1))
                .ok();
            in_type
                .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .ok();
            // F25: the low-latency media-type attribute alongside the
            // codec-API property (the crate docs claimed both; only the
            // property was set).
            in_type.SetUINT32(&MF_LOW_LATENCY, 1).ok();
            transform.SetInputType(0, &in_type, 0).map_err(|e| {
                CodecError::FormatNegotiation(format!("SetInputType: {}", e.message()))
            })?;

            transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .ok();
            transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                .ok();

            let backend = if is_async {
                let (submit_tx, submit_rx) = sync_channel::<SubmitInput>(2);
                let (output_tx, output_rx) = sync_channel::<WorkerOutput>(4);
                let shared = Arc::new(Mutex::new(AsyncShared {
                    stop: false,
                    need_input: 0,
                    have_output: false,
                    error: None,
                }));
                let worker_shared = Arc::clone(&shared);
                let dropped = Arc::new(AtomicU64::new(0));
                let worker_dropped = Arc::clone(&dropped);
                // Wrap before the move so the closure itself only captures
                // Send types; all interface calls stay on the worker.
                let event_gen: IMFMediaEventGenerator = transform.cast().expect("event generator");
                let transform = SendBox(transform);
                let event_gen = SendBox(event_gen);
                let codec_api = SendBox(codec_api);
                let join = std::thread::Builder::new()
                    .name("mft-encoder-worker".into())
                    .spawn(move || {
                        // Pass the wrappers whole into a function so the
                        // closure captures the SendBox (edition-2021
                        // disjoint captures would otherwise grab the
                        // non-Send `.0` field).
                        async_encoder_worker(
                            transform,
                            event_gen,
                            codec_api,
                            submit_rx,
                            output_tx,
                            worker_shared,
                            worker_dropped,
                        );
                    })
                    .map_err(|e| CodecError::NotReady(e.to_string()))?;
                Backend::Async(AsyncWorker {
                    shared,
                    submit_tx,
                    output_rx,
                    join: Some(join),
                    dropped_outputs: dropped,
                })
            } else {
                Backend::Sync {
                    transform,
                    codec_api,
                    in_flight: std::collections::VecDeque::new(),
                }
            };

            let kind = if candidate.hardware && manager.is_some() {
                CodecKind::Hardware
            } else {
                CodecKind::Software
            };
            let converter = Nv12Converter::new(
                device.clone(),
                config.width,
                config.height,
                config.width,
                config.height,
            )?;
            Ok(Self {
                device: device.clone(),
                config: config.clone(),
                kind,
                name: candidate.name.clone(),
                converter,
                nv12_ring: Vec::new(),
                ring_next: 0,
                backend,
                time_100ns: 0,
                bitrate_bps: config.bitrate_bps,
                force_keyframe_supported: force_kf_supported,
                bytes_emitted: 0,
                frames_encoded: 0,
            })
        }
    }

    /// The shared D3D11 device this encoder (and its converter) run on —
    /// input surfaces must live on it (same-device zero-copy contract,
    /// ADR-001 M1 amendment). Exposed for tests and node runtimes that
    /// allocate source surfaces.
    pub fn shared_device(&self) -> GpuDevice {
        self.device.clone()
    }

    /// Which MFT is active (for the diagnostics report).
    pub fn describe(&self) -> String {
        format!(
            "{} ({}, {}x{}@{}fps, {} bps CBR, GOP {})",
            self.name,
            self.kind.as_str(),
            self.config.width,
            self.config.height,
            self.config.fps,
            self.bitrate_bps,
            self.config.gop_size
        )
    }

    pub fn force_keyframe_supported(&self) -> bool {
        self.force_keyframe_supported
    }

    fn nv12_slot(&mut self) -> Result<FrameSurface, CodecError> {
        if self.nv12_ring.is_empty() {
            for _ in 0..NV12_RING {
                self.nv12_ring.push(
                    FrameSurface::new_private(
                        &self.device,
                        self.config.width,
                        self.config.height,
                        frame_surface::SurfaceFormat::Nv12,
                    )
                    .map_err(|e| CodecError::DeviceLost(e.to_string()))?,
                );
            }
        }
        let slot = self.nv12_ring[self.ring_next].clone();
        self.ring_next = (self.ring_next + 1) % self.nv12_ring.len();
        Ok(slot)
    }

    /// Rebuild the converter when the capture geometry changes (display
    /// mode change); the encoder keeps its encode resolution.
    fn rebind_converter(&mut self, width: u32, height: u32) -> Result<(), CodecError> {
        self.converter = Nv12Converter::new(
            self.device.clone(),
            width,
            height,
            self.config.width,
            self.config.height,
        )?;
        Ok(())
    }

    fn next_100ns(&mut self, fps: u32) -> i64 {
        let t = self.time_100ns;
        self.time_100ns += 10_000_000 / fps.max(1) as i64;
        t
    }
}

/// `MF_MT_FRAME_SIZE` is a packed UINT64: (width << 32) | height.
fn pack_size(width: u32, height: u32) -> u64 {
    ((width as u64) << 32) | height as u64
}

/// `MF_MT_FRAME_RATE` is a packed UINT64 ratio: (num << 32) | den.
fn pack_ratio(num: u32, den: u32) -> u64 {
    ((num as u64) << 32) | den as u64
}

unsafe fn new_media_type()
-> Result<windows::Win32::Media::MediaFoundation::IMFMediaType, CodecError> {
    unsafe {
        windows::Win32::Media::MediaFoundation::MFCreateMediaType()
            .map_err(|e| CodecError::FormatNegotiation(e.message()))
    }
}

unsafe fn make_device_manager(
    device: &GpuDevice,
) -> Result<windows::Win32::Media::MediaFoundation::IMFDXGIDeviceManager, CodecError> {
    unsafe {
        let mut token = 0u32;
        let mut manager = None;
        windows::Win32::Media::MediaFoundation::MFCreateDXGIDeviceManager(&mut token, &mut manager)
            .map_err(|e| CodecError::DeviceLost(e.message()))?;
        let manager = manager.ok_or_else(|| CodecError::DeviceLost("no device manager".into()))?;
        manager
            .ResetDevice(device.device(), token)
            .map_err(|e| CodecError::DeviceLost(e.message()))?;
        Ok(manager)
    }
}

/// Build a VT_UI4 VARIANT. `VARIANT`'s Rust layout (nested unions behind
/// `ManuallyDrop`) makes member assignment awkward; the C layout is
/// stable ABI (2-byte vt + 6 reserved bytes + 8-byte union), so write
/// via raw offsets. `VariantClear`'s job (freeing `BSTR`s etc.) does not
/// apply to numeric variants.
pub(crate) unsafe fn variant_u32_pub(value: u32) -> VARIANT {
    unsafe { variant_u32(value) }
}

unsafe fn variant_u32(value: u32) -> VARIANT {
    unsafe {
        let mut var = VariantInit();
        let p = std::ptr::addr_of_mut!(var) as *mut u8;
        (p as *mut u16).write(VT_UI4.0);
        p.add(8).cast::<u32>().write(value);
        var
    }
}

#[allow(dead_code)] // kept for M2 live-bitrate use
unsafe fn variant_u64(value: u64) -> VARIANT {
    unsafe {
        let mut var = VariantInit();
        let p = std::ptr::addr_of_mut!(var) as *mut u8;
        (p as *mut u16).write(VT_UI8.0);
        p.add(8).cast::<u64>().write(value);
        var
    }
}

#[allow(dead_code)]
unsafe fn variant_bool(value: bool) -> VARIANT {
    unsafe {
        let mut var = VariantInit();
        let p = std::ptr::addr_of_mut!(var) as *mut u8;
        (p as *mut u16).write(VT_BOOL.0);
        p.add(8).cast::<i16>().write(if value { -1 } else { 0 });
        var
    }
}

unsafe fn set_u32(
    api: &ICodecAPI,
    key: &windows::core::GUID,
    value: u32,
) -> Result<(), CodecError> {
    unsafe {
        let var = variant_u32(value);
        api.SetValue(key, &var)
            .map_err(|e| CodecError::Processing(e.message()))
    }
}

#[allow(dead_code)] // kept for M2 live-bitrate use
unsafe fn set_u64(
    api: &ICodecAPI,
    key: &windows::core::GUID,
    value: u64,
) -> Result<(), CodecError> {
    unsafe {
        let var = variant_u64(value);
        api.SetValue(key, &var)
            .map_err(|e| CodecError::Processing(e.message()))
    }
}

#[allow(dead_code)]
unsafe fn set_bool(
    api: &ICodecAPI,
    key: &windows::core::GUID,
    value: bool,
) -> Result<(), CodecError> {
    unsafe {
        let var = variant_bool(value);
        api.SetValue(key, &var)
            .map_err(|e| CodecError::Processing(e.message()))
    }
}

/// Pull one output sample from a transform (called on whichever thread
/// owns the transform).
unsafe fn extract_output_sync(transform: &IMFTransform) -> Option<WorkerOutput> {
    unsafe {
        // Sync MFTs may require the caller to allocate the output sample
        // (the inbox software encoder does: OutputStreamInfo flags lack
        // MFT_OUTPUT_STREAM_PROVIDES_SAMPLES); async MFTs provide their
        // own and ignore the caller's slot.
        let info = transform.GetOutputStreamInfo(0).ok();
        let provides_samples = info
            .as_ref()
            .map(|i| i.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32) != 0)
            .unwrap_or(false);
        let out_sample: Option<IMFSample> = if provides_samples {
            None
        } else {
            let size = info.map(|i| i.cbSize).unwrap_or(4 * 1024 * 1024).max(1);
            let buffer: IMFMediaBuffer = MFCreateMemoryBuffer(size).ok()?;
            let sample: IMFSample = MFCreateSample().ok()?;
            sample.AddBuffer(&buffer).ok()?;
            Some(sample)
        };
        let mut buffers = [MFT_OUTPUT_DATA_BUFFER {
            dwStreamID: 0,
            pSample: core::mem::ManuallyDrop::new(out_sample),
            dwStatus: 0,
            pEvents: core::mem::ManuallyDrop::new(None),
        }];
        let mut status = 0u32;
        let hr = transform.ProcessOutput(0, buffers.as_mut_slice(), &mut status);
        if let Err(e) = hr {
            let code = e.code();
            if code == MF_E_TRANSFORM_STREAM_CHANGE {
                // The encoder finalized the dynamic output type after
                // seeing the first input (SPS/PPS with the real
                // profile/level): accept it and retry once.
                if let Ok(mt) = transform.GetOutputAvailableType(0, 0) {
                    let _ = transform.SetOutputType(0, &mt, 0);
                }
                return extract_output_sync(transform);
            }
            return None;
        }
        let sample = core::mem::ManuallyDrop::take(&mut buffers[0].pSample)?;
        let clean = sample.GetUINT32(&MFSampleExtension_CleanPoint).unwrap_or(0) == 1;
        let buffer: IMFMediaBuffer = sample.ConvertToContiguousBuffer().ok()?;
        let mut ptr = std::ptr::null_mut();
        let mut len = 0u32;
        buffer.Lock(&mut ptr, None, Some(&mut len)).ok()?;
        let mut bytes = vec![0u8; len as usize];
        std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), len as usize);
        let _ = buffer.Unlock();
        let is_keyframe = clean || annex_b_is_keyframe(&bytes);
        Some(WorkerOutput { bytes, is_keyframe })
    }
}

impl VideoEncoder for MfEncoder {
    fn kind(&self) -> CodecKind {
        self.kind
    }

    fn encode(
        &mut self,
        input: EncodeInput,
        force_keyframe: bool,
    ) -> Result<EncodedPacket, CodecError> {
        // 1. GPU color convert (and scale) into an NV12 ring slot.
        if self.converter.input_geometry() != (input.surface.width(), input.surface.height()) {
            self.rebind_converter(input.surface.width(), input.surface.height())?;
        }
        let nv12 = self.nv12_slot()?;
        self.converter
            .convert(&input.surface, &nv12)
            .map_err(|e| CodecError::Processing(e.to_string()))?;

        let time = self.next_100ns(self.config.fps);
        let duration = 10_000_000 / self.config.fps.max(1) as i64;

        match &mut self.backend {
            Backend::Sync {
                transform,
                codec_api,
                in_flight,
            } => unsafe {
                // Drain any output pending from the previous input first
                // (depth-1 pipeline), stamping it with its own id.
                if let Some(out) = extract_output_sync(transform) {
                    let (fid, ts) = in_flight
                        .pop_front()
                        .unwrap_or((input.frame_id, input.timestamp_ns));
                    self.bytes_emitted += out.bytes.len() as u64;
                    self.frames_encoded += 1;
                    return Ok(EncodedPacket {
                        frame_id: fid,
                        timestamp_ns: ts,
                        is_keyframe: out.is_keyframe,
                        bytes: out.bytes,
                    });
                }
                if force_keyframe && let Some(api) = codec_api {
                    let _ = set_u32(api, &CODECAPI_AVEncVideoForceKeyFrame, 1);
                }
                // Input sample: CPU NV12 memory — the documented
                // software-fallback copy (delta D3), measured by
                // frame-surface's readback counter. GPU zero-copy input
                // is the hardware backend's path.
                let sample: IMFSample =
                    MFCreateSample().map_err(|e| CodecError::Processing(e.message()))?;
                let buffer: IMFMediaBuffer = {
                    let cpu = readback(&self.device, &nv12)
                        .map_err(|e| CodecError::Processing(e.to_string()))?;
                    let buf: IMFMediaBuffer = MFCreateMemoryBuffer(cpu.data.len() as u32)
                        .map_err(|e| CodecError::Processing(e.message()))?;
                    let mut ptr = std::ptr::null_mut();
                    buf.Lock(&mut ptr, None, Some(&mut { cpu.data.len() as u32 }))
                        .map_err(|e| CodecError::Processing(e.message()))?;
                    std::ptr::copy_nonoverlapping(cpu.data.as_ptr(), ptr, cpu.data.len());
                    buf.Unlock()
                        .map_err(|e| CodecError::Processing(e.message()))?;
                    buf.SetCurrentLength(cpu.data.len() as u32)
                        .map_err(|e| CodecError::Processing(e.message()))?;
                    buf
                };
                sample
                    .AddBuffer(&buffer)
                    .map_err(|e| CodecError::Processing(format!("AddBuffer: {}", e.message())))?;
                sample.SetSampleTime(time).map_err(|e| {
                    CodecError::Processing(format!("SetSampleTime: {}", e.message()))
                })?;
                sample.SetSampleDuration(duration).map_err(|e| {
                    CodecError::Processing(format!("SetSampleDuration: {}", e.message()))
                })?;
                transform.ProcessInput(0, &sample, 0).map_err(|e| {
                    CodecError::Processing(format!("sync ProcessInput: {}", e.message()))
                })?;
                in_flight.push_back((input.frame_id, input.timestamp_ns));
                if in_flight.len() > 2 {
                    in_flight.pop_front();
                }
                // Under low latency the output usually surfaces here
                // already; otherwise it will on the next submit.
                if let Some(out) = extract_output_sync(transform) {
                    let (fid, ts) = in_flight
                        .pop_front()
                        .unwrap_or((input.frame_id, input.timestamp_ns));
                    self.bytes_emitted += out.bytes.len() as u64;
                    self.frames_encoded += 1;
                    return Ok(EncodedPacket {
                        frame_id: fid,
                        timestamp_ns: ts,
                        is_keyframe: out.is_keyframe,
                        bytes: out.bytes,
                    });
                }
                // This frame stays in flight; the caller's queue counters
                // account for the one-frame pipeline depth.
                Err(CodecError::Timeout(
                    "sync encoder output deferred to next input".into(),
                ))
            },
            Backend::Async(worker) => {
                let sample: IMFSample = unsafe {
                    let sample: IMFSample = MFCreateSample().map_err(|e| {
                        CodecError::Processing(format!("MFCreateSample: {}", e.message()))
                    })?;
                    let buffer: IMFMediaBuffer = MFCreateDXGISurfaceBuffer(
                        &<ID3D11Texture2D as Interface>::IID,
                        nv12.texture(),
                        0,
                        false,
                    )
                    .map_err(|e| {
                        CodecError::Processing(format!(
                            "MFCreateDXGISurfaceBuffer: {}",
                            e.message()
                        ))
                    })?;
                    sample.AddBuffer(&buffer).map_err(|e| {
                        CodecError::Processing(format!("AddBuffer: {}", e.message()))
                    })?;
                    sample.SetSampleTime(time).map_err(|e| {
                        CodecError::Processing(format!("SetSampleTime: {}", e.message()))
                    })?;
                    sample.SetSampleDuration(duration).map_err(|e| {
                        CodecError::Processing(format!("SetSampleDuration: {}", e.message()))
                    })?;
                    sample
                };
                worker
                    .submit_tx
                    .send(SubmitInput {
                        sample: SendBox(sample),
                        force_keyframe,
                    })
                    .map_err(|_| CodecError::Processing("encoder worker gone".into()))?;
                // Bounded wait for the output (low-latency: one frame in,
                // one out). The wait is the encoder's measured
                // submit->done stage.
                let deadline = std::time::Instant::now() + Duration::from_millis(100);
                loop {
                    match worker.output_rx.try_recv() {
                        Ok(out) => {
                            self.bytes_emitted += out.bytes.len() as u64;
                            self.frames_encoded += 1;
                            return Ok(EncodedPacket {
                                frame_id: input.frame_id,
                                timestamp_ns: input.timestamp_ns,
                                is_keyframe: out.is_keyframe,
                                bytes: out.bytes,
                            });
                        }
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            return Err(CodecError::Processing("encoder worker gone".into()));
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            if std::time::Instant::now() >= deadline {
                                return Err(CodecError::Timeout(
                                    "async encoder did not produce output".into(),
                                ));
                            }
                            std::thread::sleep(Duration::from_micros(200));
                        }
                    }
                }
            }
        }
    }

    fn set_bitrate(&mut self, bps: u32) -> Result<(), CodecError> {
        self.bitrate_bps = bps;
        if let Backend::Sync {
            codec_api: Some(api),
            ..
        } = &self.backend
        {
            unsafe { set_u32(api, &CODECAPI_AVEncCommonMeanBitRate, bps) }
        } else {
            // Async MFTs: post through the worker's codec API is not
            // wired for live changes in M1; report unsupported rather
            // than pretending.
            Err(CodecError::Processing(
                "live bitrate change on async MFT not wired in M1".into(),
            ))
        }
    }
}

/// Encoded frames the async worker dropped because the output channel was
/// full (invariant 3 counter; surfaced in the M1 report).
impl MfEncoder {
    pub fn dropped_outputs(&self) -> u64 {
        match &self.backend {
            Backend::Async(worker) => worker
                .dropped_outputs
                .load(std::sync::atomic::Ordering::Relaxed),
            Backend::Sync { .. } => 0,
        }
    }
}

/// Names exposed for the report: which encoder candidates exist on this
/// machine right now.
#[allow(dead_code)] // consumed by the M1 diagnostic binaries
pub fn describe_encoder_candidates(preference: MfEncoderPreference) -> Vec<String> {
    let mut out = Vec::new();
    if matches!(
        preference,
        MfEncoderPreference::Auto | MfEncoderPreference::Hardware
    ) {
        for c in unsafe {
            enumerate(
                MFT_ENUM_FLAG_HARDWARE,
                MFVideoFormat_NV12,
                MFVideoFormat_H264,
            )
        } {
            out.push(format!("hw: {}", c.name));
        }
    }
    if matches!(
        preference,
        MfEncoderPreference::Auto | MfEncoderPreference::Software
    ) {
        for c in unsafe {
            enumerate(
                MFT_ENUM_FLAG_SYNCMFT,
                MFVideoFormat_NV12,
                MFVideoFormat_H264,
            )
        } {
            out.push(format!("sw: {}", c.name));
        }
    }
    out
}

/// Ensure MF is up in tests/benchmarks that construct an encoder without
/// the node runtime's `MfRuntime` guard.
#[allow(dead_code)] // consumed by codec integration tests
pub fn mf_startup_for_tests() -> Result<(), CodecError> {
    unsafe {
        MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET).map_err(|e| CodecError::NotReady(e.message()))
    }
}
