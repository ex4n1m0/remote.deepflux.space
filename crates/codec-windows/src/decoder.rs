//! MF H.264 decoder: the inbox sync decoder, DXVA-backed when a D3D11
//! device manager is attached (GPU output textures, `CodecKind::Hardware`),
//! CPU NV12 output otherwise (`CodecKind::Software`).
//!
//! Decision (documented in the M1 report): vendor *async* hardware
//! decoder MFTs are enumerated-first for reporting, but the shipped path
//! is the inbox sync decoder + DXVA — it is the reference Windows decode
//! path, hardware-accelerated through the device manager, and avoids a
//! second async event pump in M1. The encoder owns the only async-MFT
//! worker. Vendor async decoders remain an M5 optimization seam.

use windows::Win32::Graphics::Direct3D11::ID3D11Texture2D;
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_NV12;
use windows::Win32::Media::MediaFoundation::{
    CODECAPI_AVLowLatencyMode, ICodecAPI, IMFActivate, IMFDXGIBuffer, IMFDXGIDeviceManager,
    IMFMediaBuffer, IMFSample, IMFTransform, MF_E_TRANSFORM_NEED_MORE_INPUT,
    MF_E_TRANSFORM_STREAM_CHANGE, MF_LOW_LATENCY, MF_MT_FRAME_SIZE, MF_MT_MAJOR_TYPE,
    MF_MT_MINIMUM_DISPLAY_APERTURE, MF_MT_SUBTYPE, MFCreateMemoryBuffer, MFCreateSample,
    MFMediaType_Video, MFSampleExtension_CleanPoint, MFT_CATEGORY_VIDEO_DECODER,
    MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SYNCMFT, MFT_FRIENDLY_NAME_Attribute,
    MFT_MESSAGE_COMMAND_FLUSH, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, MFT_MESSAGE_SET_D3D_MANAGER,
    MFT_REGISTER_TYPE_INFO, MFVideoFormat_H264, MFVideoFormat_NV12,
};
use windows::core::Interface;

use frame_surface::{CpuSurface, FrameSurface, GpuDevice};

use crate::{CodecError, CodecKind, DecodedFrame, VideoDecoder, annex_b_is_keyframe};

/// Decoder configuration.
#[derive(Debug, Clone)]
pub struct MfDecoderConfig {
    /// Attach the shared D3D11 device (DXVA path) when true.
    pub use_gpu: bool,
}

impl Default for MfDecoderConfig {
    fn default() -> Self {
        Self { use_gpu: true }
    }
}

/// MF H.264 decoder behind [`VideoDecoder`].
///
/// `Send` safety: the MFT is constructed on the caller's thread and every
/// `ProcessInput`/`ProcessOutput` happens on the thread that calls
/// `decode` — the node runtime owns one decoder per decode thread and
/// never shares it (same discipline the MF threading model requires).
pub struct MfDecoder {
    device: GpuDevice,
    kind: CodecKind,
    name: String,
    transform: IMFTransform,
    width: u32,
    height: u32,
    /// Output is GPU (DXVA) textures vs CPU NV12 buffers.
    gpu_output: bool,
    time_100ns: i64,
    /// Pooled upload destination for the CPU-output path.
    upload_dst: Option<FrameSurface>,
    /// Bounded ring of owned output copies (DXVA path). A per-frame
    /// allocation leaked driver resources until the device suspended
    /// (~3600 frames in); the ring bounds GPU memory.
    owned_ring: Vec<FrameSurface>,
    owned_next: usize,
    /// F18 IDR gate: true after `reset()` until an IDR access unit is
    /// fed; non-keyframe packets are dropped meanwhile.
    awaiting_idr: bool,
}

unsafe impl Send for MfDecoder {}

impl MfDecoder {
    pub fn new(device: GpuDevice, config: MfDecoderConfig) -> Result<Self, CodecError> {
        unsafe {
            let candidates = enumerate_decoders();
            let mut last_err = String::new();
            for candidate in &candidates {
                match Self::try_build(&device, config.use_gpu, candidate) {
                    Ok(decoder) => return Ok(decoder),
                    Err(e) => last_err = format!("{last_err} [{}]: {e}", candidate.name),
                }
            }
            Err(CodecError::FormatNegotiation(format!(
                "no usable H.264 decoder MFT; candidates tried: {last_err}"
            )))
        }
    }

    fn try_build(
        device: &GpuDevice,
        use_gpu: bool,
        candidate: &Candidate,
    ) -> Result<Self, CodecError> {
        unsafe {
            let transform: IMFTransform = candidate
                .activate
                .ActivateObject()
                .map_err(|e| CodecError::FormatNegotiation(e.message().to_string()))?;

            let gpu_output = if use_gpu {
                let mut token = 0u32;
                let mut manager: Option<IMFDXGIDeviceManager> = None;
                windows::Win32::Media::MediaFoundation::MFCreateDXGIDeviceManager(
                    &mut token,
                    &mut manager,
                )
                .map_err(|e| CodecError::DeviceLost(e.message()))?;
                let manager = manager.ok_or_else(|| CodecError::DeviceLost("no manager".into()))?;
                manager
                    .ResetDevice(device.device(), token)
                    .map_err(|e| CodecError::DeviceLost(e.message()))?;
                let unk: windows::core::IUnknown = manager.cast().expect("manager IUnknown");
                transform
                    .ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, unk.as_raw() as usize)
                    .is_ok()
            } else {
                false
            };

            // Low latency: no reorder buffer, emit on decode.
            if let Ok(api) = transform.cast::<ICodecAPI>() {
                let var = crate::encoder::variant_u32_pub(1);
                let _ = api.SetValue(&CODECAPI_AVLowLatencyMode, &var);
            }

            // Input type: H.264 (Annex-B byte stream).
            let in_type = new_media_type()?;
            in_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).ok();
            in_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264).ok();
            // F25: low-latency media-type attribute (docs previously
            // claimed MF_LOW_LATENCY without setting it).
            in_type.SetUINT32(&MF_LOW_LATENCY, 1).ok();
            transform.SetInputType(0, &in_type, 0).map_err(|e| {
                CodecError::FormatNegotiation(format!("decoder SetInputType: {}", e.message()))
            })?;

            // Output type: first NV12 offer (size comes from the stream;
            // renegotiated on MF_E_TRANSFORM_STREAM_CHANGE).
            let out_type = negotiate_output_type(&transform, gpu_output)?;
            let (w, h) = visible_size(&out_type);
            transform.SetOutputType(0, &out_type, 0).map_err(|e| {
                CodecError::FormatNegotiation(format!("decoder SetOutputType: {}", e.message()))
            })?;

            transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .ok();

            Ok(Self {
                device: device.clone(),
                kind: if gpu_output {
                    CodecKind::Hardware
                } else {
                    CodecKind::Software
                },
                name: candidate.name.clone(),
                transform,
                width: w,
                height: h,
                gpu_output,
                time_100ns: 0,
                upload_dst: None,
                owned_ring: Vec::new(),
                owned_next: 0,
                awaiting_idr: false,
            })
        }
    }

    pub fn describe(&self) -> String {
        format!(
            "{} ({}, {}x{}, {})",
            self.name,
            self.kind.as_str(),
            self.width,
            self.height,
            if self.gpu_output { "DXVA" } else { "CPU" }
        )
    }

    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn handle_stream_change(&mut self) -> Result<(), CodecError> {
        let out_type = unsafe { negotiate_output_type(&self.transform, self.gpu_output)? };
        let (w, h) = unsafe { visible_size(&out_type) };
        unsafe {
            self.transform.SetOutputType(0, &out_type, 0).map_err(|e| {
                CodecError::FormatNegotiation(format!("renegotiate SetOutputType: {}", e.message()))
            })?;
        }
        self.width = w;
        self.height = h;
        Ok(())
    }
}

struct Candidate {
    name: String,
    activate: IMFActivate,
}

unsafe fn enumerate_decoders() -> Vec<Candidate> {
    unsafe {
        let mut out = Vec::new();
        for flags in [MFT_ENUM_FLAG_SYNCMFT, MFT_ENUM_FLAG_HARDWARE] {
            let in_info = MFT_REGISTER_TYPE_INFO {
                guidMajorType: MFMediaType_Video,
                guidSubtype: MFVideoFormat_H264,
            };
            let out_info = MFT_REGISTER_TYPE_INFO {
                guidMajorType: MFMediaType_Video,
                guidSubtype: MFVideoFormat_NV12,
            };
            let mut activates: *mut Option<IMFActivate> = std::ptr::null_mut();
            let mut count = 0u32;
            let hr = windows::Win32::Media::MediaFoundation::MFTEnumEx(
                MFT_CATEGORY_VIDEO_DECODER,
                flags,
                Some(&in_info),
                Some(&out_info),
                &mut activates,
                &mut count,
            );
            if hr.is_err() || activates.is_null() {
                continue;
            }
            let slice = std::slice::from_raw_parts(activates, count as usize);
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
                    activate: activate.clone(),
                });
            }
            windows::Win32::System::Com::CoTaskMemFree(Some(activates.cast()));
        }
        out
    }
}

unsafe fn new_media_type()
-> Result<windows::Win32::Media::MediaFoundation::IMFMediaType, CodecError> {
    unsafe {
        windows::Win32::Media::MediaFoundation::MFCreateMediaType()
            .map_err(|e| CodecError::FormatNegotiation(e.message()))
    }
}

/// Visible geometry of an output type: `MF_MT_MINIMUM_DISPLAY_APERTURE`
/// when the decoder reports a crop (DXVA pads surfaces, H.264 signals
/// cropping in the SPS), else `MF_MT_FRAME_SIZE`.
unsafe fn visible_size(mt: &windows::Win32::Media::MediaFoundation::IMFMediaType) -> (u32, u32) {
    unsafe {
        let mut area = [0u8; 16]; // MFVideoArea: 2x MFOffset(4) + SIZE(8)
        if mt
            .GetBlob(&MF_MT_MINIMUM_DISPLAY_APERTURE, &mut area, None)
            .is_ok()
        {
            // Area.cx/ Area.cy are the last two i32s of the struct.
            let cx = i32::from_le_bytes([area[8], area[9], area[10], area[11]]);
            let cy = i32::from_le_bytes([area[12], area[13], area[14], area[15]]);
            if cx > 0 && cy > 0 {
                return (cx as u32, cy as u32);
            }
        }
        let packed = mt.GetUINT64(&MF_MT_FRAME_SIZE).unwrap_or(0);
        ((packed >> 32) as u32, (packed & 0xFFFF_FFFF) as u32)
    }
}

/// Pick the first NV12 output type the decoder offers.
unsafe fn negotiate_output_type(
    transform: &IMFTransform,
    _gpu: bool,
) -> Result<windows::Win32::Media::MediaFoundation::IMFMediaType, CodecError> {
    unsafe {
        for index in 0..64 {
            let Ok(mt) = transform.GetOutputAvailableType(0, index) else {
                break;
            };
            if mt.GetGUID(&MF_MT_SUBTYPE) == Ok(MFVideoFormat_NV12) {
                return Ok(mt);
            }
        }
        Err(CodecError::FormatNegotiation(
            "decoder offers no NV12 output".into(),
        ))
    }
}

impl VideoDecoder for MfDecoder {
    fn kind(&self) -> CodecKind {
        self.kind
    }

    fn decode(
        &mut self,
        packet: &[u8],
        frame_id: u64,
        timestamp_ns: u64,
    ) -> Result<DecodedFrame, CodecError> {
        // F18: after a reset (loss recovery) the reference chain is gone —
        // drop non-IDR access units instead of decoding corruption.
        if self.awaiting_idr {
            if !annex_b_is_keyframe(packet) {
                return Err(CodecError::DroppedAfterReset(format!(
                    "frame {frame_id} is not an IDR"
                )));
            }
            self.awaiting_idr = false;
        }
        unsafe {
            // Input sample from the packet bytes (this copy is the wire
            // boundary — over the network in M2 the same bytes arrive in
            // an RTP payload).
            let sample: IMFSample =
                MFCreateSample().map_err(|e| CodecError::Processing(e.message()))?;
            let buffer: IMFMediaBuffer = MFCreateMemoryBuffer(packet.len() as u32)
                .map_err(|e| CodecError::Processing(e.message()))?;
            let mut ptr = std::ptr::null_mut();
            buffer
                .Lock(&mut ptr, None, Some(&mut { packet.len() as u32 }))
                .map_err(|e| CodecError::Processing(e.message()))?;
            std::ptr::copy_nonoverlapping(packet.as_ptr(), ptr, packet.len());
            buffer.Unlock().ok();
            buffer.SetCurrentLength(packet.len() as u32).ok();
            sample
                .AddBuffer(&buffer)
                .map_err(|e| CodecError::Processing(e.message()))?;
            let t = self.time_100ns;
            self.time_100ns += 166_667;
            sample.SetSampleTime(t).ok();
            sample.SetSampleDuration(166_667).ok();
            self.transform
                .ProcessInput(0, &sample, 0)
                .map_err(|e| CodecError::Processing(e.message()))?;

            // Drain one output; renegotiate on stream change.
            for _ in 0..4 {
                // CPU-output decoders need a caller-allocated sample
                // (DXVA decoders provide their own).
                let provides_samples = self
                    .transform
                    .GetOutputStreamInfo(0)
                    .map(|i| i.dwFlags & (windows::Win32::Media::MediaFoundation::MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32) != 0)
                    .unwrap_or(false);
                let out_sample: Option<IMFSample> = if provides_samples {
                    None
                } else {
                    let size = self
                        .transform
                        .GetOutputStreamInfo(0)
                        .map(|i| i.cbSize)
                        .unwrap_or(
                            (self.width.saturating_mul(self.height).saturating_mul(3) / 2)
                                .max(4096),
                        )
                        .max(1);
                    let buffer: IMFMediaBuffer = MFCreateMemoryBuffer(size)
                        .map_err(|e| CodecError::Processing(e.message().to_string()))?;
                    let sample: IMFSample = MFCreateSample()
                        .map_err(|e| CodecError::Processing(e.message().to_string()))?;
                    sample
                        .AddBuffer(&buffer)
                        .map_err(|e| CodecError::Processing(e.message().to_string()))?;
                    Some(sample)
                };
                let mut buffers = [
                    windows::Win32::Media::MediaFoundation::MFT_OUTPUT_DATA_BUFFER {
                        dwStreamID: 0,
                        pSample: core::mem::ManuallyDrop::new(out_sample),
                        dwStatus: 0,
                        pEvents: core::mem::ManuallyDrop::new(None),
                    },
                ];
                let mut status = 0u32;
                let hr = self
                    .transform
                    .ProcessOutput(0, buffers.as_mut_slice(), &mut status);
                if let Err(e) = hr {
                    let code = e.code();
                    if code == MF_E_TRANSFORM_STREAM_CHANGE {
                        self.handle_stream_change()?;
                        continue;
                    }
                    if code == MF_E_TRANSFORM_NEED_MORE_INPUT {
                        return Err(CodecError::Timeout(
                            "decoder needs more input (expected one-in-one-out)".into(),
                        ));
                    }
                    return Err(CodecError::Processing(format!(
                        "ProcessOutput: {}",
                        code.message()
                    )));
                }
                let Some(out_sample) = core::mem::ManuallyDrop::take(&mut buffers[0].pSample)
                else {
                    continue;
                };
                let is_clean = out_sample
                    .GetUINT32(&MFSampleExtension_CleanPoint)
                    .unwrap_or(0)
                    == 1;
                let _ = is_clean;

                if self.gpu_output {
                    // DXVA: output is a DXGI surface buffer.
                    let contiguous: IMFMediaBuffer = out_sample
                        .ConvertToContiguousBuffer()
                        .map_err(|e| CodecError::Processing(e.message()))?;
                    let dxgi_buf: IMFDXGIBuffer = contiguous.cast().map_err(|e| {
                        CodecError::Processing(format!("no DXGI buffer: {}", e.message()))
                    })?;
                    let mut raw = std::ptr::null_mut();
                    dxgi_buf
                        .GetResource(&<ID3D11Texture2D as Interface>::IID, &mut raw)
                        .map_err(|e| CodecError::Processing(e.message()))?;
                    let texture: ID3D11Texture2D = Interface::from_raw(raw);
                    let subresource = dxgi_buf.GetSubresourceIndex().unwrap_or(0);
                    // Copy out of the decoder's internal pool into a
                    // surface we own — the MFT recycles its buffers on the
                    // next ProcessInput. This is the one documented
                    // GPU->GPU copy on the decode path.
                    let mut desc = Default::default();
                    texture.GetDesc(&mut desc);
                    // DXVA surfaces may be padded; the *visible* geometry
                    // comes from the decoder's output type (set at build
                    // and on every stream change). The owned surface keeps
                    // the padded size; the renderer src-rects to visible.
                    let w = desc.Width.max(self.width);
                    let h = desc.Height.max(self.height);
                    if self.owned_ring.is_empty()
                        || self.owned_ring[0].width() != w
                        || self.owned_ring[0].height() != h
                    {
                        // (Re)build the ring on first use / size change.
                        self.owned_ring.clear();
                        for _ in 0..4 {
                            self.owned_ring.push(
                                FrameSurface::new_private(
                                    &self.device,
                                    w,
                                    h,
                                    frame_surface::SurfaceFormat::Nv12,
                                )
                                .map_err(|e| CodecError::DeviceLost(e.to_string()))?,
                            );
                        }
                        self.owned_next = 0;
                    }
                    let owned = self.owned_ring[self.owned_next].clone();
                    self.owned_next = (self.owned_next + 1) % self.owned_ring.len();
                    if subresource == 0 {
                        self.device
                            .context()
                            .CopyResource(owned.texture(), &texture);
                    } else {
                        // Planar subresource view: copy Y and UV planes.
                        let y_box = windows::Win32::Graphics::Direct3D11::D3D11_BOX {
                            left: 0,
                            top: 0,
                            front: 0,
                            right: desc.Width,
                            bottom: desc.Height,
                            back: 1,
                        };
                        self.device.context().CopySubresourceRegion(
                            owned.texture(),
                            0,
                            0,
                            0,
                            0,
                            &texture,
                            subresource,
                            Some(&y_box),
                        );
                        let uv_box = windows::Win32::Graphics::Direct3D11::D3D11_BOX {
                            left: 0,
                            top: 0,
                            front: 0,
                            right: desc.Width,
                            bottom: desc.Height.div_ceil(2),
                            back: 1,
                        };
                        self.device.context().CopySubresourceRegion(
                            owned.texture(),
                            1,
                            0,
                            0,
                            0,
                            &texture,
                            subresource,
                            Some(&uv_box),
                        );
                    }
                    return Ok(DecodedFrame {
                        frame_id,
                        timestamp_ns,
                        width: self.width,
                        height: self.height,
                        surface: owned.with_frame_id(frame_id),
                    });
                } else {
                    // CPU NV12 output -> upload to the GPU for the
                    // renderer (documented fallback upload, counted in
                    // frame-surface's UPLOAD_COUNT).
                    let contiguous: IMFMediaBuffer = out_sample
                        .ConvertToContiguousBuffer()
                        .map_err(|e| CodecError::Processing(e.message()))?;
                    let mut ptr = std::ptr::null_mut();
                    let mut len = 0u32;
                    contiguous
                        .Lock(&mut ptr, None, Some(&mut len))
                        .map_err(|e| CodecError::Processing(e.message()))?;
                    // Dimensions from the current output type.
                    let (w, h) = (self.width.max(2), self.height.max(2));
                    let expected = (w as usize * h as usize * 3) / 2;
                    if (len as usize) < expected {
                        let _ = contiguous.Unlock();
                        return Err(CodecError::Processing(format!(
                            "short NV12 output: {len} < {expected}"
                        )));
                    }
                    let mut cpu = CpuSurface::nv12_tight(w, h);
                    let stride = w as usize; // decoder pitch == width for
                    // the tight buffer we copy into
                    let pitch = stride; // MF CPU buffers are tightly packed
                    std::ptr::copy_nonoverlapping(
                        ptr,
                        cpu.data.as_mut_ptr(),
                        cpu.data.len().min(len as usize),
                    );
                    let _ = pitch;
                    let _ = contiguous.Unlock();
                    let mut dst = std::mem::take(&mut self.upload_dst);
                    frame_surface::upload_nv12_into(&self.device, &cpu, &mut dst)
                        .map_err(|e| CodecError::Processing(e.to_string()))?;
                    let surface = dst.expect("upload dst");
                    self.upload_dst = Some(surface.clone());
                    return Ok(DecodedFrame {
                        frame_id,
                        timestamp_ns,
                        width: w,
                        height: h,
                        surface: surface.with_frame_id(frame_id),
                    });
                }
            }
            Err(CodecError::Timeout(
                "decoder produced no output after 4 attempts".into(),
            ))
        }
    }

    fn reset(&mut self) -> Result<(), CodecError> {
        // F18: arm the IDR gate — the flushed reference chain cannot
        // decode mid-GOP packets.
        self.awaiting_idr = true;
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0)
                .map_err(|e| CodecError::Processing(e.message()))
        }
    }
}

#[allow(dead_code)]
fn format_is_nv12(fmt: windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT) -> bool {
    fmt == DXGI_FORMAT_NV12
}
