//! # `codec-windows` — Media Foundation H.264 encode/decode (M1, RD-005)
//!
//! Platform boundary for the codec (invariant 7). M1 implements:
//!
//! * **Hardware-first encoder selection via MFT enumeration** with the
//!   Media Foundation **software** encoder as a first-class fallback
//!   (delta D3): `MftEncoderPreference::Hardware` enumerates
//!   `MFT_ENUM_FLAG_HARDWARE` (async) MFTs whose adapter matches the
//!   shared device, drives them through the asynchronous event protocol
//!   (`METransformNeedInput`/`METransformHaveOutput` on a pump thread);
//!   `Software` uses the inbox sync encoder. `Auto` tries hardware first.
//!   The chosen path and MFT friendly name are reported through
//!   [`MfEncoder::describe`].
//! * **Low-delay settings**: no B-frames
//!   (`CODECAPI_AVEncMPVDefaultBPictureCount = 0`), short GOP (default
//!   `fps * 2`), `CODECAPI_AVLowLatencyMode` + `MF_LOW_LATENCY`,
//!   CBR rate control with a settable target
//!   ([`VideoEncoder::set_bitrate`]).
//! * **On-demand keyframe**: `force_keyframe` on [`VideoEncoder::encode`]
//!   maps to `CODECAPI_AVEncVideoForceKeyFrame` — the same request M2's
//!   `WireMessage::KeyframeRequest` will drive.
//! * **Decoder**: inbox H.264 decoder with a D3D11 device manager
//!   (DXVA-backed GPU output, `CodecKind::Hardware`) or CPU NV12 output
//!   (`CodecKind::Software`), `CODECAPI_AVLowLatencyMode` for
//!   no-reorder delivery, `MFT_MESSAGE_COMMAND_FLUSH` based [`VideoDecoder::reset`].
//! * **GPU color conversion** (`Nv12Converter`): BGRA capture surface ->
//!   scaled NV12 encode input via `ID3D11VideoProcessor` — one GPU pass,
//!   no CPU pixels.
//!
//! ## M0 -> M1 type deltas (documented)
//!
//! * `EncodeInput`/`DecodedFrame` carry the real GPU handoff
//!   (`frame_surface::FrameSurface`) plus `frame_id` (diagnostics join
//!   key) instead of the M0 `opaque: ()`.
//! * `EncodedPacket` carries `frame_id` and an `is_keyframe` flag parsed
//!   from the Annex-B NAL types (plus the MF clean-point attribute when
//!   present).
//! * `CodecError` is a structured enum (device loss distinguished from
//!   negotiation failures) instead of a bare string.

use diagnostics::PerfSink;
pub use frame_surface::FrameSurface;

mod annexb;
mod convert;
mod decoder;
mod encoder;
mod reconfig;

pub use annexb::{annex_b_is_keyframe, annex_b_nal_types};
pub use convert::Nv12Converter;
pub use decoder::{MfDecoder, MfDecoderConfig};
pub use encoder::{
    MfEncoder, MfEncoderConfig, MfEncoderPreference, describe_encoder_candidates,
    probe_reconfig_capabilities,
};
pub use reconfig::{
    CapProbe, CodecApiProbe, ParamRange, ReconfigCaps, ReconfigPlan, plan_reconfigure, probe_caps,
};

/// Encoder/decoder implementation in use — reported in diagnostics and
/// capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecKind {
    Hardware,
    Software,
}

impl CodecKind {
    pub fn as_str(self) -> &'static str {
        match self {
            CodecKind::Hardware => "hardware",
            CodecKind::Software => "software",
        }
    }
}

/// Encoder input: one captured frame, GPU-resident.
#[derive(Debug)]
pub struct EncodeInput {
    pub frame_id: u64,
    pub timestamp_ns: u64,
    pub surface: FrameSurface,
}

/// One encoded access unit (all NAL units of one frame), Annex-B byte
/// stream with start codes. Packetization belongs to M2's transport.
#[derive(Debug)]
pub struct EncodedPacket {
    pub frame_id: u64,
    pub timestamp_ns: u64,
    pub is_keyframe: bool,
    pub bytes: Vec<u8>,
}

/// Decoder output: one decoded frame, GPU-resident when the decode path
/// has a D3D11 device manager (DXVA), CPU-uploaded otherwise.
#[derive(Debug)]
pub struct DecodedFrame {
    pub frame_id: u64,
    pub timestamp_ns: u64,
    pub width: u32,
    pub height: u32,
    pub surface: FrameSurface,
}

/// Typed codec failure.
#[derive(Debug)]
pub enum CodecError {
    /// D3D device removed — recreate the device and every MFT on it.
    DeviceLost(String),
    /// No acceptable MFT / media type combination exists (selection or
    /// negotiation failed).
    FormatNegotiation(String),
    /// The transform did not produce/accept a frame within the bounded
    /// wait (encoder starved of NeedInput, or no output ready). Callers
    /// treat this frame as dropped — queue counters must show it.
    Timeout(String),
    /// The transform reported a failure while processing.
    Processing(String),
    /// The packet was dropped by the IDR-after-reset gate: `reset()` was
    /// called (loss recovery) and this access unit is not a keyframe, so
    /// decoding it would reference a broken reference chain. Feed packets
    /// until the next IDR (M2 forces one via `KeyframeRequest`).
    DroppedAfterReset(String),
    /// MF runtime not started (`MfRuntime` guard missing).
    NotReady(String),
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CodecError::DeviceLost(d) => write!(f, "codec device lost: {d}"),
            CodecError::FormatNegotiation(d) => write!(f, "codec format negotiation failed: {d}"),
            CodecError::Timeout(d) => write!(f, "codec bounded wait expired: {d}"),
            CodecError::Processing(d) => write!(f, "codec processing failed: {d}"),
            CodecError::DroppedAfterReset(d) => {
                write!(f, "packet dropped awaiting IDR after reset: {d}")
            }
            CodecError::NotReady(d) => write!(f, "codec not initialized: {d}"),
        }
    }
}

impl std::error::Error for CodecError {}

/// RAII guard for `MFStartup`/`MFShutdown`. The process (node runtime)
/// creates exactly one before constructing any MFT; MFT creation without
/// it fails with `MF_E_NOT_INITIALIZED`.
pub struct MfRuntime {
    _private: (),
}

impl MfRuntime {
    pub fn new() -> Result<Self, CodecError> {
        unsafe {
            windows::Win32::Media::MediaFoundation::MFStartup(
                windows::Win32::Media::MediaFoundation::MF_VERSION,
                windows::Win32::Media::MediaFoundation::MFSTARTUP_NOSOCKET,
            )
            .map_err(|e| CodecError::NotReady(format!("MFStartup: {}", e.message())))
        }?;
        Ok(Self { _private: () })
    }
}

impl Drop for MfRuntime {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Media::MediaFoundation::MFShutdown();
        }
    }
}

/// Runtime encoder parameters for [`VideoEncoder::reconfigure`] (M4 QA
/// F56 / CR-1). Any field left `None` keeps its current value. Changing
/// fields the active implementation cannot set live falls back to a
/// rebuild — see [`ReconfigureOutcome`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EncoderParams {
    pub bitrate_bps: Option<u32>,
    pub fps: Option<u32>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub gop_size: Option<u32>,
}

/// How a [`VideoEncoder::reconfigure`] call was carried out — the rig and
/// report distinguish leak-free live changes from rebuilds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconfigureOutcome {
    /// Properties applied on the existing transform via `ICodecAPI`; a
    /// keyframe is forced on the next encode. `clamped` names fields
    /// whose requested value was outside the probed range.
    Live { clamped: Vec<&'static str> },
    /// A new transform was constructed (geometry/fps change or an
    /// unsupported property). The encoder object is still usable; the
    /// rebuild cost was paid once.
    Rebuilt { reason: String },
    /// Nothing to change.
    Noop,
}

/// Low-latency H.264 encoder boundary.
///
/// Backpressure rule (invariant 3): `encode` is synchronous one-in-one-out
/// under the low-latency configuration; it never queues more than one
/// input — if the caller is behind, it is the caller's bounded queue that
/// drops the obsolete frame, not the encoder.
pub trait VideoEncoder: Send {
    /// Which implementation is active (reported in diagnostics and
    /// capabilities).
    fn kind(&self) -> CodecKind;

    /// Encode one frame. `force_keyframe` covers loss recovery and monitor
    /// switches (`WireMessage::KeyframeRequest` arrives over the wire in
    /// M2; this is the API it will drive).
    fn encode(
        &mut self,
        input: EncodeInput,
        force_keyframe: bool,
    ) -> Result<EncodedPacket, CodecError>;

    /// Retarget the CBR bitrate (quality presets, congestion response).
    /// Best-effort: reports an error if the active MFT refuses the change.
    /// Default routes through [`VideoEncoder::reconfigure`] semantics
    /// where implemented.
    fn set_bitrate(&mut self, _bps: u32) -> Result<(), CodecError> {
        Ok(())
    }

    /// Apply runtime parameter changes without returning the encoder to
    /// the caller's rebuild path (M4 QA F56/CR-1: each MFT rebuild leaks
    /// ~14 MiB working set / ~28 MiB private commit). Implementations
    /// that support live `ICodecAPI` reconfiguration apply bitrate/GOP
    /// in place and force a keyframe on the next encode; changes that
    /// genuinely need a new media type (resolution, fps) rebuild the
    /// transform internally and report [`ReconfigureOutcome::Rebuilt`].
    ///
    /// The default signals "not implemented": callers keep their existing
    /// behavior of constructing a replacement encoder (the pre-CR-1
    /// status quo), so no implementor breaks.
    fn reconfigure(&mut self, _params: &EncoderParams) -> Result<ReconfigureOutcome, CodecError> {
        Err(CodecError::Processing(
            "reconfigure not implemented for this encoder; rebuild required".into(),
        ))
    }

    fn set_perf_sink(&mut self, _sink: Box<dyn PerfSink>) {}
}

/// Low-latency H.264 decoder boundary. Output order is decode order; the
/// renderer pairs frames with cursor state by timestamp/sequence.
pub trait VideoDecoder: Send {
    fn kind(&self) -> CodecKind;

    /// Decode one access unit into one frame. `frame_id`/`timestamp_ns`
    /// are the join keys carried from the host half (in M1 by the local
    /// loop; over the wire in M2 by the RTP header extension, ADR-002).
    fn decode(
        &mut self,
        packet: &[u8],
        frame_id: u64,
        timestamp_ns: u64,
    ) -> Result<DecodedFrame, CodecError>;

    /// Flush after a keyframe request / loss event. The next packets fed
    /// are gated on IDR: non-keyframe access units are dropped with
    /// [`CodecError::DroppedAfterReset`] until the next IDR arrives
    /// (F18 — decoding mid-GOP after a flush would reference a broken
    /// chain and corrupt the picture).
    fn reset(&mut self) -> Result<(), CodecError>;

    fn set_perf_sink(&mut self, _sink: Box<dyn PerfSink>) {}
}
