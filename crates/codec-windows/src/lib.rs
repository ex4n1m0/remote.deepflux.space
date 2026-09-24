//! # `codec-windows` — Media Foundation H.264 encode/decode (M1)
//!
//! Platform boundary for the codec (invariant 7). M1 (RD-005) implements:
//! hardware-first encoder selection with the Media Foundation **software**
//! encoder as a first-class fallback (delta D3), low-delay settings (no
//! B-frames, short GOP, one-slice-per-frame), immediate keyframe on request,
//! and the DXVA decode path with `AVLowLatencyMode`.
//!
//! The M0 signatures below pin the shape the session/transport layers code
//! against; M1 refines the handoff types but must keep frames on the GPU
//! wherever the APIs permit and must report encode/decode stage timestamps
//! through [`PerfSink`](diagnostics::PerfSink).

use diagnostics::PerfSink;

/// Encoder/decoder selection, mirrors `protocol::capabilities::EncoderKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecKind {
    Hardware,
    Software,
}

/// M0 placeholder for the encoder input handoff. M1 replaces the payload
/// with the GPU texture handle shared with `capture-windows` (zero-copy when
/// possible; the frame-handoff type decision is tracked in ADR-001 open
/// questions).
#[derive(Debug)]
pub struct EncodeInput {
    pub timestamp_ns: u64,
    pub width_px: u32,
    pub height_px: u32,
    /// Opaque M1: GPU texture handle.
    pub opaque: (),
}

/// One encoded access unit (a full frame's worth of NAL units). No start-code
/// stuffing here — packetization belongs to the transport.
#[derive(Debug)]
pub struct EncodedPacket {
    pub timestamp_ns: u64,
    pub is_keyframe: bool,
    pub bytes: Vec<u8>,
}

/// M0 placeholder for the decode output handoff (GPU texture in M1).
#[derive(Debug)]
pub struct DecodedFrame {
    pub timestamp_ns: u64,
    pub width_px: u32,
    pub height_px: u32,
    /// Opaque M1: decoded GPU texture handle.
    pub opaque: (),
}

#[derive(Debug)]
pub struct CodecError(pub String);

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "codec failed: {}", self.0)
    }
}

impl std::error::Error for CodecError {}

/// Low-latency H.264 encoder boundary.
///
/// Backpressure rule (invariant 3): if a new input arrives while the previous
/// encode is still running, the encoder drops the queued input and encodes
/// the newest frame; it never queues depth > 1.
pub trait VideoEncoder: Send {
    /// Which implementation is active (reported in diagnostics and
    /// capabilities).
    fn kind(&self) -> CodecKind;

    /// Encode one frame. `force_keyframe` covers loss recovery and monitor
    /// switches (`WireMessage::KeyframeRequest`).
    fn encode(
        &mut self,
        input: EncodeInput,
        force_keyframe: bool,
    ) -> Result<EncodedPacket, CodecError>;

    fn set_perf_sink(&mut self, _sink: Box<dyn PerfSink>) {}
}

/// Low-latency H.264 decoder boundary. Output order is decode order; the
/// renderer pairs frames with cursor state by timestamp/sequence.
pub trait VideoDecoder: Send {
    fn kind(&self) -> CodecKind;

    fn decode(&mut self, packet: &[u8]) -> Result<DecodedFrame, CodecError>;

    /// Flush after a keyframe request / loss event.
    fn reset(&mut self) -> Result<(), CodecError>;

    fn set_perf_sink(&mut self, _sink: Box<dyn PerfSink>) {}
}
