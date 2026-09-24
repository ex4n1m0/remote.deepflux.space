//! H.264 RTP packetization, the `urn:rd:frame-id` header extension, and the
//! 90 kHz RTP clock mapping.
//!
//! Pure data plumbing (no `webrtc` types beyond the `rtc` RTP codecs) so it
//! is unit-testable without a network:
//!
//! * [`packetize_access_unit`] — Annex-B access unit → RTP payloads per
//!   RFC 6184 (single-NAL, STAP-A aggregation, FU-A fragmentation) via the
//!   `rtc` stack's `H264Payloader`.
//! * [`FrameAssembler`] — RTP payloads → Annex-B access unit, reassembling
//!   FU-A fragments and STAP-A aggregates, emitting on the marker bit.
//! * [`FrameIdExt`] — the 64-bit big-endian `urn:rd:frame-id` extension
//!   payload ([`crate::FRAME_ID_EXTENSION_URI`], ADR-002 frame-id carriage).
//!
//! Loss handling: the assembler is fed consecutive packets by the engine,
//! which tracks RTP sequence numbers; when the engine detects a gap inside a
//! frame it aborts the partial assembly (counts it) and waits for the next
//! frame boundary (marker bit) so a mid-frame hole never corrupts a frame.

use bytes::{BufMut, Bytes, BytesMut};
use rtc::rtp::codec::h264::{H264Packet, H264Payloader};
use rtc::rtp::packetizer::{Depacketizer, Payloader};
use rtc::shared::error::Error as RtcError;
use rtc::shared::marshal::{Marshal, MarshalSize};

use crate::TransportError;

/// RTP clock rate for H.264 video (RFC 6184 §5.1).
pub const RTP_CLOCK_HZ: u64 = 90_000;

/// Default maximum RTP payload size before fragmentation (Ethernet-friendly:
/// 1500 MTU − IP/UDP/RTP headers ≈ 1200).
pub const DEFAULT_MTU: usize = 1200;

/// Map a nanosecond capture timestamp onto the 90 kHz RTP clock, rounding
/// to the nearest tick. Wraps at 2^32 / 90000 s ≈ 13.25 h, as RTP
/// timestamps are defined to.
pub fn rtp_timestamp_from_ns(timestamp_ns: u64) -> u32 {
    let seconds = timestamp_ns / 1_000_000_000;
    let sub_ns = timestamp_ns % 1_000_000_000;
    let sub_ticks = (sub_ns * RTP_CLOCK_HZ + 500_000_000) / 1_000_000_000;
    (seconds * RTP_CLOCK_HZ + sub_ticks) as u32
}

/// The `urn:rd:frame-id` extension payload: a 64-bit frame id, big-endian
/// (network byte order, matching RTP header conventions).
///
/// 8 bytes fits the RFC 8285 one-byte header form (payload ≤ 16 bytes), so
/// the per-packet overhead is 1 (extension element header) + 8 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameIdExt {
    pub frame_id: u64,
}

impl MarshalSize for FrameIdExt {
    fn marshal_size(&self) -> usize {
        8
    }
}

impl Marshal for FrameIdExt {
    fn marshal_to(&self, buf: &mut [u8]) -> Result<usize, RtcError> {
        if buf.len() < 8 {
            return Err(RtcError::Other("frame-id buffer too short".into()));
        }
        buf[..8].copy_from_slice(&self.frame_id.to_be_bytes());
        Ok(8)
    }
}

/// Parse an 8-byte big-endian `urn:rd:frame-id` payload.
pub fn parse_frame_id_ext(payload: &[u8]) -> Option<u64> {
    payload.try_into().ok().map(u64::from_be_bytes)
}

/// Split one Annex-B access unit into RTP payloads (RFC 6184).
///
/// A fresh payloader is used per call: the rtc `H264Payloader` caches
/// SPS/PPS it has seen to build STAP-A aggregates, and per-call state keeps
/// a stalled stream from injecting stale parameter sets.
pub fn packetize_access_unit(annexb: &[u8], mtu: usize) -> Result<Vec<Bytes>, TransportError> {
    let mut payloader = H264Payloader::default();
    let input = Bytes::copy_from_slice(annexb);
    payloader
        .payload(mtu, &input)
        .map_err(|e| TransportError(format!("h264 packetization failed: {e}")))
}

/// Reassembles RTP payloads into Annex-B access units.
///
/// Feed [`FrameAssembler::push`] each received payload with its marker bit;
/// a complete access unit is returned exactly on the packet carrying the
/// marker (RFC 6184: the sender sets the marker on the final packet of the
/// access unit, which this crate's packetizer does).
#[derive(Default)]
pub struct FrameAssembler {
    depacketizer: H264Packet,
    buffer: BytesMut,
    started: bool,
}

impl FrameAssembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Push one RTP payload. Returns `Some(access_unit)` when `marker` marks
    /// the end of the frame.
    pub fn push(
        &mut self,
        payload: &[u8],
        marker: bool,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let chunk = self
            .depacketizer
            .depacketize(&Bytes::copy_from_slice(payload))
            .map_err(|e| TransportError(format!("h264 depacketization failed: {e}")))?;
        self.buffer.put(chunk);
        self.started = true;
        if marker {
            let frame = self.buffer.split().to_vec();
            self.started = false;
            Ok(Some(frame))
        } else {
            Ok(None)
        }
    }

    /// Drop a partially assembled frame (called on detected in-frame loss
    /// or frame-boundary timeout). Returns the discarded byte count.
    pub fn abort_partial(&mut self) -> usize {
        let dropped = self.buffer.len();
        self.buffer.clear();
        self.started = false;
        dropped
    }

    pub fn has_partial(&self) -> bool {
        self.started
    }
}

/// Best-effort keyframe detection: an access unit is a keyframe when it
/// contains an IDR slice (NAL type 5) or a sequence parameter set (NAL
/// type 7). Scan Annex-B start codes; tolerate 3- and 4-byte codes.
pub fn is_keyframe_annexb(access_unit: &[u8]) -> bool {
    for (nal_type, _) in nal_units(access_unit) {
        if nal_type == 5 || nal_type == 7 {
            return true;
        }
    }
    false
}

/// Iterate `(nal_type, nal_body_bytes)` over an Annex-B stream, tolerating
/// 3- and 4-byte start codes.
fn nal_units(access_unit: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    // Start positions of each NAL body (just past its start code).
    let mut nal_starts: Vec<usize> = Vec::new();
    let mut i = 0usize;
    while i + 3 < access_unit.len() {
        if access_unit[i] == 0
            && access_unit[i + 1] == 0
            && (access_unit[i + 2] == 1
                || (access_unit[i + 2] == 0 && access_unit.get(i + 3) == Some(&1)))
        {
            let code_len = if access_unit[i + 2] == 1 { 3 } else { 4 };
            nal_starts.push(i + code_len);
            i += code_len;
        } else {
            i += 1;
        }
    }
    let ranges: Vec<(usize, usize)> = nal_starts
        .iter()
        .enumerate()
        .map(|(idx, &start)| {
            let end = nal_starts
                .get(idx + 1)
                .copied()
                .unwrap_or(access_unit.len());
            (start, end)
        })
        .filter(|(s, e)| e > s && *e <= access_unit.len())
        .collect();
    ranges
        .into_iter()
        .map(|(s, e)| (access_unit[s] & 0x1F, &access_unit[s..e]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start_code(nal: &[u8]) -> Vec<u8> {
        let mut v = vec![0, 0, 0, 1];
        v.extend_from_slice(nal);
        v
    }

    /// SPS + PPS + IDR slice + non-IDR slice: a plausible access unit shape.
    fn sample_access_unit() -> Vec<u8> {
        let mut au = Vec::new();
        au.extend_from_slice(&start_code(&[0x67, 0x64, 0x00, 0x1e])); // SPS (type 7)
        au.extend_from_slice(&start_code(&[0x68, 0xeb, 0xec, 0xb2])); // PPS (type 8)
        au.extend_from_slice(&start_code(&[0x65, 0x88, 0x84, 0x00])); // IDR (type 5)
        au
    }

    #[test]
    fn frame_id_ext_marshal_round_trips_big_endian() {
        let ext = FrameIdExt {
            frame_id: 0x0102_0304_0506_0708,
        };
        let mut buf = vec![0u8; ext.marshal_size()];
        assert_eq!(ext.marshal_to(&mut buf).unwrap(), 8);
        assert_eq!(buf, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(parse_frame_id_ext(&buf), Some(0x0102_0304_0506_0708));
        // Malformed lengths never decode as garbage ids.
        assert_eq!(parse_frame_id_ext(&buf[..7]), None);
        assert_eq!(parse_frame_id_ext(&[]), None);
    }

    #[test]
    fn small_access_unit_packetizes_and_reassembles() {
        let au = sample_access_unit();
        // MTU large enough that everything fits without FU-A.
        let payloads = packetize_access_unit(&au, 1200).unwrap();
        assert!(!payloads.is_empty());

        let mut assembler = FrameAssembler::new();
        let mut frames = 0;
        for (i, payload) in payloads.iter().enumerate() {
            let marker = i + 1 == payloads.len();
            if let Some(frame) = assembler.push(payload, marker).unwrap() {
                frames += 1;
                assert!(
                    is_keyframe_annexb(&frame),
                    "SPS+IDR access unit must detect as keyframe"
                );
            }
        }
        assert_eq!(frames, 1, "one access unit in, one frame out");
    }

    #[test]
    fn large_nal_fragments_into_fu_a_and_reassembles() {
        // One IDR-ish NAL far larger than the MTU.
        let mut au = Vec::new();
        let big_nal: Vec<u8> = std::iter::once(0x65u8)
            .chain(std::iter::repeat_n(0xAB, 5000))
            .collect();
        au.extend_from_slice(&start_code(&big_nal));
        let payloads = packetize_access_unit(&au, 1200).unwrap();
        assert!(
            payloads.len() >= 4,
            "5000-byte NAL must FU-A fragment, got {} payloads",
            payloads.len()
        );
        for p in &payloads[..payloads.len() - 1] {
            assert_eq!(p[0] & 0x1F, 28, "FU-A NAL type expected on fragments");
        }

        let mut assembler = FrameAssembler::new();
        let mut out = None;
        for (i, payload) in payloads.iter().enumerate() {
            let marker = i + 1 == payloads.len();
            if let Some(frame) = assembler.push(payload, marker).unwrap() {
                out = Some(frame);
            }
        }
        let frame = out.expect("fragmented NAL must reassemble");
        // 4-byte start code + 1 NAL header + 5000 payload bytes.
        assert_eq!(frame.len(), 4 + 1 + 5000);
        assert!(is_keyframe_annexb(&frame));
    }

    #[test]
    fn rtp_timestamp_math_is_exact_at_common_rates() {
        // 60 fps frame interval = 16.666.. ms → 1500 ticks exactly.
        assert_eq!(rtp_timestamp_from_ns(1_000_000_000 / 60), 1500);
        assert_eq!(rtp_timestamp_from_ns(0), 0);
        assert_eq!(rtp_timestamp_from_ns(1_000_000_000), 90_000);
        // Monotonic across a 1-second step: +90k with no jump.
        let a = rtp_timestamp_from_ns(12_345);
        let b = rtp_timestamp_from_ns(12_345 + 1_000_000_000);
        assert_eq!(b.wrapping_sub(a), 90_000);
    }

    #[test]
    fn abort_partial_drops_incomplete_frame() {
        let au = sample_access_unit();
        let payloads = packetize_access_unit(&au, 1200).unwrap();
        let mut assembler = FrameAssembler::new();
        // Feed all but the last packet, then abort (simulated mid-frame loss).
        for payload in &payloads[..payloads.len() - 1] {
            assert!(assembler.push(payload, false).unwrap().is_none());
        }
        assert!(assembler.has_partial());
        let dropped = assembler.abort_partial();
        assert!(dropped > 0);
        assert!(!assembler.has_partial());
        // The assembler is reusable for the next frame afterwards.
        let next = sample_access_unit();
        let payloads = packetize_access_unit(&next, 1200).unwrap();
        let mut got = None;
        for (i, payload) in payloads.iter().enumerate() {
            let marker = i + 1 == payloads.len();
            if let Some(frame) = assembler.push(payload, marker).unwrap() {
                got = Some(frame);
            }
        }
        assert!(got.is_some(), "assembler must recover after abort");
    }

    #[test]
    fn non_keyframe_access_unit_detected() {
        let mut au = Vec::new();
        au.extend_from_slice(&start_code(&[0x41, 0x9a, 0x02, 0x05])); // non-IDR slice (type 1)
        assert!(!is_keyframe_annexb(&au));
    }

    #[test]
    fn three_byte_start_codes_are_recognized() {
        let mut au = vec![0, 0, 1, 0x67, 0x01];
        au.extend_from_slice(&[0, 0, 1, 0x41, 0x02]);
        assert!(
            is_keyframe_annexb(&au),
            "SPS behind a 3-byte start code must count"
        );
    }
}
