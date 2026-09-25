//! Quality presets (RD-012): controller-picked `QualityPreset` (wire enum)
//! mapped onto the host encoder/pacer configuration. The mapping is a
//! product decision; the wire enum is the contract (`crates/protocol`).
//!
//! M5: `Auto` is no longer an alias for `Balanced`. Manual presets pin
//! their targets and rebuild the encode stage once (geometry changes); the
//! rebuild leak is bounded by user action (F56/CR-1). `Auto` starts from
//! the Balanced geometry but hands the *bitrate/fps* to the host's
//! congestion controller (`node_runtime::congestion` over the transport's
//! GCC estimate), which retargets the encoder LIVE via
//! `VideoEncoder::reconfigure` (no MFT rebuild on this machine's encoders)
//! and the pacer via `FramePacer::retarget`; only sustained starvation
//! (<800 kbps for 10 s) steps the resolution down, once, through the
//! rebuild path.

use codec_windows::{MfEncoderConfig, MfEncoderPreference};
use protocol::wire::QualityPreset;

/// Everything a preset controls on the host pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualityPlan {
    pub preset: QualityPreset,
    pub fps: u32,
    pub bitrate_kbps: u32,
    pub encode_width: u32,
    pub encode_height: u32,
}

/// The preset table. `Auto` keeps the Balanced geometry as its starting
/// point; the congestion controller owns the runtime bitrate/fps targets
/// (see module docs and `engine::drive_congestion`).
pub fn plan_for(preset: QualityPreset) -> QualityPlan {
    let (fps, bitrate_kbps, w, h) = match preset {
        QualityPreset::Auto | QualityPreset::Balanced => (60, 6_000, 1920, 1080),
        QualityPreset::Low => (30, 2_000, 1280, 720),
        QualityPreset::High => (60, 12_000, 2560, 1440),
    };
    QualityPlan {
        preset,
        fps,
        bitrate_kbps,
        encode_width: w,
        encode_height: h,
    }
}

impl QualityPlan {
    pub fn encoder_config(&self) -> MfEncoderConfig {
        MfEncoderConfig {
            width: self.encode_width & !1,
            height: self.encode_height & !1,
            fps: self.fps,
            bitrate_bps: self.bitrate_kbps.saturating_mul(1000),
            gop_size: self.fps * 2,
            preference: MfEncoderPreference::Auto,
        }
    }
}

/// Wire name of a preset (serde tag, snake_case — pinned by `crates/protocol`).
pub fn preset_name(preset: QualityPreset) -> &'static str {
    match preset {
        QualityPreset::Auto => "auto",
        QualityPreset::Low => "low",
        QualityPreset::Balanced => "balanced",
        QualityPreset::High => "high",
    }
}

/// Parse the UI/wire name back (typed failure, never garbage).
pub fn preset_from_name(name: &str) -> Option<QualityPreset> {
    match name {
        "auto" => Some(QualityPreset::Auto),
        "low" => Some(QualityPreset::Low),
        "balanced" => Some(QualityPreset::Balanced),
        "high" => Some(QualityPreset::High),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_names_round_trip() {
        for preset in [
            QualityPreset::Auto,
            QualityPreset::Low,
            QualityPreset::Balanced,
            QualityPreset::High,
        ] {
            assert_eq!(preset_from_name(preset_name(preset)), Some(preset));
        }
        assert_eq!(preset_from_name("ultra"), None);
    }

    #[test]
    fn plan_dimensions_are_even_and_bitrate_sane() {
        for preset in [
            QualityPreset::Auto,
            QualityPreset::Low,
            QualityPreset::Balanced,
            QualityPreset::High,
        ] {
            let plan = plan_for(preset);
            let cfg = plan.encoder_config();
            assert_eq!(cfg.width % 2, 0);
            assert_eq!(cfg.height % 2, 0);
            assert!(cfg.bitrate_bps >= 2_000_000, "bitrate too low");
            assert!(cfg.gop_size >= 30);
        }
        let low = plan_for(QualityPreset::Low);
        let high = plan_for(QualityPreset::High);
        assert!(low.bitrate_kbps < high.bitrate_kbps);
        assert!(low.encode_width < high.encode_width);
    }
}
