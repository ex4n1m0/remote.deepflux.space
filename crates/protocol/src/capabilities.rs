//! Capability negotiation payloads.
//!
//! Carried in JSON inside [`crate::signaling::SignalingBody::Register`] /
//! [`crate::signaling::SignalingBody::ConnectRequest`] (what each device
//! advertises on the control plane) and in binary inside
//! [`crate::wire::WireMessage::Hello`] / [`crate::wire::WireMessage::HelloAck`]
//! (re-negotiated over the direct `control` data channel when the session
//! opens). The same struct serves both surfaces, so both encodings must keep
//! round-tripping — see the tests at the bottom of this file.

use serde::{Deserialize, Serialize};

/// Codec identifiers. H.264 is the MVP codec; the enum exists so a later
/// addition (e.g. AV1) is an explicit wire change, not a silent reinterpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Codec {
    H264,
}

/// One encoder the reporting device can offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncoderCapabilities {
    pub kind: EncoderKind,
    pub codec: Codec,
    pub max_width_px: u32,
    pub max_height_px: u32,
    pub max_fps: u32,
}

/// Hardware (GPU) or software (Media Foundation software fallback, delta D3)
/// encoder. A device lists at most one of each; hardware is preferred when
/// present and functional.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncoderKind {
    Hardware,
    Software,
}

/// One display attached to the reporting device, as enumerated at
/// registration time. `monitor_id` is a stable local identifier used by
/// [`crate::wire::WireMessage::SelectMonitor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorInfo {
    pub monitor_id: String,
    pub width_px: u32,
    pub height_px: u32,
    pub is_primary: bool,
}

/// Everything a device advertises about itself during negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Hardware encoder first when available; the software fallback
    /// (delta D3) is a first-class entry, not an afterthought.
    pub encoders: Vec<EncoderCapabilities>,
    pub monitors: Vec<MonitorInfo>,
    pub max_bitrate_kbps: u32,
    pub features: FeatureFlags,
}

/// Bitmask of protocol features. Named constants instead of a dependency:
/// values are a wire contract and must never be renumbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FeatureFlags(pub u32);

impl FeatureFlags {
    /// Trickle ICE forwarding is supported (source plan signaling list).
    pub const TRICKLE_ICE: u32 = 1 << 0;
    /// Dedicated `cursor` data channel (latest-state oriented).
    pub const CURSOR_CHANNEL: u32 = 1 << 1;
    /// Separate unordered low-latency mouse channel (`input-fast`).
    pub const INPUT_FAST_CHANNEL: u32 = 1 << 2;
    /// Hardware H.264 encode/decode path available on this device.
    pub const H264_HARDWARE: u32 = 1 << 3;

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn with(mut self, flag: u32) -> Self {
        self.0 |= flag;
        self
    }

    pub const fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }
}

/// Shared test fixture: a realistic dual-encoder, dual-monitor device.
/// Available to sibling test modules within this crate only.
#[cfg(test)]
pub(crate) fn capabilities_sample() -> Capabilities {
    Capabilities {
        encoders: vec![
            EncoderCapabilities {
                kind: EncoderKind::Hardware,
                codec: Codec::H264,
                max_width_px: 3840,
                max_height_px: 2160,
                max_fps: 60,
            },
            EncoderCapabilities {
                kind: EncoderKind::Software,
                codec: Codec::H264,
                max_width_px: 1920,
                max_height_px: 1080,
                max_fps: 30,
            },
        ],
        monitors: vec![
            MonitorInfo {
                monitor_id: "\\\\.\\DISPLAY1".to_owned(),
                width_px: 2560,
                height_px: 1440,
                is_primary: true,
            },
            MonitorInfo {
                monitor_id: "\\\\.\\DISPLAY2".to_owned(),
                width_px: 1920,
                height_px: 1080,
                is_primary: false,
            },
        ],
        max_bitrate_kbps: 20_000,
        features: FeatureFlags::empty()
            .with(FeatureFlags::TRICKLE_ICE)
            .with(FeatureFlags::CURSOR_CHANNEL)
            .with(FeatureFlags::INPUT_FAST_CHANNEL)
            .with(FeatureFlags::H264_HARDWARE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> Capabilities {
        capabilities_sample()
    }

    #[test]
    fn feature_flags_are_a_set() {
        let f = FeatureFlags::empty().with(FeatureFlags::TRICKLE_ICE);
        assert!(f.has(FeatureFlags::TRICKLE_ICE));
        assert!(!f.has(FeatureFlags::CURSOR_CHANNEL));
        assert_eq!(f, FeatureFlags(1));
    }

    #[test]
    fn capabilities_json_field_names_are_stable_snake_case() {
        let value = serde_json::to_value(sample()).expect("serialize");
        assert_eq!(value["encoders"][0]["kind"], "Hardware");
        assert_eq!(value["encoders"][0]["codec"], "H264");
        assert_eq!(value["encoders"][0]["max_width_px"], 3840);
        assert_eq!(value["encoders"][0]["max_height_px"], 2160);
        assert_eq!(value["encoders"][0]["max_fps"], 60);
        assert_eq!(value["monitors"][0]["monitor_id"], "\\\\.\\DISPLAY1");
        assert_eq!(value["monitors"][0]["width_px"], 2560);
        assert_eq!(value["monitors"][0]["height_px"], 1440);
        assert_eq!(value["monitors"][0]["is_primary"], true);
        assert_eq!(value["max_bitrate_kbps"], 20_000);
        assert_eq!(value["features"], 15);
    }

    #[test]
    fn capabilities_round_trips_through_json() {
        let json = serde_json::to_string(&sample()).expect("serialize");
        let back: Capabilities = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, sample());
    }
}
