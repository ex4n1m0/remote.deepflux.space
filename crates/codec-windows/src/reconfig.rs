//! Live-reconfiguration support (M4 QA F56 / CR-1).
//!
//! Quality-preset changes used to rebuild the encoder MFT, which leaks
//! (measured: +13.9 MiB working set / +28.1 MiB private commit / +1
//! thread / +34 handles per rebuild, linear). This module owns the
//! decision of which parameters can be applied **live** through
//! `ICodecAPI` on the existing MFT versus which require a rebuild, plus
//! the capability probing that answers that per encoder.
//!
//! The probing logic is pure over a narrow seam ([`CapProbe`]) so tests
//! can feed canned capability matrices without a GPU; the real
//! implementation ([`CodecApiProbe`]) wraps the two `ICodecAPI` queries
//! (`IsSupported`, `GetParameterRange`).
//!
//! Policy (explicit, per the work package):
//!
//! * **Live** — bitrate and GOP size, when the active MFT reports the
//!   `ICodecAPI` property as supported. Applied via `SetValue` on the
//!   existing transform; a keyframe is forced on the next encode
//!   (parameter changes mid-stream must not reference stale rate state).
//! * **Rebuild** — resolution and frame rate. No standard
//!   video-encoder `ICodecAPI` property exists for geometry; both live
//!   on the media type, and mid-stream media-type changes on these MFTs
//!   are renegotiations in disguise. The encoder rebuilds internally
//!   (paying the leak once — the caller-visible object survives) and
//!   counts it in `encoder_rebuilds`.

use windows::Win32::Media::MediaFoundation::{
    CODECAPI_AVEncCommonBufferSize, CODECAPI_AVEncCommonMeanBitRate, CODECAPI_AVEncMPVGOPSize,
    ICodecAPI,
};
use windows::Win32::System::Variant::{
    VARIANT, VT_I4, VT_I8, VT_UI4, VT_UI8, VariantClear, VariantInit,
};
use windows::core::GUID;

use crate::EncoderParams;

/// A live-settable property's knowledge: support is authoritative, the
/// range is optional (several MFTs implement `SetValue` +
/// `IsSupported`/`IsModifiable` but not `GetParameterRange` — NVENC
/// among them, measured). An unreported range disables clamping only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamRange {
    pub min: u64,
    pub max: u64,
    /// False when `GetParameterRange` did not answer: values pass
    /// through unclamped.
    pub authoritative: bool,
}

impl ParamRange {
    fn unbounded() -> Self {
        Self {
            min: 0,
            max: u64::MAX,
            authoritative: false,
        }
    }

    fn contains(&self, v: u64) -> u64 {
        if !self.authoritative || (v >= self.min && v <= self.max) {
            v
        } else {
            v.clamp(self.min, self.max)
        }
    }
}

/// What the active encoder can do with each reconfigurable field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconfigCaps {
    /// Live-settable CBR bitrate (range optional).
    pub bitrate: Option<ParamRange>,
    /// Live-settable GOP length (range optional).
    pub gop_size: Option<ParamRange>,
}

impl ReconfigCaps {
    /// Human-readable one-liner for the capability matrix in reports.
    pub fn describe(&self) -> String {
        let f = |o: &Option<ParamRange>| {
            o.map(|r| {
                if r.authoritative {
                    format!("live {}..{}", r.min, r.max)
                } else {
                    "live (range unreported)".to_string()
                }
            })
            .unwrap_or_else(|| "rebuild".to_string())
        };
        format!("bitrate: {}, gop: {}", f(&self.bitrate), f(&self.gop_size))
    }
}

/// Narrow seam over the `ICodecAPI` queries the probe uses — the policy
/// functions below are pure over this, so tests inject canned matrices.
pub trait CapProbe {
    /// `ICodecAPI::IsSupported`.
    fn is_supported(&mut self, prop: &GUID) -> bool;
    /// `ICodecAPI::GetParameterRange` as `(min, max)`, `None` on failure
    /// or an unreadable variant type.
    fn parameter_range(&mut self, prop: &GUID) -> Option<(u64, u64)>;
}

/// The real seam implementation over the transform's `ICodecAPI`. All
/// calls happen on whichever thread owns the MFT (caller thread for the
/// sync backend, the worker thread for the async backend).
pub struct CodecApiProbe<'a> {
    api: &'a ICodecAPI,
}

impl<'a> CodecApiProbe<'a> {
    pub fn new(api: &'a ICodecAPI) -> Self {
        Self { api }
    }
}

impl CapProbe for CodecApiProbe<'_> {
    fn is_supported(&mut self, prop: &GUID) -> bool {
        unsafe {
            let sup = self.api.IsSupported(prop);
            let modifiable = self.api.IsModifiable(prop);
            if std::env::var_os("CODEC_DEBUG_CAPS").is_some() {
                eprintln!(
                    "  caps query: IsSupported hr=0x{:08x} IsModifiable hr=0x{:08x}",
                    sup.clone().err().map(|e| e.code().0 as u32).unwrap_or(0),
                    modifiable.0 as u32,
                );
            }
            // IsSupported is unimplemented on several encoder MFTs
            // (returns an error even for properties SetValue accepts);
            // IsModifiable is the documented runtime-mutability query.
            sup.is_ok() || modifiable.0 == 0
        }
    }

    fn parameter_range(&mut self, prop: &GUID) -> Option<(u64, u64)> {
        unsafe {
            let mut vmin = VariantInit();
            let mut vmax = VariantInit();
            let mut vstep = VariantInit();
            let ok = self
                .api
                .GetParameterRange(prop, &mut vmin, &mut vmax, &mut vstep);
            let out = if ok.is_ok() {
                match (variant_to_u64(&vmin), variant_to_u64(&vmax)) {
                    (Some(lo), Some(hi)) if hi >= lo => Some((lo, hi)),
                    _ => None,
                }
            } else {
                None
            };
            let _ = VariantClear(&mut vmin);
            let _ = VariantClear(&mut vmax);
            let _ = VariantClear(&mut vstep);
            out
        }
    }
}

/// Read a numeric VARIANT via its stable C layout (2-byte vt + 6 reserved
/// bytes + 8-byte union). Only integer types are accepted — the encoder
/// rate-control properties are VT_UI4/VT_UI8.
unsafe fn variant_to_u64(var: &VARIANT) -> Option<u64> {
    unsafe {
        let p = std::ptr::from_ref(var) as *const u8;
        let vt = (p as *const u16).read();
        let union = p.add(8).cast::<u64>().read();
        if vt == VT_UI4.0 || vt == VT_I4.0 {
            Some(union & 0xFFFF_FFFF)
        } else if vt == VT_UI8.0 || vt == VT_I8.0 {
            Some(union)
        } else {
            None
        }
    }
}

/// Probe the live-reconfig capability matrix. Support comes from
/// `IsSupported`/`IsModifiable`; the range from `GetParameterRange` when
/// the MFT implements it (optional — see [`ParamRange`]).
pub fn probe_caps(probe: &mut dyn CapProbe) -> ReconfigCaps {
    let probe_field = |probe: &mut dyn CapProbe, prop: &GUID| {
        if !probe.is_supported(prop) {
            return None;
        }
        Some(match probe.parameter_range(prop) {
            Some((min, max)) => ParamRange {
                min,
                max,
                authoritative: true,
            },
            None => ParamRange::unbounded(),
        })
    };
    let bitrate = probe_field(probe, &CODECAPI_AVEncCommonMeanBitRate);
    let gop_size = probe_field(probe, &CODECAPI_AVEncMPVGOPSize);
    ReconfigCaps { bitrate, gop_size }
}

/// How a [`crate::EncoderParams`] application was carried out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconfigPlan {
    /// Apply these `(property, value)` pairs live on the existing MFT and
    /// force a keyframe on the next encode. `clamped` lists fields whose
    /// requested value was outside the probed range and got clamped.
    Live {
        props: Vec<(GUID, u64)>,
        clamped: Vec<&'static str>,
    },
    /// The params include a field with no live path (resolution, fps, or
    /// an unsupported property): rebuild the transform.
    Rebuild { reason: String },
}

/// Decide live-vs-rebuild for `params` given `caps` and the current
/// geometry. Pure; unit-tested with canned matrices.
pub fn plan_reconfigure(
    params: &EncoderParams,
    caps: &ReconfigCaps,
    current_width: u32,
    current_height: u32,
    current_fps: u32,
) -> ReconfigPlan {
    // Geometry and frame rate are media-type state: no live path.
    if let Some(w) = params.width
        && w != current_width
    {
        return ReconfigPlan::Rebuild {
            reason: format!("width {current_width} -> {w} is a media-type change"),
        };
    }
    if let Some(h) = params.height
        && h != current_height
    {
        return ReconfigPlan::Rebuild {
            reason: format!("height {current_height} -> {h} is a media-type change"),
        };
    }
    if let Some(fps) = params.fps
        && fps != current_fps
    {
        return ReconfigPlan::Rebuild {
            reason: format!("fps {current_fps} -> {fps} is a media-type change"),
        };
    }

    let mut props = Vec::new();
    let mut clamped = Vec::new();
    if let Some(bitrate) = params.bitrate_bps {
        match caps.bitrate {
            Some(range) => {
                let raw = bitrate as u64;
                let value = range.contains(raw);
                if value != raw {
                    clamped.push("bitrate_bps");
                }
                props.push((CODECAPI_AVEncCommonMeanBitRate, value));
                // Keep the rate-control window one frame wide when the
                // bitrate moves (the build-time pairing); best-effort.
                props.push((CODECAPI_AVEncCommonBufferSize, value));
            }
            None => {
                return ReconfigPlan::Rebuild {
                    reason: "bitrate property not supported for live set".into(),
                };
            }
        }
    }
    if let Some(gop) = params.gop_size {
        match caps.gop_size {
            Some(range) => {
                let raw = gop as u64;
                let value = range.contains(raw);
                if value != raw {
                    clamped.push("gop_size");
                }
                props.push((CODECAPI_AVEncMPVGOPSize, value));
            }
            None => {
                return ReconfigPlan::Rebuild {
                    reason: "gop property not supported for live set".into(),
                };
            }
        }
    }
    if props.is_empty() {
        // Nothing to change — nothing to do, and no IDR needed.
        return ReconfigPlan::Live { props, clamped };
    }
    ReconfigPlan::Live { props, clamped }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EncoderParams;

    /// Canned capability matrix for the pure policy tests.
    struct FakeProbe {
        bitrate: Option<(u64, u64)>,
        gop: Option<(u64, u64)>,
        queried: Vec<GUID>,
    }

    impl CapProbe for FakeProbe {
        fn is_supported(&mut self, prop: &GUID) -> bool {
            self.queried.push(*prop);
            *prop == CODECAPI_AVEncCommonMeanBitRate && self.bitrate.is_some()
                || *prop == CODECAPI_AVEncMPVGOPSize && self.gop.is_some()
        }

        fn parameter_range(&mut self, prop: &GUID) -> Option<(u64, u64)> {
            if *prop == CODECAPI_AVEncCommonMeanBitRate {
                self.bitrate
            } else if *prop == CODECAPI_AVEncMPVGOPSize {
                self.gop
            } else {
                None
            }
        }
    }

    fn caps(bitrate: Option<(u64, u64)>, gop: Option<(u64, u64)>) -> ReconfigCaps {
        probe_caps(&mut FakeProbe {
            bitrate,
            gop,
            queried: Vec::new(),
        })
    }

    #[test]
    fn probe_maps_support_to_ranges() {
        let c = caps(Some((1_000_000, 20_000_000)), None);
        assert_eq!(
            c.bitrate,
            Some(ParamRange {
                min: 1_000_000,
                max: 20_000_000,
                authoritative: true
            })
        );
        assert_eq!(c.gop_size, None);
        assert!(c.describe().contains("bitrate: live 1000000..20000000"));
        assert!(c.describe().contains("gop: rebuild"));
    }

    #[test]
    fn support_without_reported_range_is_live_unclamped() {
        // NVENC's shape (measured): IsSupported/IsModifiable OK,
        // GetParameterRange E_NOTIMPL. The property must still be live;
        // values pass through unclamped.
        let mut fake = NoRangeProbe { supported: true };
        let c = probe_caps(&mut fake);
        assert_eq!(c.bitrate, Some(ParamRange::unbounded()));
        assert!(c.describe().contains("bitrate: live (range unreported)"));
        let plan = plan_reconfigure(
            &EncoderParams {
                bitrate_bps: Some(4_000_000),
                ..Default::default()
            },
            &c,
            1920,
            1080,
            60,
        );
        match plan {
            ReconfigPlan::Live { props, clamped } => {
                assert!(clamped.is_empty());
                assert!(
                    props
                        .iter()
                        .any(|(g, v)| *g == CODECAPI_AVEncCommonMeanBitRate && *v == 4_000_000)
                );
            }
            other => panic!("expected Live, got {other:?}"),
        }
    }

    struct NoRangeProbe {
        supported: bool,
    }

    impl CapProbe for NoRangeProbe {
        fn is_supported(&mut self, _prop: &GUID) -> bool {
            self.supported
        }
        fn parameter_range(&mut self, _prop: &GUID) -> Option<(u64, u64)> {
            None
        }
    }

    #[test]
    fn live_bitrate_within_range() {
        let c = caps(Some((1_000_000, 20_000_000)), None);
        let plan = plan_reconfigure(
            &EncoderParams {
                bitrate_bps: Some(4_000_000),
                ..Default::default()
            },
            &c,
            1920,
            1080,
            60,
        );
        match plan {
            ReconfigPlan::Live { props, clamped } => {
                assert!(clamped.is_empty());
                assert!(
                    props
                        .iter()
                        .any(|(g, v)| *g == CODECAPI_AVEncCommonMeanBitRate && *v == 4_000_000)
                );
                // Buffer size follows the bitrate (build-time pairing).
                assert!(
                    props
                        .iter()
                        .any(|(g, v)| *g == CODECAPI_AVEncCommonBufferSize && *v == 4_000_000)
                );
            }
            other => panic!("expected Live, got {other:?}"),
        }
    }

    #[test]
    fn out_of_range_bitrate_clamps_and_reports() {
        let c = caps(Some((1_000_000, 20_000_000)), None);
        let plan = plan_reconfigure(
            &EncoderParams {
                bitrate_bps: Some(50_000_000),
                ..Default::default()
            },
            &c,
            1920,
            1080,
            60,
        );
        match plan {
            ReconfigPlan::Live { props, clamped } => {
                assert_eq!(clamped, vec!["bitrate_bps"]);
                assert!(
                    props
                        .iter()
                        .any(|(g, v)| *g == CODECAPI_AVEncCommonMeanBitRate && *v == 20_000_000)
                );
            }
            other => panic!("expected Live, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_bitrate_rebuilds() {
        let c = caps(None, Some((1, 512)));
        let plan = plan_reconfigure(
            &EncoderParams {
                bitrate_bps: Some(4_000_000),
                ..Default::default()
            },
            &c,
            1920,
            1080,
            60,
        );
        assert!(matches!(plan, ReconfigPlan::Rebuild { .. }));
    }

    #[test]
    fn resolution_and_fps_changes_always_rebuild() {
        let c = caps(Some((1, 1)), Some((1, 1)));
        for params in [
            EncoderParams {
                width: Some(1280),
                ..Default::default()
            },
            EncoderParams {
                height: Some(720),
                ..Default::default()
            },
            EncoderParams {
                fps: Some(30),
                ..Default::default()
            },
        ] {
            match plan_reconfigure(&params, &c, 1920, 1080, 60) {
                ReconfigPlan::Rebuild { reason } => assert!(!reason.is_empty()),
                other => panic!("expected Rebuild, got {other:?}"),
            }
        }
        // Same geometry + same fps is NOT a rebuild trigger by itself.
        let plan = plan_reconfigure(
            &EncoderParams {
                width: Some(1920),
                fps: Some(60),
                ..Default::default()
            },
            &c,
            1920,
            1080,
            60,
        );
        // No live props either -> Live with empty props (no-op).
        assert!(matches!(plan, ReconfigPlan::Live { props, .. } if props.is_empty()));
    }

    #[test]
    fn gop_live_when_supported() {
        let c = caps(Some((1, 1)), Some((1, 512)));
        let plan = plan_reconfigure(
            &EncoderParams {
                gop_size: Some(60),
                ..Default::default()
            },
            &c,
            1920,
            1080,
            60,
        );
        match plan {
            ReconfigPlan::Live { props, clamped } => {
                assert!(clamped.is_empty());
                assert!(
                    props
                        .iter()
                        .any(|(g, v)| *g == CODECAPI_AVEncMPVGOPSize && *v == 60)
                );
            }
            other => panic!("expected Live, got {other:?}"),
        }
    }

    #[test]
    fn empty_params_is_a_no_op() {
        let c = caps(None, None);
        let plan = plan_reconfigure(&EncoderParams::default(), &c, 1920, 1080, 60);
        assert!(matches!(plan, ReconfigPlan::Live { props, .. } if props.is_empty()));
    }
}
