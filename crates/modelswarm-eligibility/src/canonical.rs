//! Canonical JSON for signed payloads (msp-v1 §2.2).
//!
//! Thin adapter over the ONE implementation,
//! `modelswarm_types::canonical` (2026-10-08 collapse: three drifting
//! copies begat the lease-interop bug class; this crate's copy had
//! already drifted in error shape). Option signature preserved.

use serde_json::Value;

/// Renders `value` as canonical JSON, or `None` if it contains a
/// floating-point number (forbidden in signed payloads).
pub fn canonical_json(value: &Value) -> Option<String> {
    modelswarm_types::canonical_json(value).ok()
}
