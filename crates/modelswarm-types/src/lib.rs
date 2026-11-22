//! Fundamental types shared by every ModelSwarm crate: the protocol version
//! constant, the typed identifiers already frozen by `protocol/msp-v1.md`,
//! the canonical JSON encoding (§2.2) and the manifest-derived
//! `ModelProfileId` (ADR-011, `catalog/schema-v2.json`).
//!
//! Anything not frozen in the protocol document or an ADR must not be added
//! here without an ADR.

pub mod canonical;
pub mod gguf;
pub mod manifest;

pub use canonical::{canonical_json, CanonicalError};
pub use gguf::{
    identity_hashes, read_metadata, read_metadata_bytes, token_vocab, GgufError,
    GgufIdentityHashes, GgufValue, TokenVocab,
};
pub use manifest::{
    ArtifactHash, CloudFamily, CloudManifestError, CloudProfileManifest, CloudProviderId,
    CloudWire, ManifestError, ModelProfileManifest, QuantizationDescriptor, RuntimeDescriptor,
    SpecCapability, MANIFEST_SCHEMA_VERSION, PROFILE_ID_PREFIX,
};

use std::fmt;

/// Wire/contract version of the ModelSwarm protocol implemented by this build.
pub const MSP_PROTOCOL_VERSION: &str = "1";

/// Errors produced when a core identifier fails its frozen validation rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    /// A `ModelProfileId` did not match `msp:<family>:<quantization>:<vN>`.
    InvalidProfileId(String),
    /// A Hugging Face revision was not a 40-character lowercase hex commit hash.
    InvalidRevision(String),
    /// A SHA-256 value was not 64 lowercase hex characters.
    InvalidSha256(String),
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::InvalidProfileId(v) => write!(f, "invalid model profile id: {v:?}"),
            CoreError::InvalidRevision(v) => write!(f, "invalid HF revision: {v:?}"),
            CoreError::InvalidSha256(v) => write!(f, "invalid SHA-256: {v:?}"),
        }
    }
}

impl std::error::Error for CoreError {}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Immutable identifier of an approved model profile, e.g.
/// `msp:qwen3-4b:q4_k_m:v1`.
///
/// A profile ID names one exact artifact (repository + full revision + file +
/// digest + context policy). Any change to the artifact produces a new profile
/// ID and therefore a separate swarm (ADR-005).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ModelProfileId(String);

impl ModelProfileId {
    /// Validates and wraps a profile ID string.
    pub fn new(raw: impl Into<String>) -> Result<Self, CoreError> {
        let raw = raw.into();
        let mut parts = raw.split(':');
        let shape = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        );
        match shape {
            (Some("msp"), Some(family), Some(quant), Some(version), None)
                if is_slug(family, false)
                    && is_slug(quant, true)
                    && valid_profile_version(version) =>
            {
                Ok(Self(raw))
            }
            _ => Err(CoreError::InvalidProfileId(raw)),
        }
    }

    /// The identifier as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Lowercase slug matching catalog/schema.json: `[a-z0-9][a-z0-9_-]*`
/// (underscore additionally allowed for quantization segments).
fn is_slug(s: &str, allow_underscore: bool) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    chars.all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || (allow_underscore && c == '_')
    })
}

fn valid_profile_version(v: &str) -> bool {
    v.len() >= 2 && v.starts_with('v') && v[1..].bytes().all(|b| b.is_ascii_digit())
}

impl fmt::Display for ModelProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A full (40-character) Hugging Face commit hash. Tags and branch names are
/// never acceptable here (ADR-005).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HfRevision(String);

impl HfRevision {
    /// Validates and wraps a full commit hash.
    pub fn new(raw: impl Into<String>) -> Result<Self, CoreError> {
        let raw = raw.into();
        if raw.len() == 40 && is_lower_hex(&raw) {
            Ok(Self(raw))
        } else {
            Err(CoreError::InvalidRevision(raw))
        }
    }

    /// The commit hash as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HfRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A lowercase-hex SHA-256 digest of an artifact or request body.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Validates and wraps a 64-character hex digest.
    pub fn new(raw: impl Into<String>) -> Result<Self, CoreError> {
        let raw = raw.into();
        if raw.len() == 64 && is_lower_hex(&raw) {
            Ok(Self(raw))
        } else {
            Err(CoreError::InvalidSha256(raw))
        }
    }

    /// The digest as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_frozen_profile_id_shape() {
        let id = ModelProfileId::new("msp:qwen3-4b:q4_k_m:v1").unwrap();
        assert_eq!(id.as_str(), "msp:qwen3-4b:q4_k_m:v1");
        assert_eq!(id.to_string(), "msp:qwen3-4b:q4_k_m:v1");
    }

    #[test]
    fn rejects_malformed_profile_ids() {
        for bad in [
            "",
            "qwen3-4b",
            "msp:qwen3-4b:q4_k_m",
            "msp:qwen3-4b:q4_k_m:v1:extra",
            "msp::q4_k_m:v1",
            "msp:qwen3-4b::v1",
            "msp:qwen3-4b:q4_k_m:1",
            "msp:qwen3-4b:q4_k_m:v",
            "msp:qwen3-4b:q4_k_m:vx",
            "MSP:qwen3-4b:q4_k_m:v1",
            "msp:Qwen3-4b:q4_k_m:v1",
            "msp:qwen3-4b:Q4_K_M:v1",
            "msp:-qwen3-4b:q4_k_m:v1",
            "msp:qwen3-4b:q4!k_m:v1",
        ] {
            assert_eq!(
                ModelProfileId::new(bad),
                Err(CoreError::InvalidProfileId(bad.to_string())),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn revision_requires_full_40_char_lowercase_hash() {
        assert!(HfRevision::new("becf9571b8497476e4b3cd12908c66cf456a57bc").is_ok());
        for bad in [
            "",
            "main",
            "becf9571b8497476e4b3cd12908c66cf456a57b", // 39 chars
            "BECF9571B8497476E4B3CD12908C66CF456A57BC", // uppercase
            "gbcf9571b8497476e4b3cd12908c66cf456a57bcz", // non-hex, 41 chars
        ] {
            assert!(HfRevision::new(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn sha256_requires_64_lowercase_hex_chars() {
        assert!(Sha256Digest::new("a".repeat(64)).is_ok());
        assert!(Sha256Digest::new("0".repeat(63)).is_err());
        assert!(Sha256Digest::new("A".repeat(64)).is_err());
        assert!(Sha256Digest::new("").is_err());
    }
}
