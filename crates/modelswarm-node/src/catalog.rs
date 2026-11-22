//! Verified-catalog access for the node/desktop client (Phase H2).
//!
//! Fetches `/api/v1/catalog`, verifies the Ed25519 envelope signature
//! against the pinned hub public key (`protocol/keys/hub-public.hex`),
//! and parses the active profiles into typed manifests. A failed
//! verification is an error — the client never trusts an unsigned catalog.

use modelswarm_tracker_api::{TrackerClient, TrackerError};
use modelswarm_types::{CloudProfileManifest, ModelProfileManifest};

pub use modelswarm_types::{CloudProviderId, CloudWire};

/// Pinned hub public key (Ed25519, 64 lowercase hex). Rotation = re-release
/// of the client (deployment.md rotation procedure).
pub const HUB_PUBLIC_KEY_HEX: &str = include_str!("../../../protocol/keys/hub-public.hex");

/// One active profile from the verified catalog — the LOCAL family
/// (pinned artifact) or the CLOUD family (ADR-040: provider + exact
/// model id + policy; no artifact exists).
#[derive(Debug, Clone)]
pub struct ProfileListing {
    pub profile_id: String,
    pub display_name: String,
    pub kind: ProfileKind,
}

#[derive(Debug, Clone)]
pub enum ProfileKind {
    Local(Box<ModelProfileManifest>),
    Cloud(Box<CloudProfileManifest>),
}

impl ProfileKind {
    /// True for the cloud family (no download, key-backed serving).
    pub fn is_cloud(&self) -> bool {
        matches!(self, ProfileKind::Cloud(_))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("tracker: {0}")]
    Tracker(#[from] TrackerError),
    #[error("catalog entry {profile_id}: {message}")]
    InvalidEntry { profile_id: String, message: String },
}

/// Fetches and verifies the catalog, returning its active profiles.
pub async fn active_profiles(tracker: &TrackerClient) -> Result<Vec<ProfileListing>, CatalogError> {
    let verified = tracker.fetch_catalog_verified(HUB_PUBLIC_KEY_HEX).await?;
    let mut out = Vec::new();
    for profile in &verified.profiles {
        let status = profile
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("active");
        if status != "active" {
            continue;
        }
        let profile_id = profile
            .get("profile_id")
            .and_then(|s| s.as_str())
            .unwrap_or("<missing-id>")
            .to_string();
        let display_name = profile
            .get("display_name")
            .and_then(|s| s.as_str())
            .unwrap_or(&profile_id)
            .to_string();
        let manifest_value =
            profile
                .get("manifest")
                .cloned()
                .ok_or_else(|| CatalogError::InvalidEntry {
                    profile_id: profile_id.clone(),
                    message: "missing manifest".into(),
                })?;
        // Family dispatch (ADR-040): the cloud family carries the tag; the
        // local family never did. Both parse STRICTLY and both derive the
        // same canonical profile id — verified against the signed record.
        let kind = if manifest_value.get("family").and_then(|f| f.as_str()) == Some("cloud") {
            let cloud: CloudProfileManifest =
                serde_json::from_value::<CloudProfileManifest>(manifest_value)
                    .map_err(|e| CatalogError::InvalidEntry {
                        profile_id: profile_id.clone(),
                        message: e.to_string(),
                    })?
                    .validated()
                    .map_err(|e| CatalogError::InvalidEntry {
                        profile_id: profile_id.clone(),
                        message: e.to_string(),
                    })?;
            if cloud.derive_profile_id() != profile_id {
                return Err(CatalogError::InvalidEntry {
                    profile_id,
                    message: "profile_id does not match the cloud manifest derivation".into(),
                });
            }
            ProfileKind::Cloud(Box::new(cloud))
        } else {
            let manifest: ModelProfileManifest =
                serde_json::from_value(manifest_value).map_err(|e| CatalogError::InvalidEntry {
                    profile_id: profile_id.clone(),
                    message: e.to_string(),
                })?;
            if manifest.derive_profile_id() != profile_id {
                return Err(CatalogError::InvalidEntry {
                    profile_id,
                    message: "profile_id does not match the manifest derivation".into(),
                });
            }
            ProfileKind::Local(Box::new(manifest))
        };
        out.push(ProfileListing {
            profile_id,
            display_name,
            kind,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_hub_key_is_64_lowercase_hex() {
        let key = HUB_PUBLIC_KEY_HEX.trim();
        assert_eq!(key.len(), 64, "key: {key}");
        assert!(key
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
