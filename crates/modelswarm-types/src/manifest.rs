//! `ModelProfileManifest` and the manifest-derived `ModelProfileId`
//! (ADR-011, `catalog/schema-v2.json`).
//!
//! The manifest carries exactly the identity-bearing fields of a model
//! revision. Its canonical JSON is hashed to derive the profile id:
//!
//! ```text
//! manifest_digest = sha256(canonical_json(manifest))
//! ModelProfileId  = "msp1:" + hex(manifest_digest)
//! ```
//!
//! Every field is validated on construction, including via `serde`
//! deserialization (`deny_unknown_fields`, schema-constant checks), so an
//! invalid manifest cannot exist as a value of this type. UI-only wrapper
//! fields (`display_name`, `status`, `provenance`) live outside this type and
//! are never hashed.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::canonical_json;
use crate::{CoreError, HfRevision, Sha256Digest};

/// Prefix of every manifest-derived profile id (ADR-011).
pub const PROFILE_ID_PREFIX: &str = "msp1:";

/// The only manifest schema version accepted by this type (ADR-011).
pub const MANIFEST_SCHEMA_VERSION: u16 = 2;

/// Errors produced while constructing a [`ModelProfileManifest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// `schema_version` was not `2`.
    InvalidSchemaVersion(u16),
    /// `hf_repo` did not match `^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`.
    InvalidHfRepo(String),
    /// An artifact path did not match `^[A-Za-z0-9._/-]+$`.
    InvalidArtifactPath(String),
    /// `artifact_hashes` was empty; at least one artifact is required.
    EmptyArtifactHashes,
    /// `quantization.method` did not match `^[A-Za-z0-9_]+$`.
    InvalidQuantizationMethod(String),
    /// `quantization.bits` was outside `[1, 8]`.
    InvalidQuantizationBits(u8),
    /// `runtime.name` was not `llama.cpp`.
    InvalidRuntimeName(String),
    /// `runtime.version` was empty.
    EmptyRuntimeVersion,
    /// `decoding_abi_version` was below 1.
    InvalidDecodingAbiVersion(u16),
    /// A digest field failed `Sha256Digest` validation.
    InvalidSha256(CoreError),
    /// `hf_revision` failed `HfRevision` validation.
    InvalidRevision(CoreError),
    /// Deserialization itself failed (unknown field, wrong shape, …).
    Json(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::InvalidSchemaVersion(v) => {
                write!(f, "schema_version must be 2, got {v}")
            }
            ManifestError::InvalidHfRepo(v) => write!(f, "invalid hf_repo: {v:?}"),
            ManifestError::InvalidArtifactPath(v) => write!(f, "invalid artifact path: {v:?}"),
            ManifestError::EmptyArtifactHashes => write!(f, "artifact_hashes must not be empty"),
            ManifestError::InvalidQuantizationMethod(v) => {
                write!(f, "invalid quantization method: {v:?}")
            }
            ManifestError::InvalidQuantizationBits(v) => {
                write!(f, "quantization bits must be 1..=8, got {v}")
            }
            ManifestError::InvalidRuntimeName(v) => {
                write!(f, "runtime.name must be \"llama.cpp\", got {v:?}")
            }
            ManifestError::EmptyRuntimeVersion => write!(f, "runtime.version must not be empty"),
            ManifestError::InvalidDecodingAbiVersion(v) => {
                write!(f, "decoding_abi_version must be >= 1, got {v}")
            }
            ManifestError::InvalidSha256(e) => write!(f, "invalid digest: {e}"),
            ManifestError::InvalidRevision(e) => write!(f, "invalid hf_revision: {e}"),
            ManifestError::Json(e) => write!(f, "manifest deserialization failed: {e}"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// One artifact file of the revision, pinned by its SHA-256.
///
/// Fields are private; construction validates the schema patterns so an
/// [`ArtifactHash`] is always well-formed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawArtifactHash", into = "RawArtifactHash")]
pub struct ArtifactHash {
    path: String,
    sha256: Sha256Digest,
}

impl ArtifactHash {
    /// Validates `path` against `^[A-Za-z0-9._/-]+$` and wraps the digest.
    pub fn new(path: impl Into<String>, sha256: Sha256Digest) -> Result<Self, ManifestError> {
        let path = path.into();
        if valid_artifact_path(&path) {
            Ok(Self { path, sha256 })
        } else {
            Err(ManifestError::InvalidArtifactPath(path))
        }
    }

    /// The artifact path, e.g. `model-q4_k_m.gguf`.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The artifact digest.
    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct RawArtifactHash {
    path: String,
    sha256: String,
}

impl TryFrom<RawArtifactHash> for ArtifactHash {
    type Error = ManifestError;

    fn try_from(raw: RawArtifactHash) -> Result<Self, Self::Error> {
        let sha256 = Sha256Digest::new(raw.sha256).map_err(ManifestError::InvalidSha256)?;
        ArtifactHash::new(raw.path, sha256)
    }
}

impl From<ArtifactHash> for RawArtifactHash {
    fn from(value: ArtifactHash) -> Self {
        RawArtifactHash {
            path: value.path,
            sha256: value.sha256.to_string(),
        }
    }
}

fn valid_artifact_path(path: &str) -> bool {
    !path.is_empty()
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
}

/// Quantization method plus effective bit width.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawQuantization", into = "RawQuantization")]
pub struct QuantizationDescriptor {
    method: String,
    bits: u8,
}

impl QuantizationDescriptor {
    /// Validates `method` (`^[A-Za-z0-9_]+$`) and `bits` (`1..=8`).
    pub fn new(method: impl Into<String>, bits: u8) -> Result<Self, ManifestError> {
        let method = method.into();
        let ok = !method.is_empty()
            && method
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !ok {
            return Err(ManifestError::InvalidQuantizationMethod(method));
        }
        if !(1..=8).contains(&bits) {
            return Err(ManifestError::InvalidQuantizationBits(bits));
        }
        Ok(Self { method, bits })
    }

    /// Quantization method label, e.g. `Q4_K_M`.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Effective bit width, `1..=8`.
    pub fn bits(&self) -> u8 {
        self.bits
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct RawQuantization {
    method: String,
    bits: u8,
}

impl TryFrom<RawQuantization> for QuantizationDescriptor {
    type Error = ManifestError;

    fn try_from(raw: RawQuantization) -> Result<Self, Self::Error> {
        QuantizationDescriptor::new(raw.method, raw.bits)
    }
}

impl From<QuantizationDescriptor> for RawQuantization {
    fn from(value: QuantizationDescriptor) -> Self {
        RawQuantization {
            method: value.method,
            bits: value.bits,
        }
    }
}

/// The pinned serving runtime build (v0.1 freezes `llama.cpp`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawRuntime", into = "RawRuntime")]
pub struct RuntimeDescriptor {
    name: String,
    version: String,
    build_hash: Sha256Digest,
}

impl RuntimeDescriptor {
    /// Validates that `name` is exactly `llama.cpp`, `version` is non-empty,
    /// and `build_hash` is a well-formed digest.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        build_hash: Sha256Digest,
    ) -> Result<Self, ManifestError> {
        let name = name.into();
        let version = version.into();
        if name != "llama.cpp" {
            return Err(ManifestError::InvalidRuntimeName(name));
        }
        if version.is_empty() {
            return Err(ManifestError::EmptyRuntimeVersion);
        }
        Ok(Self {
            name,
            version,
            build_hash,
        })
    }

    /// Runtime name; always `llama.cpp` in v0.1.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Runtime version label.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Build identity digest.
    pub fn build_hash(&self) -> &Sha256Digest {
        &self.build_hash
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct RawRuntime {
    name: String,
    version: String,
    build_hash: String,
}

impl TryFrom<RawRuntime> for RuntimeDescriptor {
    type Error = ManifestError;

    fn try_from(raw: RawRuntime) -> Result<Self, Self::Error> {
        let build_hash = Sha256Digest::new(raw.build_hash).map_err(ManifestError::InvalidSha256)?;
        RuntimeDescriptor::new(raw.name, raw.version, build_hash)
    }
}

impl From<RuntimeDescriptor> for RawRuntime {
    fn from(value: RuntimeDescriptor) -> Self {
        RawRuntime {
            name: value.name,
            version: value.version,
            build_hash: value.build_hash.to_string(),
        }
    }
}

/// Speculative-decoding capability flags relevant for cooperative scheduling.
/// Serialized in `snake_case` exactly as the schema enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecCapability {
    /// Peer can draft proposal tokens.
    ProposalTokens,
    /// Peer can return per-token log probabilities.
    Logprobs,
    /// Peer can verify multiple proposals in one batch.
    BatchVerify,
    /// Peer supports tree-attention verification.
    TreeAttention,
}

/// The identity-bearing manifest of a model profile (ADR-011).
///
/// Hashed in full (canonical JSON, sorted keys) to derive the profile id.
/// All fields are private and validated; use [`ModelProfileManifest::new`] or
/// serde deserialization (equally validating) to build one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawManifest", into = "RawManifest")]
pub struct ModelProfileManifest {
    schema_version: u16,
    hf_repo: String,
    hf_revision: HfRevision,
    artifact_hashes: Vec<ArtifactHash>,
    tokenizer_hash: Sha256Digest,
    chat_template_hash: Sha256Digest,
    architecture_hash: Sha256Digest,
    quantization: QuantizationDescriptor,
    runtime: RuntimeDescriptor,
    decoding_abi_version: u16,
    speculative_capabilities: Vec<SpecCapability>,
}

impl ModelProfileManifest {
    /// Field-for-field validating constructor. `schema_version` is not a
    /// parameter: it is the constant [`MANIFEST_SCHEMA_VERSION`].
    ///
    /// A builder is deliberately not used — a field-for-field constructor
    /// makes it impossible to forget which fields are hashed (all of them).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hf_repo: impl Into<String>,
        hf_revision: HfRevision,
        artifact_hashes: Vec<ArtifactHash>,
        tokenizer_hash: Sha256Digest,
        chat_template_hash: Sha256Digest,
        architecture_hash: Sha256Digest,
        quantization: QuantizationDescriptor,
        runtime: RuntimeDescriptor,
        decoding_abi_version: u16,
        speculative_capabilities: Vec<SpecCapability>,
    ) -> Result<Self, ManifestError> {
        let hf_repo = hf_repo.into();
        if !valid_hf_repo(&hf_repo) {
            return Err(ManifestError::InvalidHfRepo(hf_repo));
        }
        if artifact_hashes.is_empty() {
            return Err(ManifestError::EmptyArtifactHashes);
        }
        if decoding_abi_version < 1 {
            return Err(ManifestError::InvalidDecodingAbiVersion(
                decoding_abi_version,
            ));
        }
        Ok(Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            hf_repo,
            hf_revision,
            artifact_hashes,
            tokenizer_hash,
            chat_template_hash,
            architecture_hash,
            quantization,
            runtime,
            decoding_abi_version,
            speculative_capabilities,
        })
    }

    /// Always [`MANIFEST_SCHEMA_VERSION`] (2).
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Hugging Face repository, e.g. `example-org/example-model-gguf`.
    pub fn hf_repo(&self) -> &str {
        &self.hf_repo
    }

    /// Full 40-character commit hash of the revision.
    pub fn hf_revision(&self) -> &HfRevision {
        &self.hf_revision
    }

    /// The pinned artifact files with their SHA-256 digests.
    pub fn artifact_hashes(&self) -> &[ArtifactHash] {
        &self.artifact_hashes
    }

    /// SHA-256 of the tokenizer files.
    pub fn tokenizer_hash(&self) -> &Sha256Digest {
        &self.tokenizer_hash
    }

    /// SHA-256 of the tokenizer's chat template string.
    pub fn chat_template_hash(&self) -> &Sha256Digest {
        &self.chat_template_hash
    }

    /// SHA-256 of the canonicalized architecture-relevant `config.json` subset.
    pub fn architecture_hash(&self) -> &Sha256Digest {
        &self.architecture_hash
    }

    /// Quantization method and bit width.
    pub fn quantization(&self) -> &QuantizationDescriptor {
        &self.quantization
    }

    /// Pinned runtime build.
    pub fn runtime(&self) -> &RuntimeDescriptor {
        &self.runtime
    }

    /// Decoding ABI version (>= 1).
    pub fn decoding_abi_version(&self) -> u16 {
        self.decoding_abi_version
    }

    /// Speculative-decoding capability flags.
    pub fn speculative_capabilities(&self) -> &[SpecCapability] {
        &self.speculative_capabilities
    }

    /// Canonical JSON of the manifest (msp-v1 §2.2 / ADR-011): recursively
    /// sorted keys, compact, integers only. Manifests contain no floats, so
    /// this cannot fail; the no-float rule is enforced on arbitrary values by
    /// [`canonical_json`].
    pub fn canonical_json(&self) -> String {
        let value = serde_json::to_value(self).expect("manifest serializes to JSON");
        canonical_json(&value).expect("manifests contain no floats by type definition")
    }

    /// Derives the profile id: `"msp1:" + hex(sha256(canonical_json))`.
    pub fn derive_profile_id(&self) -> String {
        let digest = Sha256::digest(self.canonical_json().as_bytes());
        format!("{PROFILE_ID_PREFIX}{}", hex::encode(digest))
    }
}

/// The cloud-family manifest (ADR-040 §1): a cloud profile pins the
/// provider, the provider's EXACT model id, and the context policy — no
/// artifact exists to hash, the provider pins ARE the exactness. Same
/// canonical-JSON profile-id derivation as the local family (keys sort,
/// so only field names + values matter for cross-implementation parity
/// with the tracker's TS derivation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudProfileManifest {
    schema_version: u16,
    family: CloudFamily,
    provider: CloudProviderId,
    model: String,
    context_tokens: u32,
    max_output_tokens: u32,
    wire: CloudWire,
}

/// The family discriminator (`"cloud"`; local manifests carry no field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudFamily {
    #[serde(rename = "cloud")]
    Cloud,
}

/// The two default providers (ADR-040 §5; more need an owner gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudProviderId {
    #[serde(rename = "deepseek")]
    DeepSeek,
    #[serde(rename = "openrouter")]
    OpenRouter,
}

/// The pinned request wire (the runtime analogue for cloud profiles).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloudWire {
    #[serde(rename = "openai-chat-v1")]
    OpenAiChatV1,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CloudManifestError {
    BadSchemaVersion,
    BadModelId,
    BadContextTokens,
    BadMaxOutputTokens,
}

impl fmt::Display for CloudManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudManifestError::BadSchemaVersion => write!(f, "schema_version must be 2"),
            CloudManifestError::BadModelId => {
                write!(
                    f,
                    "model id must be 1..=100 chars of [A-Za-z0-9._/-] starting alnum"
                )
            }
            CloudManifestError::BadContextTokens => {
                write!(f, "context_tokens out of range (1024..=2_000_000)")
            }
            CloudManifestError::BadMaxOutputTokens => {
                write!(f, "max_output_tokens out of range (1..=1_000_000)")
            }
        }
    }
}

impl std::error::Error for CloudManifestError {}

impl CloudProfileManifest {
    /// Field-for-field validating constructor, the local-family
    /// discipline: `schema_version` is the constant, never a parameter.
    pub fn new(
        provider: CloudProviderId,
        model: impl Into<String>,
        context_tokens: u32,
        max_output_tokens: u32,
    ) -> Result<Self, CloudManifestError> {
        let model = model.into();
        if model.is_empty()
            || model.len() > 100
            || !model
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric())
            || !model
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'))
        {
            return Err(CloudManifestError::BadModelId);
        }
        if !(1024..=2_000_000).contains(&context_tokens) {
            return Err(CloudManifestError::BadContextTokens);
        }
        if max_output_tokens == 0 || max_output_tokens > 1_000_000 {
            return Err(CloudManifestError::BadMaxOutputTokens);
        }
        Ok(Self {
            schema_version: MANIFEST_SCHEMA_VERSION,
            family: CloudFamily::Cloud,
            provider,
            model,
            context_tokens,
            max_output_tokens,
            wire: CloudWire::OpenAiChatV1,
        })
    }

    /// Re-checks every invariant on a DESERIALIZED value (the catalog
    /// layer calls this — deserialization alone is shape-only).
    pub fn validated(self) -> Result<Self, CloudManifestError> {
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(CloudManifestError::BadSchemaVersion);
        }
        CloudProfileManifest::new(
            self.provider,
            self.model.clone(),
            self.context_tokens,
            self.max_output_tokens,
        )?;
        Ok(self)
    }

    /// The provider pin (read accessors; fields stay private like local).
    pub fn provider(&self) -> CloudProviderId {
        self.provider
    }

    /// The provider's exact model id.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Canonical JSON (sorted keys) — the derivation preimage.
    pub fn canonical_json(&self) -> String {
        let value = serde_json::to_value(self).expect("cloud manifest serializes to JSON");
        crate::canonical::canonical_json(&value).expect("cloud manifests contain no floats")
    }

    /// Derives the profile id: `"msp1:" + hex(sha256(canonical_json))`.
    pub fn derive_profile_id(&self) -> String {
        let digest = Sha256::digest(self.canonical_json().as_bytes());
        format!("{PROFILE_ID_PREFIX}{}", hex::encode(digest))
    }
}

/// ADR-040: the Rust cloud derivation MUST reproduce the id the tracker
/// (TS) derived for the live DeepSeek Chat (cloud) profile — the
/// cross-implementation pin (both canonicalizations sort keys, so only
/// field names + values may differ).
#[test]
fn cloud_manifest_derivation_matches_the_live_tracker_profile() {
    let cloud = CloudProfileManifest::new(CloudProviderId::DeepSeek, "deepseek-chat", 65536, 8192)
        .expect("valid cloud manifest");
    assert_eq!(
        cloud.derive_profile_id(),
        "msp1:595bce607085cbde88a5e8a5ce26e06f686819a9deaaffd6d6346c01b172c1f0"
    );
}

#[test]
fn cloud_manifest_round_trips_and_rejects_unknown_fields() {
    let cloud = CloudProfileManifest::new(
        CloudProviderId::OpenRouter,
        "meta-llama/llama-3.3-70b-instruct",
        131072,
        16384,
    )
    .expect("valid");
    let json = serde_json::to_string(&cloud).unwrap();
    let parsed: CloudProfileManifest = serde_json::from_str(&json).unwrap();
    let back = parsed.validated().unwrap();
    assert_eq!(back.derive_profile_id(), cloud.derive_profile_id());
    let dirty = json.replace(",\"wire\":", ",\"not_a_field\":1,\"wire\":");
    assert!(serde_json::from_str::<CloudProfileManifest>(&dirty).is_err());
}

fn valid_hf_repo(repo: &str) -> bool {
    let Some((org, name)) = repo.split_once('/') else {
        return false;
    };
    valid_repo_segment(org) && valid_repo_segment(name)
}

fn valid_repo_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct RawManifest {
    schema_version: u16,
    hf_repo: String,
    hf_revision: String,
    artifact_hashes: Vec<ArtifactHash>,
    tokenizer_hash: String,
    chat_template_hash: String,
    architecture_hash: String,
    quantization: QuantizationDescriptor,
    runtime: RuntimeDescriptor,
    decoding_abi_version: u16,
    speculative_capabilities: Vec<SpecCapability>,
}

impl TryFrom<RawManifest> for ModelProfileManifest {
    type Error = ManifestError;

    fn try_from(raw: RawManifest) -> Result<Self, Self::Error> {
        if raw.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(ManifestError::InvalidSchemaVersion(raw.schema_version));
        }
        let hf_revision =
            HfRevision::new(raw.hf_revision).map_err(ManifestError::InvalidRevision)?;
        let tokenizer_hash =
            Sha256Digest::new(raw.tokenizer_hash).map_err(ManifestError::InvalidSha256)?;
        let chat_template_hash =
            Sha256Digest::new(raw.chat_template_hash).map_err(ManifestError::InvalidSha256)?;
        let architecture_hash =
            Sha256Digest::new(raw.architecture_hash).map_err(ManifestError::InvalidSha256)?;
        ModelProfileManifest::new(
            raw.hf_repo,
            hf_revision,
            raw.artifact_hashes,
            tokenizer_hash,
            chat_template_hash,
            architecture_hash,
            raw.quantization,
            raw.runtime,
            raw.decoding_abi_version,
            raw.speculative_capabilities,
        )
    }
}

impl From<ModelProfileManifest> for RawManifest {
    fn from(value: ModelProfileManifest) -> Self {
        RawManifest {
            schema_version: value.schema_version,
            hf_repo: value.hf_repo,
            hf_revision: value.hf_revision.to_string(),
            artifact_hashes: value.artifact_hashes,
            tokenizer_hash: value.tokenizer_hash.to_string(),
            chat_template_hash: value.chat_template_hash.to_string(),
            architecture_hash: value.architecture_hash.to_string(),
            quantization: value.quantization,
            runtime: value.runtime,
            decoding_abi_version: value.decoding_abi_version,
            speculative_capabilities: value.speculative_capabilities,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn digest(ch: char) -> Sha256Digest {
        Sha256Digest::new(ch.to_string().repeat(64)).unwrap()
    }

    fn sample_manifest() -> ModelProfileManifest {
        ModelProfileManifest::new(
            "example-org/example-model-gguf",
            HfRevision::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            vec![ArtifactHash::new("model-q4_k_m.gguf", digest('b')).unwrap()],
            digest('c'),
            digest('d'),
            digest('e'),
            QuantizationDescriptor::new("Q4_K_M", 4).unwrap(),
            RuntimeDescriptor::new("llama.cpp", "b0-test", digest('f')).unwrap(),
            1,
            vec![SpecCapability::ProposalTokens, SpecCapability::BatchVerify],
        )
        .unwrap()
    }

    #[test]
    fn golden_vectors_derive_expected_profile_ids() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../protocol/vectors");
        let entries =
            std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot read vectors dir {dir}: {e}"));
        let mut checked = 0;
        for entry in entries {
            let path = entry.unwrap().path();
            // Manifest fixtures only — lease-hubkey-1.json is a signed-lease
            // vector covered by the eligibility golden test.
            if !path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("manifest-"))
            {
                continue;
            }
            let doc: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap())
                    .unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()));
            let manifest: ModelProfileManifest = serde_json::from_value(doc["manifest"].clone())
                .unwrap_or_else(|e| panic!("{}: manifest invalid: {e}", path.display()));
            let expected = doc["expected_profile_id"].as_str().unwrap();
            assert_eq!(
                manifest.derive_profile_id(),
                expected,
                "profile id mismatch for {}",
                path.display()
            );
            checked += 1;
        }
        assert!(
            checked >= 2,
            "expected both golden vectors, found {checked}"
        );
    }

    #[test]
    fn canonical_json_round_trips_byte_identical() {
        let manifest = sample_manifest();
        let canonical = manifest.canonical_json();
        let reparsed: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        assert_eq!(canonical_json(&reparsed).unwrap(), canonical);
        // And survives full serde round-trip without change.
        let again: ModelProfileManifest = serde_json::from_value(reparsed).unwrap();
        assert_eq!(again, manifest);
        assert_eq!(again.canonical_json(), canonical);
    }

    #[test]
    fn canonical_json_matches_schema_shape() {
        let manifest = sample_manifest();
        let canonical = manifest.canonical_json();
        // First key in sorted order + schema_version present exactly once.
        assert!(
            canonical.starts_with(r#"{"architecture_hash":"eeee"#),
            "{canonical}"
        );
        assert!(!canonical.contains(' '));
        assert!(!canonical.contains('\n'));
        let value: serde_json::Value = serde_json::from_str(&canonical).unwrap();
        assert_eq!(value["schema_version"], json!(2));
        assert_eq!(value["runtime"]["name"], json!("llama.cpp"));
        assert_eq!(
            value["speculative_capabilities"],
            json!(["proposal_tokens", "batch_verify"])
        );
    }

    #[test]
    fn changing_one_field_changes_the_id() {
        let base = sample_manifest();
        let changed = ModelProfileManifest::new(
            "example-org/example-model-gguf",
            HfRevision::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            vec![ArtifactHash::new("model-q4_k_m.gguf", digest('b')).unwrap()],
            digest('c'),
            // Only the chat template hash differs ('0' is valid hex, 'd' was before).
            digest('0'),
            digest('e'),
            QuantizationDescriptor::new("Q4_K_M", 4).unwrap(),
            RuntimeDescriptor::new("llama.cpp", "b0-test", digest('f')).unwrap(),
            1,
            vec![SpecCapability::ProposalTokens, SpecCapability::BatchVerify],
        )
        .unwrap();
        assert_ne!(base.derive_profile_id(), changed.derive_profile_id());
    }

    #[test]
    fn invalid_fields_are_rejected_on_construction() {
        let rev = HfRevision::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let runtime = RuntimeDescriptor::new("llama.cpp", "b0-test", digest('f')).unwrap();
        let quant = QuantizationDescriptor::new("Q4_K_M", 4).unwrap();

        assert_eq!(
            ModelProfileManifest::new(
                "no-slash-repo",
                rev.clone(),
                vec![ArtifactHash::new("m.gguf", digest('b')).unwrap()],
                digest('c'),
                digest('d'),
                digest('e'),
                quant.clone(),
                runtime.clone(),
                1,
                vec![]
            )
            .unwrap_err(),
            ManifestError::InvalidHfRepo("no-slash-repo".to_string())
        );
        assert_eq!(
            ModelProfileManifest::new(
                "org/model",
                rev.clone(),
                vec![],
                digest('c'),
                digest('d'),
                digest('e'),
                quant.clone(),
                runtime.clone(),
                1,
                vec![]
            )
            .unwrap_err(),
            ManifestError::EmptyArtifactHashes
        );
        assert_eq!(
            ArtifactHash::new("bad path!", digest('b')).unwrap_err(),
            ManifestError::InvalidArtifactPath("bad path!".to_string())
        );
        assert_eq!(
            QuantizationDescriptor::new("q4!", 4).unwrap_err(),
            ManifestError::InvalidQuantizationMethod("q4!".to_string())
        );
        assert_eq!(
            QuantizationDescriptor::new("Q4_K_M", 0).unwrap_err(),
            ManifestError::InvalidQuantizationBits(0)
        );
        assert_eq!(
            QuantizationDescriptor::new("Q4_K_M", 9).unwrap_err(),
            ManifestError::InvalidQuantizationBits(9)
        );
        assert_eq!(
            RuntimeDescriptor::new("vllm", "1", digest('f')).unwrap_err(),
            ManifestError::InvalidRuntimeName("vllm".to_string())
        );
        assert_eq!(
            RuntimeDescriptor::new("llama.cpp", "", digest('f')).unwrap_err(),
            ManifestError::EmptyRuntimeVersion
        );
        assert_eq!(
            ModelProfileManifest::new(
                "org/model",
                rev,
                vec![ArtifactHash::new("m.gguf", digest('b')).unwrap()],
                digest('c'),
                digest('d'),
                digest('e'),
                quant,
                runtime,
                0,
                vec![]
            )
            .unwrap_err(),
            ManifestError::InvalidDecodingAbiVersion(0)
        );
    }

    #[test]
    fn invalid_fields_are_rejected_on_deserialization() {
        let mut raw = serde_json::to_value(sample_manifest()).unwrap();
        raw["schema_version"] = json!(3);
        assert!(matches!(
            serde_json::from_value::<ModelProfileManifest>(raw.clone()).unwrap_err(),
            e if e.to_string().contains("schema_version must be 2")
        ));

        let mut raw = serde_json::to_value(sample_manifest()).unwrap();
        raw["hf_revision"] = json!("main");
        assert!(serde_json::from_value::<ModelProfileManifest>(raw).is_err());

        // Unknown top-level field is rejected (additionalProperties: false).
        let mut raw = serde_json::to_value(sample_manifest()).unwrap();
        raw["display_name"] = json!("UI-only field must not sneak into the manifest");
        assert!(serde_json::from_value::<ModelProfileManifest>(raw).is_err());

        // Unknown speculative capability is rejected.
        let mut raw = serde_json::to_value(sample_manifest()).unwrap();
        raw["speculative_capabilities"] = json!(["quantum_verify"]);
        assert!(serde_json::from_value::<ModelProfileManifest>(raw).is_err());

        // Unknown field inside a nested descriptor is rejected too.
        let mut raw = serde_json::to_value(sample_manifest()).unwrap();
        raw["runtime"]["extra"] = json!(1);
        assert!(serde_json::from_value::<ModelProfileManifest>(raw).is_err());

        // Uppercase hex digest is rejected.
        let mut raw = serde_json::to_value(sample_manifest()).unwrap();
        raw["tokenizer_hash"] = json!("C".repeat(64));
        assert!(serde_json::from_value::<ModelProfileManifest>(raw).is_err());
    }

    #[test]
    fn spec_capabilities_serialize_snake_case() {
        assert_eq!(
            serde_json::to_value(SpecCapability::ProposalTokens).unwrap(),
            json!("proposal_tokens")
        );
        assert_eq!(
            serde_json::to_value(SpecCapability::Logprobs).unwrap(),
            json!("logprobs")
        );
        assert_eq!(
            serde_json::to_value(SpecCapability::BatchVerify).unwrap(),
            json!("batch_verify")
        );
        assert_eq!(
            serde_json::to_value(SpecCapability::TreeAttention).unwrap(),
            json!("tree_attention")
        );
    }
}
