//! Receipts v2 (ADR-030): counter-signed work receipts and granted
//! verified-work accounting evidence.
//!
//! The v1 receipt shape is untouched — v2 is a NEW signed object (old
//! verifiers unaffected). Two-phase exchange, the lease-wire discipline
//! (ADR-012/026):
//!
//! * phase 1 — the serving/coordinating peer signs the canonical JSON of
//!   the object **with both signature fields absent**;
//! * phase 2 — the requester verifies, then counter-signs the canonical
//!   JSON **with `server_signature` present and `requester_signature`
//!   absent**;
//! * `receiptDigest` (the msp-v1 §7 wire field) is
//!   `"sha256:" + hex(SHA-256(canonical JSON of the FINAL object))` —
//!   frozen by ADR-030 §2, closing the undefined-preimage finding.
//!
//! A receipt without BOTH signatures is never accounting evidence. All
//! payload fields are timings, counts, and digests — never prompt text
//! (content blindness holds).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// One engaged peer: the ADR-029 role vocabulary (coordinator/requester,
/// verifier, server — msp-v1 §7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptPeer {
    pub peer_id: String,
    pub installation_id: String,
    pub role: String,
}

/// The ADR-030 §1 object. `budgets` is the effective ADR-029 SessionOffer
/// budget actually applied — integers/strings only (canonical JSON forbids
/// floats in signed payloads).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptV2 {
    pub request_id: String,
    pub profile_id: String,
    pub preset: String,
    pub mode_id: String,
    pub cohort_digest: String,
    pub peers: Vec<ReceiptPeer>,
    pub started_at: String,
    pub ended_at: String,
    pub outcome: String,
    pub accepted_tokens: u64,
    pub verified_tokens: u64,
    pub endpoint_seconds: u64,
    pub usage_digest: String,
    pub budgets: serde_json::Value,
    /// Phase-1: ed25519 by the serving/coordinating peer over the
    /// both-signatures-absent canonical form (base64url).
    pub server_signature: String,
    /// Phase-2: ed25519 by the requesting peer over the
    /// server-present/requester-absent canonical form (base64url).
    pub requester_signature: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiptError {
    Canonical(String),
    Signature(String),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptError::Canonical(m) => write!(f, "receipt canonical form: {m}"),
            ReceiptError::Signature(m) => write!(f, "receipt signature: {m}"),
        }
    }
}

impl std::error::Error for ReceiptError {}

use base64::Engine as _;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// ADR-045 (msp-cooperative-v1 §4/§6): the frozen receipt-side preset
/// vocabulary — the five enum values plus the honest `unspecified`
/// literal ("no negotiated preset reached this object"). Construction
/// emits only these; consumers refuse anything else (fail-closed, never
/// guess). The tracker's intake zod enum mirrors this list
/// (`apps/tracker/lib/schemas.ts`).
pub fn is_valid_receipt_preset(value: &str) -> bool {
    matches!(
        value,
        "fast" | "balanced" | "deep" | "verified" | "maximum" | "unspecified"
    )
}

impl ReceiptV2 {
    /// `cohort_digest` (ADR-030 §1): `"sha256:" + hex(SHA-256(canonical
    /// JSON of the sorted "peer_id:role" strings))`.
    pub fn cohort_digest_of(peers: &[ReceiptPeer]) -> Result<String, ReceiptError> {
        let mut labels: Vec<String> = peers
            .iter()
            .map(|p| format!("{}:{}", p.peer_id, p.role))
            .collect();
        labels.sort();
        let canonical = crate::canonical::canonical_json(&serde_json::json!(labels))
            .ok_or_else(|| ReceiptError::Canonical("cohort labels not canonical".into()))?;
        Ok(format!("sha256:{}", Sha256Hex(&canonical).value()))
    }

    fn canonical_with(&self, server: bool, requester: bool) -> Option<String> {
        let mut value = serde_json::to_value(self).ok()?;
        let map = value.as_object_mut()?;
        if !server {
            map.remove("server_signature");
        }
        if !requester {
            map.remove("requester_signature");
        }
        crate::canonical::canonical_json(&value)
    }

    /// The phase-1 signing preimage: both signature fields absent.
    pub fn phase1_canonical(&self) -> Option<String> {
        self.canonical_with(false, false)
    }

    /// The phase-2 signing preimage: server signature present, requester
    /// signature absent.
    pub fn phase2_canonical(&self) -> Option<String> {
        self.canonical_with(true, false)
    }

    /// The final canonical form (both signatures present) — the
    /// `receiptDigest` preimage.
    pub fn final_canonical(&self) -> Option<String> {
        self.canonical_with(true, true)
    }

    /// The frozen `receiptDigest` (ADR-030 §2): SHA-256 over the final
    /// counter-signed canonical JSON, `"sha256:" + lowercase hex`.
    pub fn receipt_digest(&self) -> Result<String, ReceiptError> {
        let canonical = self
            .final_canonical()
            .ok_or_else(|| ReceiptError::Canonical("final canonical render failed".into()))?;
        Ok(format!("sha256:{}", Sha256Hex(&canonical).value()))
    }

    /// Phase 1: the serving/coordinating peer signs.
    pub fn sign_server(&mut self, key: &SigningKey) -> Result<(), ReceiptError> {
        let preimage = self
            .phase1_canonical()
            .ok_or_else(|| ReceiptError::Canonical("phase-1 canonical render failed".into()))?;
        self.server_signature = B64.encode(key.sign(preimage.as_bytes()).to_bytes());
        Ok(())
    }

    /// Phase 2: the requesting peer counter-signs.
    pub fn sign_requester(&mut self, key: &SigningKey) -> Result<(), ReceiptError> {
        let preimage = self
            .phase2_canonical()
            .ok_or_else(|| ReceiptError::Canonical("phase-2 canonical render failed".into()))?;
        self.requester_signature = B64.encode(key.sign(preimage.as_bytes()).to_bytes());
        Ok(())
    }

    /// Verifies both signatures against the enrolled keys of the signing
    /// peers (the caller maps roles to keys).
    pub fn verify_signatures(
        &self,
        server_key: &VerifyingKey,
        requester_key: &VerifyingKey,
    ) -> Result<(), ReceiptError> {
        let phase1 = self
            .phase1_canonical()
            .ok_or_else(|| ReceiptError::Canonical("phase-1 canonical render failed".into()))?;
        let server_sig = decode_sig(&self.server_signature, "server")?;
        server_key
            .verify(phase1.as_bytes(), &server_sig)
            .map_err(|_| ReceiptError::Signature("server signature invalid".into()))?;
        let phase2 = self
            .phase2_canonical()
            .ok_or_else(|| ReceiptError::Canonical("phase-2 canonical render failed".into()))?;
        let requester_sig = decode_sig(&self.requester_signature, "requester")?;
        requester_key
            .verify(phase2.as_bytes(), &requester_sig)
            .map_err(|_| ReceiptError::Signature("requester signature invalid".into()))?;
        Ok(())
    }

    /// Grant exclusion (ADR-030 §4): the peers this receipt grants
    /// accounting to — everyone EXCEPT installations equal to the
    /// requesting installation (self-work contributes zero). Sybil-ring
    /// diversity is tracker-side knowledge (subnet/ASN), not in the
    /// object; the tracker applies it at intake on top of this.
    pub fn granted_peers(&self, requesting_installation: &str) -> Vec<&ReceiptPeer> {
        self.peers
            .iter()
            .filter(|p| p.installation_id != requesting_installation)
            .collect()
    }

    /// Per-peer attribution of the aggregate counters (the initial frozen
    /// rule, conservative by construction): integer division across the
    /// granted peers, remainder discarded — accounting can only
    /// under-count, never over-grant.
    pub fn per_peer_share(&self, granted_count: usize) -> (u64, u64) {
        if granted_count == 0 {
            return (0, 0);
        }
        (
            self.endpoint_seconds / granted_count as u64,
            self.verified_tokens / granted_count as u64,
        )
    }
}

fn decode_sig(wire: &str, which: &str) -> Result<Signature, ReceiptError> {
    let bytes = B64
        .decode(wire)
        .map_err(|_| ReceiptError::Signature(format!("{which} signature not base64url")))?;
    Signature::from_slice(&bytes)
        .map_err(|_| ReceiptError::Signature(format!("{which} signature wrong length")))
}

struct Sha256Hex<'a>(&'a str);

impl<'a> Sha256Hex<'a> {
    fn value(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}
