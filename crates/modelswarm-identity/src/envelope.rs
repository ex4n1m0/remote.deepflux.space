//! Signed request envelope for hub-mutating calls (msp-v1 §2.3).
//!
//! The signature is detached base64 Ed25519 over the canonical JSON of the
//! payload object `{installation_id, method, path, ts, nonce, body_digest}`.
//! `method` and `path` are inside the signed payload, so a captured envelope
//! cannot be replayed against a different endpoint.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::canonical::canonical_json;
use crate::installation::{installation_id_for, InstallationIdentity};

/// The signed envelope traveling in the `Authorization: MSP1 …` header.
///
/// Wire field names are camelCase EXACTLY as msp-v1 §2.3 writes them
/// (`installationId`, `bodyDigest`, …) — the tracker's strict zod schema
/// rejects anything else. The signature payload uses the same names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedEnvelope {
    /// Signer's installation id (base58 SHA-256 of the public key).
    pub installation_id: String,
    /// HTTP method of the call, e.g. `POST`.
    pub method: String,
    /// Request path, e.g. `/api/v1/peers/heartbeat`.
    pub path: String,
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// Unique-per-installation random hex nonce.
    pub nonce: String,
    /// `sha256:<hex>` of the canonical body JSON (`sha256:` of the empty
    /// string for bodyless calls).
    pub body_digest: String,
    /// Detached base64 Ed25519 signature over the canonical payload.
    pub signature: String,
}

impl SignedEnvelope {
    /// Builds and signs an envelope. The signature covers the canonical JSON
    /// of the payload fields (`signature` excluded, keys sorted).
    pub fn sign(
        identity: &InstallationIdentity,
        method: impl Into<String>,
        path: impl Into<String>,
        ts: impl Into<String>,
        nonce: impl Into<String>,
        body_digest: impl Into<String>,
    ) -> Self {
        let method = method.into();
        let path = path.into();
        let ts = ts.into();
        let nonce = nonce.into();
        let body_digest = body_digest.into();
        let installation_id = identity.installation_id();
        let payload =
            payload_canonical_json(&installation_id, &method, &path, &ts, &nonce, &body_digest);
        let signature = identity.sign_raw(payload.as_bytes());
        Self {
            installation_id,
            method,
            path,
            ts,
            nonce,
            body_digest,
            signature: BASE64_STANDARD.encode(signature.to_bytes()),
        }
    }

    /// The canonical JSON that is (re)computed for verification — everything
    /// except the signature itself.
    pub fn payload_canonical_json(&self) -> String {
        payload_canonical_json(
            &self.installation_id,
            &self.method,
            &self.path,
            &self.ts,
            &self.nonce,
            &self.body_digest,
        )
    }

    /// Verifies the envelope against `pubkey`:
    ///
    /// 1. the signature over the canonical payload, and
    /// 2. that `installation_id` actually derives from `pubkey`.
    ///
    /// Both must hold; a payload signed by another key claiming this
    /// installation id fails the second check. Timestamp/nonce window checks
    /// are the server's job (they need the receiver's clock and nonce cache).
    pub fn verify(&self, pubkey: &VerifyingKey) -> bool {
        if self.installation_id != installation_id_for(&pubkey.to_bytes()) {
            return false;
        }
        let payload = self.payload_canonical_json();
        let Ok(sig_bytes) = BASE64_STANDARD.decode(&self.signature) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&sig_bytes) else {
            return false;
        };
        pubkey.verify(payload.as_bytes(), &sig).is_ok()
    }
}

fn payload_canonical_json(
    installation_id: &str,
    method: &str,
    path: &str,
    ts: &str,
    nonce: &str,
    body_digest: &str,
) -> String {
    let value = json!({
        "installationId": installation_id,
        "method": method,
        "path": path,
        "ts": ts,
        "nonce": nonce,
        "bodyDigest": body_digest,
    });
    canonical_json(&value).expect("payload contains only strings; no floats possible")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timestamp::{new_nonce, rfc3339_now};

    fn signed() -> (InstallationIdentity, SignedEnvelope) {
        let identity = InstallationIdentity::generate();
        let envelope = SignedEnvelope::sign(
            &identity,
            "POST",
            "/api/v1/peers/heartbeat",
            rfc3339_now(),
            new_nonce(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        (identity, envelope)
    }

    #[test]
    fn sign_verify_round_trip() {
        let (identity, envelope) = signed();
        assert!(envelope.verify(&identity.verifying_key()));
        assert_eq!(envelope.installation_id, identity.installation_id());
    }

    #[test]
    fn tampered_field_fails() {
        for tamper in [
            |e: &mut SignedEnvelope| e.installation_id = "claiming someone else".to_string(),
            |e: &mut SignedEnvelope| e.method = "GET".to_string(),
            |e: &mut SignedEnvelope| e.path = "/api/v1/peers/drain".to_string(),
            |e: &mut SignedEnvelope| e.ts = "2020-01-01T00:00:00Z".to_string(),
            |e: &mut SignedEnvelope| e.nonce = "deadbeef".repeat(4),
            |e: &mut SignedEnvelope| e.body_digest = "sha256:".to_string() + &"0".repeat(64),
            |e: &mut SignedEnvelope| e.signature = BASE64_STANDARD.encode([0u8; 64]),
        ] {
            let (identity, mut envelope) = signed();
            tamper(&mut envelope);
            assert!(
                !envelope.verify(&identity.verifying_key()),
                "tampered envelope must not verify: {:?}",
                envelope
            );
        }
    }

    #[test]
    fn wrong_key_fails() {
        let (_, envelope) = signed();
        let stranger = InstallationIdentity::generate();
        assert!(!envelope.verify(&stranger.verifying_key()));
    }

    #[test]
    fn signature_binds_method_and_path() {
        // The canonical payload keeps the frozen field set and sorted keys.
        let (_, envelope) = signed();
        let payload = envelope.payload_canonical_json();
        let reparsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let keys: Vec<&str> = reparsed
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![
                "bodyDigest",
                "installationId",
                "method",
                "nonce",
                "path",
                "ts"
            ]
        );
    }
}
