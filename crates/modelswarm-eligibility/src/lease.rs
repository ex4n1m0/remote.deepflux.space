//! `EligibilityLease` (ADR-012): the hub-signed artifact that lets a peer
//! host and consume a specific model profile.

use std::fmt;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::canonical::canonical_json;

/// Accepted clock skew for `expires_at` checks at serving peers
/// (msp-v1 §6.6, frozen: ±120 s).
pub const EXPIRY_CLOCK_SKEW_SECS: i64 = 120;

/// Grace window past the peer's lease expiry that a token may not outlive
/// (ADR-012 / msp-v1 §5: "capped at the lease expiry plus a 60 s grace").
pub const LEASE_CAP_GRACE_SECS: i64 = 60;

/// Measured serving capacity class (ADR-012). Assigned by the hub from
/// challenge timings and hardware evidence; never raised by self-report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityClass {
    /// CPU-only serving.
    Cpu,
    /// Entry GPU, <= 8 GB VRAM.
    GpuEntry,
    /// Mid GPU, 8-24 GB VRAM.
    GpuMid,
    /// High-end GPU, > 24 GB VRAM.
    GpuHigh,
}

/// Errors from [`EligibilityLease::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    /// The wire form could not be decoded (bad base64url / json / shape).
    BadWireLease(String),
    /// The detached signature did not verify against the hub key — this
    /// includes any tampering with a signed field (the payload recomputed
    /// from the struct no longer matches the signature).
    InvalidSignature,
    /// `model_profile_id` is not `msp1:` + 64 lowercase hex (ADR-011).
    InvalidProfileId(String),
    /// `now` is past `expires_at` by more than the clock-skew allowance.
    Expired {
        /// Seconds past expiry (beyond the skew allowance).
        overdue_secs: i64,
    },
    /// `expires_at` is more than [`LEASE_CAP_GRACE_SECS`] after
    /// `lease_expires_at` — the frozen cap a lease may never exceed.
    ExceedsLeaseCap {
        /// Seconds by which the cap is exceeded.
        over_secs: i64,
    },
    /// An RFC 3339 timestamp failed to parse (fail closed).
    BadTimestamp(String),
}

impl fmt::Display for LeaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeaseError::BadWireLease(why) => write!(f, "malformed wire lease: {why}"),
            LeaseError::InvalidSignature => write!(f, "lease signature invalid"),
            LeaseError::InvalidProfileId(v) => write!(f, "invalid model profile id: {v:?}"),
            LeaseError::Expired { overdue_secs } => {
                write!(f, "lease expired {overdue_secs}s beyond the skew allowance")
            }
            LeaseError::ExceedsLeaseCap { over_secs } => write!(
                f,
                "expires_at exceeds lease_expires_at + {LEASE_CAP_GRACE_SECS}s by {over_secs}s"
            ),
            LeaseError::BadTimestamp(v) => write!(f, "unparseable RFC 3339 timestamp: {v:?}"),
        }
    }
}

impl std::error::Error for LeaseError {}

/// The eligibility lease (ADR-012; renames msp-v1 §5's "capability token").
///
/// `issuer_signature` is a detached base64 Ed25519 signature by the hub
/// signing key over the canonical JSON of every other field. It is
/// `skip_serializing` so `serde_json::to_value(lease)` yields exactly the
/// signed payload.
///
/// Fields are public wire fields; integrity is enforced by
/// [`verify`](EligibilityLease::verify), not by construction — a lease with
/// arbitrary contents exists, but only hub-signed, unexpired, in-cap,
/// `msp1:`-profile leases verify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EligibilityLease {
    /// Bound libp2p peer id label (base58 SHA-256 of the peer's public key).
    pub peer_id: String,
    /// Bound installation id (base58 SHA-256 of the signing key).
    pub installation_id: String,
    /// Manifest-derived profile id, `msp1:<64 hex>` (ADR-011).
    pub model_profile_id: String,
    /// RFC 3339 UTC issue time.
    pub issued_at: String,
    /// RFC 3339 UTC expiry; capped at `lease_expires_at` + 60 s.
    pub expires_at: String,
    /// RFC 3339 UTC expiry of the peer's underlying tracker lease.
    pub lease_expires_at: String,
    /// Peer may host this profile.
    pub can_host: bool,
    /// Peer may consume this profile.
    pub can_consume: bool,
    /// Serving slots granted (>= 1 while eligible).
    pub slots: u8,
    /// Measured capacity class.
    pub verified_capacity: CapacityClass,
    /// ADR-043 fair-queueing weight class (1 base, 2 / 4 for sustained
    /// contributors, bucketed by the tracker from decayed granted tok/s).
    /// Serialized ONLY when it differs from the default so the canonical
    /// payload — and therefore the hub signature — of a base lease is
    /// byte-identical before and after this field existed (old binaries
    /// verify base leases unchanged; a >1 weight is meaningful only to
    /// ADR-043-aware serving peers).
    #[serde(
        default = "default_queue_weight",
        skip_serializing_if = "is_base_queue_weight"
    )]
    pub queue_weight: u8,
    /// Revocation/audit sweep counter; leases older than the tracker's
    /// current epoch for the peer are rejected without a lookup.
    pub audit_epoch: u64,
    /// Opaque id of the passed hosting challenge.
    pub challenge_id: String,
    /// Token identity for issuance-dedup and revocation notices.
    pub nonce: String,
    /// Detached hub signature (base64 Ed25519 over the canonical payload).
    /// Not part of the serde form (the signature travels detached); it
    /// defaults to empty and is re-attached after transport.
    #[serde(skip_serializing, default)]
    pub issuer_signature: String,
}

/// ADR-043 base queue weight: every valid lease carries at least 1.
fn default_queue_weight() -> u8 {
    1
}

fn is_base_queue_weight(w: &u8) -> bool {
    *w == default_queue_weight()
}

impl EligibilityLease {
    /// Issues (signs) a lease with the hub signing key.
    ///
    /// `issue` is a signer's helper: it signs the given field values as-is
    /// and performs no policy validation, because a well-formed
    /// policy-violating lease is exactly what [`verify`](Self::verify) must
    /// catch at every enforcing peer (a buggy or malicious hub must not be
    /// able to produce something peers accept silently). The hub caller is
    /// responsible for passing sane values.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        peer_id: impl Into<String>,
        installation_id: impl Into<String>,
        model_profile_id: impl Into<String>,
        issued_at: impl Into<String>,
        expires_at: impl Into<String>,
        lease_expires_at: impl Into<String>,
        can_host: bool,
        can_consume: bool,
        slots: u8,
        verified_capacity: CapacityClass,
        audit_epoch: u64,
        challenge_id: impl Into<String>,
        nonce: impl Into<String>,
        queue_weight: u8,
        hub_key: &SigningKey,
    ) -> Self {
        let mut lease = Self {
            peer_id: peer_id.into(),
            installation_id: installation_id.into(),
            model_profile_id: model_profile_id.into(),
            issued_at: issued_at.into(),
            expires_at: expires_at.into(),
            lease_expires_at: lease_expires_at.into(),
            can_host,
            can_consume,
            slots,
            verified_capacity,
            audit_epoch,
            challenge_id: challenge_id.into(),
            nonce: nonce.into(),
            queue_weight: queue_weight.max(default_queue_weight()),
            issuer_signature: String::new(),
        };
        let signature = hub_key.sign(lease.signed_payload().as_bytes());
        lease.issuer_signature = BASE64_STANDARD.encode(signature.to_bytes());
        lease
    }

    /// The canonical JSON covered by the signature (every field except the
    /// signature itself, keys sorted, msp-v1 §2.2).
    pub fn signed_payload(&self) -> String {
        let value = serde_json::to_value(self).expect("lease serializes to JSON");
        canonical_json(&value).expect("lease payload contains no floats by type definition")
    }

    /// Full verification against the hub public key at time `now`
    /// (RFC 3339 UTC). Checks, in order:
    ///
    /// 1. the detached signature over the canonical payload — this binds
    ///    `peer_id`, `installation_id` and every other field, so a lease
    ///    copied to or edited for another peer fails here;
    /// 2. `model_profile_id` is `msp1:` + 64 lowercase hex (ADR-011);
    /// 3. `now` is not past `expires_at` by more than
    ///    [`EXPIRY_CLOCK_SKEW_SECS`];
    /// 4. the frozen cap `expires_at <= lease_expires_at +
    ///    [`LEASE_CAP_GRACE_SECS`]`.
    pub fn verify(&self, hub_pubkey: &VerifyingKey, now: &str) -> Result<(), LeaseError> {
        // 1. Signature over the signed payload (all fields except the
        //    detached signature itself).
        let payload = self.signed_payload();
        let sig_bytes = BASE64_STANDARD
            .decode(&self.issuer_signature)
            .map_err(|_| LeaseError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| LeaseError::InvalidSignature)?;
        if hub_pubkey.verify(payload.as_bytes(), &signature).is_err() {
            return Err(LeaseError::InvalidSignature);
        }

        // 2. Profile id format (ADR-11 derived ids only).
        if !is_valid_profile_id(&self.model_profile_id) {
            return Err(LeaseError::InvalidProfileId(self.model_profile_id.clone()));
        }

        // 3. Expiry, with the frozen clock-skew allowance.
        let expires_at = parse_rfc3339(&self.expires_at)?;
        let now = parse_rfc3339(now)?;
        let overdue = (now - expires_at).whole_seconds() - EXPIRY_CLOCK_SKEW_SECS;
        if overdue > 0 {
            return Err(LeaseError::Expired {
                overdue_secs: overdue,
            });
        }

        // 4. Lease-capped TTL.
        let lease_expires_at = parse_rfc3339(&self.lease_expires_at)?;
        let over = (expires_at - lease_expires_at).whole_seconds() - LEASE_CAP_GRACE_SECS;
        if over > 0 {
            return Err(LeaseError::ExceedsLeaseCap { over_secs: over });
        }

        Ok(())
    }
}

impl EligibilityLease {
    /// Decodes the transport wire form `base64url(json).base64url(sig)`
    /// (the tracker's issuance format) and re-attaches the detached
    /// signature so [`Self::verify`] can check it.
    pub fn from_wire(wire: &str) -> Result<Self, LeaseError> {
        let (payload, sig) = wire
            .split_once('.')
            .ok_or(LeaseError::BadWireLease("missing '.' separator".into()))?;
        let decode = |part: &str| {
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(part)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(part))
        };
        let json =
            decode(payload).map_err(|e| LeaseError::BadWireLease(format!("payload: {e}")))?;
        let sig = decode(sig).map_err(|e| LeaseError::BadWireLease(format!("signature: {e}")))?;
        let mut lease: EligibilityLease = serde_json::from_slice(&json)
            .map_err(|e| LeaseError::BadWireLease(format!("json: {e}")))?;
        lease.issuer_signature = BASE64_STANDARD.encode(sig);
        Ok(lease)
    }

    /// Encodes the wire form `base64url(json).base64url(sig-bytes)`.
    /// The signature travels as raw bytes in URL-safe base64 (the issuer
    /// field's STANDARD alphabet never crosses the wire).
    pub fn to_wire(&self) -> String {
        use base64::Engine as _;
        let json = serde_json::to_vec(self).expect("lease serializes");
        let sig_bytes = BASE64_STANDARD
            .decode(&self.issuer_signature)
            .expect("issuer_signature is standard base64");
        format!(
            "{}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig_bytes)
        )
    }
}

fn parse_rfc3339(ts: &str) -> Result<OffsetDateTime, LeaseError> {
    OffsetDateTime::parse(ts, &Rfc3339).map_err(|_| LeaseError::BadTimestamp(ts.to_string()))
}

fn is_valid_profile_id(id: &str) -> bool {
    let Some(hex_part) = id.strip_prefix("msp1:") else {
        return false;
    };
    hex_part.len() == 64
        && hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn hub() -> SigningKey {
        SigningKey::generate(&mut rand_core::OsRng)
    }

    fn ts(epoch: i64) -> String {
        OffsetDateTime::from_unix_timestamp(epoch)
            .unwrap()
            .format(&Rfc3339)
            .unwrap()
    }

    const T0: i64 = 1_800_000_000;
    const PROFILE: &str = "msp1:229e17c8c6eb23101c0f7f3a005c384a0a4d27a876903ee677f2342ec818e933";

    fn valid_lease(key: &SigningKey) -> EligibilityLease {
        EligibilityLease::issue(
            "peer-a",
            "install-a",
            PROFILE,
            ts(T0),
            ts(T0 + 90),
            ts(T0 + 60),
            true,
            true,
            2,
            CapacityClass::GpuMid,
            7,
            "challenge-1",
            "nonce-1",
            1,
            key,
        )
    }

    #[test]
    fn issue_verify_happy_path() {
        let key = hub();
        let lease = valid_lease(&key);
        assert!(lease.verify(&key.verifying_key(), &ts(T0 + 45)).is_ok());
        // Signature field is populated and the payload excludes it.
        assert!(!lease.issuer_signature.is_empty());
        let payload: serde_json::Value = serde_json::from_str(&lease.signed_payload()).unwrap();
        assert!(payload.get("issuer_signature").is_none());
        assert_eq!(payload["verified_capacity"], serde_json::json!("gpu_mid"));
        assert_eq!(payload["slots"], serde_json::json!(2));
        assert_eq!(payload["audit_epoch"], serde_json::json!(7));
    }

    #[test]
    fn copied_to_other_peer_fails() {
        let key = hub();
        let mut lease = valid_lease(&key);
        // A peer relabels the lease for itself: peer_id is inside the signed
        // payload, so verify() (which recomputes the payload from the struct
        // and checks the hub signature over it) rejects it.
        lease.peer_id = "peer-b".to_string();
        assert_eq!(
            lease.verify(&key.verifying_key(), &ts(T0 + 45)),
            Err(LeaseError::InvalidSignature)
        );
        // Same for installation_id and every other signed field.
        let mut lease = valid_lease(&key);
        lease.installation_id = "install-b".to_string();
        assert_eq!(
            lease.verify(&key.verifying_key(), &ts(T0 + 45)),
            Err(LeaseError::InvalidSignature)
        );
        let mut lease = valid_lease(&key);
        lease.slots = 8;
        assert_eq!(
            lease.verify(&key.verifying_key(), &ts(T0 + 45)),
            Err(LeaseError::InvalidSignature)
        );
    }

    #[test]
    fn wrong_hub_key_fails() {
        let key = hub();
        let lease = valid_lease(&key);
        let other = hub();
        assert_eq!(
            lease.verify(&other.verifying_key(), &ts(T0 + 45)),
            Err(LeaseError::InvalidSignature)
        );
    }

    #[test]
    fn garbage_signature_fails() {
        let key = hub();
        let mut lease = valid_lease(&key);
        lease.issuer_signature = "not base64!!".to_string();
        assert_eq!(
            lease.verify(&key.verifying_key(), &ts(T0 + 45)),
            Err(LeaseError::InvalidSignature)
        );
        lease.issuer_signature = BASE64_STANDARD.encode([0u8; 64]);
        assert_eq!(
            lease.verify(&key.verifying_key(), &ts(T0 + 45)),
            Err(LeaseError::InvalidSignature)
        );
    }

    #[test]
    fn expired_beyond_skew_is_rejected_within_skew_accepted() {
        let key = hub();
        let lease = valid_lease(&key); // expires_at = T0 + 90
                                       // Inside the ±120 s skew window: accepted.
        assert!(lease
            .verify(&key.verifying_key(), &ts(T0 + 90 + 120))
            .is_ok());
        // One second beyond expiry + skew: rejected with the overdue delta.
        assert_eq!(
            lease.verify(&key.verifying_key(), &ts(T0 + 90 + 121)),
            Err(LeaseError::Expired { overdue_secs: 1 })
        );
        assert_eq!(
            lease.verify(&key.verifying_key(), &ts(T0 + 600)),
            Err(LeaseError::Expired { overdue_secs: 390 })
        );
    }

    #[test]
    fn exceeds_lease_cap_is_rejected() {
        let key = hub();
        // expires_at is 1 s beyond lease_expires_at + 60 s grace.
        let lease = EligibilityLease::issue(
            "peer-a",
            "install-a",
            PROFILE,
            ts(T0),
            ts(T0 + 61),
            ts(T0),
            true,
            true,
            1,
            CapacityClass::Cpu,
            1,
            "c",
            "n",
            1,
            &key,
        );
        assert_eq!(
            lease.verify(&key.verifying_key(), &ts(T0 + 10)),
            Err(LeaseError::ExceedsLeaseCap { over_secs: 1 })
        );
        // Exactly at the cap (grace included) is accepted.
        let at_cap = EligibilityLease::issue(
            "peer-a",
            "install-a",
            PROFILE,
            ts(T0),
            ts(T0 + 60),
            ts(T0),
            true,
            true,
            1,
            CapacityClass::Cpu,
            1,
            "c",
            "n2",
            1,
            &key,
        );
        assert!(at_cap.verify(&key.verifying_key(), &ts(T0 + 10)).is_ok());
    }

    #[test]
    fn non_msp1_profile_id_is_rejected() {
        let key = hub();
        for bad in [
            "msp:qwen3-4b:q4_k_m:v1", // legacy human-minted shape
            "msp1:NOTHEX",            // not hex
            "msp1:229E17C8C6EB23101C0F7F3A005C384A0A4D27A876903EE677F2342EC818E933", // uppercase
            "229e17c8c6eb23101c0f7f3a005c384a0a4d27a876903ee677f2342ec818e933", // no prefix
            "msp1:",                  // empty digest
            "msp1:229e17c8",          // too short
        ] {
            let lease = EligibilityLease::issue(
                "peer-a",
                "install-a",
                bad,
                ts(T0),
                ts(T0 + 90),
                ts(T0 + 60),
                true,
                true,
                1,
                CapacityClass::Cpu,
                1,
                "c",
                "n",
                1,
                &key,
            );
            assert_eq!(
                lease.verify(&key.verifying_key(), &ts(T0 + 10)),
                Err(LeaseError::InvalidProfileId(bad.to_string())),
                "must reject {bad}"
            );
        }
    }

    #[test]
    fn unparseable_timestamps_fail_closed() {
        let key = hub();
        // Signed lease with garbage timestamps: the signature is valid, so
        // verification reaches the timestamp checks and fails there.
        let broken = EligibilityLease::issue(
            "peer-a",
            "install-a",
            PROFILE,
            "yesterday",
            "tomorrow",
            "someday",
            true,
            true,
            1,
            CapacityClass::Cpu,
            1,
            "c",
            "n",
            1,
            &key,
        );
        assert_eq!(
            broken.verify(&key.verifying_key(), &ts(T0)),
            Err(LeaseError::BadTimestamp("tomorrow".to_string()))
        );
        // A garbage `now` on an otherwise valid lease also fails closed.
        let lease = valid_lease(&key);
        assert_eq!(
            lease.verify(&key.verifying_key(), "not-a-time"),
            Err(LeaseError::BadTimestamp("not-a-time".to_string()))
        );
    }

    #[test]
    fn lease_serde_form_is_the_signed_payload_plus_detached_signature() {
        let key = hub();
        let lease = valid_lease(&key);

        // The serde form IS the signed payload (no issuer_signature field).
        let json = serde_json::to_string(&lease).unwrap();
        assert!(!json.contains("issuer_signature"), "{json}");
        assert_eq!(
            crate::canonical::canonical_json(
                &serde_json::from_str::<serde_json::Value>(&json).unwrap()
            )
            .unwrap(),
            lease.signed_payload()
        );

        // Deserialization yields the payload with an empty detached
        // signature, which must fail verification until re-attached.
        let mut back: EligibilityLease = serde_json::from_str(&json).unwrap();
        assert_eq!(back.issuer_signature, "");
        assert_eq!(
            back.verify(&key.verifying_key(), &ts(T0 + 45)),
            Err(LeaseError::InvalidSignature)
        );
        back.issuer_signature = lease.issuer_signature.clone();
        assert_eq!(back, lease);
        assert!(back.verify(&key.verifying_key(), &ts(T0 + 45)).is_ok());
    }

    #[test]
    fn capacity_classes_serialize_snake_case() {
        assert_eq!(
            serde_json::to_value(CapacityClass::Cpu).unwrap(),
            serde_json::json!("cpu")
        );
        assert_eq!(
            serde_json::to_value(CapacityClass::GpuEntry).unwrap(),
            serde_json::json!("gpu_entry")
        );
        assert_eq!(
            serde_json::to_value(CapacityClass::GpuMid).unwrap(),
            serde_json::json!("gpu_mid")
        );
        assert_eq!(
            serde_json::to_value(CapacityClass::GpuHigh).unwrap(),
            serde_json::json!("gpu_high")
        );
    }

    #[test]
    fn duration_math_for_cap_and_skew() {
        // Guards the arithmetic used in verify().
        let a = OffsetDateTime::from_unix_timestamp(T0 + 90).unwrap();
        let b = OffsetDateTime::from_unix_timestamp(T0).unwrap();
        assert_eq!((a - b).whole_seconds(), 90);
        assert_eq!((a - b), Duration::seconds(90));
    }

    // Cross-language golden vector (protocol/vectors/lease-hubkey-1.json):
    // the TS issuer (apps/tracker/lib/eligibility.ts) produced this exact
    // token with the fixture key recorded in the file. Byte-parity here is
    // the gate that would have caught the 2026-10-08 interop break (the
    // tracker issued no `lease_expires_at`, so every production lease
    // failed `from_wire` at the ADR-026 serving gate).
    #[test]
    fn golden_vector_token_from_ts_issuer_verifies() {
        let doc: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/vectors/lease-hubkey-1.json"
        ))
        .expect("vector json parses");
        let token = doc["token"].as_str().expect("token").to_string();
        let pubkey_hex = doc["signing_public_key_hex"].as_str().expect("pubkey");
        let verify_at = doc["verify_at"].as_str().expect("verify_at");

        let lease = EligibilityLease::from_wire(&token).expect("TS-issued token parses");
        // issuer_signature is skip_serializing, so the serde form is
        // exactly the signed fields — must equal the recorded fields.
        assert_eq!(
            serde_json::to_value(&lease).expect("lease to value"),
            doc["fields"],
            "signed fields match the vector byte-for-byte"
        );

        let key_bytes: [u8; 32] = (0..32)
            .map(|i| u8::from_str_radix(&pubkey_hex[i * 2..i * 2 + 2], 16).expect("hex byte"))
            .collect::<Vec<u8>>()
            .try_into()
            .expect("32 bytes");
        let key = VerifyingKey::from_bytes(&key_bytes).expect("fixture key parses");
        lease
            .verify(&key, verify_at)
            .expect("signature + expiry + lease-cap policy verify");

        // Tampering with any byte of the signature must fail.
        let mut tampered: Vec<char> = token.chars().collect();
        let last = tampered.pop().expect("non-empty");
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        let tampered: String = tampered.into_iter().collect();
        let result = EligibilityLease::from_wire(&tampered).and_then(|l| l.verify(&key, verify_at));
        assert!(result.is_err(), "tampered token must fail verification");
    }

    #[test]
    fn adr043_base_weight_is_absent_from_the_wire_form() {
        let key = hub();
        let lease = valid_lease(&key);
        let value = serde_json::to_value(&lease).expect("lease to value");
        assert!(
            value.get("queue_weight").is_none(),
            "a base (weight 1) lease must serialize exactly like a pre-ADR-043 lease"
        );
        assert!(lease.verify(&key.verifying_key(), &ts(T0 + 10)).is_ok());
    }

    #[test]
    fn adr043_weighted_lease_carries_and_verifies_the_field() {
        let key = hub();
        let lease = EligibilityLease::issue(
            "peer-contributor",
            "install-a",
            PROFILE,
            ts(T0),
            ts(T0 + 90),
            ts(T0 + 60),
            true,
            true,
            2,
            CapacityClass::GpuMid,
            7,
            "challenge-1",
            "nonce-w",
            4,
            &key,
        );
        assert_eq!(lease.queue_weight, 4);
        let value = serde_json::to_value(&lease).expect("lease to value");
        assert_eq!(value.get("queue_weight").and_then(|v| v.as_u64()), Some(4));
        assert!(lease.verify(&key.verifying_key(), &ts(T0 + 10)).is_ok());
        // The wire round-trip preserves the weight.
        let back = EligibilityLease::from_wire(&lease.to_wire()).expect("round-trip");
        assert_eq!(back.queue_weight, 4);
    }

    #[test]
    fn adr043_pre_field_lease_json_still_parses_and_verifies() {
        let key = hub();
        let lease = valid_lease(&key);
        // Simulate a pre-ADR-043 issued token: the wire form of a base
        // lease omits queue_weight, exactly like every lease minted
        // before the field existed.
        let legacy = lease.to_wire();
        let payload = legacy.split('.').next().expect("wire token payload");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("payload decodes");
        let payload_json = String::from_utf8(decoded).expect("payload is JSON");
        assert!(
            !payload_json.contains("queue_weight"),
            "base lease wire payload is byte-shaped like a legacy token"
        );
        let parsed = EligibilityLease::from_wire(&legacy).expect("legacy token parses");
        assert_eq!(parsed.queue_weight, 1);
        // The signature computed over the (field-less) canonical payload
        // verifies, because the parsed struct re-serializes identically.
        assert!(parsed.verify(&key.verifying_key(), &ts(T0 + 10)).is_ok());
    }

    #[test]
    fn adr043_issue_clamps_zero_to_base_weight() {
        let key = hub();
        let lease = EligibilityLease::issue(
            "peer-a",
            "install-a",
            PROFILE,
            ts(T0),
            ts(T0 + 90),
            ts(T0 + 60),
            true,
            true,
            1,
            CapacityClass::Cpu,
            1,
            "c",
            "n-clamp",
            0,
            &key,
        );
        assert_eq!(lease.queue_weight, 1, "no lease may carry weight 0");
        assert!(lease.verify(&key.verifying_key(), &ts(T0 + 10)).is_ok());
    }
}
