//! Handshake construction and verification (msp-v1 §6.1/§6.6).
//!
//! The signature is detached base64 Ed25519 over the canonical JSON (msp-v1
//! §2.2, via `modelswarm_identity::canonical_json`) of the handshake's eight
//! non-signature fields — the same binding discipline as the §2.3 envelope:
//! every identity-claiming field is inside the signed payload.
//!
//! Division of labor follows the `SignedEnvelope` precedent in
//! `modelswarm-identity`: [`verify_handshake`] checks the signature and the
//! peer-id binding only; timestamp-window and nonce-single-use enforcement
//! belong to the accepting session layer (see `Listener::accept_with`).

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signature, SigningKey};
use modelswarm_identity::{
    canonical_json, installation_id_for, new_nonce, peer_id_for, rfc3339_now, InstallationIdentity,
};
use serde_json::json;

use crate::error::HandshakeError;
use crate::message::{Handshake, WireMessage, MSP_PROTOCOL_VERSION};

impl Handshake {
    /// Builds and signs a handshake from `identity` (ADR-004 installation
    /// key). `peer_id` is the ADR-020 identity-multihash derivation and
    /// `installation_id` the hub-side derivation (both from the same key);
    /// `ts` is now (RFC 3339 UTC); `nonce` is fresh.
    pub fn build(
        identity: &InstallationIdentity,
        profile_id: &str,
        runtime_name: &str,
        runtime_build: &str,
    ) -> Self {
        let mut handshake = Self {
            protocol_version: MSP_PROTOCOL_VERSION.to_string(),
            peer_id: identity.peer_id(),
            installation_id: identity.installation_id(),
            profile_id: profile_id.to_string(),
            runtime_name: runtime_name.to_string(),
            runtime_build: runtime_build.to_string(),
            ts: rfc3339_now(),
            nonce: new_nonce(),
            signature: String::new(),
        };
        sign(&mut handshake, identity);
        handshake
    }
}

/// Signs `handshake` in place with `identity`.
fn sign(handshake: &mut Handshake, identity: &InstallationIdentity) {
    use ed25519_dalek::Signer as _;
    // `InstallationIdentity::sign_raw` is crate-private to modelswarm-identity;
    // rebuild the ed25519 key from the identity seed instead of duplicating any
    // derivation logic.
    let key = SigningKey::from_bytes(&identity.to_bytes());
    let payload = signing_payload(handshake)
        .expect("handshake payload is all strings; canonical JSON cannot fail");
    let signature = key.sign(payload.as_bytes());
    handshake.signature = BASE64_STANDARD.encode(signature.to_bytes());
}

/// The canonical JSON that is signed/verified — the eight non-signature
/// fields, keys sorted per msp-v1 §2.2.
fn signing_payload(handshake: &Handshake) -> Option<String> {
    canonical_json(&json!({
        "protocol_version": handshake.protocol_version,
        "peer_id": handshake.peer_id,
        "installation_id": handshake.installation_id,
        "profile_id": handshake.profile_id,
        "runtime_name": handshake.runtime_name,
        "runtime_build": handshake.runtime_build,
        "ts": handshake.ts,
        "nonce": handshake.nonce,
    }))
}

/// Verifies a handshake against the expected public key.
///
/// Checks, in order:
///
/// 1. **`MissingFields`** — `msg` is a handshake variant, the protocol
///    version is `"1"`, the identity fields are non-empty, and the signature
///    decodes as 64 bytes of base64.
/// 2. **`WrongPeer`** — `installation_id` and `peer_id` both derive from
///    `expected_pubkey` (msp-v1 §6.6: the handshake peer id MUST equal the
///    authenticated remote peer; in the staged backend the expected key plays
///    that role).
/// 3. **`BadSignature`** — the Ed25519 signature verifies over the canonical
///    JSON of the eight signed fields.
///
/// Timestamp-window and nonce replay checks are deliberately NOT here (same
/// split as `SignedEnvelope::verify`): they need the receiver's clock/nonce
/// cache and are enforced by `Listener::accept_with`.
pub fn verify_handshake(
    msg: &WireMessage,
    expected_pubkey: &ed25519_dalek::VerifyingKey,
) -> Result<(), HandshakeError> {
    let WireMessage::Handshake(h) = msg else {
        return Err(HandshakeError::MissingFields);
    };
    if h.protocol_version != MSP_PROTOCOL_VERSION {
        return Err(HandshakeError::MissingFields);
    }
    for field in [
        &h.peer_id,
        &h.installation_id,
        &h.profile_id,
        &h.ts,
        &h.nonce,
        &h.signature,
    ] {
        if field.is_empty() {
            return Err(HandshakeError::MissingFields);
        }
    }
    let Ok(sig_bytes) = BASE64_STANDARD.decode(&h.signature) else {
        return Err(HandshakeError::MissingFields);
    };
    if sig_bytes.len() != 64 {
        return Err(HandshakeError::MissingFields);
    }

    // Peer binding (§6.6, ADR-020): both public labels must derive from the
    // expected key — `installation_id` = base58(sha256(pubkey)) and `peer_id`
    // = base58(0x12 0x20 ‖ sha256(pubkey)). The Phase B–E placeholder
    // equality (peer_id == installation_id) is gone; the multihash binding
    // is the contract now.
    let expected_installation = installation_id_for(&expected_pubkey.to_bytes());
    let expected_peer = peer_id_for(&expected_pubkey.to_bytes());
    if h.installation_id != expected_installation || h.peer_id != expected_peer {
        return Err(HandshakeError::WrongPeer);
    }

    let payload = signing_payload(h).ok_or(HandshakeError::MissingFields)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| HandshakeError::MissingFields)?;
    use ed25519_dalek::Verifier as _;
    expected_pubkey
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| HandshakeError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{HandshakeAck, TokenDelta};

    fn peer(seed: u8) -> InstallationIdentity {
        InstallationIdentity::from_bytes(&[seed; 32])
    }

    fn signed_wire(seed: u8) -> WireMessage {
        WireMessage::Handshake(Handshake::build(
            &peer(seed),
            "msp:sim-mock:v1",
            "llama.cpp",
            "b1234",
        ))
    }

    #[test]
    fn build_then_verify_succeeds() {
        let identity = peer(1);
        let wire = signed_wire(1);
        assert!(verify_handshake(&wire, &identity.verifying_key()).is_ok());
    }

    #[test]
    fn signature_covers_every_identity_field() {
        for tamper in [
            |h: &mut Handshake| h.protocol_version = "2".into(),
            |h: &mut Handshake| h.peer_id = "attacker".into(),
            |h: &mut Handshake| h.installation_id = "attacker".into(),
            |h: &mut Handshake| h.profile_id = "msp:other:v1".into(),
            |h: &mut Handshake| h.runtime_name = "rogue".into(),
            |h: &mut Handshake| h.runtime_build = "9999".into(),
            |h: &mut Handshake| h.ts = "2020-01-01T00:00:00Z".into(),
            |h: &mut Handshake| h.nonce = "deadbeef".repeat(4),
            |h: &mut Handshake| h.signature = BASE64_STANDARD.encode([0u8; 64]),
        ] {
            let identity = peer(2);
            let WireMessage::Handshake(mut h) = signed_wire(2) else {
                unreachable!()
            };
            tamper(&mut h);
            let err = verify_handshake(&WireMessage::Handshake(h), &identity.verifying_key())
                .unwrap_err();
            // A tampered *signature value* is BadSignature by construction;
            // tampering any signed field makes verification fail (wrong
            // protocol version surfaces as MissingFields per its §6.5 fold).
            assert!(
                matches!(
                    err,
                    HandshakeError::BadSignature
                        | HandshakeError::WrongPeer
                        | HandshakeError::MissingFields
                ),
                "tampered handshake unexpectedly accepted: {err:?}"
            );
            assert!(
                verify_handshake(
                    &WireMessage::Handshake(Handshake::build(
                        &identity,
                        "msp:sim-mock:v1",
                        "llama.cpp",
                        "b1234"
                    )),
                    &identity.verifying_key()
                )
                .is_ok(),
                "control: untampered handshake must still verify"
            );
        }
    }

    #[test]
    fn wrong_expected_key_is_wrong_peer() {
        let wire = signed_wire(3);
        let stranger = peer(4);
        assert_eq!(
            verify_handshake(&wire, &stranger.verifying_key()).unwrap_err(),
            HandshakeError::WrongPeer
        );
    }

    #[test]
    fn missing_fields_and_wrong_variant() {
        let identity = peer(5);
        let WireMessage::Handshake(mut h) = signed_wire(5) else {
            unreachable!()
        };
        h.signature = String::new();
        assert_eq!(
            verify_handshake(&WireMessage::Handshake(h), &identity.verifying_key()).unwrap_err(),
            HandshakeError::MissingFields
        );
        let not_a_handshake = WireMessage::TokenDelta(TokenDelta {
            request_id: "r".into(),
            delta: "x".into(),
            index: 0,
        });
        assert_eq!(
            verify_handshake(&not_a_handshake, &identity.verifying_key()).unwrap_err(),
            HandshakeError::MissingFields
        );
        let ack = WireMessage::HandshakeAck(HandshakeAck {
            ok: true,
            error_code: String::new(),
            queue_position: 0,
            eta_ms: 0,
        });
        assert_eq!(
            verify_handshake(&ack, &identity.verifying_key()).unwrap_err(),
            HandshakeError::MissingFields
        );
    }
}
