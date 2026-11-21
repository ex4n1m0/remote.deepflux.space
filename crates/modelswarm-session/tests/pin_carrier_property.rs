//! ADR-036 §6 property/pin tests for the pin carrier (per-push,
//! default features): the strict-schema discipline, the §1-rule-4
//! signature preimage, the commitment construction, the pure
//! validation core's first-failure semantics, and the extended
//! `SessionReject` vocabulary — all at the session-crate level. The
//! transport-facing admission order and the serve-loop lifecycle pin
//! land with the Windows Product wiring; the golden vectors
//! (`protocol/vectors/pin-carrier-*.json`) byte-pin the canonical
//! wire form this suite exercises structurally.

use modelswarm_identity::InstallationIdentity;
use modelswarm_session::negotiation::{
    pin_commitment_of, PinCarrierError, SessionReject, SessionRejectReason, WirePinCarrier,
    COOPERATIVE_PROTOCOL_VERSION,
};
use modelswarm_session::verifydrafts::{
    sign_pin_carrier, signing_preimage, verify_pin_carrier_signature,
};

fn fixture_carrier() -> WirePinCarrier {
    WirePinCarrier {
        session_id: "sess-pin-1".to_string(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
        seq: 1,
        round: 0,
        profile_id: format!("msp1:{}", "ab".repeat(32)),
        generation_params_hash: "cd".repeat(32),
        prompt_tokens: vec![11, 22, 33, 44],
        pin_commitment: pin_commitment_of(&[11, 22, 33, 44]),
        nonce: "nonce-pin-1".to_string(),
        deadline_ms: 2_500,
        sender: "coordinator".to_string(),
        signature: String::new(),
    }
}

#[test]
fn commitment_is_the_adr034_rule3_construction() {
    // hex(sha256(LE-u32 each)), NO parent — pinned against an
    // independent construction so the helper cannot drift.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for t in [11u32, 22, 33, 44] {
        hasher.update(t.to_le_bytes());
    }
    assert_eq!(
        pin_commitment_of(&[11, 22, 33, 44]),
        hex::encode(hasher.finalize())
    );
    // Order-sensitivity: a different token order is a different
    // commitment (the ids ARE the contract).
    assert_ne!(
        pin_commitment_of(&[11, 22, 33, 44]),
        pin_commitment_of(&[44, 33, 22, 11])
    );
}

#[test]
fn validate_passes_the_canonical_fixture_and_fails_first_per_field() {
    assert_eq!(fixture_carrier().validate(), Ok(()));

    let mut carrier = fixture_carrier();
    carrier.protocol_version = "msp-cooperative-v0".to_string();
    assert_eq!(carrier.validate(), Err(PinCarrierError::ProtocolVersion));

    let mut carrier = fixture_carrier();
    carrier.round = 1;
    assert_eq!(
        carrier.validate(),
        Err(PinCarrierError::RoundNotSessionOpen)
    );

    let mut carrier = fixture_carrier();
    carrier.seq = 0;
    assert_eq!(carrier.validate(), Err(PinCarrierError::SeqBaseline));

    let mut carrier = fixture_carrier();
    carrier.prompt_tokens.clear();
    // An empty payload no longer matches the commitment either — the
    // schema failure (empty tokens) is the honest first failure.
    assert_eq!(carrier.validate(), Err(PinCarrierError::EmptyPromptTokens));

    let mut carrier = fixture_carrier();
    carrier.generation_params_hash = "XYZ".to_string();
    assert_eq!(carrier.validate(), Err(PinCarrierError::ParamsHashForm));

    let mut carrier = fixture_carrier();
    carrier.pin_commitment = "AB".repeat(32); // uppercase: not the bare form
    assert_eq!(carrier.validate(), Err(PinCarrierError::CommitmentForm));

    // The commitment-mismatch core (ADR-036 §3.2, the pin_mismatch
    // admission check): a well-formed commitment that does NOT bind
    // this payload.
    let mut carrier = fixture_carrier();
    carrier.pin_commitment = pin_commitment_of(&[1, 2, 3]);
    assert_eq!(carrier.validate(), Err(PinCarrierError::CommitmentMismatch));
}

#[test]
fn strict_schema_rejects_unknown_fields() {
    let value = serde_json::to_value(fixture_carrier()).unwrap();
    let mut lax = value.clone();
    lax.as_object_mut()
        .unwrap()
        .insert("extra".into(), 1.into());
    // The carrier is deny_unknown_fields: the strict form parses, the
    // unknown-field form fails deserialization.
    serde_json::from_value::<WirePinCarrier>(value).expect("the strict form parses");
    serde_json::from_value::<WirePinCarrier>(lax)
        .expect_err("unknown fields must fail the strict carrier schema");
}

#[test]
fn signature_preimage_omits_signature_entirely_and_signs_round_trip() {
    let seed: [u8; 32] = hex::decode("11".repeat(32)).unwrap().try_into().unwrap();
    let coordinator = InstallationIdentity::from_bytes(&seed);

    let mut carrier = fixture_carrier();
    carrier.sender = coordinator.installation_id();
    carrier.signature = sign_pin_carrier(&carrier, &coordinator).expect("signs");

    // §1 rule 4: the preimage omits `signature` ENTIRELY (not null, not
    // "").
    let preimage = signing_preimage(&carrier).expect("canonical preimage");
    assert!(!preimage.contains("\"signature\""));

    // Round trip through the crate's own verification discipline
    // (sender binding first, then the Ed25519 check).
    use modelswarm_transport::ed25519_dalek::SigningKey;
    let verifying = SigningKey::from_bytes(&seed).verifying_key();
    assert!(verify_pin_carrier_signature(&carrier, &verifying).is_ok());

    // A wrong sender breaks the binding FIRST (fail-closed), and a
    // corrupted signature fails verification.
    let mut forged = carrier.clone();
    forged.sender = "someone-else".to_string();
    assert!(verify_pin_carrier_signature(&forged, &verifying).is_err());
    let mut tampered = carrier.clone();
    let mut sig_chars: Vec<u8> = tampered.signature.bytes().collect();
    sig_chars[10] = if sig_chars[10] == b'A' { b'B' } else { b'A' };
    tampered.signature = String::from_utf8(sig_chars).unwrap();
    assert!(verify_pin_carrier_signature(&tampered, &verifying).is_err());
}

#[test]
fn reject_vocabulary_extends_with_the_two_adr036_reasons() {
    // The frozen strings — one vocabulary names one fact: pin_mismatch
    // deliberately matches the probe verdict label;
    // content_carriage_refused is its own fact (a refusal is not a
    // mismatch).
    assert_eq!(SessionRejectReason::PinMismatch.as_str(), "pin_mismatch");
    assert_eq!(
        SessionRejectReason::ContentCarriageRefused.as_str(),
        "content_carriage_refused"
    );
    // Wire round trip (snake_case canonicalization).
    let reject = SessionReject {
        session_id: "sess-pin-1".to_string(),
        protocol_version: COOPERATIVE_PROTOCOL_VERSION.to_string(),
        reason: SessionRejectReason::ContentCarriageRefused,
    };
    let value = serde_json::to_value(&reject).unwrap();
    assert_eq!(value["reason"], "content_carriage_refused");
    let back: SessionReject = serde_json::from_value(value).unwrap();
    assert_eq!(back.reason, SessionRejectReason::ContentCarriageRefused);
}
