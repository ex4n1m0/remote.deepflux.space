//! ADR-038 golden-vector consumers: the relay admission ticket vectors
//! under `protocol/vectors/` are FROZEN — these tests pin the Rust
//! implementation to them byte-for-byte (the lease-hubkey discipline).
//! TS parity is pinned tracker-side against the same files.

use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use modelswarm_eligibility::{
    canonical_payload, sign_ticket, verify_wire, RelayAdmissionTicket, TicketError,
    RELAY_TICKET_SKEW_GRACE_SECS,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn fixture_key() -> SigningKey {
    let seed: [u8; 32] = [0x38; 32];
    SigningKey::from_bytes(&seed)
}

fn parse_ts(ts: &str) -> OffsetDateTime {
    OffsetDateTime::parse(ts, &Rfc3339).expect("vector timestamps are RFC-3339")
}

fn load(name: &str) -> serde_json::Value {
    let path = format!(
        "{}/../../protocol/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// relay-ticket-1: the accept vector — canonical bytes, signature, TTL,
/// admission deadline, and the token itself all byte-pinned.
#[test]
fn relay_ticket_1_accept() {
    let v = load("relay-ticket-1.json");
    let token = v["token"].as_str().unwrap();
    let verify_at = parse_ts(v["verify_at"].as_str().unwrap());
    let key = VerifyingKey::from(&fixture_key());
    assert_eq!(
        v["signing_public_key_hex"].as_str().unwrap(),
        hex(&key.to_bytes()),
        "the fixture key must derive the recorded public key"
    );

    let (ticket, _sig) = RelayAdmissionTicket::from_wire(token).expect("the accept vector parses");
    // Canonical bytes byte-pinned (the signature preimage).
    assert_eq!(
        canonical_payload(&ticket),
        v["canonical_json"].as_str().unwrap()
    );
    // Field round-trip against the recorded fields.
    for field in [
        "installation_id",
        "peer_id",
        "issued_at",
        "expires_at",
        "nonce",
    ] {
        assert_eq!(
            ticket_field(&ticket, field),
            v["fields"][field].as_str().unwrap()
        );
    }
    // Verify at mid-life.
    verify_wire(token, &key, verify_at).expect("accept vector verifies at verify_at");
    // Admission deadline = expires_at + skew grace.
    let deadline = ticket.admission_deadline().unwrap();
    assert_eq!(
        deadline,
        parse_ts(v["expected_admission_deadline"].as_str().unwrap())
    );
    // The exact 600 s delta is pinned by from_wire's frozen check; the
    // deadline arithmetic above is its visible consequence.
    assert_eq!(RELAY_TICKET_SKEW_GRACE_SECS, 120);
}

/// relay-ticket-2-expired: expiry (not signature) is the failure —
/// `permission_denied(202)` / `expired` in the ADR's vocabulary.
#[test]
fn relay_ticket_2_expired() {
    let v = load("relay-ticket-2-expired.json");
    let token = v["token"].as_str().unwrap();
    let key = VerifyingKey::from(&fixture_key());
    let verify_at = parse_ts(v["verify_at"].as_str().unwrap());
    let err = verify_wire(token, &key, verify_at).unwrap_err();
    assert!(
        matches!(err, TicketError::Expired { .. }),
        "expected Expired, got {err:?}"
    );
}

/// relay-ticket-forge-1: the hostile corpus, re-derived in code from the
/// accept fixture — each row asserting the ADR-038 §3.4 status+reason.
#[test]
fn relay_ticket_forge_corpus() {
    let v = load("relay-ticket-forge-1.json");
    let base = load("relay-ticket-1.json");
    let token = base["token"].as_str().unwrap().to_string();
    let key = fixture_key();
    let verifying = VerifyingKey::from(&key);
    let verify_at = parse_ts(base["verify_at"].as_str().unwrap());
    let (ticket, sig) = RelayAdmissionTicket::from_wire(&token).unwrap();
    let canonical = canonical_payload(&ticket);
    let remote = v["authenticated_remote_peer_id"].as_str().unwrap();
    let derived = v["derived_installation_id"].as_str().unwrap();

    // bad_signature: flip a char in the signature segment.
    let flipped = {
        let mut bytes = token.clone().into_bytes();
        let sig_start = token.rfind('.').unwrap() + 1;
        bytes[sig_start] = if bytes[sig_start] != b'A' { b'A' } else { b'B' };
        String::from_utf8(bytes).unwrap()
    };
    assert!(
        matches!(
            verify_wire(&flipped, &verifying, verify_at),
            Err(TicketError::InvalidSignature)
        ),
        "flipped signature segment must be bad_signature"
    );

    // wrong_key: a different ed25519 key signs the SAME canonical payload.
    let other = SigningKey::from_bytes(&[0x39; 32]);
    let forged = sign_ticket(&ticket, &other);
    assert!(matches!(
        verify_wire(&forged, &verifying, verify_at),
        Err(TicketError::InvalidSignature)
    ));

    // peer_mismatch: a valid ticket for another peer, presented as remote.
    let mut other_peer = ticket.clone();
    other_peer.peer_id = "12D3KooWErVrN9uT2YwALa5kSMkE2h6W8YmQz3Xp7F1cBdGtRv".into();
    other_peer
        .check_peer_binding(remote)
        .expect_err("peer mismatch must refuse");
    assert!(matches!(
        other_peer.check_peer_binding(remote),
        Err(TicketError::PeerMismatch { .. })
    ));
    // (the wrong-peer ticket itself is internally valid — its own binding
    // check against ITS peer passes:)
    other_peer.check_peer_binding(&other_peer.peer_id).unwrap();

    // installation_mismatch.
    assert!(matches!(
        ticket.check_installation("b58-someone-else"),
        Err(TicketError::InstallationMismatch { .. })
    ));
    ticket.check_installation(derived).unwrap();

    // Signature precedes binding (order note): a ticket that fails BOTH
    // signature and binding reports InvalidSignature.
    let mut both_bad = ticket.clone();
    both_bad.peer_id = "12D3KooWErVrN9uT2YwALa5kSMkE2h6W8YmQz3Xp7F1cBdGtRv".into();
    let both_bad_wire = sign_ticket(&both_bad, &SigningKey::from_bytes(&[0x39; 32]));
    assert!(matches!(
        verify_wire(&both_bad_wire, &verifying, verify_at),
        Err(TicketError::InvalidSignature)
    ));

    // unknown_field: strict parse refuses extra keys.
    let extra = canonical.replace("\"nonce\"", "\"extra_key\":1,\"nonce\"");
    assert!(serde_json::from_str::<RelayAdmissionTicket>(&extra).is_err());

    // missing_field: drop nonce (strict parse refuses; the wire form is
    // the canonical-without-nonce payload + the ORIGINAL signature).
    let missing_wire = format!(
        "{}.{}",
        b64(canonical_without(&canonical, "nonce").as_bytes()),
        b64(&sig)
    );
    assert!(matches!(
        RelayAdmissionTicket::from_wire(&missing_wire),
        Err(TicketError::Malformed(_))
    ));

    // non_canonical_segment: valid JSON, wrong key order.
    let reordered = format!(
        "{{\"nonce\":\"{}\",\"peer_id\":\"{}\",\"expires_at\":\"{}\",\"issued_at\":\"{}\",\"installation_id\":\"{}\"}}",
        ticket.nonce, ticket.peer_id, ticket.expires_at, ticket.issued_at, ticket.installation_id
    );
    let noncanon = format!("{}.{}", b64(reordered.as_bytes()), b64(&sig));
    assert!(malformed_result(&noncanon));

    // wrong_ttl_delta: 601 s, validly signed.
    let mut ttl_bad = ticket.clone();
    ttl_bad.expires_at = "2026-10-15T12:10:01.000Z".into();
    let ttl_wire = sign_ticket(&ttl_bad, &key);
    assert!(malformed_result(&ttl_wire));

    // nonce wrong charset (uppercase) and wrong length, validly signed.
    let mut nonce_bad = ticket.clone();
    nonce_bad.nonce = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6".into();
    assert!(malformed_result(&sign_ticket(&nonce_bad, &key)));
    let mut nonce_short = ticket.clone();
    nonce_short.nonce = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d".into();
    assert!(malformed_result(&sign_ticket(&nonce_short, &key)));

    // bad_timestamp.
    let mut ts_bad = ticket.clone();
    ts_bad.issued_at = "2026-10-15".into();
    assert!(malformed_result(&sign_ticket(&ts_bad, &key)));

    // single_segment.
    assert!(malformed_result(&token.replace('.', "")));

    // oversized_ticket: >1024 bytes.
    let huge = format!("{}.{}", "A".repeat(1030), b64(&sig));
    assert!(matches!(
        RelayAdmissionTicket::from_wire(&huge),
        Err(TicketError::Malformed(_))
    ));

    // The empty signature check keeps clippy honest about `sig` reuse.
    assert_eq!(sig.len(), 64);
}

/// The frame vector's composition contract (eligibility-side cross-check;
/// the wire codec itself is the transport seat's, pinned by its tests):
/// present = 0800 12 <uvarint len> <token utf-8>, byte-identical to the
/// frozen vector.
#[test]
fn admission_frame_composition_matches_vector() {
    let frame = load("relay-admission-frame-1.json");
    let base = load("relay-ticket-1.json");
    let token = base["token"].as_str().unwrap();
    let mut composed: Vec<u8> = vec![0x08, 0x00, 0x12];
    let len = token.len();
    let mut rest = len;
    loop {
        let b = (rest & 0x7f) as u8;
        rest >>= 7;
        composed.push(b | u8::from(rest > 0) << 7);
        if rest == 0 {
            break;
        }
    }
    composed.extend_from_slice(token.as_bytes());
    assert_eq!(hex(&composed), frame["present_frame_hex"].as_str().unwrap());
    // And the status encodings stay the frozen four.
    let statuses = &frame["status_frames_hex"];
    assert_eq!(statuses["ok_100"].as_str().unwrap(), "08011864");
    assert_eq!(
        statuses["permission_denied_202"].as_str().unwrap(),
        "080118ca01"
    );
    // The signature verifier accepts the fixture key's signatures (sanity
    // for the wrong_key rows above).
    let key = VerifyingKey::from(&fixture_key());
    let (ticket, sig) = RelayAdmissionTicket::from_wire(base["token"].as_str().unwrap()).unwrap();
    key.verify(
        canonical_payload(&ticket).as_bytes(),
        &ed25519_dalek::Signature::from_slice(&sig).unwrap(),
    )
    .unwrap();
}

fn ticket_field(t: &RelayAdmissionTicket, field: &str) -> String {
    let v = serde_json::to_value(t).unwrap();
    v[field].as_str().unwrap().to_string()
}

fn canonical_without(canonical: &str, field: &str) -> String {
    // Removes `"field":"…",` or `,"field":"…"` from the canonical form —
    // sufficient for the vector's exact field sets.
    let pat = format!("\"{field}\":");
    let start = canonical.find(&pat).expect("field present");
    let value_start = canonical[start..].find(':').unwrap() + start + 1;
    let value_end = canonical[value_start..].find('"').unwrap() + value_start + 1;
    let mut out = String::new();
    out.push_str(&canonical[..start]);
    out.push_str(&canonical[value_end..]);
    out.replace(",}", "}").replace(",,", ",")
}

fn malformed_result(wire: &str) -> bool {
    matches!(
        RelayAdmissionTicket::from_wire(wire),
        Err(TicketError::Malformed(_))
    )
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
