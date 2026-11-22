#![cfg(feature = "libp2p-backend")]

//! ADR-030 B2 tests: the receipts wire surface — old-frame compatibility,
//! the vector-pinned JSON shape across the wire mirror, and the
//! build→sign→countersign→digest round-trip with real identities.

use modelswarm_identity::InstallationIdentity;
use modelswarm_node::receipt_wire::{
    build_server_receipt, countersign, final_digest, receipt_to_wire, wire_to_receipt,
    ReceiptContext,
};
use modelswarm_transport::message::{Completed, WireMessage};

#[test]
fn old_receiptless_completed_frame_still_parses() {
    // The pre-B2 wire bytes: no job_receipt field anywhere.
    let old = r#"{"completed": {"request_id": "r1", "finish_reason": "stop"}}"#;
    let msg: WireMessage = serde_json::from_str(old).expect("old frame parses");
    let WireMessage::Completed(c) = &msg else {
        panic!("wrong variant");
    };
    assert_eq!(c.job_receipt, None);
    // And a receipt-carrying frame round-trips.
    let with_receipt = Completed {
        request_id: "r1".into(),
        finish_reason: "stop".into(),
        job_receipt: Some(modelswarm_transport::message::JobReceipt {
            request_id: "r1".into(),
            profile_id: "msp1:x".into(),
            preset: "unspecified".into(),
            mode_id: "single".into(),
            cohort_digest: "sha256:ab".into(),
            peers: vec![modelswarm_transport::message::JobReceiptPeer {
                peer_id: "p".into(),
                installation_id: "i".into(),
                role: "server".into(),
            }],
            started_at: "2026-10-16T09:00:00Z".into(),
            ended_at: "2026-10-16T09:00:06Z".into(),
            outcome: "stop".into(),
            accepted_tokens: 1,
            verified_tokens: 1,
            endpoint_seconds: 6,
            usage_digest: "sha256:cd".into(),
            budgets: serde_json::json!({"max_tokens": 256}),
            server_signature: "sig".into(),
            requester_signature: String::new(),
        }),
    };
    let bytes = serde_json::to_string(&WireMessage::Completed(with_receipt.clone())).unwrap();
    let back: WireMessage = serde_json::from_str(&bytes).unwrap();
    let WireMessage::Completed(c) = back else {
        panic!()
    };
    assert_eq!(c.job_receipt.as_ref().unwrap().server_signature, "sig");
    // receipt_ack round-trips.
    let ack = serde_json::to_string(&WireMessage::ReceiptAck(
        modelswarm_transport::message::ReceiptAck {
            request_id: "r1".into(),
        },
    ))
    .unwrap();
    assert!(ack.contains("receipt_ack"));
}

#[test]
fn build_countersign_and_digest_round_trip() {
    let server = InstallationIdentity::from_bytes(&[0x71; 32]);
    let requester = InstallationIdentity::from_bytes(&[0x72; 32]);
    let start = time::OffsetDateTime::from_unix_timestamp(1_792_000_000).unwrap();

    let wire = build_server_receipt(&ReceiptContext {
        request_id: "req-42",
        profile_id: "msp1:fc5a30ae",
        requester: modelswarm_eligibility::receipt_v2::ReceiptPeer {
            peer_id: requester.peer_id(),
            installation_id: requester.installation_id(),
            role: "requester".into(),
        },
        server_identity: &server,
        started_at: start,
        ended_at: start + time::Duration::seconds(6),
        finish_reason: "stop",
        accepted_tokens: 19,
        verified_tokens: 19,
        prompt_tokens: 7,
        prefill_ms: 120,
        decode_ms: 4800,
        deadline_ms: 30000,
        max_tokens: 256,
    })
    .expect("builds + signs");

    // The server signature verifies (phase 1) via the eligibility object.
    let semantic = wire_to_receipt(&wire).unwrap();
    assert!(
        semantic
            .verify_signatures(
                &ed25519_dalek::VerifyingKey::from_bytes(&server.public_key_bytes()).unwrap(),
                &ed25519_dalek::VerifyingKey::from_bytes(&requester.public_key_bytes()).unwrap(),
            )
            .is_err(),
        "phase-2 not yet signed -> verify fails for now"
    );
    assert!(semantic.server_signature.len() > 40);
    assert_eq!(semantic.requester_signature, "");
    // Honest single-mode values.
    assert_eq!(semantic.mode_id, "single");
    assert_eq!(semantic.preset, "unspecified");
    assert_eq!(semantic.endpoint_seconds, 6);
    assert!(semantic.usage_digest.starts_with("sha256:"));
    // The cohort digest re-derives.
    assert_eq!(
        modelswarm_eligibility::receipt_v2::ReceiptV2::cohort_digest_of(&semantic.peers).unwrap(),
        semantic.cohort_digest
    );

    // The requester counter-signs (correct session peer) — then both
    // signatures verify and the final digest exists.
    let counter = countersign(&wire, &requester, &server.peer_id(), None).expect("countersigns");
    let semantic2 = wire_to_receipt(&counter).unwrap();
    semantic2
        .verify_signatures(
            &ed25519_dalek::VerifyingKey::from_bytes(&server.public_key_bytes()).unwrap(),
            &ed25519_dalek::VerifyingKey::from_bytes(&requester.public_key_bytes()).unwrap(),
        )
        .expect("both signatures verify");
    let digest = final_digest(&counter).unwrap();
    assert!(digest.starts_with("sha256:"));
    assert_eq!(digest.len(), 7 + 64);

    // Wrong session peer -> the local honesty check refuses.
    assert!(countersign(&wire, &requester, "12D3KooWWrongPeer", None).is_err());
    // A different requester identity -> refused (the receipt names
    // another installation).
    let stranger = InstallationIdentity::from_bytes(&[0x73; 32]);
    assert!(countersign(&wire, &stranger, &server.peer_id(), None).is_err());

    // The wire mirror is JSON-identical to the semantic object.
    let via_wire = serde_json::to_value(&wire).unwrap();
    let via_semantic = serde_json::to_value(receipt_to_wire(&semantic).unwrap()).unwrap();
    assert_eq!(via_wire, via_semantic);
}

#[test]
fn inv4_countersign_gate_enforces_the_receipt_preset_contract() {
    let server = InstallationIdentity::from_bytes(&[0x71; 32]);
    let requester = InstallationIdentity::from_bytes(&[0x72; 32]);
    let start = time::OffsetDateTime::from_unix_timestamp(1_792_000_000).unwrap();

    let wire = build_server_receipt(&ReceiptContext {
        request_id: "req-inv4",
        profile_id: "msp1:fc5a30ae",
        requester: modelswarm_eligibility::receipt_v2::ReceiptPeer {
            peer_id: requester.peer_id(),
            installation_id: requester.installation_id(),
            role: "requester".into(),
        },
        server_identity: &server,
        started_at: start,
        ended_at: start + time::Duration::seconds(6),
        finish_reason: "stop",
        accepted_tokens: 19,
        verified_tokens: 19,
        prompt_tokens: 7,
        prefill_ms: 120,
        decode_ms: 4800,
        deadline_ms: 30000,
        max_tokens: 256,
    })
    .expect("builds + signs");

    // Baseline: the server's honest `unspecified` + no negotiation -> the
    // §6 pull path counter-signs fine (None).
    assert!(
        countersign(&wire, &requester, &server.peer_id(), None).is_ok(),
        "unspecified + no negotiation is the honest §6 shape"
    );

    // A wire whose preset claims a tier this session never negotiated:
    // refused by INV-4 (the receipt dies, no accounting moves).
    let mut tampered = wire_to_receipt(&wire).unwrap();
    tampered.preset = "verified".into();
    let claiming = receipt_to_wire(&tampered).unwrap();
    assert!(countersign(&claiming, &requester, &server.peer_id(), None).is_err());
    // ...and the same object IS honest when a negotiation DID deliver it.
    assert!(
        countersign(&claiming, &requester, &server.peer_id(), Some("verified")).is_ok(),
        "negotiated preset must match the receipt verbatim"
    );
    // A mismatch against the negotiated value is refused too.
    assert!(countersign(&claiming, &requester, &server.peer_id(), Some("balanced")).is_err());
    // Anything outside the frozen vocabulary is refused on every path.
    tampered.preset = "turbo".into();
    let junk = receipt_to_wire(&tampered).unwrap();
    assert!(countersign(&junk, &requester, &server.peer_id(), None).is_err());
    assert!(countersign(&junk, &requester, &server.peer_id(), Some("turbo")).is_err());
}
