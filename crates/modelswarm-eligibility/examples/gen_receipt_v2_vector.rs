//! Regeneration helper for the receipts-v2 golden vector
//! (`protocol/vectors/receipt-v2-1.json`, ADR-030 §6: vectors REQUIRED
//! before any second implementation reads the object). Fixture keys are
//! recorded IN the vector; the object, both signing phases, and the
//! frozen `receiptDigest` are produced by THIS implementation.
//!
//! Run: `cargo run -p modelswarm-eligibility --example gen_receipt_v2_vector`

use modelswarm_eligibility::receipt_v2::{ReceiptPeer, ReceiptV2};

fn main() {
    let server_seed: [u8; 32] = [0x61; 32];
    let requester_seed: [u8; 32] = [0x62; 32];
    let server_key = ed25519_dalek::SigningKey::from_bytes(&server_seed);
    let requester_key = ed25519_dalek::SigningKey::from_bytes(&requester_seed);

    let peers = vec![
        ReceiptPeer {
            peer_id: "12D3KooWA7L8TiZt1WXFCPeoFYR7EASz5B2PVyZNKGebB7F1BK7zM".into(),
            installation_id: "InstRequester0000000000000000000000000001".into(),
            role: "requester".into(),
        },
        ReceiptPeer {
            peer_id: "12D3KooWHqHP3TVKBbRxBD39kQzR89ceLDxbAjWeg4QsWewJyppz".into(),
            installation_id: "InstServer00000000000000000000000000002".into(),
            role: "server".into(),
        },
        ReceiptPeer {
            peer_id: "12D3KooWJkrYdaeCNMh3wDe3RCa833LN281DqZPjnMDfzuED1fFk".into(),
            installation_id: "InstVerifier0000000000000000000000000003".into(),
            role: "verifier".into(),
        },
    ];

    let mut receipt = ReceiptV2 {
        request_id: "req-0001".into(),
        profile_id: "msp1:fc5a30ae36257718afbd1062f2920b47576eed72ee8d172eac35248034b2dcbe".into(),
        preset: "FAST".into(),
        mode_id: "single".into(),
        cohort_digest: ReceiptV2::cohort_digest_of(&peers).expect("cohort digest"),
        peers,
        started_at: "2026-10-16T09:00:00Z".into(),
        ended_at: "2026-10-16T09:00:06Z".into(),
        outcome: "completed".into(),
        accepted_tokens: 19,
        verified_tokens: 19,
        endpoint_seconds: 6,
        usage_digest: "sha256:7f3a9c1d".into(),
        budgets: serde_json::json!({ "max_tokens": 256, "deadline_ms": 30000 }),
        server_signature: String::new(),
        requester_signature: String::new(),
    };
    receipt.sign_server(&server_key).expect("phase-1 sign");
    let phase1 = receipt.phase1_canonical().expect("phase1");
    let phase2_unsigned = receipt.phase2_canonical().expect("phase2 preimage");
    receipt
        .sign_requester(&requester_key)
        .expect("phase-2 sign");
    let final_canonical = receipt.final_canonical().expect("final");
    let digest = receipt.receipt_digest().expect("digest");

    let vector = serde_json::json!({
        "name": "receipt-v2-1",
        "description": "ADR-030 §1/§2 golden vector: the full ReceiptV2 object, both signing-phase preimages, both signatures, the final canonical form, and the frozen receiptDigest. Consumed by Rust (modelswarm-eligibility receipt_v2 tests) and TS (tracker lib/receipt-v2) — the cross-language byte-parity gate.",
        "adr": "ADR-030 §1/§2/§6",
        "server_signing_seed_hex": hex(&server_seed),
        "requester_signing_seed_hex": hex(&requester_seed),
        "server_public_key_hex": hex(&server_key.verifying_key().to_bytes()),
        "requester_public_key_hex": hex(&requester_key.verifying_key().to_bytes()),
        "phase1_canonical_json": phase1,
        "phase2_canonical_json": phase2_unsigned,
        "final_canonical_json": final_canonical,
        "receipt": receipt,
        "receipt_digest": digest,
    });
    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
