//! ADR-030 golden-vector consumer: the receipts-v2 vector under
//! `protocol/vectors/receipt-v2-1.json` is FROZEN — these tests pin the
//! Rust implementation to it byte-for-byte (the lease-hubkey / relay-ticket
//! discipline). TS parity is pinned tracker-side against the same file.

use ed25519_dalek::{SigningKey, VerifyingKey};
use modelswarm_eligibility::receipt_v2::{ReceiptPeer, ReceiptV2};

fn load() -> serde_json::Value {
    let path = format!(
        "{}/../../protocol/vectors/receipt-v2-1.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn unhex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in (0..64).step_by(2).enumerate() {
        out[i] = u8::from_str_radix(&s[chunk..chunk + 2], 16).unwrap();
    }
    out
}

#[test]
fn receipt_v2_1_both_phases_and_digest_byte_pinned() {
    let v = load();
    let receipt: ReceiptV2 = serde_json::from_value(v["receipt"].clone()).unwrap();

    // The recorded fixture keys derive the recorded public keys.
    let server_key = SigningKey::from_bytes(&unhex(v["server_signing_seed_hex"].as_str().unwrap()));
    let requester_key =
        SigningKey::from_bytes(&unhex(v["requester_signing_seed_hex"].as_str().unwrap()));
    assert_eq!(
        hex(&server_key.verifying_key().to_bytes()),
        v["server_public_key_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex(&requester_key.verifying_key().to_bytes()),
        v["requester_public_key_hex"].as_str().unwrap()
    );

    // Both canonical preimages are byte-pinned.
    assert_eq!(
        receipt.phase1_canonical().unwrap(),
        v["phase1_canonical_json"].as_str().unwrap(),
        "phase-1 preimage: both signature fields absent"
    );
    assert_eq!(
        receipt.phase2_canonical().unwrap(),
        v["phase2_canonical_json"].as_str().unwrap(),
        "phase-2 preimage: server signature present, requester absent"
    );
    assert_eq!(
        receipt.final_canonical().unwrap(),
        v["final_canonical_json"].as_str().unwrap()
    );

    // Both signatures verify against the fixture keys.
    receipt
        .verify_signatures(
            &VerifyingKey::from_bytes(&unhex(v["server_public_key_hex"].as_str().unwrap()))
                .expect("server key"),
            &VerifyingKey::from_bytes(&unhex(v["requester_public_key_hex"].as_str().unwrap()))
                .expect("requester key"),
        )
        .expect("both signatures verify");

    // The frozen digest rule (ADR-030 §2).
    assert_eq!(
        receipt.receipt_digest().unwrap(),
        v["receipt_digest"].as_str().unwrap()
    );

    // Re-signing both phases from the seeds reproduces the recorded
    // signatures bit-for-bit (deterministic ed25519).
    let mut rebuilt = receipt.clone();
    rebuilt.server_signature = String::new();
    rebuilt.requester_signature = String::new();
    rebuilt.sign_server(&server_key).unwrap();
    rebuilt.sign_requester(&requester_key).unwrap();
    assert_eq!(rebuilt.server_signature, receipt.server_signature);
    assert_eq!(rebuilt.requester_signature, receipt.requester_signature);
}

#[test]
fn cohort_digest_is_the_sorted_labels_canonical() {
    let v = load();
    let receipt: ReceiptV2 = serde_json::from_value(v["receipt"].clone()).unwrap();
    assert_eq!(
        ReceiptV2::cohort_digest_of(&receipt.peers).unwrap(),
        receipt.cohort_digest,
        "the recorded cohort digest re-derives from the peer list"
    );
    // Order-independence: permuting the peers list yields the same digest.
    let mut permuted = receipt.peers.clone();
    permuted.reverse();
    assert_eq!(
        ReceiptV2::cohort_digest_of(&permuted).unwrap(),
        receipt.cohort_digest
    );
}

#[test]
fn grant_rules_self_work_zero_and_conservative_attribution() {
    let v = load();
    let receipt: ReceiptV2 = serde_json::from_value(v["receipt"].clone()).unwrap();
    // The requester's own installation is excluded (ADR-030 §4).
    let granted = receipt.granted_peers("InstRequester0000000000000000000000000001");
    assert_eq!(granted.len(), 2, "server + verifier granted, requester not");
    assert!(granted
        .iter()
        .all(|p| p.installation_id != "InstRequester0000000000000000000000000001"));
    // Self-work: a single-peer receipt grants nothing.
    let solo = ReceiptV2 {
        peers: vec![ReceiptPeer {
            peer_id: "12D3KooWSolo".into(),
            installation_id: "InstSolo".into(),
            role: "server".into(),
        }],
        ..receipt.clone()
    };
    assert!(solo.granted_peers("InstSolo").is_empty());
    assert_eq!(solo.per_peer_share(0), (0, 0));
    // Conservative attribution: integer division across granted peers,
    // remainder discarded (6 seconds / 2 peers = 3 each; 7/2 = 3 too).
    assert_eq!(receipt.per_peer_share(2), (3, 9));
    let seven = ReceiptV2 {
        endpoint_seconds: 7,
        verified_tokens: 7,
        ..receipt.clone()
    };
    assert_eq!(seven.per_peer_share(2), (3, 3));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---- ADR-045: the presets golden vector (receipt-v2-2-presets.json) ----

fn load_presets() -> serde_json::Value {
    let path = format!(
        "{}/../../protocol/vectors/receipt-v2-2-presets.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn golden_receipt_v2_2_presets_vocabulary_digest_sensitive_and_signed() {
    let v = load_presets();
    let cases = v["cases"].as_array().expect("cases array");
    assert_eq!(
        cases.len(),
        6,
        "exactly the six-value receipt-side vocabulary"
    );

    let server_key = SigningKey::from_bytes(&unhex(v["server_signing_seed_hex"].as_str().unwrap()));
    let requester_key =
        SigningKey::from_bytes(&unhex(v["requester_signing_seed_hex"].as_str().unwrap()));

    let vocabulary = [
        "fast",
        "balanced",
        "deep",
        "verified",
        "maximum",
        "unspecified",
    ];
    let mut seen_digests = std::collections::HashSet::new();
    let mut first: Option<ReceiptV2> = None;

    for case in cases {
        let preset = case["preset"].as_str().unwrap();
        assert!(vocabulary.contains(&preset), "frozen vocabulary: {preset}");

        let mut receipt: ReceiptV2 = serde_json::from_value(case["receipt"].clone()).unwrap();
        assert_eq!(receipt.preset, preset);

        // Byte-pinned preimages + digest, recomputed from the parsed object.
        assert_eq!(
            receipt.phase1_canonical().unwrap(),
            case["phase1_canonical_json"].as_str().unwrap()
        );
        assert_eq!(
            receipt.phase2_canonical().unwrap(),
            case["phase2_canonical_json"].as_str().unwrap()
        );
        assert_eq!(
            receipt.final_canonical().unwrap(),
            case["final_canonical_json"].as_str().unwrap()
        );
        assert_eq!(
            receipt.receipt_digest().unwrap(),
            case["receipt_digest"].as_str().unwrap()
        );

        // Both signatures verify against the fixture keys.
        receipt
            .verify_signatures(&server_key.verifying_key(), &requester_key.verifying_key())
            .expect("both signatures valid");

        // Digest sensitivity: six DISTINCT digests — the field cannot be
        // dropped or normalized before digesting (the B2 trap's pin).
        assert!(
            seen_digests.insert(case["receipt_digest"].as_str().unwrap().to_string()),
            "digest for preset {preset} collides with an earlier case — the vector's whole point is six distinct digests"
        );

        // Isolation: the cases differ ONLY in preset — blank it and the
        // objects are equal (any other field drifting would silently
        // weaken the sensitivity pin).
        receipt.preset = String::new();
        receipt.server_signature = String::new();
        receipt.requester_signature = String::new();
        match &first {
            None => first = Some(receipt),
            Some(baseline) => assert_eq!(&receipt, baseline, "case {preset} differs beyond preset"),
        }
    }
}

#[test]
fn frozen_receipt_preset_vocabulary() {
    use modelswarm_eligibility::receipt_v2::is_valid_receipt_preset;
    for ok in [
        "fast",
        "balanced",
        "deep",
        "verified",
        "maximum",
        "unspecified",
    ] {
        assert!(
            is_valid_receipt_preset(ok),
            "{ok} is in the frozen vocabulary"
        );
    }
    // Case-sensitive, closed, and the legacy uppercase form is OUT
    // (intake and countersign both refuse it — never relabel).
    for bad in ["FAST", "turbo", "", "Verified", "fast ", "single"] {
        assert!(!is_valid_receipt_preset(bad), "{bad:?} must be refused");
    }
}
