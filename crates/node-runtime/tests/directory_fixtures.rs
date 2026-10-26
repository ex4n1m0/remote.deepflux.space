//! Golden wire fixtures for the circle-directory API
//! (`services/signaling`, `POST /api/directory`) — ADR-006.
//!
//! Same discipline as `account_fixtures.rs`: requests serialized from the
//! `protocol::directory` types and byte-compared; responses declared in the
//! service's emission shape (`{ok:true, protocol_version, action, …}`) and
//! decoded back through the Rust types; rejects are must-fail probes
//! enforced against the TS schemas by `scripts/validate-wires.mjs`.
//! Regenerate with `UPDATE_DIRECTORY_FIXTURES=1 cargo test -p node-runtime
//! --test directory_fixtures`.

use std::path::PathBuf;

use protocol::directory::{
    CIRCLE_ID_HEX_LEN, DIRECTORY_PROTOCOL_VERSION, DirectoryCall, DirectoryRequest,
    DirectoryResponse, NONCE_HEX_LEN,
};

fn requests() -> Vec<(&'static str, DirectoryCall)> {
    vec![
        (
            "put",
            DirectoryCall::new(DirectoryRequest::Put {
                device: "0123456789abcdef".to_owned(),
                circle_id: "a1".repeat(CIRCLE_ID_HEX_LEN / 2),
                ciphertext_hex: "5f".repeat(32),
                nonce_hex: "6a".repeat(NONCE_HEX_LEN / 2),
            }),
        ),
        (
            "list",
            DirectoryCall::new(DirectoryRequest::List {
                device: "0123456789abcdef".to_owned(),
                circle_id: "a1".repeat(CIRCLE_ID_HEX_LEN / 2),
            }),
        ),
        (
            "remove",
            DirectoryCall::new(DirectoryRequest::Remove {
                device: "0123456789abcdef".to_owned(),
                circle_id: "a1".repeat(CIRCLE_ID_HEX_LEN / 2),
            }),
        ),
    ]
}

fn responses() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "put",
            serde_json::json!({
                "ok": true,
                "protocol_version": DIRECTORY_PROTOCOL_VERSION,
                "action": "put",
                "refreshed_ms": 1_760_000_000_000u64,
            }),
        ),
        (
            "list",
            serde_json::json!({
                "ok": true,
                "protocol_version": DIRECTORY_PROTOCOL_VERSION,
                "action": "list",
                "entries": [
                    {
                        "device": "0123456789abcdef",
                        "ciphertext_hex": "5f".repeat(32),
                        "nonce_hex": "6a".repeat(NONCE_HEX_LEN / 2),
                        "refreshed_ms": 1_760_000_000_000u64,
                        "online": true
                    },
                    {
                        "device": "fedcba9876543210",
                        "ciphertext_hex": "7c".repeat(32),
                        "nonce_hex": "8d".repeat(NONCE_HEX_LEN / 2),
                        "refreshed_ms": 1_759_999_000_000u64,
                        "online": false
                    }
                ],
                "truncated": false,
            }),
        ),
        (
            "remove",
            serde_json::json!({
                "ok": true,
                "protocol_version": DIRECTORY_PROTOCOL_VERSION,
                "action": "remove",
            }),
        ),
        (
            "list_empty",
            serde_json::json!({
                "ok": true,
                "protocol_version": DIRECTORY_PROTOCOL_VERSION,
                "action": "list",
                "entries": [],
                "truncated": false,
            }),
        ),
    ]
}

fn rejects() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "unknown_action",
            serde_json::json!({
                "protocol_version": DIRECTORY_PROTOCOL_VERSION,
                "action": "purge",
                "device": "0123456789abcdef",
                "circle_id": "a1".repeat(CIRCLE_ID_HEX_LEN / 2),
            }),
        ),
        (
            "camelcase_probe",
            serde_json::json!({
                "protocolVersion": DIRECTORY_PROTOCOL_VERSION,
                "action": "list",
                "device": "0123456789abcdef",
                "circle_id": "a1".repeat(CIRCLE_ID_HEX_LEN / 2),
            }),
        ),
        (
            "v0_put",
            serde_json::json!({
                "protocol_version": 0,
                "action": "put",
                "device": "0123456789abcdef",
                "circle_id": "a1".repeat(CIRCLE_ID_HEX_LEN / 2),
                "ciphertext_hex": "5f".repeat(32),
                "nonce_hex": "6a".repeat(NONCE_HEX_LEN / 2),
            }),
        ),
    ]
}

fn fixtures_dir(kind: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../services/signaling/fixtures/directory")
        .join(kind)
}

#[test]
fn golden_directory_fixtures_match_rust_serialization() {
    let update = std::env::var("UPDATE_DIRECTORY_FIXTURES").as_deref() == Ok("1");
    let request_values: Vec<(&'static str, serde_json::Value)> = requests()
        .into_iter()
        .map(|(name, call)| {
            (
                name,
                serde_json::to_value(&call).expect("serialize request fixture"),
            )
        })
        .collect();
    for (kind, fixtures) in [
        ("request", request_values),
        ("response", responses()),
        ("reject", rejects()),
    ] {
        let dir = fixtures_dir(kind);
        if update {
            std::fs::create_dir_all(&dir).expect("create fixtures dir");
        } else {
            assert!(
                dir.is_dir(),
                "fixtures missing: run UPDATE_DIRECTORY_FIXTURES=1 cargo test -p node-runtime --test directory_fixtures"
            );
        }
        for (name, value) in fixtures {
            let json = serde_json::to_string_pretty(&value).expect("serialize fixture");
            let path = dir.join(format!("{name}.json"));
            if update {
                std::fs::write(&path, json + "\n").expect("write fixture");
            } else {
                let existing = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                assert_eq!(
                    existing.trim(),
                    json,
                    "fixture drift at {} — directory wire contract changed; regenerate \
                     consciously (UPDATE_DIRECTORY_FIXTURES=1) and update the TS schemas",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn directory_fixtures_round_trip_through_the_rust_types() {
    for entry in std::fs::read_dir(fixtures_dir("request")).expect("request dir") {
        let path = entry.expect("dir entry").path();
        let text = std::fs::read_to_string(&path).expect("read fixture");
        let parsed: DirectoryCall =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(parsed.protocol_version, DIRECTORY_PROTOCOL_VERSION);
        parsed.check_version().expect("version check");
    }

    for entry in std::fs::read_dir(fixtures_dir("response")).expect("response dir") {
        let path = entry.expect("dir entry").path();
        let text = std::fs::read_to_string(&path).expect("read fixture");
        let value: serde_json::Value = serde_json::from_str(&text).expect("parse response fixture");
        assert_eq!(value["ok"], serde_json::json!(true), "{}", path.display());
        let parsed: DirectoryResponse = serde_json::from_value(value.clone())
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        if let DirectoryResponse::List { entries, truncated } = &parsed {
            assert!(!truncated);
            assert!(entries.len() <= 2);
        }
    }

    for entry in std::fs::read_dir(fixtures_dir("reject")).expect("reject dir") {
        let path = entry.expect("dir entry").path();
        let text = std::fs::read_to_string(&path).expect("read fixture");
        let value: serde_json::Value =
            serde_json::from_str(&text).expect("reject fixtures are valid JSON");
        let decoded: Result<DirectoryCall, _> = serde_json::from_value(value.clone());
        match decoded {
            Err(_) => {}
            Ok(call) => assert!(
                call.check_version().is_err(),
                "{} must fail the version gate",
                path.display()
            ),
        }
    }
}
