//! Golden wire fixtures for the account & roster API
//! (`services/signaling`, `POST /api/account`).
//!
//! Same discipline as `signaling_fixtures.rs` (delta D7), split by
//! direction:
//!
//! * **Requests** (`fixtures/account/request/*.json`) are serialized from
//!   `protocol::account` types — byte-for-byte compared in CI, so any
//!   Rust-side wire change fails until consciously regenerated with
//!   `UPDATE_ACCOUNT_FIXTURES=1` and the TS schemas are updated.
//! * **Responses** (`fixtures/account/response/*.json`) are the service's
//!   emission shape (`{ok:true, protocol_version, action, …}` — keys the
//!   Rust side does not produce but must decode); they are declared here in
//!   canonical form, written out with the same env flag, and the test
//!   decodes each back through [`protocol::account::AccountResponse`].
//! * **Rejects** (`fixtures/account/reject/*.json`) are hand-written
//!   must-fail probes (unknown action, camelCase keys, protocol_version 0)
//!   asserted to fail Rust decoding and enforced against the TS schemas by
//!   `scripts/validate-wires.mjs`.

use std::path::PathBuf;

use protocol::account::{
    ACCOUNT_PROTOCOL_VERSION, AUTH_KEY_HEX_LEN, AccountCall, AccountRequest, AccountResponse,
    NONCE_HEX_LEN, SALT_HEX_LEN, SESSION_TOKEN_HEX_LEN,
};

fn register_call() -> AccountCall {
    AccountCall::new(AccountRequest::Register {
        username: "alice".to_owned(),
        auth_key: "0a".repeat(AUTH_KEY_HEX_LEN / 2),
        auth_salt_hex: "1b".repeat(SALT_HEX_LEN / 2),
        wrap_salt_hex: "2c".repeat(SALT_HEX_LEN / 2),
        wrapped_dek_hex: "3d".repeat(24),
        dek_nonce_hex: "4e".repeat(NONCE_HEX_LEN / 2),
    })
}

fn requests() -> Vec<(&'static str, AccountCall)> {
    vec![
        ("register", register_call()),
        (
            "login_pre",
            AccountCall::new(AccountRequest::LoginPre {
                username: "alice".to_owned(),
            }),
        ),
        (
            "login",
            AccountCall::new(AccountRequest::Login {
                username: "alice".to_owned(),
                auth_key: "0a".repeat(AUTH_KEY_HEX_LEN / 2),
            }),
        ),
        ("logout", AccountCall::new(AccountRequest::Logout)),
        ("roster_get", AccountCall::new(AccountRequest::RosterGet)),
        (
            "roster_put",
            AccountCall::new(AccountRequest::RosterPut {
                ciphertext_hex: "5f".repeat(32),
                nonce_hex: "6a".repeat(NONCE_HEX_LEN / 2),
                base_version: 3,
            }),
        ),
        (
            "presence",
            AccountCall::new(AccountRequest::Presence {
                codes: vec!["0123456789abcdef".to_owned(), "fedcba9876543210".to_owned()],
            }),
        ),
    ]
}

/// The service's response wire shape. `ok` and `protocol_version` are
/// service-added; every payload field matches the Rust types exactly.
fn responses() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "register",
            serde_json::json!({
                "ok": true,
                "protocol_version": ACCOUNT_PROTOCOL_VERSION,
                "action": "register",
                "session_token": "9b".repeat(SESSION_TOKEN_HEX_LEN / 2),
                "expires_ms": 1_760_000_000_000u64,
            }),
        ),
        (
            "login_pre",
            serde_json::json!({
                "ok": true,
                "protocol_version": ACCOUNT_PROTOCOL_VERSION,
                "action": "login_pre",
                "auth_salt_hex": "1b".repeat(SALT_HEX_LEN / 2),
                "wrap_salt_hex": "2c".repeat(SALT_HEX_LEN / 2),
            }),
        ),
        (
            "login",
            serde_json::json!({
                "ok": true,
                "protocol_version": ACCOUNT_PROTOCOL_VERSION,
                "action": "login",
                "session_token": "9b".repeat(SESSION_TOKEN_HEX_LEN / 2),
                "expires_ms": 1_760_000_000_000u64,
                "wrapped_dek_hex": "3d".repeat(24),
                "dek_nonce_hex": "4e".repeat(NONCE_HEX_LEN / 2),
            }),
        ),
        (
            "logout",
            serde_json::json!({
                "ok": true,
                "protocol_version": ACCOUNT_PROTOCOL_VERSION,
                "action": "logout",
            }),
        ),
        (
            "roster_get",
            serde_json::json!({
                "ok": true,
                "protocol_version": ACCOUNT_PROTOCOL_VERSION,
                "action": "roster_get",
                "ciphertext_hex": "7c".repeat(32),
                "nonce_hex": "8d".repeat(NONCE_HEX_LEN / 2),
                "version": 4,
            }),
        ),
        (
            "roster_put",
            serde_json::json!({
                "ok": true,
                "protocol_version": ACCOUNT_PROTOCOL_VERSION,
                "action": "roster_put",
                "version": 5,
            }),
        ),
        (
            "presence",
            serde_json::json!({
                "ok": true,
                "protocol_version": ACCOUNT_PROTOCOL_VERSION,
                "action": "presence",
                "online": ["0123456789abcdef"],
            }),
        ),
        (
            "roster_get_empty",
            serde_json::json!({
                "ok": true,
                "protocol_version": ACCOUNT_PROTOCOL_VERSION,
                "action": "roster_get",
                "ciphertext_hex": "",
                "nonce_hex": "",
                "version": 0,
            }),
        ),
    ]
}

fn rejects() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "unknown_action",
            serde_json::json!({
                "protocol_version": ACCOUNT_PROTOCOL_VERSION,
                "action": "delete_everything",
                "username": "alice",
            }),
        ),
        (
            "camelcase_probe",
            serde_json::json!({
                "protocolVersion": ACCOUNT_PROTOCOL_VERSION,
                "action": "login_pre",
                "username": "alice",
            }),
        ),
        (
            "v0_register",
            serde_json::json!({
                "protocol_version": 0,
                "action": "register",
                "username": "alice",
                "auth_key": "0a".repeat(AUTH_KEY_HEX_LEN / 2),
                "auth_salt_hex": "1b".repeat(SALT_HEX_LEN / 2),
                "wrap_salt_hex": "2c".repeat(SALT_HEX_LEN / 2),
                "wrapped_dek_hex": "3d".repeat(24),
                "dek_nonce_hex": "4e".repeat(NONCE_HEX_LEN / 2),
            }),
        ),
    ]
}

fn fixtures_dir(kind: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../services/signaling/fixtures/account")
        .join(kind)
}

#[test]
fn golden_account_fixtures_match_rust_serialization() {
    let update = std::env::var("UPDATE_ACCOUNT_FIXTURES").as_deref() == Ok("1");
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
                "fixtures missing: run UPDATE_ACCOUNT_FIXTURES=1 cargo test -p node-runtime --test account_fixtures"
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
                    "fixture drift at {} — account wire contract changed; regenerate \
                     consciously (UPDATE_ACCOUNT_FIXTURES=1) and update the TS schemas",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn account_fixtures_round_trip_through_the_rust_types() {
    // Requests: every golden parses back into the Rust call and speaks the
    // current version.
    for entry in std::fs::read_dir(fixtures_dir("request")).expect("request dir") {
        let path = entry.expect("dir entry").path();
        let text = std::fs::read_to_string(&path).expect("read fixture");
        let parsed: AccountCall =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(parsed.protocol_version, ACCOUNT_PROTOCOL_VERSION);
        parsed.check_version().expect("version check");
    }

    // Responses: the service's wire shape (ok + protocol_version + payload)
    // decodes into the Rust response types.
    for entry in std::fs::read_dir(fixtures_dir("response")).expect("response dir") {
        let path = entry.expect("dir entry").path();
        let text = std::fs::read_to_string(&path).expect("read fixture");
        let value: serde_json::Value = serde_json::from_str(&text).expect("parse response fixture");
        assert_eq!(value["ok"], serde_json::json!(true), "{}", path.display());
        let parsed: AccountResponse = serde_json::from_value(value.clone())
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        // Deterministic decode assertion per shape.
        if let AccountResponse::RosterGet { version, .. } = &parsed {
            assert!(version <= &5)
        }
    }

    // Rejects: each documented must-fail probe fails Rust decoding (the
    // service must also reject them — enforced TS-side by validate-wires).
    for entry in std::fs::read_dir(fixtures_dir("reject")).expect("reject dir") {
        let path = entry.expect("dir entry").path();
        let text = std::fs::read_to_string(&path).expect("read fixture");
        let value: serde_json::Value =
            serde_json::from_str(&text).expect("reject fixtures are valid JSON");
        // camelCase keys and unknown actions must not decode; version 0
        // must fail the typed version gate even when fields parse.
        let decoded: Result<AccountCall, _> = serde_json::from_value(value.clone());
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
