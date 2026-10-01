//! Account & roster API — the second JSON surface owned by this crate
//! (post-MVP "trusted-device roster with optional accounts", user-committed
//! 2026-09-25, activated 2026-10-01).
//!
//! This is **not** the signaling-envelope surface (`signaling.rs`): those
//! messages are relayed between devices by the mailbox. Account messages are
//! request/response calls to the service itself (`POST /api/account`), so the
//! discriminant is `action`, not `type`, and there is no
//! from/to/message-id routing. Both surfaces follow the same wire policy
//! (AGENTS.md "Wire-format & versioning policy"): stable snake_case keys,
//! additive-optional fields only within a version, unknown versions rejected
//! with a typed error, and the TypeScript service mirrors these schemas
//! field-for-field (pinned by the golden fixtures this crate's tests export).
//!
//! # Cryptographic envelope (why the odd fields)
//!
//! The service stores no plaintext user data. At registration the client
//! mints a random 32-byte data key (DEK) and wraps it with a key derived
//! from the password:
//!
//! * `auth_key  = scrypt(password, auth_salt, 32)` — sent to the server as a
//!   password equivalent; the server stores only `scrypt(auth_key,
//!   server_salt)` so a store leak grants neither login nor roster access.
//! * `kek       = scrypt(password, wrap_salt, 32)` — never sent; wraps the
//!   DEK as AES-256-GCM (`wrapped_dek_hex`, AAD `acct-dek:v1:{username}`).
//! * the roster is AES-256-GCM under the DEK (`ciphertext_hex`, AAD
//!   `roster:v1:{username}`) — the server only ever sees ciphertext.
//!
//! All binary values travel as lowercase hex strings (`*_hex`).

use serde::{Deserialize, Serialize};

/// Current account-API protocol version. Bumps follow the same explicit
/// contract-change rule as [`crate::signaling::SIGNALING_PROTOCOL_VERSION`].
///
/// Version history:
/// - **1** (post-MVP accounts patch, 2026-10-01): initial schema.
pub const ACCOUNT_PROTOCOL_VERSION: u16 = 1;

/// Username rules, enforced identically client- and server-side: 3–32 chars
/// of `[a-z0-9._-]`, starting with a letter or digit. Clients normalize to
/// lowercase before validation.
pub const USERNAME_MIN_CHARS: usize = 3;
pub const USERNAME_MAX_CHARS: usize = 32;

/// `auth_key` is scrypt output: 32 bytes → 64 hex chars.
pub const AUTH_KEY_HEX_LEN: usize = 64;
/// Salts are 16 bytes → 32 hex chars.
pub const SALT_HEX_LEN: usize = 32;
/// AES-GCM nonces are 12 bytes → 24 hex chars.
pub const NONCE_HEX_LEN: usize = 24;
/// Session tokens are 32 bytes → 64 hex chars.
pub const SESSION_TOKEN_HEX_LEN: usize = 64;

/// Roster bounds (server rejects larger; client validates before sending).
pub const ROSTER_MAX_COMPUTERS: usize = 128;
/// Ciphertext byte cap before hex encoding.
pub const ROSTER_MAX_CIPHERTEXT_BYTES: usize = 64 * 1024;
/// Maximum codes per `presence` query.
pub const PRESENCE_MAX_CODES: usize = 50;

/// Validates a (already lowercased) username against the wire rules.
pub fn valid_username(username: &str) -> bool {
    let len = username.chars().count();
    if !(USERNAME_MIN_CHARS..=USERNAME_MAX_CHARS).contains(&len) {
        return false;
    }
    let mut chars = username.chars();
    let first = chars.next().expect("len checked above");
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    username
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// Validates a lowercase hex string of the expected byte length.
pub fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// One request. Carried as the JSON body of `POST /api/account` inside
/// [`AccountCall`]; authenticated actions additionally send
/// `Authorization: Bearer {session_token}` (header, never the body — same
/// rule as the signaling endpoint).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "snake_case"
)]
pub enum AccountRequest {
    /// Create an account. All key material is generated client-side; the
    /// server never sees the password or the unwrapped DEK.
    Register {
        username: String,
        auth_key: String,
        auth_salt_hex: String,
        wrap_salt_hex: String,
        wrapped_dek_hex: String,
        dek_nonce_hex: String,
    },
    /// Fetch the two KDF salts for a username (enables client-side scrypt
    /// before [`AccountRequest::Login`]). Unknown usernames get
    /// deterministic decoy salts so existence is not disclosed.
    LoginPre { username: String },
    /// Prove knowledge of the password. `auth_key` is the client-side
    /// scrypt(password, auth_salt) value — a password equivalent protected
    /// in transit only by TLS, exactly like a password would be.
    Login { username: String, auth_key: String },
    /// Invalidate the presented session token. Authenticated.
    Logout,
    /// Fetch the encrypted roster. Authenticated. A fresh account answers
    /// `version: 0` and an empty `ciphertext_hex`.
    RosterGet,
    /// Store the encrypted roster with optimistic concurrency: the server
    /// rejects with `roster_conflict` (HTTP 409) unless its current version
    /// equals `base_version`. Authenticated.
    RosterPut {
        ciphertext_hex: String,
        nonce_hex: String,
        base_version: u32,
    },
    /// Which of these device codes have live presence? Authenticated. Codes
    /// are device ids exactly as used in signaling envelopes (the CR-4
    /// presence-query op).
    Presence { codes: Vec<String> },
}

/// `Debug` redacts credential-bearing values (`auth_key`, the DEK wrap) —
/// invariant 6: a request Debug-printed into a log must not carry the
/// password equivalent. Usernames, salts, and roster metadata stay visible.
impl core::fmt::Debug for AccountRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AccountRequest::Register { username, .. } => f
                .debug_struct("Register")
                .field("username", username)
                .field("auth_key", &"<redacted>")
                .field("auth_salt_hex", &"<redacted>")
                .field("wrap_salt_hex", &"<redacted>")
                .field("wrapped_dek_hex", &"<redacted>")
                .field("dek_nonce_hex", &"<redacted>")
                .finish(),
            AccountRequest::LoginPre { username } => f
                .debug_struct("LoginPre")
                .field("username", username)
                .finish(),
            AccountRequest::Login { username, .. } => f
                .debug_struct("Login")
                .field("username", username)
                .field("auth_key", &"<redacted>")
                .finish(),
            AccountRequest::Logout => f.debug_struct("Logout").finish(),
            AccountRequest::RosterGet => f.debug_struct("RosterGet").finish(),
            AccountRequest::RosterPut { base_version, .. } => f
                .debug_struct("RosterPut")
                .field("ciphertext_hex", &"<redacted>")
                .field("nonce_hex", &"<redacted>")
                .field("base_version", base_version)
                .finish(),
            AccountRequest::Presence { codes } => {
                f.debug_struct("Presence").field("codes", codes).finish()
            }
        }
    }
}

/// The request envelope. Flattens the [`AccountRequest`] discriminant to the
/// top level, mirroring [`crate::signaling::SignalingEnvelope`]'s layout.
/// `Debug` delegates to [`AccountRequest`]'s redacted impl.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AccountCall {
    pub protocol_version: u16,
    #[serde(flatten)]
    pub body: AccountRequest,
}

impl core::fmt::Debug for AccountCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccountCall")
            .field("protocol_version", &self.protocol_version)
            .field("body", &self.body)
            .finish()
    }
}

impl AccountCall {
    pub fn new(body: AccountRequest) -> Self {
        Self {
            protocol_version: ACCOUNT_PROTOCOL_VERSION,
            body,
        }
    }

    /// Typed version check (same rule as signaling: unknown versions fail
    /// loudly, never decode into garbage).
    pub fn check_version(&self) -> Result<(), AccountVersionError> {
        ensure_account_version(self.protocol_version)
    }
}

/// One successful response. On the wire every variant also carries
/// `"ok": true` (added by the service; serde ignores it when decoding —
/// responses are decoded after the `ok` flag is inspected).
///
/// `Debug` is manual and redacts credential-bearing values
/// (`session_token`, `wrapped_dek_hex`/`dek_nonce_hex`, roster
/// `ciphertext_hex`) — invariant 6 discipline, so a misrouted response
/// logged as an error string cannot leak a live session token. Salts,
/// versions, and expiry stay visible (not secrets, useful in diagnostics).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "snake_case"
)]
pub enum AccountResponse {
    Register {
        session_token: String,
        expires_ms: u64,
    },
    LoginPre {
        auth_salt_hex: String,
        wrap_salt_hex: String,
    },
    Login {
        session_token: String,
        expires_ms: u64,
        /// Echoed so the client can re-wrap its DEK after a password change
        /// without a second round trip (future); also lets a login on a new
        /// machine unwrap the roster without ever re-sending key material.
        wrapped_dek_hex: String,
        dek_nonce_hex: String,
    },
    Logout,
    RosterGet {
        /// Empty string when `version == 0` (no roster stored yet).
        ciphertext_hex: String,
        nonce_hex: String,
        version: u32,
    },
    RosterPut {
        version: u32,
    },
    Presence {
        online: Vec<String>,
    },
}

impl core::fmt::Debug for AccountResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AccountResponse::Register { expires_ms, .. } => f
                .debug_struct("Register")
                .field("session_token", &"<redacted>")
                .field("expires_ms", expires_ms)
                .finish(),
            AccountResponse::LoginPre {
                auth_salt_hex,
                wrap_salt_hex,
            } => f
                .debug_struct("LoginPre")
                .field("auth_salt_hex", auth_salt_hex)
                .field("wrap_salt_hex", wrap_salt_hex)
                .finish(),
            AccountResponse::Login { expires_ms, .. } => f
                .debug_struct("Login")
                .field("session_token", &"<redacted>")
                .field("expires_ms", expires_ms)
                .field("wrapped_dek_hex", &"<redacted>")
                .field("dek_nonce_hex", &"<redacted>")
                .finish(),
            AccountResponse::Logout => f.debug_struct("Logout").finish(),
            AccountResponse::RosterGet { version, .. } => f
                .debug_struct("RosterGet")
                .field("ciphertext_hex", &"<redacted>")
                .field("nonce_hex", &"<redacted>")
                .field("version", version)
                .finish(),
            AccountResponse::RosterPut { version } => f
                .debug_struct("RosterPut")
                .field("version", version)
                .finish(),
            AccountResponse::Presence { online } => {
                f.debug_struct("Presence").field("online", online).finish()
            }
        }
    }
}

/// Typed error for an unsupported `protocol_version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountVersionError {
    Unsupported { supported: u16, found: u16 },
}

impl core::fmt::Display for AccountVersionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AccountVersionError::Unsupported { supported, found } => write!(
                f,
                "unsupported account protocol_version {found} (this build speaks {supported})"
            ),
        }
    }
}

impl std::error::Error for AccountVersionError {}

pub fn ensure_account_version(version: u16) -> Result<(), AccountVersionError> {
    if version == ACCOUNT_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(AccountVersionError::Unsupported {
            supported: ACCOUNT_PROTOCOL_VERSION,
            found: version,
        })
    }
}

/// Machine-readable error codes the service can return as
/// `{ok:false, error:"<code>", detail?}`. Kept as constants (not an enum)
/// because the strings are the wire contract and unknown future codes must
/// not fail Rust decoding of the *transport* — callers surface them as
/// typed account errors via [`AccountErrorCode::from_wire`].
pub mod error_code {
    pub const UNSUPPORTED_VERSION: &str = "unsupported_version";
    pub const MALFORMED: &str = "malformed";
    pub const USERNAME_TAKEN: &str = "username_taken";
    pub const INVALID_CREDENTIALS: &str = "invalid_credentials";
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const ROSTER_CONFLICT: &str = "roster_conflict";
    pub const ROSTER_TOO_LARGE: &str = "roster_too_large";
    pub const TOO_LARGE: &str = "too_large";
    pub const INTERNAL: &str = "internal";
}

/// The roster document, after decryption. This schema is a durable client
/// format, not a service API: old ciphertext must stay decryptable by newer
/// builds, so additive-optional rules apply here too (`v` gates layout
/// changes; v1 is the initial layout).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RosterDoc {
    pub v: u16,
    pub computers: Vec<RosterEntry>,
}

/// One saved computer. `code` is the device's signaling id (the connection
/// code users already exchange); it is shareable metadata, but travels only
/// inside the encrypted roster.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RosterEntry {
    /// Client-minted 8-hex id (same shape as favorites ids).
    pub id: String,
    /// Display name, 1–64 chars.
    pub name: String,
    /// 16-hex device id (= connection code).
    pub code: String,
    pub added_at_ms: u64,
    /// Bumped on rename/re-add; merged copies keep the newest value.
    pub updated_at_ms: u64,
}

impl RosterDoc {
    pub fn v1(computers: Vec<RosterEntry>) -> Self {
        Self { v: 1, computers }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_call(body: AccountRequest) -> AccountCall {
        AccountCall::new(body)
    }

    fn all_bodies() -> Vec<AccountRequest> {
        vec![
            AccountRequest::Register {
                username: "alice".to_owned(),
                auth_key: "a".repeat(AUTH_KEY_HEX_LEN),
                auth_salt_hex: "b".repeat(SALT_HEX_LEN),
                wrap_salt_hex: "c".repeat(SALT_HEX_LEN),
                wrapped_dek_hex: "d".repeat(96),
                dek_nonce_hex: "e".repeat(NONCE_HEX_LEN),
            },
            AccountRequest::LoginPre {
                username: "alice".to_owned(),
            },
            AccountRequest::Login {
                username: "alice".to_owned(),
                auth_key: "a".repeat(AUTH_KEY_HEX_LEN),
            },
            AccountRequest::Logout,
            AccountRequest::RosterGet,
            AccountRequest::RosterPut {
                ciphertext_hex: "ab".repeat(48),
                nonce_hex: "0".repeat(NONCE_HEX_LEN),
                base_version: 3,
            },
            AccountRequest::Presence {
                codes: vec!["0123456789abcdef".to_owned()],
            },
        ]
    }

    #[test]
    fn every_request_round_trips_through_json() {
        for body in all_bodies() {
            let json = serde_json::to_string(&sample_call(body.clone())).expect("serialize");
            let back: AccountCall = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, sample_call(body), "mismatch for {json}");
        }
    }

    #[test]
    fn request_discriminants_and_fields_are_stable_snake_case() {
        let value = serde_json::to_value(sample_call(AccountRequest::Register {
            username: "alice".to_owned(),
            auth_key: "a".repeat(AUTH_KEY_HEX_LEN),
            auth_salt_hex: "b".repeat(SALT_HEX_LEN),
            wrap_salt_hex: "c".repeat(SALT_HEX_LEN),
            wrapped_dek_hex: "d".repeat(96),
            dek_nonce_hex: "e".repeat(NONCE_HEX_LEN),
        }))
        .expect("serialize");
        assert_eq!(value["protocol_version"], ACCOUNT_PROTOCOL_VERSION);
        assert_eq!(value["action"], "register");
        assert_eq!(value["username"], "alice");
        assert!(value.get("type").is_none(), "no signaling-style tag");
        // Flat layout: no nested body/payload object.
        assert!(value.get("payload").is_none());

        let value = serde_json::to_value(sample_call(AccountRequest::RosterPut {
            ciphertext_hex: "ab".to_owned(),
            nonce_hex: "00".to_owned(),
            base_version: 1,
        }))
        .expect("serialize");
        assert_eq!(value["action"], "roster_put");
        assert_eq!(value["base_version"], 1);
    }

    #[test]
    fn responses_round_trip_and_tolerate_ok_flag() {
        let bodies = vec![
            AccountResponse::Register {
                session_token: "f".repeat(SESSION_TOKEN_HEX_LEN),
                expires_ms: 1_750_000_000_000,
            },
            AccountResponse::LoginPre {
                auth_salt_hex: "b".repeat(SALT_HEX_LEN),
                wrap_salt_hex: "c".repeat(SALT_HEX_LEN),
            },
            AccountResponse::Login {
                session_token: "f".repeat(SESSION_TOKEN_HEX_LEN),
                expires_ms: 1_750_000_000_000,
                wrapped_dek_hex: "d".repeat(96),
                dek_nonce_hex: "e".repeat(NONCE_HEX_LEN),
            },
            AccountResponse::Logout,
            AccountResponse::RosterGet {
                ciphertext_hex: String::new(),
                nonce_hex: String::new(),
                version: 0,
            },
            AccountResponse::RosterPut { version: 4 },
            AccountResponse::Presence {
                online: vec!["0123456789abcdef".to_owned()],
            },
        ];
        for body in bodies {
            let mut value = serde_json::to_value(&body).expect("serialize");
            // The service adds ok:true + protocol_version; decoding must not
            // care (serde ignores unknown keys by default — asserted here).
            value["ok"] = serde_json::json!(true);
            value["protocol_version"] = serde_json::json!(ACCOUNT_PROTOCOL_VERSION);
            let back: AccountResponse = serde_json::from_value(value.clone()).expect("deserialize");
            assert_eq!(
                serde_json::to_value(&back).expect("serialize"),
                // Strip the injected keys again for comparison.
                {
                    let mut expected = serde_json::to_value(&body).unwrap();
                    expected.as_object_mut().unwrap().remove("ok");
                    expected.as_object_mut().unwrap().remove("protocol_version");
                    expected
                },
                "mismatch for {value}"
            );
        }
    }

    #[test]
    fn version_gate_rejects_unknown_versions() {
        let err = ensure_account_version(0).expect_err("v0 must fail");
        assert_eq!(
            err,
            AccountVersionError::Unsupported {
                supported: ACCOUNT_PROTOCOL_VERSION,
                found: 0
            }
        );
        assert!(ensure_account_version(ACCOUNT_PROTOCOL_VERSION).is_ok());
    }

    #[test]
    fn username_rules() {
        for good in [
            "alice",
            "a1b",
            "a.b_c-d",
            "0x9",
            "u1234567890123456789012345678901",
        ] {
            assert!(valid_username(good), "{good} should be valid");
        }
        for bad in [
            "",
            "ab", // too short
            "Alice",
            "alice!",
            " alice",
            "alice ",
            "-alice",
            ".alice",
            "_alice", // charset / start
            "alice@host",
            "alices-laptop-with-a-very-long-name", // charset / too long (35)
        ] {
            assert!(!valid_username(bad), "{bad:?} should be invalid");
        }
    }

    #[test]
    fn hex_validator() {
        assert!(valid_hex("0a0b0c0d0e0f0a0b0c0d0e0f0a0b0c0d", 16));
        assert!(!valid_hex("0a0b", 16), "wrong length");
        assert!(!valid_hex("zz", 1), "non-hex");
        assert!(
            !valid_hex("0A0B", 2),
            "uppercase rejected (normalize first)"
        );
    }

    #[test]
    fn roster_doc_round_trips_and_tolerates_additive_fields() {
        let doc = RosterDoc::v1(vec![RosterEntry {
            id: "ab12cd34".to_owned(),
            name: "Desk PC".to_owned(),
            code: "0123456789abcdef".to_owned(),
            added_at_ms: 1_750_000_000_000,
            updated_at_ms: 1_750_000_000_001,
        }]);
        let json = serde_json::to_string(&doc).expect("serialize");
        let back: RosterDoc = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, doc);
        assert_eq!(serde_json::from_str::<RosterDoc>(&json).unwrap().v, 1);

        // Additive-optional tolerance: an unknown field from a newer build
        // must not break an older decoder.
        let extended = json.replace("\"added_at_ms\"", "\"future_field\":\"x\",\"added_at_ms\"");
        let tolerated: RosterDoc = serde_json::from_str(&extended).expect("tolerate additive");
        assert_eq!(tolerated.computers[0].name, "Desk PC");
    }
}
