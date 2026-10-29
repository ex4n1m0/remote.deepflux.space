//! Circle directory API — the family-circle machine directory (ADR-006,
//! 2026-10-26): a shared, searchable list of the machines in one family
//! circle, stored on the control plane as **sealed entries only**.
//!
//! This is the request/response surface of `POST /api/directory`, the same
//! shape of surface as [`crate::account`] (flattened `action` discriminant,
//! snake_case keys, additive-optional within a version, typed unknown-version
//! error, TS mirror + golden fixtures in `services/signaling`). It is NOT the
//! relayed-envelope surface of [`crate::signaling`].
//!
//! # Cryptographic envelope (why the odd fields)
//!
//! Membership unit is the machine, not an account. A circle is a 32-byte
//! random key shared out-of-band (the invite; embedded in the family
//! installer). `circle_id = sha256("deepflux-circle:" + key_hex)` — only the
//! hash ever reaches the server, where it acts as an unguessable namespace.
//! The derivation itself is client-side crypto and lives in
//! `node-runtime::directory` (this crate stays dependency-minimal per
//! ADR-001); the wire rules below pin its *shape*.
//!
//! Each member registers exactly one sealed entry for its own device id:
//! `DirectoryEntryDoc {v, name, joined_ms}` as AES-256-GCM under the circle
//! key, AAD [`entry_aad`] = `"dir-entry:v1:{circle_id}|{device_id}"` (binds
//! both the circle and the owner, so ciphertext cannot be replayed into
//! another circle or another member's slot). The machine id is **never**
//! inside the ciphertext — the server-attested `device` field is the
//! identity, which removes the cross-member code-spoofing class.
//!
//! The server stores ciphertext, server-minted timestamps, and online flags
//! only (invariant 2, ADR-006 widening). All binary values travel as
//! lowercase hex (`*_hex`).

use serde::{Deserialize, Serialize};

/// Current directory-API protocol version. Bumps follow the explicit
/// contract-change rule of [`crate::signaling::SIGNALING_PROTOCOL_VERSION`].
///
/// Version history:
/// - **1** (ADR-006, 2026-10-26): initial schema — put/list/remove.
pub const DIRECTORY_PROTOCOL_VERSION: u16 = 1;

/// `circle_id` is sha256 output: 32 bytes → 64 hex chars.
pub const CIRCLE_ID_HEX_LEN: usize = 64;
/// Circle keys are 32 bytes → 64 hex chars (the invite text itself).
pub const CIRCLE_KEY_HEX_LEN: usize = 64;
/// Device ids are the 16-hex signaling ids (chat parity).
pub const DEVICE_HEX_LEN: usize = 16;
/// AES-GCM nonces are 12 bytes → 24 hex chars.
pub const NONCE_HEX_LEN: usize = 24;
/// Pairing proofs are HMAC-SHA256 output: 32 bytes → 64 hex chars
/// (see [`crate::signaling::SignalingBody::ConnectRequest`]).
pub const PAIRING_PROOF_HEX_LEN: usize = 64;

/// Entry nickname bounds (same as [`crate::account::RosterEntry::name`]).
pub const NAME_MIN_CHARS: usize = 1;
pub const NAME_MAX_CHARS: usize = 64;

/// Directory bounds (server rejects larger; client validates before sending).
pub const DIRECTORY_MAX_MEMBERS: usize = 128;
/// Sealed-entry ciphertext byte cap **before** hex encoding (2048 bytes is
/// ~6× a real 64-char-name entry; the cap keeps a `list` of 128 entries
/// comfortably under the 1 MiB body limit even hex-encoded).
pub const ENTRY_MAX_CIPHERTEXT_BYTES: usize = 2048;

/// AAD binding an entry to its circle and its owner slot.
pub fn entry_aad(circle_id: &str, device_id: &str) -> String {
    format!("dir-entry:v1:{circle_id}|{device_id}")
}

/// Validates a directory nickname (trim first; 1–64 chars after).
pub fn valid_name(name: &str) -> bool {
    let len = name.chars().count();
    (NAME_MIN_CHARS..=NAME_MAX_CHARS).contains(&len)
}

/// Validates a lowercase hex string of the expected byte length (moved
/// here from the retired `account` module, ADR-009 — the directory and
/// its fixtures validation still need it).
pub fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Validates a device id (16 lowercase hex — the signaling id / connection
/// code).
pub fn valid_device(device: &str) -> bool {
    valid_hex(device, DEVICE_HEX_LEN / 2)
}

/// One request, carried as the JSON body of `POST /api/directory` inside
/// [`DirectoryCall`]. Every action sends `Authorization: Bearer
/// {device_token}` (header, never the body) and identifies the caller with
/// `device`; the service authenticates the `(device, token)` pair against
/// signaling presence exactly like `/api/chat`, and every action applies to
/// the caller's **own** entry — `device` must match the authenticated id.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "snake_case"
)]
pub enum DirectoryRequest {
    /// Register or refresh the caller's sealed entry. Timestamps are
    /// server-minted; there is deliberately no client-supplied time field.
    Put {
        device: String,
        circle_id: String,
        ciphertext_hex: String,
        nonce_hex: String,
    },
    /// List every live entry in the circle (search is client-side over the
    /// decrypted ≤ [`DIRECTORY_MAX_MEMBERS`] entries; there is no
    /// server-side search by design).
    List { device: String, circle_id: String },
    /// Delete the caller's own entry. Idempotent (absent → success).
    Remove { device: String, circle_id: String },
}

/// `Debug` redacts ciphertext and nonce (invariant 6 discipline — a
/// directory call logged as an error string must not carry entry payload,
/// which would leak nicknames once the circle key is known).
impl core::fmt::Debug for DirectoryRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DirectoryRequest::Put {
                device, circle_id, ..
            } => f
                .debug_struct("Put")
                .field("device", device)
                .field("circle_id", circle_id)
                .field("ciphertext_hex", &"<redacted>")
                .field("nonce_hex", &"<redacted>")
                .finish(),
            DirectoryRequest::List { device, circle_id } => f
                .debug_struct("List")
                .field("device", device)
                .field("circle_id", circle_id)
                .finish(),
            DirectoryRequest::Remove { device, circle_id } => f
                .debug_struct("Remove")
                .field("device", device)
                .field("circle_id", circle_id)
                .finish(),
        }
    }
}

/// The request envelope. Flattens the [`DirectoryRequest`] discriminant to
/// the top level, mirroring [`crate::account::AccountCall`].
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectoryCall {
    pub protocol_version: u16,
    #[serde(flatten)]
    pub body: DirectoryRequest,
}

impl core::fmt::Debug for DirectoryCall {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DirectoryCall")
            .field("protocol_version", &self.protocol_version)
            .field("body", &self.body)
            .finish()
    }
}

impl DirectoryCall {
    pub fn new(body: DirectoryRequest) -> Self {
        Self {
            protocol_version: DIRECTORY_PROTOCOL_VERSION,
            body,
        }
    }

    /// Typed version check (unknown versions fail loudly, never garbage).
    pub fn check_version(&self) -> Result<(), DirectoryVersionError> {
        ensure_directory_version(self.protocol_version)
    }
}

/// One successful response. On the wire every variant also carries
/// `"ok": true` (added by the service; serde ignores it when decoding).
///
/// `Debug` redacts entry ciphertext (invariant 6); device ids, timestamps,
/// and online flags stay visible — they are already server-visible metadata.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "snake_case",
    rename_all_fields = "snake_case"
)]
pub enum DirectoryResponse {
    /// `refreshed_ms` is server-minted (`Date.now()` at write time).
    Put {
        refreshed_ms: u64,
    },
    /// All live entries. `truncated` is true only if the server's own
    /// safety cap returned fewer rows than exist (never in normal
    /// operation — the member cap makes a full list the common case).
    List {
        entries: Vec<DirectoryRow>,
        truncated: bool,
    },
    Remove,
}

impl core::fmt::Debug for DirectoryResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DirectoryResponse::Put { refreshed_ms } => f
                .debug_struct("Put")
                .field("refreshed_ms", refreshed_ms)
                .finish(),
            DirectoryResponse::List { entries, truncated } => f
                .debug_struct("List")
                .field(
                    "entries",
                    &format!("<{} rows, ciphertext redacted>", entries.len()),
                )
                .field("truncated", truncated)
                .finish(),
            DirectoryResponse::Remove => f.debug_struct("Remove").finish(),
        }
    }
}

/// One listed machine. `device` is the server-attested identity (the
/// connection code); `online` is the live signaling-presence flag.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryRow {
    pub device: String,
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub refreshed_ms: u64,
    pub online: bool,
}

impl core::fmt::Debug for DirectoryRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DirectoryRow")
            .field("device", &self.device)
            .field("ciphertext_hex", &"<redacted>")
            .field("nonce_hex", &"<redacted>")
            .field("refreshed_ms", &self.refreshed_ms)
            .field("online", &self.online)
            .finish()
    }
}

/// Typed error for an unsupported `protocol_version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryVersionError {
    Unsupported { supported: u16, found: u16 },
}

impl core::fmt::Display for DirectoryVersionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DirectoryVersionError::Unsupported { supported, found } => write!(
                f,
                "unsupported directory protocol_version {found} (this build speaks {supported})"
            ),
        }
    }
}

impl std::error::Error for DirectoryVersionError {}

pub fn ensure_directory_version(version: u16) -> Result<(), DirectoryVersionError> {
    if version == DIRECTORY_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(DirectoryVersionError::Unsupported {
            supported: DIRECTORY_PROTOCOL_VERSION,
            found: version,
        })
    }
}

/// Machine-readable error codes the service can return as
/// `{ok:false, error:"<code>", detail?, retry_after_s?}`. Constants, not an
/// enum — the strings are the wire contract (same rationale as
/// [`crate::account::error_code`]).
pub mod error_code {
    pub const UNSUPPORTED_VERSION: &str = "unsupported_version";
    pub const MALFORMED: &str = "malformed";
    pub const UNKNOWN_ACTION: &str = "unknown_action";
    pub const UNAUTHORIZED: &str = "unauthorized";
    /// Circle already at [`super::DIRECTORY_MAX_MEMBERS`] distinct devices.
    pub const CIRCLE_FULL: &str = "circle_full";
    /// Sealed entry exceeds [`super::ENTRY_MAX_CIPHERTEXT_BYTES`] decoded.
    pub const ENTRY_TOO_LARGE: &str = "entry_too_large";
    pub const TOO_LARGE: &str = "too_large";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const STORE_UNAVAILABLE: &str = "store_unavailable";
    pub const INTERNAL: &str = "internal";
}

/// The entry plaintext (after decryption): a durable client-side format,
/// not a service API. Additive-optional rules apply within `v` (v1 is the
/// initial layout). The machine id is deliberately absent — the
/// server-attested `device` is the identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntryDoc {
    pub v: u16,
    /// 1–64 chars, self-chosen nickname ("Mom's PC").
    pub name: String,
    /// First-join time (client-minted at entry creation, kept stable across
    /// refreshes; display-only, never trusted by the server).
    pub joined_ms: u64,
}

impl DirectoryEntryDoc {
    pub fn v1(name: String, joined_ms: u64) -> Self {
        Self {
            v: 1,
            name,
            joined_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_call(body: DirectoryRequest) -> DirectoryCall {
        DirectoryCall::new(body)
    }

    #[test]
    fn every_request_round_trips_through_json() {
        let bodies = vec![
            DirectoryRequest::Put {
                device: "0123456789abcdef".to_owned(),
                circle_id: "c".repeat(CIRCLE_ID_HEX_LEN),
                ciphertext_hex: "ab".repeat(96),
                nonce_hex: "0".repeat(NONCE_HEX_LEN),
            },
            DirectoryRequest::List {
                device: "0123456789abcdef".to_owned(),
                circle_id: "c".repeat(CIRCLE_ID_HEX_LEN),
            },
            DirectoryRequest::Remove {
                device: "0123456789abcdef".to_owned(),
                circle_id: "c".repeat(CIRCLE_ID_HEX_LEN),
            },
        ];
        for body in bodies {
            let json = serde_json::to_string(&sample_call(body.clone())).expect("serialize");
            let back: DirectoryCall = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, sample_call(body), "mismatch for {json}");
        }
    }

    #[test]
    fn request_discriminants_and_fields_are_stable_snake_case() {
        let value = serde_json::to_value(sample_call(DirectoryRequest::Put {
            device: "0123456789abcdef".to_owned(),
            circle_id: "c".repeat(CIRCLE_ID_HEX_LEN),
            ciphertext_hex: "ab".repeat(96),
            nonce_hex: "0".repeat(NONCE_HEX_LEN),
        }))
        .expect("serialize");
        assert_eq!(value["protocol_version"], DIRECTORY_PROTOCOL_VERSION);
        assert_eq!(value["action"], "put");
        assert_eq!(value["device"], "0123456789abcdef");
        assert_eq!(value["circle_id"], "c".repeat(CIRCLE_ID_HEX_LEN));
        // Flat layout: no nested body/payload object, no signaling-style tag.
        assert!(value.get("type").is_none());
        assert!(value.get("payload").is_none());

        let value = serde_json::to_value(sample_call(DirectoryRequest::List {
            device: "0123456789abcdef".to_owned(),
            circle_id: "c".repeat(CIRCLE_ID_HEX_LEN),
        }))
        .expect("serialize");
        assert_eq!(value["action"], "list");
    }

    #[test]
    fn responses_round_trip_and_tolerate_ok_flag() {
        let bodies = vec![
            DirectoryResponse::Put {
                refreshed_ms: 1_750_000_000_000,
            },
            DirectoryResponse::List {
                entries: vec![DirectoryRow {
                    device: "0123456789abcdef".to_owned(),
                    ciphertext_hex: "ab".repeat(96),
                    nonce_hex: "0".repeat(NONCE_HEX_LEN),
                    refreshed_ms: 1_750_000_000_000,
                    online: true,
                }],
                truncated: false,
            },
            DirectoryResponse::Remove,
        ];
        for body in bodies {
            let mut value = serde_json::to_value(&body).expect("serialize");
            value["ok"] = serde_json::json!(true);
            value["protocol_version"] = serde_json::json!(DIRECTORY_PROTOCOL_VERSION);
            let back: DirectoryResponse =
                serde_json::from_value(value.clone()).expect("deserialize");
            assert_eq!(
                serde_json::to_value(&back).expect("serialize"),
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
        let err = ensure_directory_version(2).expect_err("v2 must fail");
        assert_eq!(
            err,
            DirectoryVersionError::Unsupported {
                supported: DIRECTORY_PROTOCOL_VERSION,
                found: 2
            }
        );
        assert!(ensure_directory_version(DIRECTORY_PROTOCOL_VERSION).is_ok());
    }

    #[test]
    fn entry_doc_round_trips_and_tolerates_additive_fields() {
        let doc = DirectoryEntryDoc::v1("Mom's PC".to_owned(), 1_750_000_000_000);
        let json = serde_json::to_string(&doc).expect("serialize");
        let back: DirectoryEntryDoc = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, doc);
        // The machine id must NOT be part of the sealed plaintext.
        assert!(!json.contains("device"));
        assert!(!json.contains("code"));

        let extended = json.replace("\"joined_ms\"", "\"future_field\":\"x\",\"joined_ms\"");
        let tolerated: DirectoryEntryDoc =
            serde_json::from_str(&extended).expect("tolerate additive");
        assert_eq!(tolerated.name, "Mom's PC");
    }

    #[test]
    fn aad_format_is_pinned() {
        assert_eq!(
            entry_aad(&"c".repeat(CIRCLE_ID_HEX_LEN), "0123456789abcdef"),
            format!(
                "dir-entry:v1:{}|0123456789abcdef",
                "c".repeat(CIRCLE_ID_HEX_LEN)
            )
        );
    }

    #[test]
    fn name_and_device_validation() {
        assert!(valid_name("a"));
        assert!(valid_name("Mom's PC"));
        assert!(valid_name(&"x".repeat(NAME_MAX_CHARS)));
        assert!(!valid_name(""));
        assert!(!valid_name(&"x".repeat(NAME_MAX_CHARS + 1)));
        assert!(valid_device("0123456789abcdef"));
        assert!(!valid_device("0123456789ABCDEF"), "uppercase rejected");
        assert!(!valid_device("0123456789abcde"), "wrong length");
    }

    #[test]
    fn redacted_debug_never_carries_ciphertext() {
        let call = sample_call(DirectoryRequest::Put {
            device: "0123456789abcdef".to_owned(),
            circle_id: "c".repeat(CIRCLE_ID_HEX_LEN),
            ciphertext_hex: "deadbeef".to_owned(),
            nonce_hex: "0102030405060708090a0b0c".to_owned(),
        });
        let dbg = format!("{call:?}");
        assert!(!dbg.contains("deadbeef"), "ciphertext leaked: {dbg}");
        assert!(dbg.contains("<redacted>"));

        let row = DirectoryRow {
            device: "0123456789abcdef".to_owned(),
            ciphertext_hex: "deadbeef".to_owned(),
            nonce_hex: "0102030405060708090a0b0c".to_owned(),
            refreshed_ms: 1,
            online: false,
        };
        let dbg = format!("{row:?}");
        assert!(!dbg.contains("deadbeef"), "ciphertext leaked: {dbg}");
    }
}
