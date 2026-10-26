//! Circle-directory service client — `POST /api/directory` (ADR-006) plus
//! the client-side crypto the contract defines: the `circle_id` derivation
//! and the sealed-entry AES-256-GCM envelope.
//!
//! Blocking request/response JSON over ureq, mirroring
//! [`crate::account_remote`] conventions (version gate on both directions,
//! structured Api errors, header-only bearer). Auth is the **device token**
//! — the same presence-binding secret [`crate::signaling_remote`] uses —
//! and every action names the caller's own `device`; the service
//! authenticates the pair against live presence exactly like `/api/chat`,
//! which is why the directory client retries with backoff until the engine
//! has registered (put/list are called once the node is Online).
//!
//! Crypto (ADR-006 §2):
//! * `circle_id = sha256("deepflux-circle:" + key_hex)` — only the hash
//!   crosses the wire; the key itself is the invite, stored client-side in
//!   the Windows Credential Manager ([`CircleKey`]'s Debug is redacted).
//! * entries are `DirectoryEntryDoc` sealed AES-256-GCM under the circle
//!   key with AAD `protocol::directory::entry_aad(circle_id, device)` —
//!   binding circle and owner slot so ciphertext cannot be replayed into
//!   another circle or another member's row.

use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde_json::Value;
use sha2::{Digest, Sha256};
use ureq::Agent;

use protocol::account::valid_hex;
use protocol::directory::{
    CIRCLE_ID_HEX_LEN, CIRCLE_KEY_HEX_LEN, DIRECTORY_MAX_MEMBERS, DIRECTORY_PROTOCOL_VERSION,
    DirectoryCall, DirectoryEntryDoc, DirectoryRequest, DirectoryResponse, DirectoryRow,
    ENTRY_MAX_CIPHERTEXT_BYTES, NONCE_HEX_LEN, entry_aad, error_code, valid_device, valid_name,
};

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// Circle-domain prefix for the id derivation (pinned by tests).
const CIRCLE_DOMAIN: &str = "deepflux-circle:";

/// Everything that can go wrong in one directory call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    Network(String),
    /// Local validation refused the request before it was sent.
    Invalid(String),
    /// Crypto failure (bad key shape, unopenable ciphertext).
    Crypto(String),
    /// The service answered `{ok:false, error:"…"}` (`retry_after_s`
    /// carried for `rate_limited`).
    Api {
        status: u16,
        code: String,
        detail: Option<String>,
        retry_after_s: Option<u64>,
    },
    Decode(String),
}

impl DirectoryError {
    /// True when the engine is not registered yet (presence auth) and the
    /// call should be retried after backoff rather than surfaced as an error.
    pub fn is_not_online(&self) -> bool {
        matches!(self, DirectoryError::Api { code, .. } if code == error_code::UNAUTHORIZED)
    }

    pub fn api_code(&self) -> Option<&str> {
        match self {
            DirectoryError::Api { code, .. } => Some(code.as_str()),
            _ => None,
        }
    }
}

impl core::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DirectoryError::Network(e) => write!(f, "network error: {e}"),
            DirectoryError::Invalid(e) => write!(f, "invalid request: {e}"),
            DirectoryError::Crypto(e) => write!(f, "crypto error: {e}"),
            DirectoryError::Api {
                status,
                code,
                detail,
                ..
            } => match detail {
                Some(d) => write!(f, "service error {status} {code}: {d}"),
                None => write!(f, "service error {status} {code}"),
            },
            DirectoryError::Decode(e) => write!(f, "unexpected response: {e}"),
        }
    }
}

impl std::error::Error for DirectoryError {}

/// A circle key (the invite). 32 bytes as 64 lowercase hex; `Debug` is
/// redacted (invariant 6 — knowing it reads the whole directory).
#[derive(Clone)]
pub struct CircleKey(String);

impl CircleKey {
    /// Accepts a pasted invite (64 hex chars, whitespace and common
    /// grouping separators trimmed) or fails with a friendly error.
    pub fn parse(invite: &str) -> Result<Self, DirectoryError> {
        let cleaned: String = invite
            .trim()
            .chars()
            .filter(|c| !matches!(c, ' ' | '-' | '_'))
            .collect();
        if !valid_hex(&cleaned, CIRCLE_KEY_HEX_LEN / 2) {
            return Err(DirectoryError::Invalid(
                "invite code must be 64 hex characters".to_owned(),
            ));
        }
        Ok(Self(cleaned))
    }

    /// Mint a fresh circle key (the "create a circle" path).
    pub fn generate() -> Self {
        Self(secure_hex(CIRCLE_KEY_HEX_LEN / 2))
    }

    /// The hex invite (for display/copy in the UI — the user chose to share
    /// it; never for logs).
    pub fn invite_hex(&self) -> &str {
        &self.0
    }

    fn key_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = hex::decode(&self.0).expect("validated 64-hex at construction");
        out.copy_from_slice(&bytes);
        out
    }
}

impl core::fmt::Debug for CircleKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CircleKey(<redacted>)")
    }
}

/// `circle_id = sha256("deepflux-circle:" + key_hex)` — 64 lowercase hex.
/// Only this hash reaches the service; it is an unguessable namespace id,
/// not a secret (safe to log, same class as device ids).
pub fn circle_id_from_key(key: &CircleKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CIRCLE_DOMAIN.as_bytes());
    hasher.update(key.invite_hex().as_bytes());
    hex::encode(hasher.finalize())
}

/// A decrypted directory entry as the UI consumes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircleEntry {
    pub device: String,
    pub name: String,
    pub joined_ms: u64,
    pub refreshed_ms: u64,
    pub online: bool,
}

/// Seal one entry under the circle key (AAD binds circle + owner slot).
pub fn seal_entry(
    key: &CircleKey,
    circle_id: &str,
    device: &str,
    doc: &DirectoryEntryDoc,
) -> Result<(String, String), DirectoryError> {
    let plaintext = serde_json::to_vec(doc)
        .map_err(|e| DirectoryError::Crypto(format!("entry serialize: {e}")))?;
    let nonce_bytes = secure_nonce();
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.key_bytes()));
    let aad = entry_aad(circle_id, device);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| DirectoryError::Crypto("entry seal failed".to_owned()))?;
    if ct.len() > ENTRY_MAX_CIPHERTEXT_BYTES {
        return Err(DirectoryError::Invalid(
            "sealed entry exceeds the wire cap".to_owned(),
        ));
    }
    Ok((hex::encode(ct), hex::encode(nonce_bytes)))
}

/// Open one listed row. Fails closed on wrong key, wrong circle, or a row
/// re-bound to a different owner slot (AAD mismatch).
pub fn open_entry(
    key: &CircleKey,
    circle_id: &str,
    row: &DirectoryRow,
) -> Result<DirectoryEntryDoc, DirectoryError> {
    let ct = hex::decode(&row.ciphertext_hex)
        .map_err(|_| DirectoryError::Crypto("row ciphertext not hex".to_owned()))?;
    let nonce = hex::decode(&row.nonce_hex)
        .map_err(|_| DirectoryError::Crypto("row nonce not hex".to_owned()))?;
    if nonce.len() != NONCE_HEX_LEN / 2 {
        return Err(DirectoryError::Crypto("row nonce length".to_owned()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.key_bytes()));
    let aad = entry_aad(circle_id, &row.device);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ct,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| {
            DirectoryError::Crypto("entry open failed (wrong key or rebinding)".to_owned())
        })?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| DirectoryError::Crypto(format!("entry decode: {e}")))
}

fn secure_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).expect("CSPRNG available");
    hex::encode(buf)
}

fn secure_nonce() -> [u8; NONCE_HEX_LEN / 2] {
    let mut nonce = [0u8; NONCE_HEX_LEN / 2];
    getrandom::fill(&mut nonce).expect("CSPRNG available");
    nonce
}

/// Blocking client for the directory surface.
pub struct DirectoryClient {
    base_url: String,
    agent: Agent,
}

impl DirectoryClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            agent: crate::http::https_agent(HTTP_TIMEOUT, "remote-desktop-app"),
        }
    }

    fn call(
        &self,
        body: DirectoryRequest,
        device_token: &str,
    ) -> Result<DirectoryResponse, DirectoryError> {
        let call = DirectoryCall::new(body);
        let url = format!("{}/api/directory", self.base_url);
        let request = self
            .agent
            .post(&url)
            .set("content-type", "application/json")
            .set("authorization", &format!("Bearer {device_token}"));
        let value =
            serde_json::to_value(&call).map_err(|e| DirectoryError::Decode(e.to_string()))?;
        let response = request
            .send_string(&value.to_string())
            .map_err(|e| match e {
                ureq::Error::Status(status, resp) => {
                    let body: Value = resp.into_json::<Value>().unwrap_or(Value::Null);
                    parse_api_error(status, &body)
                }
                other => DirectoryError::Network(other.to_string()),
            })?;
        let body: Value = response
            .into_json::<Value>()
            .map_err(|e| DirectoryError::Decode(format!("body: {e}")))?;
        match body.get("ok").and_then(Value::as_bool) {
            Some(true) => {
                match body.get("protocol_version").and_then(Value::as_u64) {
                    Some(v) if v == u64::from(DIRECTORY_PROTOCOL_VERSION) => {}
                    Some(v) => {
                        return Err(DirectoryError::Decode(format!(
                            "unsupported directory protocol_version {v} (this build speaks {DIRECTORY_PROTOCOL_VERSION})"
                        )));
                    }
                    None => {
                        return Err(DirectoryError::Decode(
                            "ok-body missing protocol_version".to_owned(),
                        ));
                    }
                }
                serde_json::from_value::<DirectoryResponse>(body.clone())
                    .map_err(|e| DirectoryError::Decode(format!("unexpected ok-body: {e}")))
            }
            Some(false) => Err(parse_api_error(200, &body)),
            _ => Err(DirectoryError::Decode(
                "response missing ok flag".to_owned(),
            )),
        }
    }

    /// Register or refresh this machine's sealed entry. `joined_ms` is
    /// carried inside the sealed doc and should stay stable across
    /// refreshes (pass the first-join value).
    pub fn put(
        &self,
        key: &CircleKey,
        circle_id: &str,
        device: &str,
        device_token: &str,
        name: &str,
        joined_ms: u64,
    ) -> Result<u64, DirectoryError> {
        if !valid_device(device) || !valid_hex(circle_id, CIRCLE_ID_HEX_LEN / 2) {
            return Err(DirectoryError::Invalid(
                "device or circle_id has wrong shape".to_owned(),
            ));
        }
        if !valid_name(name) {
            return Err(DirectoryError::Invalid(
                "nickname must be 1-64 characters".to_owned(),
            ));
        }
        let (ciphertext_hex, nonce_hex) = seal_entry(
            key,
            circle_id,
            device,
            &DirectoryEntryDoc::v1(name.to_owned(), joined_ms),
        )?;
        match self.call(
            DirectoryRequest::Put {
                device: device.to_owned(),
                circle_id: circle_id.to_owned(),
                ciphertext_hex,
                nonce_hex,
            },
            device_token,
        )? {
            DirectoryResponse::Put { refreshed_ms } => Ok(refreshed_ms),
            other => Err(DirectoryError::Decode(format!(
                "expected put, got {other:?}"
            ))),
        }
    }

    /// List and decrypt every live entry. Rows that fail to open (foreign
    /// key material, rebinding) are skipped, never fatal — a hostile or
    /// corrupt row must not hide the rest of the directory.
    pub fn list(
        &self,
        key: &CircleKey,
        circle_id: &str,
        device: &str,
        device_token: &str,
    ) -> Result<Vec<CircleEntry>, DirectoryError> {
        if !valid_device(device) || !valid_hex(circle_id, CIRCLE_ID_HEX_LEN / 2) {
            return Err(DirectoryError::Invalid(
                "device or circle_id has wrong shape".to_owned(),
            ));
        }
        match self.call(
            DirectoryRequest::List {
                device: device.to_owned(),
                circle_id: circle_id.to_owned(),
            },
            device_token,
        )? {
            DirectoryResponse::List { entries, .. } => {
                let mut out = Vec::with_capacity(entries.len().min(DIRECTORY_MAX_MEMBERS));
                for row in &entries {
                    if !valid_device(&row.device) {
                        continue;
                    }
                    if let Ok(doc) = open_entry(key, circle_id, row) {
                        if !valid_name(&doc.name) {
                            continue;
                        }
                        out.push(CircleEntry {
                            device: row.device.clone(),
                            name: doc.name,
                            joined_ms: doc.joined_ms,
                            refreshed_ms: row.refreshed_ms,
                            online: row.online,
                        });
                    }
                }
                out.sort_by(|a, b| {
                    b.refreshed_ms
                        .cmp(&a.refreshed_ms)
                        .then(a.device.cmp(&b.device))
                });
                Ok(out)
            }
            other => Err(DirectoryError::Decode(format!(
                "expected list, got {other:?}"
            ))),
        }
    }

    /// Remove this machine's own entry (idempotent).
    pub fn remove(
        &self,
        circle_id: &str,
        device: &str,
        device_token: &str,
    ) -> Result<(), DirectoryError> {
        if !valid_device(device) || !valid_hex(circle_id, CIRCLE_ID_HEX_LEN / 2) {
            return Err(DirectoryError::Invalid(
                "device or circle_id has wrong shape".to_owned(),
            ));
        }
        match self.call(
            DirectoryRequest::Remove {
                device: device.to_owned(),
                circle_id: circle_id.to_owned(),
            },
            device_token,
        )? {
            DirectoryResponse::Remove => Ok(()),
            other => Err(DirectoryError::Decode(format!(
                "expected remove, got {other:?}"
            ))),
        }
    }
}

fn parse_api_error(status: u16, body: &Value) -> DirectoryError {
    let code = body
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("internal")
        .to_owned();
    let detail = body
        .get("detail")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let retry_after_s = body.get("retry_after_s").and_then(Value::as_u64);
    DirectoryError::Api {
        status,
        code,
        detail,
        retry_after_s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circle_key_parses_and_redacts() {
        let invite = "ab".repeat(32);
        let key = CircleKey::parse(&invite).expect("valid invite");
        assert_eq!(key.invite_hex(), invite);
        // Tolerates paste artifacts: surrounding whitespace and separators.
        assert!(
            CircleKey::parse(&format!(
                " {} ",
                invite
                    .chars()
                    .enumerate()
                    .map(|(i, c)| if i == 16 {
                        format!("-{c}")
                    } else {
                        c.to_string()
                    })
                    .collect::<String>()
            ))
            .is_ok()
        );
        assert!(CircleKey::parse("nothex").is_err());
        assert!(CircleKey::parse(&"ab".repeat(31)).is_err());
        let dbg = format!("{:?}", CircleKey::parse(&invite).unwrap());
        assert_eq!(dbg, "CircleKey(<redacted>)");
        // Generated keys are valid invites of full entropy length.
        assert!(CircleKey::parse(CircleKey::generate().invite_hex()).is_ok());
    }

    #[test]
    fn circle_id_derivation_is_deterministic_64_hex_and_key_sensitive() {
        let a = CircleKey::parse(&"ab".repeat(32)).unwrap();
        let b = CircleKey::parse(&"cd".repeat(32)).unwrap();
        let id_a = circle_id_from_key(&a);
        assert_eq!(id_a.len(), CIRCLE_ID_HEX_LEN);
        assert!(id_a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(id_a, circle_id_from_key(&a), "deterministic");
        assert_ne!(id_a, circle_id_from_key(&b), "key-sensitive");
    }

    #[test]
    fn seal_open_round_trip_and_aad_binding() {
        let key = CircleKey::parse(&"ab".repeat(32)).unwrap();
        let circle_id = &circle_id_from_key(&key);
        let device = "0123456789abcdef";
        let doc = DirectoryEntryDoc::v1("Mom's PC".to_owned(), 1_750_000_000_000);

        let (ct, nonce) = seal_entry(&key, circle_id, device, &doc).expect("seal");
        let row = DirectoryRow {
            device: device.to_owned(),
            ciphertext_hex: ct,
            nonce_hex: nonce,
            refreshed_ms: 1,
            online: true,
        };
        let opened = open_entry(&key, circle_id, &row).expect("open");
        assert_eq!(opened, doc);

        // Wrong key cannot open.
        let other_key = CircleKey::parse(&"cd".repeat(32)).unwrap();
        assert!(open_entry(&other_key, circle_id, &row).is_err());

        // Re-binding the row to a different owner slot fails (AAD).
        let mut rebound = row.clone();
        rebound.device = "ffffffffffffffff".to_owned();
        assert!(open_entry(&key, circle_id, &rebound).is_err());

        // And into a different circle id fails.
        let foreign_circle = &"e".repeat(CIRCLE_ID_HEX_LEN);
        assert!(open_entry(&key, foreign_circle, &row).is_err());
    }

    #[test]
    fn oversized_names_are_refused_locally() {
        let key = CircleKey::parse(&"ab".repeat(32)).unwrap();
        let circle_id = circle_id_from_key(&key);
        let client = DirectoryClient::new("http://127.0.0.1:1");
        assert!(matches!(
            client.put(
                &key,
                &circle_id,
                "0123456789abcdef",
                "t",
                &"x".repeat(65),
                1
            ),
            Err(DirectoryError::Invalid(_))
        ));
        assert!(matches!(
            client.list(&key, &circle_id, "nothex", "t"),
            Err(DirectoryError::Invalid(_))
        ));
    }

    #[test]
    fn api_error_parses_extras_and_not_online_helper() {
        let body = serde_json::json!({
            "ok": false,
            "error": "rate_limited",
            "retry_after_s": 7,
        });
        let err = parse_api_error(429, &body);
        assert!(matches!(
            &err,
            DirectoryError::Api {
                status: 429,
                retry_after_s: Some(7),
                ..
            }
        ));
        assert_eq!(err.api_code(), Some("rate_limited"));

        let offline = parse_api_error(
            401,
            &serde_json::json!({"ok": false, "error": "unauthorized"}),
        );
        assert!(offline.is_not_online());
        assert!(!err.is_not_online());
    }
}
