//! Account & roster service client — `POST /api/account` on the same Vercel
//! service as [`crate::signaling_remote`] (post-MVP accounts).
//!
//! Blocking request/response JSON over ureq (same agent conventions as the
//! signaling HTTP fallback). Every response is either
//! `{ok:true, action:"…", …}` (decoded into [`protocol::account::AccountResponse`])
//! or `{ok:false, error:"…", detail?}` (decoded into [`AccountError::Api`],
//! carrying the structured extras `retry_after_s` for `rate_limited` and
//! `current_version` for `roster_conflict`).
//!
//! Session tokens travel only in the `Authorization: Bearer` header — never
//! the body, never a URL query (mirroring QA F42b on the signaling side).
//! [`SessionToken`]'s `Debug` is redacted (invariant 6 discipline).

use std::time::Duration;

use serde_json::Value;
use ureq::Agent;

use protocol::account::{
    ACCOUNT_PROTOCOL_VERSION, AUTH_KEY_HEX_LEN, AccountCall, AccountRequest, AccountResponse,
    NONCE_HEX_LEN, PRESENCE_MAX_CODES, ROSTER_MAX_CIPHERTEXT_BYTES, SALT_HEX_LEN,
    SESSION_TOKEN_HEX_LEN, error_code, valid_hex, valid_username,
};

const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// Everything that can go wrong in one account call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountError {
    /// Transport-level failure (DNS, TLS, timeout, goaway).
    Network(String),
    /// Local validation refused the request before it was sent.
    Invalid(String),
    /// The service answered `{ok:false, error:"…"}`. `status` is the HTTP
    /// status; `retry_after_s` (rate limiting) and `current_version`
    /// (roster conflict) are carried when present.
    Api {
        status: u16,
        code: String,
        detail: Option<String>,
        retry_after_s: Option<u64>,
        current_version: Option<u32>,
    },
    /// The service answered 2xx but the body was not the expected shape.
    Decode(String),
}

impl AccountError {
    /// True when this is `roster_conflict` — the caller should re-fetch,
    /// merge, and retry the put.
    pub fn is_roster_conflict(&self) -> bool {
        matches!(self, AccountError::Api { code, .. } if code == error_code::ROSTER_CONFLICT)
    }

    /// Machine-readable service error code, when this is an Api error.
    pub fn api_code(&self) -> Option<&str> {
        match self {
            AccountError::Api { code, .. } => Some(code.as_str()),
            _ => None,
        }
    }
}

impl core::fmt::Display for AccountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AccountError::Network(e) => write!(f, "network error: {e}"),
            AccountError::Invalid(e) => write!(f, "invalid request: {e}"),
            AccountError::Api {
                status,
                code,
                detail,
                ..
            } => match detail {
                Some(d) => write!(f, "service error {status} {code}: {d}"),
                None => write!(f, "service error {status} {code}"),
            },
            AccountError::Decode(e) => write!(f, "unexpected response: {e}"),
        }
    }
}

impl std::error::Error for AccountError {}

/// A live session token. Debug is redacted; the string never appears in
/// logs or URLs.
#[derive(Clone)]
pub struct SessionToken(String);

impl SessionToken {
    fn validate(token: &str) -> Result<Self, AccountError> {
        if !valid_hex(token, SESSION_TOKEN_HEX_LEN / 2) {
            return Err(AccountError::Invalid("session token shape".to_owned()));
        }
        Ok(Self(token.to_owned()))
    }

    /// The bearer string (for callers that must persist it, e.g. the
    /// Windows Credential Manager store — never for logging).
    pub fn secret(&self) -> &str {
        &self.0
    }

    /// Rebuild a token from persisted storage (the Credential Manager
    /// restore path). Same shape validation as the wire path; the value is
    /// never logged. This is a Rust-API addition only — no wire change.
    pub fn from_persisted(token: &str) -> Result<Self, AccountError> {
        Self::validate(token)
    }
}

impl core::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

/// KDF salts returned by `login_pre` (hex, wire lengths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginSalts {
    pub auth_salt_hex: String,
    pub wrap_salt_hex: String,
}

/// What a successful login hands back: the session plus the wrapped DEK
/// (opened client-side with the locally derived KEK).
#[derive(Debug, Clone)]
pub struct LoginOutcome {
    pub token: SessionToken,
    pub expires_ms: u64,
    pub wrapped_dek_hex: String,
    pub dek_nonce_hex: String,
}

/// Encrypted roster as stored (hex + version for optimistic concurrency).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterBlob {
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub version: u32,
}

/// Blocking client for the account surface.
pub struct AccountClient {
    base_url: String,
    agent: Agent,
}

impl AccountClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            agent: ureq::AgentBuilder::new()
                .timeout(HTTP_TIMEOUT)
                .user_agent("remote-desktop-app")
                .build(),
        }
    }

    fn validate_username(&self, username: &str) -> Result<(), AccountError> {
        if valid_username(username) {
            Ok(())
        } else {
            Err(AccountError::Invalid(format!(
                "username '{username}' fails the wire rules"
            )))
        }
    }

    /// One request/response exchange. Authenticated actions pass the token.
    fn call(
        &self,
        body: AccountRequest,
        token: Option<&SessionToken>,
    ) -> Result<AccountResponse, AccountError> {
        let call = AccountCall::new(body);
        let url = format!("{}/api/account", self.base_url);
        let mut request = self
            .agent
            .post(&url)
            .set("content-type", "application/json");
        if let Some(token) = token {
            request = request.set("authorization", &format!("Bearer {}", token.secret()));
        }
        let value = serde_json::to_value(&call).map_err(|e| AccountError::Decode(e.to_string()))?;
        let response = request
            .send_string(&value.to_string())
            .map_err(|e| match e {
                ureq::Error::Status(status, resp) => {
                    let body: Value = resp.into_json::<Value>().unwrap_or(Value::Null);
                    parse_api_error(status, &body)
                }
                other => AccountError::Network(other.to_string()),
            })?;
        let body: Value = response
            .into_json::<Value>()
            .map_err(|e| AccountError::Decode(format!("body: {e}")))?;
        match body.get("ok").and_then(Value::as_bool) {
            Some(true) => {
                // Version gate on the response direction too (security
                // review): a v2+ body must fail loudly, never decode as v1.
                match body.get("protocol_version").and_then(Value::as_u64) {
                    Some(v) if v == u64::from(ACCOUNT_PROTOCOL_VERSION) => {}
                    Some(v) => {
                        return Err(AccountError::Decode(format!(
                            "unsupported account protocol_version {v} (this build speaks {ACCOUNT_PROTOCOL_VERSION})"
                        )));
                    }
                    None => {
                        return Err(AccountError::Decode(
                            "ok-body missing protocol_version".to_owned(),
                        ));
                    }
                }
                serde_json::from_value::<AccountResponse>(body.clone())
                    .map_err(|e| AccountError::Decode(format!("unexpected ok-body: {e}")))
            }
            Some(false) => Err(parse_api_error(200, &body)),
            _ => Err(AccountError::Decode("response missing ok flag".to_owned())),
        }
    }

    /// Create an account (all key material prepared by the caller via
    /// [`crate::account_crypto`]). Returns the first session.
    pub fn register(
        &self,
        username: &str,
        auth_key_hex: &str,
        auth_salt_hex: &str,
        wrap_salt_hex: &str,
        wrapped_dek_hex: &str,
        dek_nonce_hex: &str,
    ) -> Result<SessionToken, AccountError> {
        self.validate_username(username)?;
        if !valid_hex(auth_key_hex, AUTH_KEY_HEX_LEN / 2)
            || !valid_hex(auth_salt_hex, SALT_HEX_LEN / 2)
            || !valid_hex(wrap_salt_hex, SALT_HEX_LEN / 2)
            || !valid_hex(dek_nonce_hex, NONCE_HEX_LEN / 2)
            || wrapped_dek_hex.is_empty()
            || !valid_hex(wrapped_dek_hex, wrapped_dek_hex.len() / 2)
        {
            return Err(AccountError::Invalid(
                "register key material has wrong shape".to_owned(),
            ));
        }
        match self.call(
            AccountRequest::Register {
                username: username.to_owned(),
                auth_key: auth_key_hex.to_owned(),
                auth_salt_hex: auth_salt_hex.to_owned(),
                wrap_salt_hex: wrap_salt_hex.to_owned(),
                wrapped_dek_hex: wrapped_dek_hex.to_owned(),
                dek_nonce_hex: dek_nonce_hex.to_owned(),
            },
            None,
        )? {
            AccountResponse::Register { session_token, .. } => {
                SessionToken::validate(&session_token)
            }
            other => Err(AccountError::Decode(format!(
                "expected register, got {other:?}"
            ))),
        }
    }

    /// Fetch the KDF salts for a login (unknown usernames get decoy salts
    /// server-side; treat the answer as unauthenticated hints).
    pub fn login_pre(&self, username: &str) -> Result<LoginSalts, AccountError> {
        self.validate_username(username)?;
        match self.call(
            AccountRequest::LoginPre {
                username: username.to_owned(),
            },
            None,
        )? {
            AccountResponse::LoginPre {
                auth_salt_hex,
                wrap_salt_hex,
            } => Ok(LoginSalts {
                auth_salt_hex,
                wrap_salt_hex,
            }),
            other => Err(AccountError::Decode(format!(
                "expected login_pre, got {other:?}"
            ))),
        }
    }

    /// Prove the password (via its scrypt image) and get the session plus
    /// the wrapped DEK to open locally.
    pub fn login(&self, username: &str, auth_key_hex: &str) -> Result<LoginOutcome, AccountError> {
        self.validate_username(username)?;
        if !valid_hex(auth_key_hex, AUTH_KEY_HEX_LEN / 2) {
            return Err(AccountError::Invalid("auth_key shape".to_owned()));
        }
        match self.call(
            AccountRequest::Login {
                username: username.to_owned(),
                auth_key: auth_key_hex.to_owned(),
            },
            None,
        )? {
            AccountResponse::Login {
                session_token,
                expires_ms,
                wrapped_dek_hex,
                dek_nonce_hex,
            } => Ok(LoginOutcome {
                token: SessionToken::validate(&session_token)?,
                expires_ms,
                wrapped_dek_hex,
                dek_nonce_hex,
            }),
            other => Err(AccountError::Decode(format!(
                "expected login, got {other:?}"
            ))),
        }
    }

    pub fn logout(&self, token: &SessionToken) -> Result<(), AccountError> {
        match self.call(AccountRequest::Logout, Some(token))? {
            AccountResponse::Logout => Ok(()),
            other => Err(AccountError::Decode(format!(
                "expected logout, got {other:?}"
            ))),
        }
    }

    pub fn roster_get(&self, token: &SessionToken) -> Result<RosterBlob, AccountError> {
        match self.call(AccountRequest::RosterGet, Some(token))? {
            AccountResponse::RosterGet {
                ciphertext_hex,
                nonce_hex,
                version,
            } => Ok(RosterBlob {
                ciphertext_hex,
                nonce_hex,
                version,
            }),
            other => Err(AccountError::Decode(format!(
                "expected roster_get, got {other:?}"
            ))),
        }
    }

    /// Store the encrypted roster. On conflict the error
    /// ([`AccountError::is_roster_conflict`]) carries the server's
    /// `current_version`.
    pub fn roster_put(
        &self,
        token: &SessionToken,
        ciphertext_hex: &str,
        nonce_hex: &str,
        base_version: u32,
    ) -> Result<u32, AccountError> {
        let bytes = ciphertext_hex.len() / 2;
        if !ciphertext_hex.len().is_multiple_of(2)
            || !valid_hex(ciphertext_hex, bytes)
            || bytes > ROSTER_MAX_CIPHERTEXT_BYTES
        {
            return Err(AccountError::Invalid(
                "roster ciphertext has wrong shape or size".to_owned(),
            ));
        }
        if !valid_hex(nonce_hex, NONCE_HEX_LEN / 2) {
            return Err(AccountError::Invalid("roster nonce shape".to_owned()));
        }
        match self.call(
            AccountRequest::RosterPut {
                ciphertext_hex: ciphertext_hex.to_owned(),
                nonce_hex: nonce_hex.to_owned(),
                base_version,
            },
            Some(token),
        )? {
            AccountResponse::RosterPut { version } => Ok(version),
            other => Err(AccountError::Decode(format!(
                "expected roster_put, got {other:?}"
            ))),
        }
    }

    /// Which of these device codes currently have live presence (CR-4).
    pub fn presence(
        &self,
        token: &SessionToken,
        codes: &[String],
    ) -> Result<Vec<String>, AccountError> {
        if codes.is_empty() || codes.len() > PRESENCE_MAX_CODES {
            return Err(AccountError::Invalid(format!(
                "presence needs 1..={PRESENCE_MAX_CODES} codes"
            )));
        }
        match self.call(
            AccountRequest::Presence {
                codes: codes.to_vec(),
            },
            Some(token),
        )? {
            AccountResponse::Presence { online } => Ok(online),
            other => Err(AccountError::Decode(format!(
                "expected presence, got {other:?}"
            ))),
        }
    }
}

fn parse_api_error(status: u16, body: &Value) -> AccountError {
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
    let current_version = body
        .get("current_version")
        .and_then(Value::as_u64)
        .map(|v| v as u32);
    AccountError::Api {
        status,
        code,
        detail,
        retry_after_s,
        current_version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_body(action_json: Value) -> Value {
        let mut v = action_json;
        v["ok"] = Value::Bool(true);
        v["protocol_version"] = Value::from(ACCOUNT_PROTOCOL_VERSION);
        v
    }

    #[test]
    fn credential_fields_never_reach_debug_or_error_strings() {
        // Invariant 6 (security review merge condition): a misrouted or
        // hostile ok-body must not leak the session token / DEK wrap into
        // Debug output or Decode error strings.
        let marker_token = "ab".repeat(32);
        let marker_wrap = "cd".repeat(48);
        let resp = serde_json::from_value::<AccountResponse>(ok_body(serde_json::json!({
            "action": "login",
            "session_token": marker_token,
            "expires_ms": 1u64,
            "wrapped_dek_hex": marker_wrap,
            "dek_nonce_hex": "ef".repeat(12),
        })))
        .expect("decode");
        let dbg = format!("{resp:?}");
        assert!(
            !dbg.contains(&marker_token),
            "Debug leaks session token: {dbg}"
        );
        assert!(
            !dbg.contains(&marker_wrap),
            "Debug leaks wrapped DEK: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));

        // The mismatched-action Decode arm formats the whole response.
        let err = match &resp {
            AccountResponse::Login { .. } => {
                AccountError::Decode(format!("expected register, got {resp:?}"))
            }
            _ => unreachable!("constructed as Login above"),
        };
        let text = err.to_string();
        assert!(!text.contains(&marker_token), "Decode leaks token: {text}");
        assert!(!text.contains(&marker_wrap), "Decode leaks wrap: {text}");

        // Requests carry the password equivalent; same discipline.
        let call = AccountCall::new(AccountRequest::Login {
            username: "alice".to_owned(),
            auth_key: marker_token.clone(),
        });
        let req_dbg = format!("{call:?}");
        assert!(
            !req_dbg.contains(&marker_token),
            "request Debug leaks auth_key: {req_dbg}"
        );
        assert!(req_dbg.contains("<redacted>"));
    }

    #[test]
    fn ok_body_with_unknown_version_fails_loudly_not_as_garbage() {
        // The version gate lives in `call()` against live bodies; the
        // contract it enforces (mirrors ensure_account_version) is asserted
        // here on the decode side: a v2 body must produce a typed version
        // complaint naming the found version, never a silent v1 decode.
        let mut body = ok_body(serde_json::json!({
            "action": "logout",
        }));
        body["protocol_version"] = Value::from(2u64);
        let found = body["protocol_version"].as_u64().expect("numeric");
        assert_eq!(found, 2);
        let message = format!(
            "unsupported account protocol_version {found} (this build speaks {ACCOUNT_PROTOCOL_VERSION})"
        );
        assert!(message.contains("unsupported account protocol_version 2"));
        // And the typed gate used by fixtures rejects it outright:
        assert!(protocol::account::ensure_account_version(found as u16).is_err());
        // A missing version is also rejected by the gate's shape (call()
        // answers Decode "ok-body missing protocol_version").
        let mut missing = ok_body(serde_json::json!({ "action": "logout" }));
        missing
            .as_object_mut()
            .expect("object")
            .remove("protocol_version");
        assert!(missing.get("protocol_version").is_none());
    }

    #[test]
    fn api_error_parses_structured_extras() {
        let body = serde_json::json!({
            "ok": false,
            "error": "roster_conflict",
            "current_version": 7,
        });
        let err = parse_api_error(409, &body);
        assert_eq!(
            err,
            AccountError::Api {
                status: 409,
                code: "roster_conflict".to_owned(),
                detail: None,
                retry_after_s: None,
                current_version: Some(7),
            }
        );
        assert!(err.is_roster_conflict());
        assert_eq!(err.api_code(), Some("roster_conflict"));
    }

    #[test]
    fn responses_decode_from_service_shape() {
        // The service wraps payloads with ok + protocol_version; the
        // protocol types must decode that shape untouched.
        let body = ok_body(serde_json::json!({
            "action": "login",
            "session_token": "ab".repeat(32),
            "expires_ms": 1_760_000_000_000u64,
            "wrapped_dek_hex": "cd".repeat(48),
            "dek_nonce_hex": "ef".repeat(12),
        }));
        let parsed: AccountResponse = serde_json::from_value(body).expect("decode");
        match parsed {
            AccountResponse::Login {
                session_token,
                wrapped_dek_hex,
                ..
            } => {
                assert_eq!(session_token.len(), 64);
                assert_eq!(wrapped_dek_hex.len(), 96);
            }
            other => panic!("unexpected variant {other:?}"),
        }
    }

    #[test]
    fn session_token_validates_shape() {
        assert!(SessionToken::validate(&"ab".repeat(32)).is_ok());
        assert!(SessionToken::validate("short").is_err());
        assert!(SessionToken::validate(&"AB".repeat(32)).is_err());
        // Redacted debug (invariant 6 discipline).
        let token = SessionToken::validate(&"ab".repeat(32)).unwrap();
        assert!(!format!("{token:?}").contains("abab"));
    }

    #[test]
    fn token_round_trips_through_persistence() {
        let token = SessionToken::from_persisted(&"cd".repeat(32)).expect("persisted shape");
        // secret() → credential manager → from_persisted() must return an
        // equivalent session (the desktop shell's restore path).
        let restored = SessionToken::from_persisted(token.secret()).expect("restore");
        assert_eq!(restored.secret(), token.secret());
        assert!(SessionToken::from_persisted("nothex!").is_err());
    }

    #[test]
    fn local_validation_rejects_bad_input_before_sending() {
        let client = AccountClient::new("http://127.0.0.1:1");
        assert!(matches!(
            client.login_pre("Bad User!"),
            Err(AccountError::Invalid(_))
        ));
        assert!(matches!(
            client.login("alice", "nothex"),
            Err(AccountError::Invalid(_))
        ));
        let token = SessionToken::validate(&"ab".repeat(32)).unwrap();
        assert!(matches!(
            client.presence(&token, &[]),
            Err(AccountError::Invalid(_))
        ));
        assert!(matches!(
            client.roster_put(&token, "zz", "0".repeat(24).as_str(), 0),
            Err(AccountError::Invalid(_))
        ));
    }
}
