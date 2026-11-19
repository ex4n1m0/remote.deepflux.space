//! Swarm enrollment, app side (ADR-013 P1): the tracker-side account
//! system already owns users, device-code enrollment and machine binding;
//! this module is the app's half. One persistent Ed25519 device identity
//! (the `machine-identity` anchor precedent: seed in the Windows
//! Credential Manager, so it survives reinstalls), a "Join a swarm" flow
//! (`/auth/device/start` → 8-char userCode for the website dashboard →
//! `/auth/device/complete` polling), the resulting session (bearer in the
//! Credential Manager, never in settings/IPC), and a liveness heartbeat.
//!
//! Wire discipline: the `deviceCode` and the session bearer live in Rust
//! state + credstore ONLY — they never cross IPC (the ipc_surface walk
//! asserts this). Background work follows the directory/chat poller
//! pattern: named std::thread loops with an AtomicBool cancel flag plus a
//! cycle counter, so a stale poller can never overwrite a newer join's
//! state.

use std::io::Read as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tauri::{AppHandle, Emitter, Manager};

use crate::credstore::SessionStore;
use modelswarm_identity::canonical_json;
use modelswarm_identity::{InstallationIdentity, SignedEnvelope, new_nonce, rfc3339_now};

/// Where the tracker lives. Override for dev/tests with the
/// `DEEPFLUX_TRACKER_URL` env var (the updater's `DEEPFLUX_UPDATE_MANIFEST`
/// pattern — e.g. a loopback server; https required outside loopback, see
/// [`allow_tracker_url`]).
pub const DEFAULT_TRACKER_URL: &str = "https://modelswarm.deepflux.space";

/// Credential-manager synthetic user for the 32-byte device seed (hex).
const SEED_USER: &str = "swarm-device-seed";
/// Credential-manager synthetic user for the tracker session (a JSON
/// [`SessionDoc`]; the bearer only ever moves between here and the
/// `x-msp-session` header).
const SESSION_USER: &str = "swarm-session";

/// Join-poll cadence. The tracker's enroll rate bucket is 10 req/min per
/// IP, SHARED between `/start` and every `/complete` poll — a faster poll
/// self-trips it. 10 s = start + ~5 polls/min, safely under the bucket
/// even single-instance.
const JOIN_POLL_PERIOD: Duration = Duration::from_secs(10);

/// How often the join thread checks for the user's ConfirmClaim answer
/// ([`SwarmService::claim_answer`]) — short, so the Allow/Deny click feels
/// immediate while staying a poll (no new sync primitives on the UI path).
const CLAIM_ANSWER_POLL: Duration = Duration::from_millis(400);
/// Heartbeat cadence (liveness only — the tracker needs "machine is up").
/// Account-directory poll cadence (the heartbeat rides every other tick —
/// the P1 60 s liveness cadence is unchanged).
const DIRECTORY_POLL_PERIOD: Duration = Duration::from_secs(30);
/// Per-request timeout + user agent for all enrollment calls.
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const ENROLL_UA: &str = "modelswarm-enroll";

// ---------------------------------------------------------------------------
// URL / time / hex helpers (pure, unit-tested)
// ---------------------------------------------------------------------------

fn tracker_url() -> String {
    let raw = std::env::var("DEEPFLUX_TRACKER_URL").unwrap_or_else(|_| DEFAULT_TRACKER_URL.into());
    if allow_tracker_url(&raw, cfg!(debug_assertions)) {
        raw
    } else {
        // Never silently downgrade to plaintext toward a non-loopback
        // host — the enrollment requests carry signed identities and the
        // session bearer. Fall back to the production tracker and say so.
        eprintln!(
            "[swarm] refusing non-https DEEPFLUX_TRACKER_URL {raw:?} — using {DEFAULT_TRACKER_URL}"
        );
        DEFAULT_TRACKER_URL.to_owned()
    }
}

/// Scheme gate for `DEEPFLUX_TRACKER_URL`: https always; http only for
/// loopback hosts (dev/test stub servers) or debug builds. Pure for unit
/// tests (`tracker_url` itself always sees this build's debug_assertions).
fn allow_tracker_url(url: &str, debug_build: bool) -> bool {
    if debug_build {
        return true;
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    if scheme.eq_ignore_ascii_case("https") {
        return true;
    }
    scheme.eq_ignore_ascii_case("http") && is_loopback_host(authority_host(rest))
}

/// The host portion of a URL's authority (userinfo, port, and path
/// stripped; IPv6 brackets kept so `[::1]` matches).
fn authority_host(authority_and_path: &str) -> &str {
    let authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let without_user = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(stripped) = without_user.strip_prefix('[') {
        return stripped.split(']').next().unwrap_or(stripped);
    }
    // host[:port] — the host is BEFORE the colon (a bare IPv6 literal is
    // not a valid authority without brackets).
    without_user.split(':').next().unwrap_or(without_user)
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Lowercase hex of `bytes` (64 chars for a seed; no new dep for one call).
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Parse exactly 64 hex chars into 32 bytes (the stored seed form).
fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    let text = text.trim();
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut seed = [0u8; 32];
    for (slot, pair) in seed.iter_mut().zip(text.as_bytes().chunks(2)) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        *slot = (hi * 16 + lo) as u8;
    }
    Some(seed)
}

/// Days from 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil` — the standard compact civil-calendar algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (i64::from(month) + 9) % 12; // Mar=0 … Feb=11
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Parse the tracker's ISO timestamps into Unix epoch milliseconds.
///
/// The tracker contract is frozen on `Date.prototype.toISOString` output
/// (`2026-11-19T12:34:56.789Z` — always UTC, `Z`, optional milliseconds);
/// only that canonical shape is accepted, fail-closed like the rest of the
/// enrollment path. Cross-checked against the identity crate's RFC 3339
/// parser in tests.
fn parse_iso_ms(ts: &str) -> Option<u64> {
    let bytes = ts.as_bytes();
    let millis = match bytes.len() {
        20 => 0u64,
        24 if bytes[19] == b'.' => ts.get(20..23)?.parse::<u64>().ok()?,
        _ => return None,
    };
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[bytes.len() - 1] != b'Z'
    {
        return None;
    }
    let year: i64 = ts.get(0..4)?.parse().ok()?;
    let month: u32 = ts.get(5..7)?.parse().ok()?;
    let day: u32 = ts.get(8..10)?.parse().ok()?;
    let hour: u64 = ts.get(11..13)?.parse().ok()?;
    let minute: u64 = ts.get(14..16)?.parse().ok()?;
    let second: u64 = ts.get(17..19)?.parse().ok()?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + (hour * 3600 + minute * 60 + second) as i64;
    u64::try_from(secs).ok().map(|s| s * 1000 + millis)
}

// ---------------------------------------------------------------------------
// MSP1 Authorization header (byte-exact tracker mirror)
// ---------------------------------------------------------------------------

/// Build the `Authorization: MSP1 <base64url(canonical envelope JSON)>`
/// header exactly as the tracker's `encodeAuthorization` does: sign the
/// canonical payload via [`SignedEnvelope`], serialize the FULL envelope
/// (signature included, camelCase wire names), canonicalize (sorted keys,
/// compact), and base64url WITHOUT padding (Node's `base64url`).
fn msp1_authorization(
    identity: &InstallationIdentity,
    method: &str,
    path: &str,
    body: &str,
) -> Result<String, String> {
    let digest = format!("sha256:{}", hex_lower(&Sha256::digest(body.as_bytes())));
    let envelope = SignedEnvelope::sign(identity, method, path, rfc3339_now(), new_nonce(), digest);
    let value = serde_json::to_value(&envelope)
        .map_err(|e| format!("swarm enroll: envelope serialization: {e}"))?;
    let canonical = canonical_json(&value)
        .ok_or_else(|| "swarm enroll: canonical JSON rejected the envelope".to_owned())?;
    Ok(format!(
        "MSP1 {}",
        URL_SAFE_NO_PAD.encode(canonical.as_bytes())
    ))
}

// ---------------------------------------------------------------------------
// Device identity + session (Credential Manager; secrets never cross IPC)
// ---------------------------------------------------------------------------

/// This installation's swarm identity: a 32-byte Ed25519 seed loaded from
/// (or minted into) the Credential Manager, wrapped in the identity
/// crate's [`InstallationIdentity`]. Survives reinstalls like the
/// `machine-identity` anchor.
#[derive(Clone)]
pub struct SwarmIdentity {
    identity: InstallationIdentity,
}

impl SwarmIdentity {
    pub fn load_or_create(creds: &dyn SessionStore) -> Result<Self, String> {
        if let Ok(Some(stored)) = creds.load(SEED_USER)
            && let Some(seed) = parse_hex32(&stored)
        {
            return Ok(Self {
                identity: InstallationIdentity::from_bytes(&seed),
            });
        }
        // Missing or malformed: mint a fresh seed and persist it (the next
        // load — including after a reinstall — restores the same identity).
        let fresh = InstallationIdentity::generate();
        creds
            .save(SEED_USER, &hex_lower(&fresh.to_bytes()))
            .map_err(|e| format!("swarm identity: {e}"))?;
        Ok(Self { identity: fresh })
    }

    /// Gate (d) recovery: OVERWRITE the stored seed with a fresh one. The
    /// returned identity has a new installation id — the old one is dead
    /// locally the moment this returns (its server row must be revoked on
    /// the dashboard). Caller must also clear the session.
    pub fn rekey(creds: &dyn SessionStore) -> Result<Self, String> {
        let fresh = InstallationIdentity::generate();
        creds
            .save(SEED_USER, &hex_lower(&fresh.to_bytes()))
            .map_err(|e| format!("swarm rekey: {e}"))?;
        Ok(Self { identity: fresh })
    }

    /// ADR-013 P2: the controller-side account-proof signer handed to the
    /// engine at connect (the private key stays inside the closure — and
    /// inside this process's Credential Manager).
    pub fn account_prover(&self) -> node_runtime::account_proof::AccountProver {
        let signing = self.identity.clone();
        node_runtime::account_proof::AccountProver::new(
            self.installation_id(),
            self.pub_key_b58(),
            std::sync::Arc::new(move |domain: &str| {
                let signature = signing.sign_raw(domain.as_bytes());
                Ok(hex_lower(&signature.to_bytes()))
            }),
        )
    }

    /// base58(SHA-256(pubkey)) — the enrollment wire identity.
    pub fn installation_id(&self) -> String {
        self.identity.installation_id()
    }

    /// The public key, base58 — the `/auth/device/start` `pubKey` field.
    pub fn pub_key_b58(&self) -> String {
        self.identity.pub_key_b58()
    }
}

/// The tracker session mirror stored under [`SESSION_USER`]. `Debug`
/// redacts the bearer (invariant-6 discipline — it is a secret).
#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct SessionDoc {
    v: u8,
    token: String,
    expires_at_ms: u64,
}

impl core::fmt::Debug for SessionDoc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionDoc")
            .field("v", &self.v)
            .field("token", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

fn save_session(creds: &dyn SessionStore, doc: &SessionDoc) -> Result<(), String> {
    let blob = serde_json::to_string(doc).map_err(|e| format!("swarm session: {e}"))?;
    creds
        .save(SESSION_USER, &blob)
        .map_err(|e| format!("swarm session: {e}"))
}

fn load_session(creds: &dyn SessionStore) -> Option<SessionDoc> {
    let blob = creds.load(SESSION_USER).ok().flatten()?;
    // A corrupt blob is dead data: clear it so the state can never pin to
    // a session nobody can read back.
    match serde_json::from_str(&blob) {
        Ok(doc) => Some(doc),
        Err(_) => {
            let _ = creds.clear(SESSION_USER);
            None
        }
    }
}

fn clear_session(creds: &dyn SessionStore) {
    let _ = creds.clear(SESSION_USER);
}

// ---------------------------------------------------------------------------
// UI state (serde DTO, no secrets — walked by the ipc_surface test)
// ---------------------------------------------------------------------------

/// Swarm membership state for the webview, emitted on `swarm://state` and
/// returned by `swarm_status`. Field names deliberately avoid the IPC
/// surface's forbidden substrings; the deviceCode and session bearer are
/// structurally absent (Rust state + credstore only).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SwarmState {
    NotJoined,
    /// Pairing code shown; the user approves on the website dashboard.
    Joining {
        user_code: String,
        expires_at_ms: u64,
    },
    /// An account claimed this machine's pairing code (gate (a) handshake):
    /// the dashboard approve no longer binds directly — the person AT this
    /// machine decides. `claimed_by` is the tracker's masked claimer email.
    /// `swarm_claim_answer` resolves it (Allow → binding + enrollment;
    /// Deny → the code returns to pending for the right owner).
    ConfirmClaim {
        claimed_by: String,
        expires_at_ms: u64,
    },
    Joined {
        installation_id: String,
        session_expires_at_ms: u64,
    },
    /// The binding or session is gone server-side (revoked on the
    /// dashboard, or the 24 h session expired) — rejoin is the answer.
    NeedsRejoin {
        reason: String,
    },
    Failed {
        reason: String,
    },
}

/// Managed state + lifecycle flags for the join/heartbeat threads.
pub struct SwarmService {
    state: Mutex<SwarmState>,
    /// Cancels an in-flight join poller (checked every tick).
    join_cancel: AtomicBool,
    /// The user's answer to a pending [`SwarmState::ConfirmClaim`] — set by
    /// `swarm_claim_answer`, drained by the join thread (which owns the
    /// deviceCode, so only it can POST the confirm). `None` = no answer yet.
    claim_answer: Mutex<Option<bool>>,
    /// Monotonic lifecycle counter: every begin (join / startup restore /
    /// cancel / leave) bumps it, and poller/heartbeat state writes are
    /// only applied while the cycle they were spawned for is still
    /// current — a stale thread can never clobber a newer cycle's state.
    cycle: AtomicU64,
}

impl Default for SwarmService {
    fn default() -> Self {
        Self {
            state: Mutex::new(SwarmState::NotJoined),
            join_cancel: AtomicBool::new(false),
            claim_answer: Mutex::new(None),
            cycle: AtomicU64::new(0),
        }
    }
}

impl SwarmService {
    /// Begin a new lifecycle (a join attempt or the startup restore).
    /// Returns the cycle token every later state write must carry.
    fn begin_cycle(&self) -> u64 {
        let cycle = self.cycle.fetch_add(1, Ordering::SeqCst) + 1;
        self.join_cancel.store(false, Ordering::SeqCst);
        *self.claim_answer.lock().expect("swarm claim answer") = None;
        cycle
    }

    /// Record the user's answer to a pending claim prompt (the join thread
    /// drains it on its next tick). True iff a ConfirmClaim is on screen.
    fn answer_claim(&self, accept: bool) -> bool {
        let mut guard = self.claim_answer.lock().expect("swarm claim answer");
        match *self.state.lock().expect("swarm state") {
            SwarmState::ConfirmClaim { .. } => {
                *guard = Some(accept);
                true
            }
            _ => false,
        }
    }

    /// Take the pending claim answer, if any (join thread only).
    fn take_claim_answer(&self) -> Option<bool> {
        self.claim_answer.lock().expect("swarm claim answer").take()
    }

    /// Apply `next` only while `cycle` is still current. Returns the new
    /// DTO for the caller to emit, or `None` when the cycle went stale
    /// (a stale thread must not clobber a newer cycle's state).
    fn try_apply(&self, cycle: u64, next: SwarmState) -> Option<SwarmState> {
        let mut guard = self.state.lock().expect("swarm state");
        if self.cycle.load(Ordering::SeqCst) != cycle {
            return None;
        }
        *guard = next;
        Some(guard.clone())
    }

    /// Cycle currency under the state lock — cancel/leave bump the cycle
    /// while holding the same lock, so a `true` here + a later
    /// [`Self::try_apply`] can only be split by an interleaved bump,
    /// which the caller's compensating clear covers.
    fn cycle_current(&self, cycle: u64) -> bool {
        let _guard = self.state.lock().expect("swarm state");
        self.cycle.load(Ordering::SeqCst) == cycle
    }

    /// Cancel any in-flight join: bumps the cycle (a late start/poll
    /// result for the old cycle is discarded by [`Self::try_apply`]) and
    /// returns to NotJoined — an established membership (Joined) is NOT
    /// touched; leaving is `swarm_leave`'s job. Returns the DTO to emit.
    fn cancel_local(&self) -> SwarmState {
        let mut guard = self.state.lock().expect("swarm state");
        self.cycle.fetch_add(1, Ordering::SeqCst);
        self.join_cancel.store(true, Ordering::SeqCst);
        if !matches!(*guard, SwarmState::Joined { .. }) {
            *guard = SwarmState::NotJoined;
        }
        guard.clone()
    }

    pub fn current(&self) -> SwarmState {
        self.state.lock().expect("swarm state").clone()
    }
}

/// Apply + emit, cycle-guarded: the emit happens outside the state lock.
fn apply_state(app: &AppHandle, cycle: u64, next: SwarmState) -> bool {
    let dto = app
        .state::<crate::commands::AppServices>()
        .swarm
        .try_apply(cycle, next);
    match dto {
        Some(dto) => {
            let _ = app.emit(crate::commands::events::SWARM, dto);
            true
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Pure decisions (watchdog style — unit-tested with synthetic clocks)
// ---------------------------------------------------------------------------

/// True when the pairing-code window is over (the tracker's deviceCode
/// TTL; a poll past this point can only ever answer 401).
fn join_expired(expires_at_ms: u64, now_ms: u64) -> bool {
    now_ms >= expires_at_ms
}

/// Decision of one heartbeat tick. `http_status` is `None` on a transport
/// error (offline / timeout) — one bad network tick never drops a healthy
/// membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeartbeatDecision {
    /// 200 — stay Joined.
    Keep,
    /// 401/404 — the session or the machine binding is gone server-side.
    NeedsRejoin,
    /// Transport error or an unexpected status — keep the session and
    /// retry on the next tick.
    Retry,
    /// The 24 h session window is over locally (no auto-refresh —
    /// NeedsRejoin is the P1 answer per ADR-013).
    Expired,
}

fn heartbeat_decision(
    http_status: Option<u16>,
    session_expires_at_ms: u64,
    now_ms: u64,
) -> HeartbeatDecision {
    if now_ms >= session_expires_at_ms {
        return HeartbeatDecision::Expired;
    }
    match http_status {
        Some(200..=299) => HeartbeatDecision::Keep,
        Some(401) | Some(404) => HeartbeatDecision::NeedsRejoin,
        _ => HeartbeatDecision::Retry,
    }
}

/// Classification of one `/auth/device/complete` poll. 2xx never reaches
/// [`complete_outcome`] (ureq only returns Ok for success — the caller
/// parses that body directly); this classifies the ERROR statuses, body
/// included (the tracker answers `{error:{code,message,retryable}}`).
#[derive(Clone, PartialEq, Eq)]
enum CompleteOutcome {
    /// 200 — the dashboard approved; carry the session.
    Approved { token: String, expires_at_ms: u64 },
    /// 200 with `{status:"claim_pending"}` — an account claimed the code;
    /// surface the masked claimer and wait for this machine's answer.
    ClaimPending { claimed_by: String },
    /// 403 — awaiting the user's approval; keep polling.
    Pending,
    /// 429 / 5xx / transport error — the enroll rate bucket tripped or the
    /// server/network blipped; keep polling until the join window ends.
    Retry,
    /// 401 (unknown/expired code), a stale timestamp, or any other 4xx —
    /// retrying cannot change the answer; stop and say why.
    Denied(String),
}

/// `Debug` redacts the session bearer (invariant-6 discipline).
impl core::fmt::Debug for CompleteOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Approved {
                token: _,
                expires_at_ms,
            } => f
                .debug_struct("Approved")
                .field("token", &"<redacted>")
                .field("expires_at_ms", expires_at_ms)
                .finish(),
            Self::ClaimPending { claimed_by } => f
                .debug_struct("ClaimPending")
                .field("claimed_by", claimed_by)
                .finish(),
            Self::Pending => f.write_str("Pending"),
            Self::Retry => f.write_str("Retry"),
            Self::Denied(reason) => f.debug_tuple("Denied").field(reason).finish(),
        }
    }
}

/// True when a tracker error body parses and its `error.code` equals
/// `code` (e.g. `stale_timestamp`) — the body decides some 400s.
fn tracker_error_code_is(body: &str, code: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(|error| error.get("code"))
        .and_then(serde_json::Value::as_str)
        == Some(code)
}

fn complete_outcome(status: u16, body: &str) -> CompleteOutcome {
    match status {
        403 => CompleteOutcome::Pending,
        401 => CompleteOutcome::Denied(
            "The pairing code wasn't recognized — it may have expired. Start again.".to_owned(),
        ),
        429 => CompleteOutcome::Retry,
        500..=599 => CompleteOutcome::Retry,
        // A stale envelope timestamp means THIS machine's clock is off —
        // polling cannot fix it, but the user can.
        400 if tracker_error_code_is(body, "stale_timestamp") => CompleteOutcome::Denied(
            "This PC's clock is off, so the tracker rejected the request as too old — sync your computer's time and try again.".to_owned(),
        ),
        other => CompleteOutcome::Denied(format!("swarm enroll: HTTP {other}")),
    }
}

// ---------------------------------------------------------------------------
// Tracker client (thin; schannel TLS via the node-runtime connector, and
// redirects DISABLED — the MSP1 Authorization header must never be
// re-sent cross-host by a 3xx)
// ---------------------------------------------------------------------------

struct StartReply {
    /// SECRET (256-bit hex) — Rust state only, never IPC.
    device_code: String,
    user_code: String,
    expires_at_ms: u64,
}

/// `Debug` redacts the deviceCode (it is the enrollment bearer).
impl core::fmt::Debug for StartReply {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StartReply")
            .field("device_code", &"<redacted>")
            .field("user_code", &self.user_code)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

struct TrackerClient {
    base: String,
    agent: ureq::Agent,
}

impl TrackerClient {
    fn new() -> Self {
        Self {
            base: tracker_url().trim_end_matches('/').to_owned(),
            // Same schannel connector + timeout + UA as
            // `node_runtime::http::https_agent` (the workspace TLS rule),
            // built here because enrollment must also pin `redirects(0)`:
            // a 3xx must surface as an error, never be followed with the
            // MSP1 Authorization header re-sent to another host.
            agent: ureq::AgentBuilder::new()
                .tls_connector(std::sync::Arc::new(
                    native_tls::TlsConnector::new().expect("schannel TlsConnector"),
                ))
                .redirects(0)
                .timeout(HTTP_TIMEOUT)
                .user_agent(ENROLL_UA)
                .build(),
        }
    }

    /// POST /api/v1/auth/device/start — plain JSON (unsigned; the
    /// "enroll" rate bucket on the server).
    fn device_start(&self, identity: &SwarmIdentity) -> Result<StartReply, String> {
        let body = canonical_json(&json!({
            "installationId": identity.installation_id(),
            "pubKey": identity.pub_key_b58(),
        }))
        .ok_or_else(|| "swarm enroll: canonical body".to_owned())?;
        let url = format!("{}/api/v1/auth/device/start", self.base);
        let resp = self
            .agent
            .post(&url)
            .set("content-type", "application/json")
            .send_string(&body)
            .map_err(|e| format!("swarm enroll: {e}"))?;
        if resp.status() != 200 {
            return Err(format!("swarm enroll: HTTP {}", resp.status()));
        }
        let value: serde_json::Value = resp
            .into_json()
            .map_err(|e| format!("swarm enroll: bad reply: {e}"))?;
        let field = |name: &str| -> Result<String, String> {
            value
                .get(name)
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("swarm enroll: reply missing {name}"))
        };
        let expires_at_ms = parse_iso_ms(&field("expiresAt")?)
            .ok_or_else(|| "swarm enroll: reply expiresAt is not an ISO timestamp".to_owned())?;
        Ok(StartReply {
            device_code: field("deviceCode")?,
            user_code: field("userCode")?,
            expires_at_ms,
        })
    }

    /// POST /api/v1/auth/device/complete — MSP1-signed (no session yet:
    /// the tracker's `sessionRequired: false` for this route). Transport
    /// errors are surfaced as `Err` — the poller treats them as Retry.
    fn device_complete(
        &self,
        identity: &SwarmIdentity,
        device_code: &str,
    ) -> Result<CompleteOutcome, String> {
        let path = "/api/v1/auth/device/complete";
        let body = canonical_json(&json!({ "deviceCode": device_code }))
            .ok_or_else(|| "swarm enroll: canonical body".to_owned())?;
        let auth = msp1_authorization(&identity.identity, "POST", path, &body)?;
        let resp = self
            .agent
            .post(&format!("{}{path}", self.base))
            .set("content-type", "application/json")
            .set("authorization", &auth)
            .send_string(&body);
        match resp {
            Ok(resp) if resp.status() == 200 => {
                let value: serde_json::Value = resp
                    .into_json()
                    .map_err(|e| format!("swarm enroll: bad reply: {e}"))?;
                // Gate (a) handshake: a claimed-but-unconfirmed code answers
                // claim_pending INSTEAD of a session — the claimer's masked
                // email rides along for the ConfirmClaim prompt.
                if value.get("status").and_then(|v| v.as_str()) == Some("claim_pending") {
                    let claimed_by = value
                        .get("claimedBy")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.trim().is_empty())
                        .map(str::to_owned)
                        .ok_or_else(|| {
                            "swarm enroll: claim_pending without claimedBy".to_owned()
                        })?;
                    return Ok(CompleteOutcome::ClaimPending { claimed_by });
                }
                let token = value
                    .get("token")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.trim().is_empty())
                    .map(str::to_owned)
                    .ok_or_else(|| "swarm enroll: reply missing token".to_owned())?;
                let expires_at_ms = parse_iso_ms(
                    value
                        .get("expiresAt")
                        .and_then(|v| v.as_str())
                        .ok_or("swarm enroll: reply missing expiresAt")?,
                )
                .ok_or_else(|| {
                    "swarm enroll: reply expiresAt is not an ISO timestamp".to_owned()
                })?;
                Ok(CompleteOutcome::Approved {
                    token,
                    expires_at_ms,
                })
            }
            Ok(resp) => Err(format!("swarm enroll: HTTP {}", resp.status())),
            Err(ureq::Error::Status(status, resp)) => {
                // The body decides: 400 stale_timestamp is THIS machine's
                // clock, not a bad code.
                let body = read_error_body(resp);
                Ok(complete_outcome(status, &body))
            }
            Err(e) => Err(format!("swarm enroll: {e}")),
        }
    }

    /// POST /api/v1/auth/device/claim-confirm — MSP1-signed exactly like
    /// `device_complete` (no session yet). `accept` answers a pending
    /// account claim: the tracker binds on accept and frees the code on
    /// deny. Returns the HTTP status; the caller treats anything but 200
    /// as "keep polling" (a transient failure resolves on the next
    /// complete poll either way).
    fn claim_confirm(
        &self,
        identity: &SwarmIdentity,
        device_code: &str,
        accept: bool,
    ) -> Result<u16, String> {
        let path = "/api/v1/auth/device/claim-confirm";
        let body = canonical_json(&json!({ "deviceCode": device_code, "accept": accept }))
            .ok_or_else(|| "swarm enroll: canonical body".to_owned())?;
        let auth = msp1_authorization(&identity.identity, "POST", path, &body)?;
        match self
            .agent
            .post(&format!("{}{path}", self.base))
            .set("content-type", "application/json")
            .set("authorization", &auth)
            .send_string(&body)
        {
            Ok(_) => Ok(200),
            Err(ureq::Error::Status(status, _)) => Ok(status),
            Err(e) => Err(format!("swarm enroll: {e}")),
        }
    }

    /// POST /api/v1/account/machines/{installationId}/heartbeat —
    /// MSP1-signed + `x-msp-session`; body carries the P2 contact info
    /// (migration 0011): the signaling mailbox id (present-means-set —
    /// `Some` maps/shares it, `None` clears it for sharing-off machines)
    /// and the display name (fills an unnamed machine's label once).
    /// Returns the HTTP status (200 = alive; 401/404 = session/binding
    /// gone).
    fn heartbeat(
        &self,
        identity: &SwarmIdentity,
        session_token: &str,
        signaling_device_id: Option<&str>,
        display_name: &str,
    ) -> Result<u16, String> {
        let path = format!(
            "/api/v1/account/machines/{}/heartbeat",
            identity.installation_id()
        );
        let body = canonical_json(&json!({
            "signalingDeviceId": signaling_device_id,
            "displayName": display_name,
        }))
        .ok_or_else(|| "swarm heartbeat: canonical body".to_owned())?;
        let auth = msp1_authorization(&identity.identity, "POST", &path, &body)?;
        match self
            .agent
            .post(&format!("{}{path}", self.base))
            .set("content-type", "application/json")
            .set("authorization", &auth)
            .set("x-msp-session", session_token)
            .send_string(&body)
        {
            Ok(_) => Ok(200),
            Err(ureq::Error::Status(status, _)) => Ok(status),
            Err(e) => Err(format!("swarm heartbeat: {e}")),
        }
    }

    /// GET /api/v1/account/directory — the account's machines, machine-
    /// signed like the heartbeat (empty-body digest). `Err(Some(status))`
    /// is an HTTP answer the poller may act on (401/404 = auth death →
    /// the cache must fail closed); `Err(None)` is a transport blip (keep
    /// the last snapshot).
    fn account_directory(
        &self,
        identity: &SwarmIdentity,
        session_token: &str,
    ) -> Result<Vec<crate::account_directory::AccountMachineDto>, Option<u16>> {
        let path = "/api/v1/account/directory";
        let auth = msp1_authorization(&identity.identity, "GET", path, "").map_err(|e| {
            eprintln!("swarm directory: {e}");
            None
        })?;
        let resp = self
            .agent
            .get(&format!("{}{path}", self.base))
            .set("authorization", &auth)
            .set("x-msp-session", session_token)
            .call();
        let resp = match resp {
            Ok(resp) if resp.status() == 200 => resp,
            Ok(resp) => return Err(Some(resp.status())),
            Err(ureq::Error::Status(status, _)) => return Err(Some(status)),
            Err(e) => {
                eprintln!("swarm directory: {e}");
                return Err(None);
            }
        };
        let value: serde_json::Value = match resp.into_json() {
            Ok(value) => value,
            Err(e) => {
                eprintln!("swarm directory: bad reply: {e}");
                return Err(None); // transient — the poller keeps the snapshot
            }
        };
        let Some(rows) = value.get("machines").and_then(|m| m.as_array()) else {
            eprintln!("swarm directory: reply missing machines");
            return Err(None);
        };
        let mut machines = Vec::with_capacity(rows.len());
        for row in rows {
            let Some(installation_id) = row
                .get("installationId")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
            else {
                eprintln!("swarm directory: row missing installationId");
                return Err(None);
            };
            let installation_id = installation_id.to_owned();
            let label = row
                .get("label")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(str::to_owned);
            let last_seen_at_ms = row
                .get("lastSeenAt")
                .and_then(|v| v.as_str())
                .and_then(parse_iso_ms);
            let signaling_device_id = row
                .get("signalingDeviceId")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .map(str::to_owned);
            machines.push(crate::account_directory::AccountMachineDto {
                installation_id,
                label,
                last_seen_at_ms,
                signaling_device_id,
                is_self: false,
            });
        }
        Ok(machines)
    }
}

/// Read an error response's body, bounded — the tracker's error JSON is
/// well under 1 KiB; a huge error body is not ours (and never trusted
/// beyond the `error.code` string [`complete_outcome`] looks at).
fn read_error_body(resp: ureq::Response) -> String {
    let mut text = String::new();
    let _ = resp.into_reader().take(4096).read_to_string(&mut text);
    text
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

type CmdResult<T> = Result<T, String>;

/// Current swarm state (pull; the `swarm://state` push mirrors it).
#[tauri::command]
pub fn swarm_status(app: AppHandle) -> CmdResult<SwarmState> {
    Ok(app.state::<crate::commands::AppServices>().swarm.current())
}

/// Start the join flow: mint a cycle, hand the work to the join thread,
/// return immediately. The command itself does NO network I/O — a sync
/// Tauri command runs on the WebView dispatch thread, and the start POST
/// can take up to the 15 s timeout.
#[tauri::command]
pub fn swarm_join(app: AppHandle) -> CmdResult<()> {
    let cycle = {
        let services = app.state::<crate::commands::AppServices>();
        services.swarm.begin_cycle()
    };
    spawn_join(app, cycle)
}

/// Abandon an in-flight join (the modal's Cancel). Works in every join
/// phase — including while the start POST is still in flight: the cycle
/// bump makes the join thread's late result a no-op.
#[tauri::command]
pub fn swarm_cancel_join(app: AppHandle) -> CmdResult<()> {
    let dto = app
        .state::<crate::commands::AppServices>()
        .swarm
        .cancel_local();
    let _ = app.emit(crate::commands::events::SWARM, dto);
    Ok(())
}

/// Leave the swarm locally. NOTE: this clears the local membership (state
/// + the credstore session) only — the DASHBOARD-side revoke remains
/// authoritative for the account binding. The server keeps this machine's
/// row until the account owner revokes it there; local leave just stops
/// the app from presenting (and heartbeating) a session it no longer wants.
#[tauri::command]
pub fn swarm_leave(app: AppHandle) -> CmdResult<()> {
    let dto = {
        let services = app.state::<crate::commands::AppServices>();
        let swarm = &services.swarm;
        let mut guard = swarm.state.lock().expect("swarm state");
        swarm.cycle.fetch_add(1, Ordering::SeqCst);
        swarm.join_cancel.store(true, Ordering::SeqCst);
        *guard = SwarmState::NotJoined;
        guard.clone()
    };
    clear_session(&crate::credstore::WindowsCredStore);
    // No membership, no account view (security review finding 2).
    app.state::<crate::commands::AppServices>()
        .account_directory
        .clear();
    let _ = app.emit(crate::commands::events::SWARM, dto);
    Ok(())
}

/// Answer a pending account claim ([`SwarmState::ConfirmClaim`]): the join
/// thread picks the answer up and POSTs the signed confirm (only it holds
/// the deviceCode). Errors when no claim prompt is on screen.
#[tauri::command]
pub fn swarm_claim_answer(app: AppHandle, accept: bool) -> CmdResult<()> {
    let services = app.state::<crate::commands::AppServices>();
    if !services.swarm.answer_claim(accept) {
        return Err("no claim is waiting for an answer".to_owned());
    }
    Ok(())
}

/// Gate (d) re-key: mint a FRESH Ed25519 device seed (new installation id)
/// and drop the local session. The old identity is gone for good — its
/// server row dies with the dashboard-side revoke (heartbeats already
/// stopped here), and the new identity must enroll from scratch (fresh
/// pairing code, fresh claim confirm, fresh consent on every other
/// machine). This is the owner's recovery path when the never-rotating
/// seed is suspected stolen: docs/security/device-seed-theft.md.
#[tauri::command]
pub fn swarm_rekey(app: AppHandle) -> CmdResult<String> {
    let dto = {
        let services = app.state::<crate::commands::AppServices>();
        let swarm = &services.swarm;
        let mut guard = swarm.state.lock().expect("swarm state");
        swarm.cycle.fetch_add(1, Ordering::SeqCst);
        swarm.join_cancel.store(true, Ordering::SeqCst);
        *guard = SwarmState::NotJoined;
        guard.clone()
    };
    // Mint the new seed FIRST (security review note): a credstore failure
    // then leaves everything untouched instead of a cleared session with
    // the suspected-stolen identity still installed.
    let identity = SwarmIdentity::rekey(&crate::credstore::WindowsCredStore)?;
    clear_session(&crate::credstore::WindowsCredStore);
    // The old identity's account view is dead (finding 2).
    app.state::<crate::commands::AppServices>()
        .account_directory
        .clear();
    let _ = app.emit(crate::commands::events::SWARM, dto);
    Ok(identity.installation_id())
}

// ---------------------------------------------------------------------------
// Background threads (directory-poller pattern: named thread, app.state
// each tick, AtomicBool cancel; dies with the process by design)
// ---------------------------------------------------------------------------

/// Result of handling one Approved poll ([`complete_approved`]). No
/// secrets: the session token never appears here (it lives in the
/// credstore by the time this returns).
#[derive(Debug)]
enum Approval {
    /// Session stored + Joined applied; the DTO is the caller's to emit,
    /// and the heartbeat should start.
    Applied(SwarmState),
    /// The cycle went stale (leave/cancel won mid-flight) — nothing to
    /// emit; stand down silently.
    Stale,
    /// The session could not be persisted — surface as Failed.
    SaveFailed(String),
}

/// Handle one Approved `/complete` outcome for the credstore + state:
/// cycle currency is checked BEFORE the session is written (a stale
/// poller must not resurrect a session the user just cleared), and a
/// cycle that goes stale between that check and the apply gets a
/// compensating clear of the just-written session.
fn complete_approved(
    swarm: &SwarmService,
    creds: &dyn SessionStore,
    cycle: u64,
    installation_id: String,
    session: SessionDoc,
) -> Approval {
    if !swarm.cycle_current(cycle) {
        return Approval::Stale;
    }
    if let Err(err) = save_session(creds, &session) {
        return Approval::SaveFailed(err);
    }
    match swarm.try_apply(
        cycle,
        SwarmState::Joined {
            installation_id,
            session_expires_at_ms: session.expires_at_ms,
        },
    ) {
        Some(dto) => Approval::Applied(dto),
        None => {
            // The cycle went stale after the save — the membership this
            // session represented is gone; clear what we just wrote.
            clear_session(creds);
            Approval::Stale
        }
    }
}

/// The join worker: identity + start POST + the approval poll, all off
/// the UI thread. The deviceCode never leaves this thread's stack.
/// Returns Err only when the thread itself could not spawn.
fn spawn_join(app: AppHandle, cycle: u64) -> CmdResult<()> {
    std::thread::Builder::new()
        .name("swarm-join".into())
        .spawn(move || {
            let identity = match SwarmIdentity::load_or_create(&crate::credstore::WindowsCredStore)
            {
                Ok(identity) => identity,
                Err(reason) => {
                    apply_state(&app, cycle, SwarmState::Failed { reason });
                    return;
                }
            };
            let client = TrackerClient::new();
            let start = match client.device_start(&identity) {
                Ok(start) => start,
                Err(reason) => {
                    apply_state(&app, cycle, SwarmState::Failed { reason });
                    return;
                }
            };
            // Cancelled while the start POST was in flight: the cycle
            // bump already returned the user to NotJoined — stand down.
            let user_code = start.user_code.clone();
            if !apply_state(
                &app,
                cycle,
                SwarmState::Joining {
                    user_code: start.user_code,
                    expires_at_ms: start.expires_at_ms,
                },
            ) {
                return;
            }
            let device_code = start.device_code; // never leaves this thread
            let expires_at_ms = start.expires_at_ms;
            loop {
                std::thread::sleep(JOIN_POLL_PERIOD);
                {
                    let services = app.state::<crate::commands::AppServices>();
                    if services.swarm.join_cancel.load(Ordering::SeqCst)
                        || services.swarm.cycle.load(Ordering::SeqCst) != cycle
                    {
                        return;
                    }
                }
                if join_expired(expires_at_ms, now_ms()) {
                    apply_state(
                        &app,
                        cycle,
                        SwarmState::Failed {
                            reason:
                                "The pairing code expired before it was approved — start again."
                                    .to_owned(),
                        },
                    );
                    return;
                }
                match client.device_complete(&identity, &device_code) {
                    Ok(CompleteOutcome::Approved {
                        token,
                        expires_at_ms: session_expires,
                    }) => {
                        let outcome = {
                            let services = app.state::<crate::commands::AppServices>();
                            complete_approved(
                                &services.swarm,
                                &crate::credstore::WindowsCredStore,
                                cycle,
                                identity.installation_id(),
                                SessionDoc {
                                    v: 1,
                                    token,
                                    expires_at_ms: session_expires,
                                },
                            )
                        };
                        match outcome {
                            Approval::Applied(dto) => {
                                let _ = app.emit(crate::commands::events::SWARM, dto);
                                let _ = spawn_heartbeat(app, identity, cycle);
                            }
                            Approval::Stale => {}
                            Approval::SaveFailed(reason) => {
                                apply_state(&app, cycle, SwarmState::Failed { reason });
                            }
                        }
                        return;
                    }
                    Ok(CompleteOutcome::ClaimPending { claimed_by }) => {
                        // Gate (a): the machine asks its own user before any
                        // account binding sticks. Show the claimer and wait.
                        if !apply_state(
                            &app,
                            cycle,
                            SwarmState::ConfirmClaim {
                                claimed_by,
                                expires_at_ms,
                            },
                        ) {
                            return;
                        }
                        let accept = loop {
                            std::thread::sleep(CLAIM_ANSWER_POLL);
                            let services = app.state::<crate::commands::AppServices>();
                            if services.swarm.join_cancel.load(Ordering::SeqCst)
                                || services.swarm.cycle.load(Ordering::SeqCst) != cycle
                            {
                                return;
                            }
                            if let Some(answer) = services.swarm.take_claim_answer() {
                                break answer;
                            }
                            if join_expired(expires_at_ms, now_ms()) {
                                apply_state(
                                    &app,
                                    cycle,
                                    SwarmState::Failed {
                                        reason: "The pairing code expired before the claim was \
                                                 confirmed — start again."
                                            .to_owned(),
                                    },
                                );
                                return;
                            }
                        };
                        // Best-effort confirm: on a transport blip the next
                        // complete poll re-reports claim_pending and the
                        // prompt waits for another click.
                        let _ = client.claim_confirm(&identity, &device_code, accept);
                        if !accept {
                            // Denied: the code is pending again — back to the
                            // pairing-code screen for the right owner (a
                            // deny can repeat — the next claim may be
                            // someone else's).
                            if !apply_state(
                                &app,
                                cycle,
                                SwarmState::Joining {
                                    user_code: user_code.clone(),
                                    expires_at_ms,
                                },
                            ) {
                                return;
                            }
                        }
                        continue;
                    }
                    // Pending (403), rate-limited (429), server errors
                    // (5xx), and transport blips all keep polling until
                    // the join-window expiry above stops the loop.
                    Ok(CompleteOutcome::Pending | CompleteOutcome::Retry) | Err(_) => continue,
                    Ok(CompleteOutcome::Denied(reason)) => {
                        apply_state(&app, cycle, SwarmState::Failed { reason });
                        return;
                    }
                }
            }
        })
        .map_err(|e| format!("swarm enroll: couldn't start the join task: {e}"))
        .map(|_| ())
}

/// Heartbeat every 60 s while Joined (every other 30 s tick), the account
/// directory poll on each tick (ADR-013 P2 — the rail's discovery source
/// and the host-side consent-membership cache, so its freshness bounds how
/// long a freshly-added machine waits before first connect works).
/// 401/404 (or local expiry) moves to NeedsRejoin and clears the dead
/// session; transient errors retry. Returns false (applying NeedsRejoin)
/// when the thread could not spawn — a membership with no liveness
/// reporter is not a membership.
fn spawn_heartbeat(app: AppHandle, identity: SwarmIdentity, cycle: u64) -> bool {
    let worker_app = app.clone();
    let spawned = std::thread::Builder::new()
        .name("swarm-heartbeat".into())
        .spawn(move || {
            let app = worker_app;
            let client = TrackerClient::new();
            let mut tick: u32 = 0;
            loop {
                std::thread::sleep(DIRECTORY_POLL_PERIOD);
                tick = tick.wrapping_add(1);
                let (session_token, session_expires, contact) = {
                    let services = app.state::<crate::commands::AppServices>();
                    if services.swarm.cycle.load(Ordering::SeqCst) != cycle {
                        return;
                    }
                    match services.swarm.current() {
                        SwarmState::Joined {
                            session_expires_at_ms,
                            ..
                        } => {
                            let Some(session) = load_session(&crate::credstore::WindowsCredStore)
                            else {
                                // The session vanished underneath us (leave /
                                // wipe / corrupt blob): standing down
                                // silently would leave a Joined UI forever —
                                // surface the rejoin instead.
                                heartbeat_missing_session(&app, cycle);
                                return;
                            };
                            // Contact (P2): the signaling id is shared only
                            // while host sharing is on; a sharing-off machine
                            // reports null so the directory drops it from the
                            // controllable set.
                            let store = services.store.lock().expect("store");
                            let settings = store.settings();
                            let signaling = if settings.host_sharing {
                                Some(settings.device_id.clone())
                            } else {
                                None
                            };
                            let name =
                                crate::commands::display_name(settings).to_owned();
                            (session.token, session_expires_at_ms, (signaling, name))
                        }
                        _ => return, // superseded by a newer cycle's state
                    }
                };
                // Directory every tick (30 s) — the discovery + membership
                // snapshot. A successful poll also PRUNES armed account
                // intents for machines no longer in the account (security
                // review finding 3); a transport blip keeps the last
                // snapshot; auth death (401/404) FAILS CLOSED — an empty
                // cache means a revoked installation's proof immediately
                // stops matching "same account" (finding 2).
                match client.account_directory(&identity, &session_token) {
                    Ok(machines) => {
                        let present: Vec<String> =
                            machines.iter().map(|m| m.installation_id.clone()).collect();
                        {
                            let services = app.state::<crate::commands::AppServices>();
                            services
                                .account_directory
                                .update(&identity.installation_id(), machines.clone());
                        }
                        let _ = app.emit(crate::commands::events::ACCOUNT_DIRECTORY, Some(machines));
                        let _ = crate::chat::prune_account_intents(&app, &present);
                    }
                    Err(Some(401)) | Err(Some(404)) => {
                        {
                            let services = app.state::<crate::commands::AppServices>();
                            services.account_directory.clear();
                        }
                        let _ = app.emit(
                            crate::commands::events::ACCOUNT_DIRECTORY,
                            Some(Vec::<crate::account_directory::AccountMachineDto>::new()),
                        );
                    }
                    Err(_) => { /* transient: keep the last snapshot */ }
                }
                // Heartbeat every other tick (60 s, the P1 cadence).
                if !tick.is_multiple_of(2) {
                    continue;
                }
                let (signaling, name) = &contact;
                let status = client
                    .heartbeat(&identity, &session_token, signaling.as_deref(), name)
                    .ok();
                let decision = heartbeat_decision(status, session_expires, now_ms());
                match decision {
                    HeartbeatDecision::Keep | HeartbeatDecision::Retry => continue,
                    HeartbeatDecision::NeedsRejoin | HeartbeatDecision::Expired => {
                        clear_session(&crate::credstore::WindowsCredStore);
                        // Membership is gone: the directory cache dies with
                        // it (finding 2 — never leave a stale account view
                        // behind an exited poller).
                        app.state::<crate::commands::AppServices>()
                            .account_directory
                            .clear();
                        let reason = if matches!(decision, HeartbeatDecision::Expired) {
                            "The swarm session expired (24 h) — rejoin from Config → Swarm."
                                .to_owned()
                        } else {
                            "This machine was removed from the swarm on the website (or its session was revoked) — rejoin from Config → Swarm.".to_owned()
                        };
                        if apply_state(
                            &app,
                            cycle,
                            SwarmState::NeedsRejoin {
                                reason: reason.clone(),
                            },
                        ) {
                            let _ = app.emit(
                                crate::commands::events::INFO,
                                Some(json!({ "message": reason })),
                            );
                        }
                        return;
                    }
                }
            }
        });
    match spawned {
        Ok(_) => true,
        Err(err) => {
            let reason = format!("Couldn't start the swarm heartbeat thread: {err}");
            if apply_state(
                &app,
                cycle,
                SwarmState::NeedsRejoin {
                    reason: reason.clone(),
                },
            ) {
                let _ = app.emit(
                    crate::commands::events::INFO,
                    Some(json!({ "message": reason })),
                );
            }
            false
        }
    }
}

/// A Joined machine whose credstore session is gone cannot heartbeat:
/// transition to NeedsRejoin (state event + info line) instead of dying
/// silently.
fn heartbeat_missing_session(app: &AppHandle, cycle: u64) {
    let reason =
        "The saved swarm session is missing or unreadable — rejoin from Config → Swarm.".to_owned();
    if apply_state(
        app,
        cycle,
        SwarmState::NeedsRejoin {
            reason: reason.clone(),
        },
    ) {
        let _ = app.emit(
            crate::commands::events::INFO,
            Some(json!({ "message": reason })),
        );
    }
}

/// Startup restore: a surviving credstore session picks up where the last
/// run left off (Joined + heartbeat), or reports NeedsRejoin when the 24 h
/// window is over (no auto-refresh by design — ADR-013 P1). Only runs when
/// nothing else has touched the swarm yet this run.
pub fn spawn_startup(app: AppHandle) {
    std::thread::Builder::new()
        .name("swarm-restore".into())
        .spawn(move || {
            let Some(session) = load_session(&crate::credstore::WindowsCredStore) else {
                return;
            };
            let Ok(identity) = SwarmIdentity::load_or_create(&crate::credstore::WindowsCredStore)
            else {
                return;
            };
            let restored = {
                let services = app.state::<crate::commands::AppServices>();
                let swarm = &services.swarm;
                let mut guard = swarm.state.lock().expect("swarm state");
                // Only an untouched service restores (a join already in
                // flight, or a leave, owns the state now).
                if !matches!(*guard, SwarmState::NotJoined)
                    || swarm.cycle.load(Ordering::SeqCst) != 0
                {
                    None
                } else {
                    // Decide under the lock; the expired-session CLEAR is
                    // credstore I/O and happens after the lock drops (the
                    // swarm_leave ordering).
                    let expired = now_ms() >= session.expires_at_ms;
                    let cycle = swarm.begin_cycle();
                    let next = if expired {
                        SwarmState::NeedsRejoin {
                            reason: "The swarm session expired while the app was closed — rejoin from Config → Swarm.".to_owned(),
                        }
                    } else {
                        SwarmState::Joined {
                            installation_id: identity.installation_id(),
                            session_expires_at_ms: session.expires_at_ms,
                        }
                    };
                    *guard = next.clone();
                    Some((cycle, next, expired))
                }
            };
            let Some((cycle, next, expired)) = restored else {
                return;
            };
            if expired {
                clear_session(&crate::credstore::WindowsCredStore);
            }
            let _ = app.emit(crate::commands::events::SWARM, next.clone());
            if matches!(next, SwarmState::Joined { .. }) {
                let _ = spawn_heartbeat(app, identity, cycle);
            }
        })
        .expect("spawn swarm restore");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credstore::InMemorySessionStore;
    use modelswarm_identity::within_window;
    use std::io::Write as _;
    use std::net::TcpListener;

    /// Serializes the env-var-touching tests (std::env is process-global).
    static ENV_GUARD: Mutex<()> = Mutex::new(());

    #[test]
    fn seed_round_trips_through_the_credstore() {
        let creds = InMemorySessionStore::default();
        let first = SwarmIdentity::load_or_create(&creds).unwrap();
        let second = SwarmIdentity::load_or_create(&creds).unwrap();
        assert_eq!(first.installation_id(), second.installation_id());
        assert_eq!(first.pub_key_b58(), second.pub_key_b58());
        // The stored form is the 64-hex seed; the public key derives from
        // it (base58, 43+ chars per the tracker's schema).
        let stored = creds.load(SEED_USER).unwrap().unwrap();
        assert_eq!(stored.len(), 64);
        assert!(stored.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(first.pub_key_b58().len() >= 43);
        // A fresh store mints a DIFFERENT identity (per-installation).
        let other = SwarmIdentity::load_or_create(&InMemorySessionStore::default()).unwrap();
        assert_ne!(first.installation_id(), other.installation_id());
    }

    #[test]
    fn malformed_seed_is_replaced_not_fatal() {
        let creds = InMemorySessionStore::default();
        creds.save(SEED_USER, "not-a-seed").unwrap();
        let identity = SwarmIdentity::load_or_create(&creds).unwrap();
        assert!(!identity.installation_id().is_empty());
        // ...and the repair persisted a valid seed.
        assert!(parse_hex32(&creds.load(SEED_USER).unwrap().unwrap()).is_some());
    }

    #[test]
    fn session_doc_debug_redacts_the_bearer() {
        let doc = SessionDoc {
            v: 1,
            token: "a".repeat(64),
            expires_at_ms: 1,
        };
        let dbg = format!("{doc:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("aaaa"));
    }

    #[test]
    fn session_store_round_trip_and_clear() {
        let creds = InMemorySessionStore::default();
        assert!(load_session(&creds).is_none());
        save_session(
            &creds,
            &SessionDoc {
                v: 1,
                token: "t".repeat(64),
                expires_at_ms: 42,
            },
        )
        .unwrap();
        let loaded = load_session(&creds).unwrap();
        assert_eq!(loaded.expires_at_ms, 42);
        clear_session(&creds);
        assert!(load_session(&creds).is_none());
    }

    #[test]
    fn tracker_url_env_override_and_default() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::remove_var("DEEPFLUX_TRACKER_URL") };
        assert_eq!(tracker_url(), DEFAULT_TRACKER_URL);
        unsafe { std::env::set_var("DEEPFLUX_TRACKER_URL", "http://127.0.0.1:9") };
        assert_eq!(tracker_url(), "http://127.0.0.1:9");
        unsafe { std::env::remove_var("DEEPFLUX_TRACKER_URL") };
    }

    #[test]
    fn iso_parser_handles_the_tracker_shape_and_fails_closed() {
        assert_eq!(parse_iso_ms("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(parse_iso_ms("1970-01-01T00:00:00Z"), Some(0));
        // Leap-year boundary: 2024-02-29 → 2024-03-01 is exactly one day.
        let feb = parse_iso_ms("2024-02-29T00:00:00Z").unwrap();
        let mar = parse_iso_ms("2024-03-01T00:00:00Z").unwrap();
        assert_eq!(mar - feb, 86_400_000);
        // Milliseconds are kept.
        assert_eq!(
            parse_iso_ms("2026-11-19T12:34:56.789Z").unwrap() % 1000,
            789
        );
        // Fail-closed shapes.
        assert_eq!(parse_iso_ms("2026-11-19 12:34:56Z"), None); // no T
        assert_eq!(parse_iso_ms("2026-11-19T12:34:56"), None); // no Z
        assert_eq!(parse_iso_ms("2026-13-19T12:34:56Z"), None); // month 13
        assert_eq!(parse_iso_ms("2026-11-19T25:34:56Z"), None); // hour 25
        assert_eq!(parse_iso_ms(""), None);
    }

    /// Cross-check the hand-rolled parser against the identity crate's
    /// RFC 3339 (`time`-backed) window arithmetic: `within_window`
    /// compares truncated whole seconds, so the smallest whole-second
    /// window that accepts the pair must be the parser's millisecond
    /// difference divided by 1000 — i.e. the two parsers agree on every
    /// shape the tracker emits.
    #[test]
    fn iso_parser_agrees_with_the_identity_crate_window() {
        let cases = [
            ("2026-11-19T00:00:00Z", "2026-11-19T00:00:00Z"),
            ("2026-11-19T12:00:00.500Z", "2026-11-19T12:01:00Z"),
            ("2024-02-29T23:59:59Z", "2024-03-01T00:00:01Z"),
            ("2030-01-01T00:00:00.000Z", "2026-11-19T00:00:00Z"),
        ];
        for (a, b) in cases {
            let diff_ms = parse_iso_ms(a).unwrap().abs_diff(parse_iso_ms(b).unwrap());
            let min_window_secs = i64::try_from(diff_ms / 1000).unwrap();
            assert!(
                within_window(a, b, min_window_secs),
                "{a} vs {b}: parser diff {diff_ms} ms must satisfy within_window(+{min_window_secs}s)"
            );
            if min_window_secs >= 1 {
                assert!(
                    !within_window(a, b, min_window_secs - 1),
                    "{a} vs {b}: a {diff_ms} ms gap must not fit a {} s window",
                    min_window_secs - 1
                );
            }
        }
    }

    #[test]
    fn hex_helpers_round_trip() {
        let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
        let text = hex_lower(&seed);
        assert_eq!(text.len(), 64);
        assert_eq!(parse_hex32(&text).unwrap(), seed);
        assert_eq!(parse_hex32("zz"), None);
        assert_eq!(parse_hex32(&text[..63]), None);
        // Uppercase hex is accepted (to_digit is case-insensitive).
        assert_eq!(parse_hex32(&text.to_uppercase()).unwrap(), seed);
    }

    /// Trap-2 assertion: the header mirrors the tracker's
    /// `encodeAuthorization` byte-for-byte in form — "MSP1 " + unpadded
    /// base64url over the CANONICAL JSON of the FULL camelCase envelope,
    /// with a signature that verifies against the signer's public key.
    #[test]
    fn msp1_header_mirrors_the_tracker_envelope_form() {
        let identity = InstallationIdentity::from_bytes(&[3u8; 32]);
        let body = r#"{"deviceCode":"00ff"}"#;
        let header =
            msp1_authorization(&identity, "POST", "/api/v1/auth/device/complete", body).unwrap();
        let encoded = header.strip_prefix("MSP1 ").expect("MSP1 prefix");
        assert!(!encoded.contains('='), "Node base64url is unpadded");
        let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let text = String::from_utf8(decoded).unwrap();
        // Canonical JSON: exactly the sorted camelCase key set, compact.
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            vec![
                "bodyDigest",
                "installationId",
                "method",
                "nonce",
                "path",
                "signature",
                "ts"
            ]
        );
        // It IS a SignedEnvelope, and its signature verifies.
        let envelope: SignedEnvelope = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(envelope.method, "POST");
        assert_eq!(envelope.path, "/api/v1/auth/device/complete");
        assert_eq!(envelope.installation_id, identity.installation_id());
        assert_eq!(
            envelope.body_digest,
            format!("sha256:{}", hex_lower(&Sha256::digest(body.as_bytes())))
        );
        assert!(envelope.verify(&identity.verifying_key()));
        // Round trip: canonicalizing the deserialized envelope reproduces
        // the exact wire bytes (no drift between the two serializations).
        let recanonical = canonical_json(&serde_json::to_value(&envelope).unwrap()).unwrap();
        assert_eq!(text, recanonical);
    }

    #[test]
    fn join_expiry_follows_the_clock() {
        assert!(!join_expired(1_000, 999));
        assert!(join_expired(1_000, 1_000)); // boundary counts as expired
        assert!(join_expired(1_000, 2_000));
    }

    #[test]
    fn heartbeat_decision_covers_fresh_expired_and_gone() {
        let expires = 10_000u64;
        // Fresh session, alive.
        assert_eq!(
            heartbeat_decision(Some(200), expires, 9_999),
            HeartbeatDecision::Keep
        );
        // Session/binding gone server-side.
        assert_eq!(
            heartbeat_decision(Some(401), expires, 0),
            HeartbeatDecision::NeedsRejoin
        );
        assert_eq!(
            heartbeat_decision(Some(404), expires, 0),
            HeartbeatDecision::NeedsRejoin
        );
        // One bad network tick (or an unexpected status) retries.
        assert_eq!(
            heartbeat_decision(None, expires, 0),
            HeartbeatDecision::Retry
        );
        assert_eq!(
            heartbeat_decision(Some(500), expires, 0),
            HeartbeatDecision::Retry
        );
        assert_eq!(
            heartbeat_decision(Some(429), expires, 0),
            HeartbeatDecision::Retry
        );
        // Local expiry wins even when the server still answers 200.
        assert_eq!(
            heartbeat_decision(Some(200), expires, expires),
            HeartbeatDecision::Expired
        );
    }

    #[test]
    fn complete_outcome_classifies_the_frozen_statuses() {
        let body = |code: &str| format!(r#"{{"error":{{"code":"{code}","message":"x"}}}}"#);
        // 403 pending; 401 terminal with the pairing-code copy.
        assert!(matches!(
            complete_outcome(403, &body("pending")),
            CompleteOutcome::Pending
        ));
        match complete_outcome(401, &body("unauthorized")) {
            CompleteOutcome::Denied(reason) => assert!(reason.contains("pairing code")),
            other => panic!("401 must be terminal, got {other:?}"),
        }
        // 429 (the shared enroll bucket) and 5xx retry — the poller keeps
        // going until the join window expires.
        assert!(matches!(
            complete_outcome(429, &body("rate_limited")),
            CompleteOutcome::Retry
        ));
        assert!(matches!(
            complete_outcome(500, &body("internal")),
            CompleteOutcome::Retry
        ));
        assert!(matches!(
            complete_outcome(503, &body("unavailable")),
            CompleteOutcome::Retry
        ));
        // 400 stale_timestamp is THIS machine's clock — terminal, with
        // copy that names the actual cause.
        match complete_outcome(400, &body("stale_timestamp")) {
            CompleteOutcome::Denied(reason) => {
                assert!(reason.to_lowercase().contains("clock"), "got {reason:?}")
            }
            other => panic!("stale_timestamp must be terminal, got {other:?}"),
        }
        // Any other 4xx is terminal-generic.
        assert!(matches!(
            complete_outcome(400, &body("invalid_body")),
            CompleteOutcome::Denied(_)
        ));
        assert!(matches!(
            complete_outcome(404, "{}"),
            CompleteOutcome::Denied(_)
        ));
        // The body is only trusted for the code comparison — garbage
        // bodies never crash the classifier.
        assert!(matches!(
            complete_outcome(400, "not json"),
            CompleteOutcome::Denied(_)
        ));
    }

    #[test]
    fn tracker_url_gate_allows_https_loopback_and_debug_only() {
        // Release-build rules (the pure decision; tracker_url itself sees
        // this build's cfg!(debug_assertions)).
        assert!(allow_tracker_url(
            "https://modelswarm.deepflux.space",
            false
        ));
        assert!(allow_tracker_url("https://example.com/path", false));
        assert!(
            allow_tracker_url("http://127.0.0.1:1234", false),
            "loopback"
        );
        assert!(allow_tracker_url("http://localhost:9", false), "loopback");
        assert!(allow_tracker_url("http://[::1]:8080", false), "loopback v6");
        assert!(!allow_tracker_url("http://staging.example.com", false));
        assert!(
            !allow_tracker_url("http://10.0.0.5:8443", false),
            "private ≠ loopback"
        );
        assert!(!allow_tracker_url("ftp://modelswarm.deepflux.space", false));
        assert!(!allow_tracker_url("no-schema-here", false));
        // Debug builds keep the escape hatch for any dev target.
        assert!(allow_tracker_url("http://staging.example.com", true));
        // Authority parsing: userinfo and ports stripped, path ignored.
        assert!(is_loopback_host(authority_host("127.0.0.1:9/x?y")));
        assert!(is_loopback_host(authority_host("user@LOCALHOST:80/")));
    }

    #[test]
    fn start_reply_and_complete_outcome_debug_redact_secrets() {
        let start = StartReply {
            device_code: "d".repeat(64),
            user_code: "AB2CDEFG".to_owned(),
            expires_at_ms: 1,
        };
        let dbg = format!("{start:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("dddd"));
        assert!(dbg.contains("AB2CDEFG"), "the userCode is display-safe");

        let approved = CompleteOutcome::Approved {
            token: "t".repeat(64),
            expires_at_ms: 1,
        };
        let dbg = format!("{approved:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("tttt"));
        // Panics in earlier match arms printed these via Debug — make sure
        // the non-secret variants still render.
        assert_eq!(format!("{:?}", CompleteOutcome::Pending), "Pending");
        assert_eq!(format!("{:?}", CompleteOutcome::Retry), "Retry");
    }

    /// Cancel while the start POST is still in flight: the cycle bump
    /// must discard the join thread's late result (the old
    /// swarm_cancel_join no-op'd in this window and the Joining state
    /// landed afterwards anyway).
    #[test]
    fn cancel_during_start_discards_the_late_result() {
        let service = SwarmService::default();
        let join_cycle = service.begin_cycle(); // swarm_join spawns, start in flight
        // User cancels now — before any Joining state existed.
        let dto = service.cancel_local();
        assert!(matches!(dto, SwarmState::NotJoined));
        // The start POST succeeds late; the thread tries to apply Joining.
        assert!(
            service
                .try_apply(
                    join_cycle,
                    SwarmState::Joining {
                        user_code: "AB2CDEFG".to_owned(),
                        expires_at_ms: 1,
                    }
                )
                .is_none(),
            "a stale cycle must not apply Joining"
        );
        assert!(matches!(service.current(), SwarmState::NotJoined));
        // Cancel also stands down an in-flight approval poll...
        let join2 = service.begin_cycle();
        assert!(
            service
                .try_apply(
                    join2,
                    SwarmState::Joining {
                        user_code: "AB2CDEFG".to_owned(),
                        expires_at_ms: u64::MAX,
                    }
                )
                .is_some()
        );
        let dto = service.cancel_local();
        assert!(matches!(dto, SwarmState::NotJoined));
        // ...but never tears down an established membership.
        let joined_cycle = service.begin_cycle();
        assert!(
            service
                .try_apply(
                    joined_cycle,
                    SwarmState::Joined {
                        installation_id: "9ZkdqFPeqQFMbAtgS2M8b1aVvzGk4TQsN1WjnUpeTXW2".to_owned(),
                        session_expires_at_ms: u64::MAX,
                    }
                )
                .is_some()
        );
        let dto = service.cancel_local();
        assert!(matches!(dto, SwarmState::Joined { .. }), "cancel ≠ leave");
    }

    /// A stale approval must not write the session credstore entry (the
    /// leave/cancel that won mid-flight had cleared it); a current-cycle
    /// approval saves + applies.
    #[test]
    fn approval_respects_cycle_currency_for_the_credstore() {
        let creds = InMemorySessionStore::default();
        let sentinel = SessionDoc {
            v: 1,
            token: "old".to_owned(),
            expires_at_ms: 7,
        };
        save_session(&creds, &sentinel).unwrap();

        // Stale: the cycle moved on (leave/cancel) before approval landed.
        let service = SwarmService::default();
        let stale_cycle = service.begin_cycle();
        service.begin_cycle(); // a newer lifecycle owns the state now
        match complete_approved(
            &service,
            &creds,
            stale_cycle,
            "9ZkdqFPeqQFMbAtgS2M8b1aVvzGk4TQsN1WjnUpeTXW2".to_owned(),
            SessionDoc {
                v: 1,
                token: "new".to_owned(),
                expires_at_ms: 9,
            },
        ) {
            Approval::Stale => {}
            other => panic!("stale approval must be Stale, got {other:?}"),
        }
        assert_eq!(
            creds.load(SESSION_USER).unwrap().as_deref(),
            Some(serde_json::to_string(&sentinel).unwrap().as_str()),
            "the stale poller must leave the session entry untouched"
        );

        // Current: the session is stored and Joined applies.
        let live_cycle = service.begin_cycle();
        match complete_approved(
            &service,
            &creds,
            live_cycle,
            "9ZkdqFPeqQFMbAtgS2M8b1aVvzGk4TQsN1WjnUpeTXW2".to_owned(),
            SessionDoc {
                v: 1,
                token: "new".to_owned(),
                expires_at_ms: 9,
            },
        ) {
            Approval::Applied(dto) => assert!(matches!(dto, SwarmState::Joined { .. })),
            other => panic!("current approval must apply, got {other:?}"),
        }
        let stored: SessionDoc =
            serde_json::from_str(&creds.load(SESSION_USER).unwrap().unwrap()).unwrap();
        assert_eq!(stored.token, "new");
        assert!(matches!(service.current(), SwarmState::Joined { .. }));
    }

    // -----------------------------------------------------------------------
    // Wire-contract integration: a std::net::TcpListener stub tracker on
    // 127.0.0.1, reached through DEEPFLUX_TRACKER_URL, serving the frozen
    // responses while capturing the exact requests.
    // -----------------------------------------------------------------------

    #[derive(Debug, Clone)]
    struct CapturedRequest {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl CapturedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        }
    }

    /// One canned tracker exchange: reads a full HTTP/1.1 request (headers
    /// + Content-Length body), then writes `response`.
    ///
    /// `None` closes the socket without answering (a transport drop).
    fn serve_exchange(mut stream: std::net::TcpStream, response: Option<&str>) -> CapturedRequest {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        // Read until the header terminator, then the declared body length.
        let header_end = loop {
            if let Some(pos) = find_subslice(&buffer, b"\r\n\r\n") {
                break pos;
            }
            let n = stream.read(&mut chunk).expect("stub read");
            assert!(n > 0, "client closed before sending headers");
            buffer.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
        let content_length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while buffer.len() < header_end + 4 + content_length {
            let n = stream.read(&mut chunk).expect("stub body read");
            assert!(n > 0, "client closed mid-body");
            buffer.extend_from_slice(&chunk[..n]);
        }
        let body =
            String::from_utf8_lossy(&buffer[header_end + 4..header_end + 4 + content_length])
                .to_string();
        let mut lines = head.lines();
        let request_line = lines.next().unwrap_or_default().to_owned();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_owned();
        let path = parts.next().unwrap_or_default().to_owned();
        let headers = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            })
            .collect();
        if let Some(response) = response {
            stream.write_all(response.as_bytes()).expect("stub write");
            let _ = stream.flush();
        } else {
            // Transport drop: answer nothing, kill the connection.
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        CapturedRequest {
            method,
            path,
            headers,
            body,
        }
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn http_response(status_line: &str, json_body: &str) -> String {
        format!(
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json_body}",
            json_body.len()
        )
    }

    #[test]
    fn wire_contract_against_a_stub_tracker() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let captured: std::sync::Arc<Mutex<Vec<CapturedRequest>>> = Default::default();
        let sink = captured.clone();

        // start → 200 userCode; complete: 403 pending → 429 (enroll bucket)
        // → 503 → transport drop → 200 token; heartbeat → 200 seenAt. The
        // retryable middle answers must not stop the sequence.
        std::thread::spawn(move || {
            let start = http_response(
                "200 OK",
                r#"{"deviceCode":"882c895e6a1d4f7bb1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4","userCode":"AB2CDEFG","verifyUrl":"https://modelswarm.deepflux.space/account","expiresAt":"2030-01-01T00:00:00.000Z"}"#,
            );
            let pending = http_response("403 Forbidden", r#"{"error":{"code":"pending"}}"#);
            let limited = http_response(
                "429 Too Many Requests",
                r#"{"error":{"code":"rate_limited","retryable":true}}"#,
            );
            let unavailable = http_response(
                "503 Service Unavailable",
                r#"{"error":{"code":"internal","retryable":true}}"#,
            );
            let approved = http_response(
                "200 OK",
                r#"{"token":"77aa11223344556677889900aabbccddeeff00112233445566778899aabbccdd","expiresAt":"2030-01-01T00:00:00.000Z"}"#,
            );
            let heartbeat = http_response("200 OK", r#"{"seenAt":"2026-11-19T00:00:00.000Z"}"#);
            let script: [Option<&str>; 7] = [
                Some(&start),
                Some(&pending),
                Some(&limited),
                Some(&unavailable),
                None, // transport drop
                Some(&approved),
                Some(&heartbeat),
            ];
            for response in script {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let request = serve_exchange(stream, response);
                sink.lock().unwrap_or_else(|p| p.into_inner()).push(request);
            }
        });

        unsafe { std::env::set_var("DEEPFLUX_TRACKER_URL", format!("http://{addr}")) };
        let identity = SwarmIdentity::load_or_create(&InMemorySessionStore::default()).unwrap();
        let client = TrackerClient::new();
        assert_eq!(
            client.base,
            format!("http://{addr}"),
            "env override reached the client"
        );

        // -- start ----------------------------------------------------------
        let start = client.device_start(&identity).unwrap();
        assert_eq!(start.user_code, "AB2CDEFG");
        assert_eq!(start.user_code.len(), 8);
        assert!(
            start.expires_at_ms > now_ms(),
            "stub expiry is in the future"
        );

        // -- complete: pending, rate-limited, unavailable, dropped — then
        //    approved. The retryable answers surface as Retry/Err, not as
        //    terminal failures.
        assert_eq!(
            client
                .device_complete(&identity, &start.device_code)
                .unwrap(),
            CompleteOutcome::Pending
        );
        assert_eq!(
            client
                .device_complete(&identity, &start.device_code)
                .unwrap(),
            CompleteOutcome::Retry,
            "429 must classify as Retry"
        );
        assert_eq!(
            client
                .device_complete(&identity, &start.device_code)
                .unwrap(),
            CompleteOutcome::Retry,
            "5xx must classify as Retry"
        );
        assert!(
            client
                .device_complete(&identity, &start.device_code)
                .is_err(),
            "a transport drop surfaces as Err for the poller to retry"
        );
        let token = match client
            .device_complete(&identity, &start.device_code)
            .unwrap()
        {
            CompleteOutcome::Approved {
                token,
                expires_at_ms,
            } => {
                assert!(expires_at_ms > now_ms());
                token
            }
            other => panic!("expected approval, got {other:?}"),
        };

        // -- heartbeat -------------------------------------------------------
        assert_eq!(
            client
                .heartbeat(&identity, &token, Some("0123456789abcdef"), "Test Rig")
                .unwrap(),
            200
        );

        unsafe { std::env::remove_var("DEEPFLUX_TRACKER_URL") };

        // -- captured-wire assertions ----------------------------------------
        let requests = captured.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(requests.len(), 7);
        let (
            start_req,
            complete_pending,
            _limited,
            _unavailable,
            _dropped,
            complete_ok,
            heartbeat_req,
        ) = (
            &requests[0],
            &requests[1],
            &requests[2],
            &requests[3],
            &requests[4],
            &requests[5],
            &requests[6],
        );

        // Exact paths.
        assert_eq!(start_req.method, "POST");
        assert_eq!(start_req.path, "/api/v1/auth/device/start");
        assert_eq!(complete_pending.path, "/api/v1/auth/device/complete");
        assert_eq!(complete_ok.path, "/api/v1/auth/device/complete");
        assert_eq!(
            heartbeat_req.path,
            format!(
                "/api/v1/account/machines/{}/heartbeat",
                identity.installation_id()
            )
        );

        // Bodies are canonical-compact JSON, byte-exact.
        assert_eq!(
            start_req.body,
            canonical_json(&json!({
                "installationId": identity.installation_id(),
                "pubKey": identity.pub_key_b58(),
            }))
            .unwrap()
        );
        assert_eq!(
            complete_ok.body,
            format!("{{\"deviceCode\":\"{}\"}}", start.device_code)
        );
        assert_eq!(complete_pending.body, complete_ok.body);
        // P2: the heartbeat carries the contact mapping (canonical order).
        assert_eq!(
            heartbeat_req.body,
            "{\"displayName\":\"Test Rig\",\"signalingDeviceId\":\"0123456789abcdef\"}"
        );
        for request in requests.iter() {
            assert_eq!(request.header("content-type"), Some("application/json"));
        }

        // start is PLAIN JSON: no Authorization envelope on it.
        assert_eq!(start_req.header("authorization"), None);

        // complete/heartbeat carry the MSP1 header; decode and verify the
        // envelope exactly as the tracker's decodeAuthorization does.
        for (request, path) in [
            (complete_ok, "/api/v1/auth/device/complete"),
            (heartbeat_req, heartbeat_req.path.as_str()),
        ] {
            let auth = request.header("authorization").unwrap();
            let encoded = auth.strip_prefix("MSP1 ").expect("MSP1 prefix");
            let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
            let envelope: SignedEnvelope =
                serde_json::from_str(&String::from_utf8(decoded).unwrap()).unwrap();
            assert_eq!(envelope.method, "POST");
            assert_eq!(envelope.path, path);
            assert_eq!(envelope.installation_id, identity.installation_id());
            assert!(envelope.verify(&identity.identity.verifying_key()));
            assert_eq!(
                envelope.body_digest,
                format!(
                    "sha256:{}",
                    hex_lower(&Sha256::digest(request.body.as_bytes()))
                )
            );
        }

        // The session rides ONLY on the heartbeat's x-msp-session header.
        assert_eq!(complete_ok.header("x-msp-session"), None);
        assert_eq!(heartbeat_req.header("x-msp-session"), Some(token.as_str()));
    }

    /// 401 on /complete is terminal with the pairing-code copy (unknown or
    /// expired device code — the dashboard never approved).
    #[test]
    fn complete_401_is_terminal() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let denied = http_response("401 Unauthorized", r#"{"error":{"code":"unauthorized"}}"#);
            for _ in 0..1 {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                serve_exchange(stream, Some(&denied));
            }
        });
        unsafe { std::env::set_var("DEEPFLUX_TRACKER_URL", format!("http://{addr}")) };
        let identity = SwarmIdentity::load_or_create(&InMemorySessionStore::default()).unwrap();
        let client = TrackerClient::new();
        match client
            .device_complete(&identity, "00".repeat(32).as_str())
            .unwrap()
        {
            CompleteOutcome::Denied(reason) => {
                assert!(reason.contains("pairing code"), "got {reason:?}");
            }
            other => panic!("401 must be terminal, got {other:?}"),
        }
        unsafe { std::env::remove_var("DEEPFLUX_TRACKER_URL") };
    }

    /// 400 stale_timestamp is terminal with the clock copy — the tracker's
    /// body decides, not the bare status.
    #[test]
    fn complete_400_stale_timestamp_names_the_clock() {
        let _guard = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let stale = http_response(
                "400 Bad Request",
                r#"{"error":{"code":"stale_timestamp","message":"envelope ts outside the ±120 s replay window"}}"#,
            );
            for _ in 0..1 {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                serve_exchange(stream, Some(&stale));
            }
        });
        unsafe { std::env::set_var("DEEPFLUX_TRACKER_URL", format!("http://{addr}")) };
        let identity = SwarmIdentity::load_or_create(&InMemorySessionStore::default()).unwrap();
        let client = TrackerClient::new();
        match client
            .device_complete(&identity, "00".repeat(32).as_str())
            .unwrap()
        {
            CompleteOutcome::Denied(reason) => {
                assert!(reason.to_lowercase().contains("clock"), "got {reason:?}");
            }
            other => panic!("stale_timestamp must be terminal, got {other:?}"),
        }
        unsafe { std::env::remove_var("DEEPFLUX_TRACKER_URL") };
    }

    /// LIVE P2 smoke (loopback): the full account flow against a REAL
    /// Next.js tracker - run the dev server with
    /// `ACCOUNT_SIGNUP_OPEN=1 MSP_RATE_ENROLL_PER_IP=60 npm run dev
    /// -- --port 3210` (memory store; no DATABASE_URL) and then
    /// `DEEPFLUX_P2_LIVE_TRACKER=http://127.0.0.1:3210 cargo test ...
    /// p2_account_flow -- --nocapture`. Skipped without the env var -
    /// this is the runtime pass the unit suites cannot be (real route
    /// wiring, cookies, the claim UX data flow end to end).
    #[test]
    fn p2_account_flow_against_a_live_tracker() {
        let Ok(base) = std::env::var("DEEPFLUX_P2_LIVE_TRACKER") else {
            eprintln!("SKIP p2 live smoke: DEEPFLUX_P2_LIVE_TRACKER not set");
            return;
        };
        let _guard = ENV_GUARD.lock().unwrap_or_else(|p| p.into_inner());
        unsafe { std::env::set_var("DEEPFLUX_TRACKER_URL", &base) };

        let identity_a = SwarmIdentity {
            identity: modelswarm_identity::InstallationIdentity::generate(),
        };
        let identity_b = SwarmIdentity {
            identity: modelswarm_identity::InstallationIdentity::generate(),
        };
        let client = TrackerClient::new();

        // The website half of the ceremony (the dashboard user): signup ->
        // msw_session cookie, then the claim/revoke verbs with that cookie.
        let web = |method: &str,
                   path: &str,
                   body: Option<&str>,
                   cookie: Option<&str>|
         -> (u16, String, String) {
            let mut request = client.agent.request(method, &format!("{base}{path}"));
            request = request.set("content-type", "application/json");
            if let Some(cookie) = cookie {
                request = request.set("cookie", &format!("msw_session={cookie}"));
            }
            let result = match body {
                Some(body) => request.send_string(body),
                None => request.call(),
            };
            match result {
                Ok(resp) => {
                    let status = resp.status();
                    let set_cookie = resp.header("set-cookie").unwrap_or_default().to_owned();
                    let mut text = String::new();
                    use std::io::Read as _;
                    let _ = resp.into_reader().take(8192).read_to_string(&mut text);
                    (status, text, set_cookie)
                }
                Err(ureq::Error::Status(status, resp)) => {
                    let mut text = String::new();
                    let _ = resp.into_reader().take(8192).read_to_string(&mut text);
                    (status, text, String::new())
                }
                Err(e) => panic!("p2 smoke: {method} {path}: {e}"),
            }
        };
        let json_field = |text: &str, field: &str| -> String {
            serde_json::from_str::<serde_json::Value>(text)
                .ok()
                .and_then(|v| v.get(field).and_then(|f| f.as_str()).map(str::to_owned))
                .unwrap_or_default()
        };

        // -- the website account ------------------------------------------
        let tag = now_ms();
        let email = format!("p2smoke-{tag}@example.com");
        let (status, _, set_cookie) = web(
            "POST",
            "/api/v1/account/signup",
            Some(&format!(
                "{{\"email\":\"{email}\",\"password\":\"correct-horse-battery\",\"displayName\":\"P2 Smoke\"}}"
            )),
            None,
        );
        assert_eq!(status, 201, "signup failed");
        let cookie = set_cookie
            .split(';')
            .next()
            .unwrap_or_default()
            .strip_prefix("msw_session=")
            .expect("signup set-cookie carries msw_session")
            .to_owned();
        assert!(cookie.bytes().all(|b| b.is_ascii_hexdigit()) && cookie.len() == 64);

        // -- machine A enrolls; the account claims; A confirms ------------
        let start_a = client.device_start(&identity_a).expect("A start");
        let (status, body, _) = web(
            "POST",
            "/api/v1/account/devices/approve",
            Some(&format!(
                "{{\"userCode\":\"{}\",\"label\":\"Smoke A\"}}",
                start_a.user_code
            )),
            Some(&cookie),
        );
        assert_eq!(status, 202, "claim A failed: {body}");
        assert_eq!(json_field(&body, "status"), "claim_pending");
        match client
            .device_complete(&identity_a, &start_a.device_code)
            .unwrap()
        {
            CompleteOutcome::ClaimPending { claimed_by } => {
                // The masked claimer: first char + domain (maskEmail).
                assert_eq!(claimed_by, "p***@example.com", "mask");
            }
            other => panic!("A complete must be claim_pending, got {other:?}"),
        }
        assert_eq!(
            client
                .claim_confirm(&identity_a, &start_a.device_code, true)
                .unwrap(),
            200
        );
        let token_a = match client
            .device_complete(&identity_a, &start_a.device_code)
            .unwrap()
        {
            CompleteOutcome::Approved { token, .. } => token,
            other => panic!("A complete must be approved, got {other:?}"),
        };

        // -- machine B: same handshake -------------------------------------
        let start_b = client.device_start(&identity_b).expect("B start");
        let (status, body, _) = web(
            "POST",
            "/api/v1/account/devices/approve",
            Some(&format!(
                "{{\"userCode\":\"{}\",\"label\":\"Smoke B\"}}",
                start_b.user_code
            )),
            Some(&cookie),
        );
        assert_eq!(status, 202, "claim B failed: {body}");
        match client
            .device_complete(&identity_b, &start_b.device_code)
            .unwrap()
        {
            CompleteOutcome::ClaimPending { .. } => {}
            other => panic!("B complete must be claim_pending, got {other:?}"),
        }
        assert_eq!(
            client
                .claim_confirm(&identity_b, &start_b.device_code, true)
                .unwrap(),
            200
        );
        let token_b = match client
            .device_complete(&identity_b, &start_b.device_code)
            .unwrap()
        {
            CompleteOutcome::Approved { token, .. } => token,
            other => panic!("B complete must be approved, got {other:?}"),
        };

        // -- liveness + the signaling mapping ------------------------------
        let sig_a = "a1b2c3d4e5f60718";
        let sig_b = "b1a2c3d4e5f60718";
        assert_eq!(
            client
                .heartbeat(&identity_a, &token_a, Some(sig_a), "Smoke A")
                .unwrap(),
            200
        );
        assert_eq!(
            client
                .heartbeat(&identity_b, &token_b, Some(sig_b), "Smoke B")
                .unwrap(),
            200
        );

        // -- the directory: B sees the account, A controllable -------------
        let directory = client
            .account_directory(&identity_b, &token_b)
            .expect("directory");
        let row_a = directory
            .iter()
            .find(|m| m.installation_id == identity_a.installation_id())
            .expect("A in directory");
        assert_eq!(row_a.signaling_device_id.as_deref(), Some(sig_a));
        assert_eq!(row_a.label.as_deref(), Some("Smoke A"));
        assert!(row_a.last_seen_at_ms.is_some(), "heartbeat touched A's row");
        assert!(
            directory
                .iter()
                .any(|m| m.installation_id == identity_b.installation_id())
        );

        // -- dashboard revoke A: the directory drops it, A's liveness dies --
        let (status, body, _) = web(
            "POST",
            &format!(
                "/api/v1/account/machines/{}/revoke",
                identity_a.installation_id()
            ),
            Some("{}"),
            Some(&cookie),
        );
        assert_eq!(status, 200, "revoke A failed: {body}");
        assert_eq!(
            client
                .heartbeat(&identity_a, &token_a, Some(sig_a), "Smoke A")
                .unwrap(),
            404
        );
        let directory = client
            .account_directory(&identity_b, &token_b)
            .expect("directory after revoke");
        assert!(
            !directory
                .iter()
                .any(|m| m.installation_id == identity_a.installation_id()),
            "revoked A must leave the directory"
        );

        eprintln!(
            "p2 live smoke OK: claim handshake, directory mapping, and revoke all verified against {base}"
        );
        unsafe { std::env::remove_var("DEEPFLUX_P2_LIVE_TRACKER") };
        unsafe { std::env::remove_var("DEEPFLUX_TRACKER_URL") };
    }
}
