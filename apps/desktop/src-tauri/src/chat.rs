//! Machine chat + pairing (ADR-005 §3–§5, RD-022/RD-023).
//!
//! Responsibilities:
//! - **Pairing store** (`pairings.json`): peer code → 32-byte secret hex,
//!   established automatically on the first session (controller offers,
//!   host acks; the session's consent click was the trust ceremony).
//! - **Standing remember-intent** (ADR-006 amendment, 2026-10-28): the
//!   "Always allow" click is durable from the moment it happens — if the
//!   controller's `PairOffer` was lost to a short session, the intent
//!   completes the pairing in the next accepted session instead of
//!   silently voiding the click.
//! - **Chat history** (`chat/<code>.json`): bounded per-peer message log.
//! - **Out-of-session inbox** (`/api/chat` on the signaling service):
//!   envelopes sealed with AES-256-GCM under the pairing secret — the
//!   service stores ciphertext only (invariant 2, ADR-003's widened
//!   reading). A slow poller drains the inbox while the app runs.
//! - **Silent reconnect** (user decision, 2026-10-24): a consent prompt
//!   from a paired controller auto-accepts — full control once connected.
//!
//! Invariant 6: chat bodies are user text — never logged; the pairing
//! secret never appears in logs or events.

use std::path::PathBuf;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager};

/// A pairing secret in transit (ADR-006): `Debug` is redacted so the
/// secret can ride `EngineCmd` without becoming loggable (invariant 6).
#[derive(Clone)]
pub struct PairingSecret(pub String);

impl core::fmt::Debug for PairingSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PairingSecret(<redacted>)")
    }
}

/// One established pairing (RD-023). `code` is the peer's device id.
/// `Debug` is manual and redacts `secret_hex` (invariant 6 — the pairing
/// secret is a full-control trust grant for the other machine).
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Pairing {
    pub code: String,
    pub secret_hex: String,
    pub created_ms: u64,
    /// Controller-side offers keep `pending_ack` until the host's PairAck.
    #[serde(default)]
    pub pending_ack: bool,
    /// ADR-006: which side recorded it — "host" (they may connect without
    /// asking) or "controller" (we may connect/chat with them). Entries
    /// from before the field existed load as "legacy".
    #[serde(default = "legacy_role")]
    pub role: String,
}

impl core::fmt::Debug for Pairing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pairing")
            .field("code", &self.code)
            .field("secret_hex", &"<redacted>")
            .field("created_ms", &self.created_ms)
            .field("pending_ack", &self.pending_ack)
            .field("role", &self.role)
            .finish()
    }
}

fn legacy_role() -> String {
    "legacy".to_owned()
}

/// Host-side pairing-ceremony state (ADR-006). The consent click happens
/// BEFORE the controller's PairOffer arrives (the offer is sent on session
/// establishment), so the host records its DECISION at click time and
/// applies it when the offer lands: persist + ack only on an
/// accept-with-remember; otherwise the offer is dropped un-acked. Nothing
/// touches `pairings.json` before the owner's explicit choice. Also
/// carries the prompt-flood cooldowns (explicit reject: 5 min; timeout:
/// 60 s; in-memory, cleared on restart, bounded server-side by the
/// send-path rate limits).
#[derive(Default)]
pub struct TrustState {
    /// The recorded consent decision for the current session:
    /// (controller code, remember?).
    pub decision: Option<(String, bool)>,
    /// The consent prompt currently (or last) shown: (controller, accepted,
    /// rejected) — resolved by the accept command, the reject command, or
    /// host-state inference for the timeout.
    pub prompt: Option<(String, bool, bool)>,
    /// controller code -> blocked-until epoch ms.
    pub block_until: std::collections::HashMap<String, u64>,
    /// The outbound pairing offer our own `connect` command owes this peer
    /// (ADR-006 amendment, 2026-10-28). Set when the user presses Control,
    /// consumed at session establishment: only the CONTROLLER side of a
    /// session may offer pairing. Without it the establish handler could
    /// not tell its role apart and the host minted spurious offers toward
    /// its controller, cross-wiring the two sides' secrets.
    pub owed_pair_offer: Option<String>,
}

/// Prompt-flood cooldown after an explicit user reject (ADR-006 B3).
pub const REJECT_COOLDOWN_MS: u64 = 5 * 60 * 1000;
/// Cooldown after a consent timeout (the prompt expired unanswered).
pub const TIMEOUT_COOLDOWN_MS: u64 = 60 * 1000;
/// Controller-side pending offers older than this are purged on read.
pub const PENDING_PAIRING_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000;

impl TrustState {
    pub fn blocked(&self, controller: &str, now: u64) -> bool {
        self.block_until
            .get(controller)
            .is_some_and(|until| *until > now)
    }

    pub fn block(&mut self, controller: &str, until_ms: u64) {
        self.block_until.insert(controller.to_owned(), until_ms);
    }

    /// Forget expired blocks (bounded memory).
    pub fn sweep(&mut self, now: u64) {
        self.block_until.retain(|_, until| *until > now);
    }
}

/// Cap on standing remember-intents (ADR-006 amendment, 2026-10-28).
/// Each intent is one 16-hex device id armed by an explicit "Always
/// allow" click; the cap is pure paranoia (invariant-3 discipline), the
/// real bound is how many machines the owner clicks Always for.
const REMEMBERED_CAP: usize = 32;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PairingsDoc {
    pairings: Vec<Pairing>,
    /// Device ids with a standing "Always allow" whose pairing offer has
    /// not completed yet (ADR-006 amendment, 2026-10-28 — see
    /// [`remember_intent`]). The click is durable from the moment it
    /// happens; the secret lands only when the controller's `PairOffer`
    /// finally arrives in an accepted session.
    #[serde(default)]
    remembered: Vec<String>,
}

/// One stored chat line. `sender`: "user" | "agent" | "peer-user" |
/// "peer-agent" (perspective: this machine's store) — plus "to-agent":
/// this machine's human addressed the peer's assistant via the
/// Conversation toggle (the wire still carries the agent bit, so the
/// peer labels the same line "peer-agent" on its side).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChatLine {
    pub id: u64,
    pub ts_ms: u64,
    pub sender: String,
    pub body: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ChatDoc {
    lines: Vec<ChatLine>,
}

/// Per-peer history cap (bounded stores — invariant 3 discipline).
const HISTORY_CAP: usize = 500;

// ADR-006 §7 (code-review B1): the chat-inbox envelope contract is owned
// by `crates/protocol::chat` — this module re-exports it so the historical
// call sites keep working while the duplicate definition is gone.
pub use protocol::chat::{CHAT_PROTOCOL_VERSION, ChatEnvelope};

// ---------------------------------------------------------------------------
// Storage (locks: take the store lock only; never inside the engine lock)
// ---------------------------------------------------------------------------

fn pairings_path(app: &AppHandle) -> PathBuf {
    let dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    dir.join("pairings.json")
}

fn chat_dir(app: &AppHandle) -> PathBuf {
    let dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::env::temp_dir());
    let d = dir.join("chat");
    let _ = std::fs::create_dir_all(&d);
    d
}

fn read_pairings(app: &AppHandle) -> PairingsDoc {
    std::fs::read_to_string(pairings_path(app))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn write_pairings(app: &AppHandle, doc: &PairingsDoc) {
    let path = pairings_path(app);
    let tmp = path.with_extension("tmp");
    if let Ok(text) = serde_json::to_string(doc)
        && std::fs::write(&tmp, text).is_ok()
    {
        let _ = std::fs::rename(&tmp, &path);
    }
}

pub fn pairings(app: &AppHandle) -> Vec<Pairing> {
    purge_stale_pending(app);
    read_pairings(app).pairings
}

pub fn pairing_for(app: &AppHandle, code: &str) -> Option<Pairing> {
    purge_stale_pending(app);
    read_pairings(app)
        .pairings
        .into_iter()
        .find(|p| p.code == code && !p.pending_ack)
}

/// Controller-side housekeeping: un-acked offers expire — the host chose
/// not to remember (or crashed); a stale `pending_ack` row must not linger
/// forever (ADR-006).
fn purge_stale_pending(app: &AppHandle) {
    let mut doc = read_pairings(app);
    if purge_stale_pending_in_doc(&mut doc, now_ms()) {
        write_pairings(app, &doc);
    }
}

/// Pure core of [`purge_stale_pending`]. Returns whether the doc changed.
fn purge_stale_pending_in_doc(doc: &mut PairingsDoc, now: u64) -> bool {
    let before = doc.pairings.len();
    doc.pairings.retain(|p| {
        !p.pending_ack || now.saturating_sub(p.created_ms) < PENDING_PAIRING_MAX_AGE_MS
    });
    doc.pairings.len() != before
}

/// Host side: store a pairing offered by a controller — but only on the
/// owner's explicit "remember" choice (ADR-006). An ESTABLISHED (non-
/// pending) pairing is never *silently* overwritten: re-pairing is either
/// an explicit removal (Trusted machines) or — since the 2026-10-28
/// amendment — a fresh human "Always allow" click for this machine
/// (`human_backed`), which replaces a stale secret so a controller
/// reinstall or a lost `PairAck` cannot strand both sides at endless
/// consent prompts. A squatter holding the id gains nothing: their fresh
/// secret reaches this path only after a human clicked Allow for this
/// very device id in that session. Returns whether the OFFERED secret is
/// the live stored one — the caller acks the offer only when true (acking
/// a secret we refused to store would desync both sides' "trusted"
/// forever).
pub fn record_pairing(app: &AppHandle, code: &str, secret_hex: &str, human_backed: bool) -> bool {
    let mut doc = read_pairings(app);
    let recorded = record_pairing_in_doc(&mut doc, code, secret_hex, now_ms(), human_backed);
    if recorded {
        write_pairings(app, &doc);
    }
    recorded
}

/// Pure core of [`record_pairing`] (testable without an app handle).
/// Consumes the standing remember-intent for `code` on every success.
fn record_pairing_in_doc(
    doc: &mut PairingsDoc,
    code: &str,
    secret_hex: &str,
    now: u64,
    human_backed: bool,
) -> bool {
    let code = code.trim().to_lowercase();
    let valid = secret_hex.len() == 64 && secret_hex.chars().all(|c| c.is_ascii_hexdigit());
    if !valid {
        return false; // malformed offers are ignored, never stored
    }
    match doc.pairings.iter_mut().find(|p| p.code == code) {
        Some(existing) => {
            if !existing.pending_ack {
                if existing.secret_hex == secret_hex {
                    // Same secret re-offered: live, nothing to change.
                } else if human_backed {
                    // Fresh human "Always allow" backs the new secret —
                    // replace the stale one (controller reinstall / lost
                    // ack); refusing here is what stranded pairings at
                    // endless prompts before the amendment.
                    existing.secret_hex = secret_hex.to_owned();
                    existing.role = "host".to_owned();
                } else {
                    // Established pairing + unbacked different secret:
                    // refuse (the existing trust stands; re-pairing needs
                    // an explicit remove or a fresh Always-allow click).
                    return false;
                }
            } else {
                existing.secret_hex = secret_hex.to_owned();
                existing.pending_ack = false;
                existing.role = "host".to_owned();
                existing.created_ms = now;
            }
        }
        None => doc.pairings.push(Pairing {
            code: code.clone(),
            secret_hex: secret_hex.to_owned(),
            created_ms: now,
            pending_ack: false,
            role: "host".to_owned(),
        }),
    }
    doc.remembered.retain(|c| c != &code);
    true
}

/// Controller side: our offer was acknowledged — clear the pending flag.
pub fn pairing_ack(app: &AppHandle, code: &str) {
    let mut doc = read_pairings(app);
    let code = code.trim().to_lowercase();
    if let Some(p) = doc.pairings.iter_mut().find(|p| p.code == code) {
        p.pending_ack = false;
        write_pairings(app, &doc);
    }
}

/// Controller side: mint + store a pending pairing, return the secret hex.
/// A re-mint refreshes `created_ms` so the 24 h pending purge measures the
/// LAST offer, not the first (a controller re-offering daily must not have
/// its row purged as stale mid-courtship).
pub fn mint_pairing(app: &AppHandle, code: &str) -> String {
    let mut bytes = [0u8; 32];
    let _ = getrandom::fill(&mut bytes);
    let secret_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut doc = read_pairings(app);
    mint_pairing_in_doc(&mut doc, code, &secret_hex, now_ms());
    write_pairings(app, &doc);
    secret_hex
}

/// Pure core of [`mint_pairing`] (testable without an app handle).
fn mint_pairing_in_doc(doc: &mut PairingsDoc, code: &str, secret_hex: &str, now: u64) {
    let code = code.trim().to_lowercase();
    match doc.pairings.iter_mut().find(|p| p.code == code) {
        Some(existing) => {
            existing.secret_hex = secret_hex.to_owned();
            existing.pending_ack = true;
            existing.role = "controller".to_owned();
            existing.created_ms = now;
        }
        None => doc.pairings.push(Pairing {
            code,
            secret_hex: secret_hex.to_owned(),
            created_ms: now,
            pending_ack: true,
            role: "controller".to_owned(),
        }),
    }
}

pub fn remove_pairing(app: &AppHandle, code: &str) {
    let mut doc = read_pairings(app);
    if remove_pairing_in_doc(&mut doc, code) {
        write_pairings(app, &doc);
    }
}

/// Pure core of [`remove_pairing`]. Removing a machine also revokes any
/// standing remember-intent for it — Trusted-machines removal is the
/// explicit un-trust gesture (ADR-006 amendment: intent is armed only by
/// a fresh "Always allow" click).
fn remove_pairing_in_doc(doc: &mut PairingsDoc, code: &str) -> bool {
    let code = code.trim().to_lowercase();
    let before = doc.pairings.len() + doc.remembered.len();
    doc.pairings.retain(|p| p.code != code);
    doc.remembered.retain(|c| *c != code);
    doc.pairings.len() + doc.remembered.len() != before
}

// ---------------------------------------------------------------------------
// Standing remember-intent (ADR-006 amendment, 2026-10-28)
// ---------------------------------------------------------------------------

/// The owner clicked "Always allow this machine" — durably, before any
/// secret exists. The ADR-006 ceremony applies the click when the
/// controller's `PairOffer` arrives, but that offer can be lost to a
/// session that ended first (short session, teardown race), which used to
/// void the click silently — the "I approved forever and it asked again"
/// bug. The intent makes the click durable: whenever the offer finally
/// arrives in ANY later session the owner allowed, the pairing completes.
/// Revoked by an explicit Decline or by removing the machine in Trusted
/// machines; consumed when the pairing records.
pub fn remember_intent(app: &AppHandle, code: &str) {
    let mut doc = read_pairings(app);
    if remember_intent_in_doc(&mut doc, code) {
        write_pairings(app, &doc);
    }
}

/// Pure core of [`remember_intent`]. Returns whether the doc changed.
fn remember_intent_in_doc(doc: &mut PairingsDoc, code: &str) -> bool {
    let code = crate::store::normalize_machine_code(code);
    if !crate::store::is_machine_code(&code) || doc.remembered.contains(&code) {
        return false;
    }
    doc.remembered.push(code);
    if doc.remembered.len() > REMEMBERED_CAP {
        doc.remembered
            .drain(..doc.remembered.len() - REMEMBERED_CAP);
    }
    true
}

/// Revoke a standing intent (explicit Decline on the consent prompt).
pub fn revoke_intent(app: &AppHandle, code: &str) {
    let mut doc = read_pairings(app);
    let code = crate::store::normalize_machine_code(code);
    let before = doc.remembered.len();
    doc.remembered.retain(|c| *c != code);
    if doc.remembered.len() != before {
        write_pairings(app, &doc);
    }
}

/// Is there a standing "Always allow" for this controller?
pub fn has_remember_intent(app: &AppHandle, code: &str) -> bool {
    let code = crate::store::normalize_machine_code(code);
    read_pairings(app).remembered.contains(&code)
}

// ---------------------------------------------------------------------------
// Dead-key purge (2026-10-27 duplicate-list fix)
// ---------------------------------------------------------------------------

/// Pairing rows keyed by anything but a device id can never match a live
/// machine (connect, chat, and the trust lookups all key by device id) —
/// drop them from the doc.
fn purge_dead_pairings_in_doc(doc: &mut PairingsDoc) -> bool {
    let before = doc.pairings.len();
    doc.pairings
        .retain(|p| crate::store::is_machine_code(&p.code));
    doc.pairings.len() != before
}

/// Startup sweep: dead pairing rows out of `pairings.json`, dead chat
/// threads (`chat/<key>.json` for a non-device-id key) deleted. Idempotent;
/// mirrors the favorite purge in `LocalStore::load` so every store that
/// keys machines by code agrees on which keys are real.
pub fn purge_dead_data(app: &AppHandle) {
    let mut doc = read_pairings(app);
    if purge_dead_pairings_in_doc(&mut doc) {
        write_pairings(app, &doc);
    }
    if let Ok(entries) = std::fs::read_dir(chat_dir(app)) {
        for entry in entries.flatten() {
            let dead = entry
                .path()
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|stem| !crate::store::is_machine_code(stem))
                .unwrap_or(true);
            if dead {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

pub fn history(app: &AppHandle, code: &str) -> Vec<ChatLine> {
    let path = chat_dir(app).join(safe_code(code));
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<ChatDoc>(&t).ok())
        .map(|d| d.lines)
        .unwrap_or_default()
}

fn append_history(app: &AppHandle, code: &str, line: ChatLine) {
    let code = code.trim().to_lowercase();
    let path = chat_dir(app).join(safe_code(&code));
    let mut doc = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<ChatDoc>(&t).ok())
        .unwrap_or_default();
    doc.lines.push(line);
    if doc.lines.len() > HISTORY_CAP {
        let drop = doc.lines.len() - HISTORY_CAP;
        doc.lines.drain(..drop);
    }
    let tmp = path.with_extension("tmp");
    if let Ok(text) = serde_json::to_string(&doc)
        && std::fs::write(&tmp, text).is_ok()
    {
        let _ = std::fs::rename(&tmp, &path);
    }
}

fn safe_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(64)
        .collect::<String>()
        + ".json"
}

/// Incoming (in-session) chat line → store (dedupe by id) + agent wake.
pub fn record_incoming(app: &AppHandle, peer: &str, id: u64, ts_ms: u64, sender: &str, body: &str) {
    let existing = history(app, peer);
    if existing.iter().any(|l| l.id == id) {
        return;
    }
    let line = ChatLine {
        id,
        ts_ms,
        sender: format!("peer-{sender}"),
        body: body.to_owned(),
    };
    append_history(app, peer, line);
    // Agent-to-agent (ADR-005 §4): agent-authored messages wake the local
    // assistant as an instruction turn; user-authored ones only display.
    if sender == "agent" {
        app.state::<crate::commands::AppServices>()
            .assistant
            .deliver_peer_agent(peer, body);
    }
}

/// Outgoing line (this machine's user or agent) → store.
pub fn record_outgoing(app: &AppHandle, peer: &str, sender: &str, body: &str) -> ChatLine {
    let line = ChatLine {
        id: now_ms(),
        ts_ms: now_ms(),
        sender: sender.to_owned(),
        body: body.to_owned(),
    };
    append_history(app, peer, line.clone());
    line
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Sealing (AES-256-GCM under the pairing secret; AAD = from|to|ts)
// ---------------------------------------------------------------------------

fn seal(secret_hex: &str, from: &str, to: &str, ts_ms: u64, body: &str) -> Option<ChatEnvelope> {
    let key_bytes = hex_decode(secret_hex)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    let _ = getrandom::fill(&mut nonce_bytes);
    let aad = format!("{CHAT_PROTOCOL_VERSION}|{from}|{to}|{ts_ms}");
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: body.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .ok()?;
    Some(ChatEnvelope {
        v: CHAT_PROTOCOL_VERSION,
        from: from.to_owned(),
        nonce_hex: nonce_bytes.iter().map(|b| format!("{b:02x}")).collect(),
        ct_hex: ct.iter().map(|b| format!("{b:02x}")).collect(),
        ts_ms,
    })
}

fn open(secret_hex: &str, to: &str, env: &ChatEnvelope) -> Option<String> {
    if env.v != CHAT_PROTOCOL_VERSION {
        return None;
    }
    let key_bytes = hex_decode(secret_hex)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes = hex_decode(&env.nonce_hex)?;
    let ct = hex_decode(&env.ct_hex)?;
    let aad = format!("{CHAT_PROTOCOL_VERSION}|{}|{to}|{}", env.from, env.ts_ms);
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ct,
                aad: aad.as_bytes(),
            },
        )
        .ok()?;
    String::from_utf8(pt).ok()
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Inbox transport (signaling `/api/chat`; auth = the device token header)
// ---------------------------------------------------------------------------

fn chat_api(base: &str) -> String {
    format!("{}/api/chat", base.trim_end_matches('/'))
}

/// Send one out-of-session chat message (sealed with the pairing secret).
pub fn inbox_send(
    app: &AppHandle,
    base_url: &str,
    token: &str,
    from: &str,
    to: &str,
    body: &str,
) -> Result<(), String> {
    let Some(pairing) = pairing_for(app, to) else {
        return Err(format!(
            "no pairing with {to} — connect once to establish chat"
        ));
    };
    let ts = now_ms();
    let env =
        seal(&pairing.secret_hex, from, to, ts, body).ok_or_else(|| "sealing failed".to_owned())?;
    let agent = node_runtime::http::https_agent(Duration::from_secs(15), "remote-desktop-chat");
    let response = agent
        .post(&chat_api(base_url))
        .set("Authorization", format!("Bearer {token}").as_str())
        .send_json(json!({ "to": to, "envelope": env }))
        .map_err(|e| format!("inbox send: {e}"))?;
    if response.status() != 200 {
        return Err(format!("inbox send: HTTP {}", response.status()));
    }
    Ok(())
}

/// Drain our inbox; every decryptable envelope becomes a stored line +
/// webview event. Returns the count delivered.
pub fn inbox_drain(app: &AppHandle, base_url: &str, token: &str, me: &str) -> usize {
    let agent = node_runtime::http::https_agent(Duration::from_secs(15), "remote-desktop-chat");
    let Ok(response) = agent
        .get(&chat_api(base_url))
        .set("Authorization", format!("Bearer {token}").as_str())
        .call()
    else {
        return 0;
    };
    let Ok(value) = response.into_json::<serde_json::Value>() else {
        return 0;
    };
    let Some(envelopes) = value.get("envelopes").and_then(|v| v.as_array()) else {
        return 0;
    };
    let mut delivered = 0;
    for raw in envelopes {
        let Ok(env) = serde_json::from_value::<ChatEnvelope>(raw.clone()) else {
            continue;
        };
        let Some(pairing) = pairing_for(app, &env.from) else {
            continue; // unknown sender: the service already dropped it for us
        };
        let Some(body) = open(&pairing.secret_hex, me, &env) else {
            continue; // failed auth: skip, never store
        };
        // Inbox envelopes carry no sender kind (v1): treat as the peer's
        // human. Agent-authored offline messages are a later variant.
        record_incoming(app, &env.from, env.ts_ms, env.ts_ms, "user", &body);
        let _ = app.emit(
            "engine://chat",
            json!({ "peer": env.from, "id": env.ts_ms, "ts_ms": env.ts_ms, "sender": "user", "body": body }),
        );
        delivered += 1;
    }
    delivered
}

/// Spawn the slow inbox poller (5 s while the app runs). Cheap: one GET
/// per tick, ciphertext only.
pub fn spawn_poller(app: AppHandle) {
    std::thread::Builder::new()
        .name("chat-inbox".into())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(5));
                let services = app.state::<crate::commands::AppServices>();
                let Ok(store) = services.store.lock() else {
                    continue;
                };
                let settings = store.settings().clone();
                drop(store);
                if settings.signaling_base_url.trim().is_empty() {
                    continue;
                }
                let _ = inbox_drain(
                    &app,
                    &settings.signaling_base_url,
                    &settings.device_token,
                    &settings.device_id,
                );
            }
        })
        .expect("spawn chat poller");
}

// ---------------------------------------------------------------------------
// Silent reconnect for paired controllers (user decision 2, 2026-10-24)
// ---------------------------------------------------------------------------

/// Called by the event forwarder on `ConsentRequested` — but only after the
/// ADR-006 pairing PROOF verified: a proven-paired controller is
/// auto-accepted (full control, silently). Returns true when the prompt was
/// auto-accepted (the UI's prompt resolves via state change). `remember: true`
/// is moot here — the pairing already exists, so nothing new is persisted.
pub fn auto_accept_if_paired(app: &AppHandle, controller_device_id: &str) -> bool {
    if pairing_for(app, controller_device_id).is_none() {
        return false;
    }
    let services = app.state::<crate::commands::AppServices>();
    let Ok(slot) = services.engine.lock() else {
        return false;
    };
    let Some(handle) = slot.as_ref() else {
        return false;
    };
    handle
        .send(crate::engine::EngineCmd::ConsentAccept { remember: true })
        .is_ok()
}

/// Controller side of auto-pairing: after `SessionEstablished`, offer
/// pairing to the host if we have none (or a pending one) with it.
pub fn offer_pairing_if_new(app: &AppHandle, host_device_id: &str) {
    let code = host_device_id.trim().to_lowercase();
    if code.is_empty() {
        return;
    }
    let already = read_pairings(app)
        .pairings
        .iter()
        .any(|p| p.code == code && !p.pending_ack);
    if already {
        return;
    }
    let secret_hex = mint_pairing(app, &code);
    let services = app.state::<crate::commands::AppServices>();
    if let Ok(slot) = services.engine.lock()
        && let Some(handle) = slot.as_ref()
    {
        let _ = handle.send(crate::engine::EngineCmd::SendPairOffer { secret_hex });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_A: &str = "aa9d6c507d4a3e2f1b8c7d6e5f4a3b2c1908a7b6c5d4e3f2a1b0c9d8e7f6a5b4";
    const SECRET_B: &str = "bb1e5f4a3b2c1908a7b6c5d4e3f2a1b0c9d8e7f6a5b4aa9d6c507d4a3e2f8c7d";

    fn doc(pairs: Vec<Pairing>) -> PairingsDoc {
        PairingsDoc {
            pairings: pairs,
            remembered: Vec::new(),
        }
    }

    #[test]
    fn dead_code_pairings_are_purged() {
        // 2026-10-27 duplicate-list fix: a pairing keyed by anything but a
        // device id can never match a live machine — dropped on startup.
        let mut d = doc(vec![
            Pairing {
                code: "291452".to_owned(),
                secret_hex: SECRET_A.to_owned(),
                created_ms: 1,
                pending_ack: false,
                role: "controller".to_owned(),
            },
            Pairing {
                code: "abcdef0123456789".to_owned(),
                secret_hex: SECRET_B.to_owned(),
                created_ms: 2,
                pending_ack: false,
                role: "host".to_owned(),
            },
        ]);
        assert!(purge_dead_pairings_in_doc(&mut d));
        assert_eq!(d.pairings.len(), 1);
        assert_eq!(d.pairings[0].code, "abcdef0123456789");
        // Idempotent: a clean doc reports no change.
        assert!(!purge_dead_pairings_in_doc(&mut d));
        assert!(!purge_dead_pairings_in_doc(&mut doc(vec![])));
    }

    #[test]
    fn pairing_debug_never_carries_the_secret() {
        let p = Pairing {
            code: "abcdef0123456789".to_owned(),
            secret_hex: SECRET_A.to_owned(),
            created_ms: 1,
            pending_ack: false,
            role: "host".to_owned(),
        };
        let dbg = format!("{p:?}");
        assert!(
            !dbg.contains(SECRET_A),
            "pairing Debug leaks the secret: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn stale_reoffer_of_established_pairing_is_reported() {
        let mut d = doc(vec![Pairing {
            code: "abcdef0123456789".to_owned(),
            secret_hex: SECRET_A.to_owned(),
            created_ms: 1,
            pending_ack: false,
            role: "host".to_owned(),
        }]);
        // Same secret re-offered: live, ack it.
        assert!(record_pairing_in_doc(
            &mut d,
            "abcdef0123456789",
            SECRET_A,
            20,
            false
        ));
        // Fresh secret from a reinstalled controller, NOT human-backed:
        // refused, not live (pre-amendment anti-silent-overwrite rule).
        assert!(!record_pairing_in_doc(
            &mut d,
            "abcdef0123456789",
            SECRET_B,
            20,
            false
        ));
        assert_eq!(d.pairings[0].secret_hex, SECRET_A);
    }

    #[test]
    fn trust_state_blocks_and_sweeps() {
        let mut t = TrustState::default();
        let now = 1_000u64;
        assert!(!t.blocked("ctrl", now));
        t.block("ctrl", now + REJECT_COOLDOWN_MS);
        assert!(t.blocked("ctrl", now + 1));
        assert!(!t.blocked("ctrl", now + REJECT_COOLDOWN_MS + 1), "expired");
        assert!(!t.blocked("other", now), "per-controller");
        t.block("old", now - 1);
        t.sweep(now);
        assert!(t.block_until.len() == 1, "swept the expired block");
    }

    #[test]
    fn record_pairing_tags_host_role_and_normalizes() {
        let mut d = doc(vec![]);
        assert!(record_pairing_in_doc(
            &mut d,
            "  ABCDEF0123456789 ",
            SECRET_A,
            10,
            false
        ));
        assert_eq!(d.pairings.len(), 1);
        assert_eq!(d.pairings[0].code, "abcdef0123456789");
        assert_eq!(d.pairings[0].role, "host");
        assert!(!d.pairings[0].pending_ack);
    }

    #[test]
    fn established_pairing_is_never_overwritten() {
        let mut d = doc(vec![Pairing {
            code: "abcdef0123456789".to_owned(),
            secret_hex: SECRET_A.to_owned(),
            created_ms: 1,
            pending_ack: false,
            role: "host".to_owned(),
        }]);
        // A squatter's re-offer: same id, fresh secret — refused AND
        // reported not-live (the caller must not ack it).
        assert!(!record_pairing_in_doc(
            &mut d,
            "abcdef0123456789",
            SECRET_B,
            20,
            false
        ));
        assert_eq!(d.pairings[0].secret_hex, SECRET_A, "secret unchanged");
        assert_eq!(d.pairings.len(), 1);
    }

    #[test]
    fn pending_offer_is_replaced_by_the_real_one() {
        // Controller-side pending row (our own outbound offer) — the host's
        // ack path re-records host-side with the SAME secret once acked.
        let mut d = doc(vec![Pairing {
            code: "abcdef0123456789".to_owned(),
            secret_hex: SECRET_A.to_owned(),
            created_ms: 1,
            pending_ack: true,
            role: "controller".to_owned(),
        }]);
        assert!(record_pairing_in_doc(
            &mut d,
            "abcdef0123456789",
            SECRET_A,
            20,
            false
        ));
        assert!(!d.pairings[0].pending_ack);
    }

    #[test]
    fn malformed_secrets_are_refused() {
        let mut d = doc(vec![]);
        assert!(!record_pairing_in_doc(
            &mut d,
            "abcdef0123456789",
            "nothex",
            1,
            false
        ));
        assert!(!record_pairing_in_doc(
            &mut d,
            "abcdef0123456789",
            "ab",
            1,
            false
        ));
        assert!(d.pairings.is_empty());
    }

    // ---- ADR-006 amendment (2026-10-28): durable remember-intent ----

    #[test]
    fn human_backed_record_replaces_a_stale_secret() {
        // The lost-ack / reinstall deadlock: established pairing with a
        // secret the controller no longer holds. One fresh human
        // "Always allow" must re-pair, not prompt forever.
        let mut d = doc(vec![Pairing {
            code: "abcdef0123456789".to_owned(),
            secret_hex: SECRET_A.to_owned(),
            created_ms: 1,
            pending_ack: false,
            role: "host".to_owned(),
        }]);
        assert!(record_pairing_in_doc(
            &mut d,
            "abcdef0123456789",
            SECRET_B,
            20,
            true
        ));
        assert_eq!(d.pairings.len(), 1);
        assert_eq!(d.pairings[0].secret_hex, SECRET_B, "stale secret replaced");
        assert!(!d.pairings[0].pending_ack);
    }

    #[test]
    fn record_consumes_the_remember_intent() {
        let mut d = doc(vec![]);
        d.remembered = vec!["abcdef0123456789".to_owned(), "1111111111111111".to_owned()];
        assert!(record_pairing_in_doc(
            &mut d,
            "abcdef0123456789",
            SECRET_A,
            10,
            false
        ));
        assert_eq!(d.remembered, vec!["1111111111111111".to_owned()]);
        // Malformed refusals consume nothing.
        assert!(!record_pairing_in_doc(
            &mut d,
            "1111111111111111",
            "nothex",
            10,
            false
        ));
        assert_eq!(d.remembered.len(), 1);
    }

    #[test]
    fn remember_intent_normalizes_dedupes_and_caps() {
        let mut d = doc(vec![]);
        assert!(remember_intent_in_doc(&mut d, "  ABCDEF0123456789 "));
        assert!(!remember_intent_in_doc(&mut d, "abcdef0123456789"), "dedup");
        assert!(!remember_intent_in_doc(&mut d, "not-a-code"), "invalid id");
        assert_eq!(d.remembered, vec!["abcdef0123456789".to_owned()]);
        for i in 0..REMEMBERED_CAP {
            let code = format!("{i:016x}");
            remember_intent_in_doc(&mut d, &code);
        }
        assert!(d.remembered.len() <= REMEMBERED_CAP, "bounded");
        assert!(
            !d.remembered.contains(&"abcdef0123456789".to_owned()),
            "oldest dropped"
        );
    }

    #[test]
    fn remove_pairing_revokes_the_intent() {
        let mut d = doc(vec![Pairing {
            code: "abcdef0123456789".to_owned(),
            secret_hex: SECRET_A.to_owned(),
            created_ms: 1,
            pending_ack: false,
            role: "host".to_owned(),
        }]);
        d.remembered = vec!["abcdef0123456789".to_owned()];
        assert!(remove_pairing_in_doc(&mut d, " ABCDEF0123456789 "));
        assert!(d.pairings.is_empty());
        assert!(d.remembered.is_empty(), "un-trust revokes the intent");
        assert!(
            !remove_pairing_in_doc(&mut d, "abcdef0123456789"),
            "idempotent"
        );
    }

    #[test]
    fn re_mint_refreshes_created_ms() {
        // A controller re-offering daily must not be purged as stale: the
        // 24 h pending purge measures the LAST offer.
        let mut d = doc(vec![]);
        mint_pairing_in_doc(&mut d, "abcdef0123456789", SECRET_A, 100);
        mint_pairing_in_doc(&mut d, "abcdef0123456789", SECRET_B, 200);
        assert_eq!(d.pairings.len(), 1);
        assert_eq!(d.pairings[0].created_ms, 200);
        assert_eq!(d.pairings[0].secret_hex, SECRET_B);
        assert!(d.pairings[0].pending_ack);
        // The refreshed row is not yet purgeable at 100 + MAX_AGE.
        let now = 100 + PENDING_PAIRING_MAX_AGE_MS + 1;
        assert!(!purge_stale_pending_in_doc(&mut d, now));
    }

    #[test]
    fn stale_pending_offers_purge_at_24h() {
        let now = 100 * PENDING_PAIRING_MAX_AGE_MS;
        let mut d = doc(vec![
            Pairing {
                code: "0000000000000001".to_owned(),
                secret_hex: SECRET_A.to_owned(),
                created_ms: now - PENDING_PAIRING_MAX_AGE_MS - 1,
                pending_ack: true,
                role: "controller".to_owned(),
            },
            Pairing {
                code: "0000000000000002".to_owned(),
                secret_hex: SECRET_A.to_owned(),
                created_ms: now - PENDING_PAIRING_MAX_AGE_MS + 1,
                pending_ack: true,
                role: "controller".to_owned(),
            },
            Pairing {
                code: "0000000000000003".to_owned(),
                secret_hex: SECRET_A.to_owned(),
                created_ms: 1,
                pending_ack: false,
                role: "host".to_owned(),
            },
        ]);
        assert!(purge_stale_pending_in_doc(&mut d, now));
        assert_eq!(
            d.pairings.len(),
            2,
            "stale pending gone; fresh pending + established stay"
        );
    }

    #[test]
    fn pre_adr006_pairings_load_as_legacy_role() {
        let json = format!(
            "{{\"code\":\"abcdef0123456789\",\"secret_hex\":\"{SECRET_A}\",\"created_ms\":1}}"
        );
        let p: Pairing = serde_json::from_str(&json).expect("legacy pairing loads");
        assert_eq!(p.role, "legacy");
        assert!(!p.pending_ack);
    }
}
