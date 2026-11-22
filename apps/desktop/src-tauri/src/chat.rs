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
    /// ADR-009: cached display name of the peer machine (learned from the
    /// wire — `accept.host_name` controller-side, `connect_request.
    /// requester_name` host-side; editable in Trusted machines). Absent on
    /// pre-0.10 rows and until the first session supplies it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl core::fmt::Debug for Pairing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pairing")
            .field("code", &self.code)
            .field("secret_hex", &"<redacted>")
            .field("created_ms", &self.created_ms)
            .field("pending_ack", &self.pending_ack)
            .field("role", &self.role)
            .field("name", &self.name)
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
    /// (controller code, remember?, wire requester name). The name
    /// (ADR-009) is cached onto the host-role pairing row when the
    /// controller's PairOffer lands.
    pub decision: Option<(String, bool, Option<String>)>,
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
    /// Prompt-flood follow-up (post-0.10.2 security review): timestamps
    /// of prompts shown to UNVERIFIED requesters (unpaired AND
    /// paired-without-valid-proof — both land on the prompt path), pruned
    /// to the flood window. The per-controller cooldowns above key on
    /// device ids an attacker freely rotates; this bounds the aggregate
    /// no matter how many fresh ids arrive.
    pub untrusted_prompt_times: std::collections::VecDeque<u64>,
    /// ADR-013 P2: when the prompt on screen is an ACCOUNT-scope proof
    /// prompt, the proven installation id (set with the prompt, consumed
    /// by the accept/decline commands to remember/revoke the account
    /// intent). `None` on ordinary pairing prompts.
    pub prompt_account: Option<String>,
}

/// Prompt-flood cooldown after an explicit user reject (ADR-006 B3).
pub const REJECT_COOLDOWN_MS: u64 = 5 * 60 * 1000;
/// Cooldown after a consent timeout (the prompt expired unanswered).
pub const TIMEOUT_COOLDOWN_MS: u64 = 60 * 1000;
/// Controller-side pending offers older than this are purged on read.
pub const PENDING_PAIRING_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000;
/// Global prompt budget (prompt-flood follow-up, post-0.10.2): at most
/// this many prompts for UNVERIFIED requesters per hour, across ALL ids — beyond it the
/// host quietly auto-rejects instead of flashing the window. Generous
/// for a family (a couple of machines, a few retries), fatal for an
/// id-rotating flood: one pending prompt at a time means the attacker's
/// ceiling is LIMIT prompts per hour either way.
pub const PROMPT_FLOOD_GLOBAL_LIMIT: usize = 10;
/// The budget's sliding window (1 hour).
pub const PROMPT_FLOOD_WINDOW_MS: u64 = 60 * 60 * 1000;
/// Hard memory cap on the timestamp deque (invariant-3 paranoia: the
/// window prune already bounds it; this is the belt to those braces).
const PROMPT_FLOOD_TIMES_CAP: usize = 64;

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

    /// Global prompt budget: call before showing a prompt to an
    /// UNPAIRED controller. Records the prompt and returns true while
    /// the last-hour count is under the limit; false means the budget is
    /// spent — auto-reject without prompting (the same silent path as
    /// the per-controller cooldown). Paired-and-proven reconnects never
    /// prompt and never touch this.
    pub fn prompt_budget_ok(&mut self, now: u64) -> bool {
        let window_start = now.saturating_sub(PROMPT_FLOOD_WINDOW_MS);
        while self
            .untrusted_prompt_times
            .front()
            .is_some_and(|t| *t < window_start)
        {
            self.untrusted_prompt_times.pop_front();
        }
        if self.untrusted_prompt_times.len() >= PROMPT_FLOOD_GLOBAL_LIMIT {
            return false;
        }
        self.untrusted_prompt_times.push_back(now);
        if self.untrusted_prompt_times.len() > PROMPT_FLOOD_TIMES_CAP {
            self.untrusted_prompt_times.pop_front();
        }
        true
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
    /// ADR-013 P2: installation ids with a standing "Always allow" for
    /// their ACCOUNT-scope proofs (account-scoped remote control's
    /// consent-once). Keyed by the proof's self-certifying installation
    /// id — not the claimable signaling device id — so a re-keyed or
    /// revoked installation loses trust by construction (its id can never
    /// be re-earned by a different key).
    #[serde(default)]
    account_remembered: Vec<String>,
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
    /// ADR-013 P3 slice 2 (additive): fleet call correlation id from the
    /// sealed v2 payload, kept for slice 3 reply routing. Absent on v1
    /// lines and ordinary chat — pre-slice-2 history loads unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet_call_id: Option<String>,
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
// ADR-013 P3 slice 2 adds the v2 sealed payload (the authoritative agent
// bit + fleet correlation id ride INSIDE the ciphertext).
pub use protocol::chat::{
    CHAT_PAYLOAD_VERSION_V2, CHAT_PROTOCOL_VERSION, ChatEnvelope, ChatPayload,
};

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
            name: None,
        }),
    }
    doc.remembered.retain(|c| c != &code);
    true
}

/// Control (Cc) AND invisible-format (Cf) characters — zero-width spaces,
/// bidi overrides (U+202E etc.), BOM — the visual-spoofing class the
/// service schema rejects on the wire and local names must match.
pub(crate) fn is_invisible_char(c: char) -> bool {
    if c.is_control() {
        return true;
    }
    matches!(c as u32,
        0x00AD            // soft hyphen
        | 0x200B..=0x200F // zero-width + LRM/RLM
        | 0x2028..=0x202E // line/para sep + bidi overrides
        | 0x2060..=0x206F // word joiner + invisible operators
        | 0xFEFF          // BOM
        | 0xFFF9..=0xFFFB // interlinear annotation
    )
}

/// Validate a LOCAL display name (rename paths) against the same rule
/// the signaling service enforces on wire names: trimmed, 1-64 chars, no
/// control characters (0.10.2 security review — an unbounded local name
/// could bloat pairings.json and stretch the UI). Returns the trimmed,
/// accepted form.
pub fn sanitize_local_name(raw: &str) -> Option<String> {
    // Strict (matches the service): a name CONTAINING an invisible
    // character is rejected outright, not cleaned — silent rewriting of
    // what the user typed hides the problem.
    if raw.chars().any(is_invisible_char) {
        return None;
    }
    let trimmed = raw.trim();
    let count = trimmed.chars().count();
    if count == 0 || count > 64 {
        return None;
    }
    Some(trimmed.to_owned())
}

/// ADR-009: cache a display name onto the pairing row for `code` (any
/// role, pending or established). Invalid names (empty, over 64 chars,
/// control characters) and missing rows are no-ops — the name is a
/// convenience label, never load-bearing.
pub fn set_pairing_name(app: &AppHandle, code: &str, name: &str) {
    let mut doc = read_pairings(app);
    if set_pairing_name_in_doc(&mut doc, code, name) {
        write_pairings(app, &doc);
    }
}

/// Pure core of [`set_pairing_name`]: false = nothing changed (no row,
/// empty name, or the same name already cached).
fn set_pairing_name_in_doc(doc: &mut PairingsDoc, code: &str, name: &str) -> bool {
    let Some(name) = sanitize_local_name(name) else {
        return false;
    };
    let code = code.trim().to_lowercase();
    match doc.pairings.iter_mut().find(|p| p.code == code) {
        Some(p) if p.name.as_deref() != Some(name.as_str()) => {
            p.name = Some(name);
            true
        }
        _ => false,
    }
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
            name: None,
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
// ADR-013 P2: standing "Always allow" for ACCOUNT-scope proofs (keyed by
// the proven installation id — see PairingsDoc::account_remembered)
// ---------------------------------------------------------------------------

/// Remember an account-scope "Always allow" (the account prompt's Always
/// choice; durable at click time exactly like [`remember_intent`]).
pub fn remember_account_intent(app: &AppHandle, installation_id: &str) {
    let mut doc = read_pairings(app);
    if remember_account_intent_in_doc(&mut doc, installation_id) {
        write_pairings(app, &doc);
    }
}

fn remember_account_intent_in_doc(doc: &mut PairingsDoc, installation_id: &str) -> bool {
    let id = installation_id.trim();
    // Installation ids are base58(SHA-256(pubkey)) — 44 chars today. The
    // 20..=64 band deliberately sits ABOVE the 16-char signaling ids: the
    // two trust keys (device id vs installation id) must never be
    // confusable, so a hex signaling id is rejected on shape alone.
    let valid = (20..=64).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric())
        && !doc.account_remembered.iter().any(|i| i == id);
    if !valid {
        return false;
    }
    doc.account_remembered.push(id.to_owned());
    if doc.account_remembered.len() > REMEMBERED_CAP {
        doc.account_remembered
            .drain(..doc.account_remembered.len() - REMEMBERED_CAP);
    }
    true
}

/// Revoke one (explicit Decline on an account prompt).
pub fn revoke_account_intent(app: &AppHandle, installation_id: &str) {
    let mut doc = read_pairings(app);
    let id = installation_id.trim();
    let before = doc.account_remembered.len();
    doc.account_remembered.retain(|i| i != id);
    if doc.account_remembered.len() != before {
        write_pairings(app, &doc);
    }
}

/// Standing account "Always allow" for this installation?
pub fn has_account_intent(app: &AppHandle, installation_id: &str) -> bool {
    let id = installation_id.trim();
    read_pairings(app)
        .account_remembered
        .iter()
        .any(|i| i == id)
}

/// Security review finding 3: armed account intents are revocable after
/// all — a machine removed from the account (dashboard revoke) vanishes
/// from every directory snapshot, and the next successful poll prunes its
/// intent here. Called ONLY with a fresh, successful snapshot (an empty
/// cache from a failed poll must never prune). Returns whether the doc
/// changed.
pub fn prune_account_intents(app: &AppHandle, present: &[String]) -> bool {
    if present.is_empty() {
        return false; // defensive: never wipe trust on an empty read
    }
    let mut doc = read_pairings(app);
    let before = doc.account_remembered.len();
    doc.account_remembered
        .retain(|id| present.iter().any(|p| p == id));
    if doc.account_remembered.len() != before {
        write_pairings(app, &doc);
        true
    } else {
        false
    }
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
        fleet_call_id: None,
    };
    append_history(app, peer, line);
    // Agent-to-agent (ADR-005 §4): agent-authored messages wake the local
    // assistant as an instruction turn; user-authored ones only display.
    // 0.11.1: an agent-bit arrival that is the REPLY to this machine's
    // human ask (an unanswered "to-agent" below) must NOT wake — that is
    // the answer coming home, not an instruction (the same wire bit
    // carries both meanings).
    if sender == "agent" && should_wake_for_agent_line(&existing) {
        app.state::<crate::commands::AppServices>()
            .assistant
            .deliver_peer_agent(peer, body);
    }
}

/// Wake gate for an agent-bit arrival, judged on the lines already stored
/// for this peer (the new line is appended by the caller): wake unless
/// the last agent-box line from THIS machine is an unanswered human ask
/// ("to-agent") — that arrival is its reply. Once a peer-agent line
/// follows the ask, later arrivals are fresh instructions (or
/// agent-to-agent traffic) and wake again.
fn should_wake_for_agent_line(prior: &[ChatLine]) -> bool {
    for line in prior.iter().rev() {
        match line.sender.as_str() {
            // The human asked the peer's assistant and nothing
            // agent-authored has arrived since → the next agent-bit
            // message is the reply to display, not an instruction.
            "to-agent" => return false,
            "peer-agent" | "agent" => return true,
            // Plain traffic (user / peer-user) keeps looking further
            // back for the last agent-box line.
            _ => continue,
        }
    }
    true
}

/// Inbox arrival (ADR-013 P3 fleet slice 2): store the decrypted line
/// (dedupe by id) and route an agent-bit arrival through the SAME wake
/// gate as in-session chat — but only when this machine opted in
/// (`allow_remote_agent_instructions`, default false). Opted out: the
/// line still lands as "peer-agent" (the fleet delivered it; the human
/// can read it), it just never wakes the assistant. `fleet_call_id`
/// rides along for slice 3 reply correlation. Returns whether the line
/// was stored (false = duplicate id).
pub fn record_incoming_inbox(
    app: &AppHandle,
    peer: &str,
    id: u64,
    ts_ms: u64,
    agent_bit: bool,
    body: &str,
    fleet_call_id: Option<String>,
    allow_remote_agent_instructions: bool,
) -> bool {
    let existing = history(app, peer);
    if existing.iter().any(|l| l.id == id) {
        return false;
    }
    let sender = if agent_bit { "peer-agent" } else { "peer-user" };
    let line = ChatLine {
        id,
        ts_ms,
        sender: sender.to_owned(),
        body: body.to_owned(),
        fleet_call_id,
    };
    append_history(app, peer, line);
    // The wake gate is the in-session one (reply-to-our-ask suppression
    // included); deliver_peer_agent keeps the rolling wake budget. The
    // opt-in is checked HERE, at the only inbox wake site — a non-opted-in
    // machine stores agent-bit lines but never auto-acts on them.
    if inbox_should_wake(agent_bit, allow_remote_agent_instructions, &existing) {
        app.state::<crate::commands::AppServices>()
            .assistant
            .deliver_peer_agent(peer, body);
    }
    true
}

/// Pure wake decision for an inbox arrival (ADR-013 P3 slice 2): an
/// agent-bit line wakes the assistant only when the machine opted in
/// (`allow_remote_agent_instructions`) AND the in-session reply gate
/// agrees (an unanswered human "to-agent" ask means the arrival is its
/// reply — display, don't wake). Human arrivals never wake.
fn inbox_should_wake(
    agent_bit: bool,
    allow_remote_agent_instructions: bool,
    prior: &[ChatLine],
) -> bool {
    agent_bit && allow_remote_agent_instructions && should_wake_for_agent_line(prior)
}

/// Outgoing line (this machine's user or agent) → store.
pub fn record_outgoing(app: &AppHandle, peer: &str, sender: &str, body: &str) -> ChatLine {
    let line = ChatLine {
        id: now_ms(),
        ts_ms: now_ms(),
        sender: sender.to_owned(),
        body: body.to_owned(),
        fleet_call_id: None,
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

fn seal(
    secret_hex: &str,
    from: &str,
    to: &str,
    ts_ms: u64,
    body: &str,
    agent: bool,
    fleet_call_id: Option<&str>,
) -> Option<ChatEnvelope> {
    let key_bytes = hex_decode(secret_hex)?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    let _ = getrandom::fill(&mut nonce_bytes);
    let aad = format!("{CHAT_PROTOCOL_VERSION}|{from}|{to}|{ts_ms}");
    // ADR-013 P3 slice 2: fleet metadata rides INSIDE the seal (v2 JSON
    // payload) so the service can neither read nor forge the agent bit.
    // Plain human chat keeps the v1 plain-text payload byte-for-byte.
    let plaintext = if agent || fleet_call_id.is_some() {
        ChatPayload {
            v: CHAT_PAYLOAD_VERSION_V2,
            body: body.to_owned(),
            agent,
            fleet_call_id: fleet_call_id.map(str::to_owned),
        }
        .to_json()
    } else {
        body.to_owned()
    };
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext.as_bytes(),
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
        // Outside-seal routing hints (additive; the receiver trusts only
        // the sealed payload — see protocol::chat).
        agent,
        fleet_call_id: fleet_call_id.map(str::to_owned),
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
    // Reject non-ASCII before byte-index slicing: a hostile server could send
    // multi-byte UTF-8 (e.g. "aéb") whose even byte length passes the parity
    // check but whose byte slices split a char boundary and PANIC, killing the
    // inbox poller thread permanently (security review F1). ASCII-hex only.
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
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
/// Human chat: v1 plain-text payload, no agent bit — the historical
/// signature and wire shape are unchanged.
pub fn inbox_send(
    app: &AppHandle,
    base_url: &str,
    token: &str,
    from: &str,
    to: &str,
    body: &str,
) -> Result<(), String> {
    inbox_send_agent(app, base_url, token, from, to, body, false, None)
}

/// ADR-013 P3 fleet slice 2: send an out-of-session message carrying the
/// agent bit and/or a fleet call id INSIDE the sealed v2 payload. The
/// receiver wakes its assistant only if it opted in
/// (`allow_remote_agent_instructions`); paired machines only — the seal
/// is the pairing secret, so an unpaired party cannot forge an agent-bit
/// arrival that opens.
pub fn inbox_send_agent(
    app: &AppHandle,
    base_url: &str,
    token: &str,
    from: &str,
    to: &str,
    body: &str,
    agent: bool,
    fleet_call_id: Option<&str>,
) -> Result<(), String> {
    let Some(pairing) = pairing_for(app, to) else {
        return Err(format!(
            "no pairing with {to} — connect once to establish chat"
        ));
    };
    let ts = now_ms();
    let env = seal(
        &pairing.secret_hex,
        from,
        to,
        ts,
        body,
        agent,
        fleet_call_id,
    )
    .ok_or_else(|| "sealing failed".to_owned())?;
    let http = node_runtime::http::https_agent(Duration::from_secs(15), "remote-desktop-chat");
    let response = http
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
///
/// ADR-013 P3 fleet slice 2: a v2 sealed payload's agent bit routes the
/// arrival through the in-session wake gate — but only when this machine
/// opted in (`allow_remote_agent_instructions`, default false). Opted
/// out, agent-bit lines are stored ("peer-agent") without waking. The
/// outer envelope's `agent`/`fleet_call_id` hints are server-visible and
/// therefore NEVER drive the wake decision; only the sealed payload does.
pub fn inbox_drain(app: &AppHandle, base_url: &str, token: &str, me: &str) -> usize {
    // The opt-in is read once per drain (the poller holds no store lock
    // across the network call; a settings flip applies next tick).
    let allow_remote = {
        let services = app.state::<crate::commands::AppServices>();
        let Ok(store) = services.store.lock() else {
            return 0;
        };
        store.settings().allow_remote_agent_instructions
    };
    let http = node_runtime::http::https_agent(Duration::from_secs(15), "remote-desktop-chat");
    // The drain contract requires the caller's `device` as a query param
    // (GET /api/chat?device=…): without it the service 400s every poll and
    // the inbox never delivers (the live 400 flood, diagnosed 2026-11-03).
    let url = format!("{}?device={me}", chat_api(base_url));
    let Ok(response) = http
        .get(&url)
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
        // The authoritative sender kind rides INSIDE the seal: a v2 JSON
        // payload carries the agent bit + fleet id; a v1 payload is plain
        // text (the peer's human — the pre-slice-2 behavior, unchanged).
        let (agent_bit, text, fleet_call_id) = match ChatPayload::parse(&body) {
            Some(payload) => (payload.agent, payload.body, payload.fleet_call_id),
            None => (false, body, None),
        };
        let stored = record_incoming_inbox(
            app,
            &env.from,
            env.ts_ms,
            env.ts_ms,
            agent_bit,
            &text,
            fleet_call_id,
            allow_remote,
        );
        if stored {
            // Wire-style sender (the webview prefixes "peer-"), matching
            // the in-session ChatReceived event convention.
            let sender = if agent_bit { "agent" } else { "user" };
            let _ = app.emit(
                "engine://chat",
                json!({ "peer": env.from, "id": env.ts_ms, "ts_ms": env.ts_ms, "sender": sender, "body": text }),
            );
            delivered += 1;
        }
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

/// ADR-013 P2 twin of [`auto_accept_if_paired`] for account-scope proofs:
/// a verified proof from an installation with a standing account "Always
/// allow" is silently accepted. `remember: true` on the engine command is
/// deliberate — it also completes the pairing ceremony when the
/// controller offers (stronger proof on every later connect), exactly
/// like a pairing-verified accept.
pub fn auto_accept_account(app: &AppHandle) -> bool {
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

    #[test]
    fn hex_decode_rejects_non_ascii_without_panicking() {
        // Security review F1: a hostile server could send multi-byte UTF-8 with
        // an even byte length; byte-index slicing must not panic (it would kill
        // the inbox poller). Non-ASCII hex is rejected, valid hex still decodes.
        assert_eq!(hex_decode("aéb"), None); // 4 bytes, splits a char boundary
        assert_eq!(hex_decode("zz"), None); // even length, non-hex digits
        assert_eq!(hex_decode("abc"), None); // odd length
        assert_eq!(hex_decode("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(hex_decode(""), Some(vec![]));
    }

    const SECRET_A: &str = "aa9d6c507d4a3e2f1b8c7d6e5f4a3b2c1908a7b6c5d4e3f2a1b0c9d8e7f6a5b4";
    const SECRET_B: &str = "bb1e5f4a3b2c1908a7b6c5d4e3f2a1b0c9d8e7f6a5b4aa9d6c507d4a3e2f8c7d";

    fn doc(pairs: Vec<Pairing>) -> PairingsDoc {
        PairingsDoc {
            pairings: pairs,
            remembered: Vec::new(),
            account_remembered: Vec::new(),
        }
    }

    fn line(sender: &str, id: u64) -> ChatLine {
        ChatLine {
            id,
            ts_ms: id,
            sender: sender.to_owned(),
            body: "x".to_owned(),
            fleet_call_id: None,
        }
    }

    #[test]
    fn agent_reply_to_our_ask_displays_without_waking() {
        // 0.11.1: the wire's agent bit means BOTH "addressed to the peer's
        // assistant" (our ask) and "authored by an assistant" (the reply).
        // A reply directly following our unanswered human ask must not
        // wake our own assistant as if it were an instruction.
        let prior = [
            line("user", 1),      // plain chat earlier
            line("peer-user", 2), // their reply
            line("to-agent", 3),  // our human asks their assistant
        ];
        assert!(
            !should_wake_for_agent_line(&prior),
            "reply must display only"
        );

        // After the reply lands, a NEW agent-bit arrival is a fresh
        // instruction (their side asked OUR assistant) and wakes again.
        let answered = [
            line("to-agent", 3),
            line("peer-agent", 4), // the reply
        ];
        assert!(should_wake_for_agent_line(&answered));

        // Agent-to-agent: our assistant instructed theirs ("agent" out) —
        // their assistant's answer is conversational and wakes us.
        let instructed = [line("agent", 5), line("peer-user", 6)];
        assert!(should_wake_for_agent_line(&instructed));

        // No history at all: a first-ever agent arrival wakes (their
        // human used their agent box against us).
        assert!(should_wake_for_agent_line(&[]));

        // Plain-only history changes nothing.
        let plain = [line("user", 7), line("peer-user", 8)];
        assert!(should_wake_for_agent_line(&plain));
    }

    // ---- ADR-013 P3 fleet slice 2: inbox agent-bit + opt-in wake gate ----

    #[test]
    fn inbox_wake_requires_the_opt_in() {
        // Opted in: a fresh agent-bit arrival wakes (same gate as
        // in-session chat).
        assert!(inbox_should_wake(true, true, &[]));
        // Opted OUT (the serde default): the line is stored by the caller
        // but never wakes — a non-opted-in slave does not auto-act.
        assert!(!inbox_should_wake(true, false, &[]));
        // Human arrivals never wake, opt-in or not.
        assert!(!inbox_should_wake(false, true, &[]));
        assert!(!inbox_should_wake(false, false, &[]));
        // The in-session reply suppression still applies when opted in:
        // an agent-bit arrival right after our unanswered human ask is
        // the reply coming home, not an instruction.
        let ask = [line("to-agent", 1)];
        assert!(!inbox_should_wake(true, true, &ask));
        // Once the reply landed, the next agent-bit arrival wakes again.
        let answered = [line("to-agent", 1), line("peer-agent", 2)];
        assert!(inbox_should_wake(true, true, &answered));
    }

    #[test]
    fn agent_bit_and_fleet_id_ride_inside_the_seal() {
        let env = seal(
            SECRET_A,
            "abcdef0123456789",
            "1111111111111111",
            42,
            "free some disk space",
            true,
            Some("fleet-7"),
        )
        .expect("seal");
        // The outer hints mirror the payload (additive, untrusted).
        assert!(env.agent);
        assert_eq!(env.fleet_call_id.as_deref(), Some("fleet-7"));
        assert_eq!(env.v, CHAT_PROTOCOL_VERSION, "no envelope version bump");
        // The receiver opens the seal and finds the authoritative bits.
        let pt = open(SECRET_A, "1111111111111111", &env).expect("open");
        let payload = ChatPayload::parse(&pt).expect("v2 payload");
        assert!(payload.agent);
        assert_eq!(payload.body, "free some disk space");
        assert_eq!(payload.fleet_call_id.as_deref(), Some("fleet-7"));
    }

    #[test]
    fn human_inbox_send_keeps_the_v1_plain_text_payload() {
        let env = seal(
            SECRET_A,
            "abcdef0123456789",
            "1111111111111111",
            42,
            "hello there",
            false,
            None,
        )
        .expect("seal");
        assert!(!env.agent);
        assert_eq!(env.fleet_call_id, None);
        let pt = open(SECRET_A, "1111111111111111", &env).expect("open");
        assert_eq!(pt, "hello there", "v1 payload stays plain text");
        assert_eq!(ChatPayload::parse(&pt), None, "no agent routing");
    }

    #[test]
    fn outer_hints_cannot_forge_a_wake() {
        // The service (or anyone editing the stored row) can flip the
        // outside-seal hints — the receiver must still route by the
        // sealed payload. A human message with tampered hints stays
        // human: no agent bit, no fleet id, no wake.
        let mut env = seal(
            SECRET_A,
            "abcdef0123456789",
            "1111111111111111",
            42,
            "just chatting",
            false,
            None,
        )
        .expect("seal");
        env.agent = true;
        env.fleet_call_id = Some("forged".to_owned());
        let pt = open(SECRET_A, "1111111111111111", &env).expect("open");
        assert_eq!(ChatPayload::parse(&pt), None, "hints are not authority");
        assert!(!inbox_should_wake(false, true, &[]));
    }

    #[test]
    fn an_unpaired_secret_never_opens_an_agent_envelope() {
        // The inbox is pairing-sealed: a party without the pairing secret
        // (another machine, the service itself) cannot produce an
        // agent-bit arrival that opens — wrong key fails the GCM tag.
        let env = seal(
            SECRET_A,
            "abcdef0123456789",
            "1111111111111111",
            42,
            "instruction",
            true,
            Some("fleet-1"),
        )
        .expect("seal");
        assert!(open(SECRET_B, "1111111111111111", &env).is_none());
        // Wrong recipient binding (AAD) also fails.
        assert!(open(SECRET_A, "2222222222222222", &env).is_none());
    }

    #[test]
    fn chat_line_fleet_id_is_additive() {
        // Pre-slice-2 history (no fleet_call_id key) loads unchanged.
        let legacy = serde_json::json!({
            "id": 1, "ts_ms": 1, "sender": "peer-user", "body": "hi"
        });
        let l: ChatLine = serde_json::from_value(legacy).expect("legacy line loads");
        assert_eq!(l.fleet_call_id, None);
        // A fleet line round-trips its correlation id; None stays absent.
        let fleet = ChatLine {
            id: 2,
            ts_ms: 2,
            sender: "peer-agent".to_owned(),
            body: "done".to_owned(),
            fleet_call_id: Some("fleet-9".to_owned()),
        };
        let json = serde_json::to_string(&fleet).unwrap();
        assert!(json.contains("\"fleet_call_id\":\"fleet-9\""));
        let back: ChatLine = serde_json::from_str(&json).unwrap();
        assert_eq!(back, fleet);
        let plain = serde_json::to_string(&line("user", 3)).unwrap();
        assert!(!plain.contains("fleet_call_id"));
    }

    #[test]
    fn prompt_budget_bounds_stranger_floods_across_rotating_ids() {
        // 0.10.3: the per-controller cooldowns key on device ids an
        // attacker rotates freely; the GLOBAL budget caps unpaired
        // prompts per hour no matter how many fresh ids arrive.
        let mut t = TrustState::default();
        let hour = PROMPT_FLOOD_WINDOW_MS;
        for i in 0..PROMPT_FLOOD_GLOBAL_LIMIT {
            assert!(t.prompt_budget_ok(i as u64), "prompt {i} must show");
        }
        // The 11th within the hour — a FRESH id — is silently rejected.
        assert!(!t.prompt_budget_ok(1_000));
        // ...and stays spent for the rest of the hour.
        assert!(!t.prompt_budget_ok(30 * 60 * 1000));
        // An hour later the window has rolled: prompts show again.
        assert!(t.prompt_budget_ok(hour + 1));
        // Old timestamps are pruned (bounded memory under sustained
        // pressure: the deque never outgrows the cap).
        assert!(t.untrusted_prompt_times.len() <= PROMPT_FLOOD_GLOBAL_LIMIT);
    }

    #[test]
    fn cooldown_rejections_do_not_consume_prompt_budget() {
        // The `blocked(..) || !budget_ok(..)` short-circuit is load-
        // bearing: a per-controller cooldown rejection must not spend a
        // global slot, or an attacker could drain the budget via ids
        // already in cooldown (free noise, less headroom for family).
        let mut t = TrustState::default();
        t.block("aaaaaaaaaaaaaaaa", 60_000);
        // A blocked id asks again (rejected by the caller before the
        // budget is consulted) — then a FRESH id still gets a full
        // budget: every slot available.
        assert!(t.blocked("aaaaaaaaaaaaaaaa", 1));
        for i in 0..PROMPT_FLOOD_GLOBAL_LIMIT {
            assert!(t.prompt_budget_ok(i as u64));
        }
    }

    #[test]
    fn pairing_names_cache_and_survive_round_trips() {
        // ADR-009: the trusted-host label is learned from the wire (any
        // role, pending or established), empty never overwrites, and the
        // field survives a JSON round trip (absent when None).
        let mut d = doc(vec![Pairing {
            code: "abcdef0123456789".to_owned(),
            secret_hex: SECRET_A.to_owned(),
            created_ms: 1,
            pending_ack: true,
            role: "controller".to_owned(),
            name: None,
        }]);
        assert!(set_pairing_name_in_doc(
            &mut d,
            "ABCDEF0123456789",
            "  MOMS-PC  "
        ));
        assert_eq!(d.pairings[0].name.as_deref(), Some("MOMS-PC"));
        // Same name again → no change reported.
        assert!(!set_pairing_name_in_doc(
            &mut d,
            "abcdef0123456789",
            "MOMS-PC"
        ));
        // Empty never overwrites a learned name.
        assert!(!set_pairing_name_in_doc(&mut d, "abcdef0123456789", "   "));
        assert_eq!(d.pairings[0].name.as_deref(), Some("MOMS-PC"));
        // Unknown code \u2192 no-op.
        assert!(!set_pairing_name_in_doc(&mut d, "1111111111111111", "Lab"));
        // 0.10.2 security review: oversized and control-character names
        // are rejected outright (service wire rule), never stored.
        assert!(!set_pairing_name_in_doc(
            &mut d,
            "abcdef0123456789",
            &"x".repeat(65)
        ));
        assert!(!set_pairing_name_in_doc(
            &mut d,
            "abcdef0123456789",
            "bad\u{202e}name"
        ));
        assert!(!set_pairing_name_in_doc(
            &mut d,
            "abcdef0123456789",
            "bad\u{0007}name"
        ));
        // Round trip: None stays absent, Some serializes.
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("MOMS-PC"));
        let back: PairingsDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pairings[0].name.as_deref(), Some("MOMS-PC"));
        let unnamed = serde_json::to_string(&doc(vec![])).unwrap();
        assert!(!unnamed.contains("name"));
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
                name: None,
            },
            Pairing {
                code: "abcdef0123456789".to_owned(),
                secret_hex: SECRET_B.to_owned(),
                created_ms: 2,
                pending_ack: false,
                role: "host".to_owned(),
                name: None,
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
            name: None,
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
            name: None,
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
            name: None,
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
            name: None,
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
            name: None,
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
            name: None,
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
    fn account_intents_remember_revoke_and_validate() {
        let mut d = doc(vec![]);
        // base58-shaped installation ids land, dedupe, and trim.
        assert!(remember_account_intent_in_doc(
            &mut d,
            " 9ZkdqFPeqQFMbAtgS2M8b1aVvzGk4TQsN1WjnUpeTXW2 "
        ));
        assert!(!remember_account_intent_in_doc(
            &mut d,
            "9ZkdqFPeqQFMbAtgS2M8b1aVvzGk4TQsN1WjnUpeTXW2"
        ));
        // A 16-hex SIGNALING id is NOT a valid installation id: the two
        // trust keys must never be confusable.
        assert!(!remember_account_intent_in_doc(&mut d, "abcdef0123456789"));
        assert!(!remember_account_intent_in_doc(&mut d, ""));
        assert!(!remember_account_intent_in_doc(&mut d, &"x".repeat(65)));
        // Bounded like the pairing intents.
        for i in 0..REMEMBERED_CAP {
            remember_account_intent_in_doc(&mut d, &format!("inst{i:05}"));
        }
        assert!(d.account_remembered.len() <= REMEMBERED_CAP);
    }

    #[test]
    fn pairings_doc_without_account_field_still_loads() {
        // Pre-P2 pairings.json (no account_remembered key) must deserialize
        // via the serde default — the field is additive.
        let legacy = serde_json::json!({
            "pairings": [],
            "remembered": ["abcdef0123456789"]
        });
        let d: PairingsDoc = serde_json::from_value(legacy).expect("legacy doc loads");
        assert!(d.account_remembered.is_empty());
        assert_eq!(d.remembered.len(), 1);
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
                name: None,
            },
            Pairing {
                code: "0000000000000002".to_owned(),
                secret_hex: SECRET_A.to_owned(),
                created_ms: now - PENDING_PAIRING_MAX_AGE_MS + 1,
                pending_ack: true,
                role: "controller".to_owned(),
                name: None,
            },
            Pairing {
                code: "0000000000000003".to_owned(),
                secret_hex: SECRET_A.to_owned(),
                created_ms: 1,
                pending_ack: false,
                role: "host".to_owned(),
                name: None,
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
