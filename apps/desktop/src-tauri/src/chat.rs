//! Machine chat + pairing (ADR-005 §3–§5, RD-022/RD-023).
//!
//! Responsibilities:
//! - **Pairing store** (`pairings.json`): peer code → 32-byte secret hex,
//!   established automatically on the first session (controller offers,
//!   host acks; the session's consent click was the trust ceremony).
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

/// One established pairing (RD-023). `code` is the peer's device id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pairing {
    pub code: String,
    pub secret_hex: String,
    pub created_ms: u64,
    /// Controller-side offers keep `pending_ack` until the host's PairAck.
    #[serde(default)]
    pub pending_ack: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PairingsDoc {
    pairings: Vec<Pairing>,
}

/// One stored chat line. `sender`: "user" | "agent" | "peer-user" |
/// "peer-agent" (perspective: this machine's store).
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

/// Sealed envelope stored by the signaling service (`/api/chat`).
/// Ciphertext only; the service can neither read nor forge it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatEnvelope {
    pub v: u32,
    pub from: String,
    pub nonce_hex: String,
    pub ct_hex: String,
    pub ts_ms: u64,
}

pub const CHAT_PROTOCOL_VERSION: u32 = 1;

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
    read_pairings(app).pairings
}

pub fn pairing_for(app: &AppHandle, code: &str) -> Option<Pairing> {
    read_pairings(app)
        .pairings
        .into_iter()
        .find(|p| p.code == code && !p.pending_ack)
}

/// Host side: store a pairing offered by a controller (PairOfferReceived).
pub fn record_pairing(app: &AppHandle, code: &str, secret_hex: &str) {
    let mut doc = read_pairings(app);
    let code = code.trim().to_lowercase();
    let valid = secret_hex.len() == 64 && secret_hex.chars().all(|c| c.is_ascii_hexdigit());
    if !valid {
        return; // malformed offers are ignored, never stored
    }
    match doc.pairings.iter_mut().find(|p| p.code == code) {
        Some(existing) => {
            existing.secret_hex = secret_hex.to_owned();
            existing.pending_ack = false;
        }
        None => doc.pairings.push(Pairing {
            code,
            secret_hex: secret_hex.to_owned(),
            created_ms: now_ms(),
            pending_ack: false,
        }),
    }
    write_pairings(app, &doc);
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
pub fn mint_pairing(app: &AppHandle, code: &str) -> String {
    let mut bytes = [0u8; 32];
    let _ = getrandom::fill(&mut bytes);
    let secret_hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut doc = read_pairings(app);
    let code = code.trim().to_lowercase();
    match doc.pairings.iter_mut().find(|p| p.code == code) {
        Some(existing) => {
            existing.secret_hex = secret_hex.clone();
            existing.pending_ack = true;
        }
        None => doc.pairings.push(Pairing {
            code,
            secret_hex: secret_hex.clone(),
            created_ms: now_ms(),
            pending_ack: true,
        }),
    }
    write_pairings(app, &doc);
    secret_hex
}

pub fn remove_pairing(app: &AppHandle, code: &str) {
    let mut doc = read_pairings(app);
    let code = code.trim().to_lowercase();
    doc.pairings.retain(|p| p.code != code);
    write_pairings(app, &doc);
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

fn now_ms() -> u64 {
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

/// Called by the event forwarder on `ConsentRequested`: if the controller
/// is paired, auto-accept (full control, silently). Returns true when the
/// prompt was auto-accepted (the UI's prompt resolves via state change).
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
    handle.send(crate::engine::EngineCmd::ConsentAccept).is_ok()
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
