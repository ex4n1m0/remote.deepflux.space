//! Typed Tauri commands — a THIN veneer over the engine (RD-011). Every
//! command maps 1:1 onto an [`engine::EngineCmd`] or a local store read;
//! every payload is metadata (strings/numbers). No command or event in
//! this file can transport frame bytes, GPU handles, SDP bodies, or input
//! payloads (invariant 1 — asserted by the IPC surface test).

use std::sync::Mutex;

use tauri::{AppHandle, Emitter, Manager};

use crate::engine::{
    self, EngineCmd, EngineConfig, EngineEvent, EngineHandle, preset_from_name, scale_from_name,
};
use crate::ipc::*;
use crate::store::{AppSettings, LocalStore};

/// Event channel names (engine → UI). Payloads: see `forward_event`.
pub mod events {
    pub const STATE: &str = "engine://state";
    pub const CONSENT: &str = "engine://consent";
    pub const SESSION_ESTABLISHED: &str = "engine://session-established";
    pub const SESSION_ENDED: &str = "engine://session-ended";
    pub const PEER: &str = "engine://peer";
    pub const CAPS: &str = "engine://caps";
    pub const DIAGNOSTICS: &str = "engine://diagnostics";
    pub const ERROR: &str = "engine://error";
    pub const INFO: &str = "engine://info";
    pub const CHAT: &str = "engine://chat";
    pub const PAIRING: &str = "engine://pairing";
    /// ADR-013 swarm enrollment state (app-layer, like the directory
    /// event); payload = `swarm::SwarmState` — metadata only.
    pub const SWARM: &str = "swarm://state";
    /// ADR-013 P2 account directory snapshot; payload =
    /// `[account_directory::AccountMachineDto]` — metadata only.
    pub const ACCOUNT_DIRECTORY: &str = "app://account-directory";
    /// ADR-013 D4/P3 human chat (humans-only E2E rooms): the room state
    /// snapshot; payload = `human_chat::HumanRoomState` — metadata only
    /// (the room word never crosses IPC).
    pub const HUMAN_ROOM_STATE: &str = "human-chat://state";
    /// ADR-013 D4/P3 human chat: one decrypted room message; payload =
    /// `human_chat::HumanRoomMessage`.
    pub const HUMAN_ROOM_MESSAGE: &str = "human-chat://message";
    /// ADR-013 D4/P3 human chat: a non-fatal node log line (join progress,
    /// hub/mailbox notes); payload = `human_chat::HumanRoomLog`.
    pub const HUMAN_ROOM_LOG: &str = "human-chat://log";
}

pub struct AppServices {
    pub store: Mutex<LocalStore>,
    pub engine: Mutex<Option<EngineHandle>>,
    /// In-app assistant (ADR-005): worker thread + busy flag.
    pub assistant: crate::agent::AssistantState,
    /// ADR-006 pairing-ceremony state: the in-memory pairing offer, the
    /// live prompt mark, and prompt-flood cooldowns.
    pub trust: Mutex<crate::chat::TrustState>,
    /// ADR-010 discovery list cache (sealed circle directory, decrypted
    /// rows only — latest-wins, never queue-shaped).
    pub directory: Mutex<crate::directory::DirectoryCache>,
    /// ADR-013 swarm enrollment: membership state + the join/heartbeat
    /// thread lifecycle (secrets stay in Rust state + credstore).
    pub swarm: crate::swarm::SwarmService,
    /// ADR-013 D4/P3 human chat: the humans-only E2E room service — the
    /// control channel to the dedicated node thread + the mirrored room
    /// state (the room word stays in Rust state + settings, never IPC).
    pub human_chat: crate::human_chat::HumanChatService,
    /// ADR-013 P2 account directory: the account's machines, polled by
    /// the swarm heartbeat thread (latest-wins snapshot, no secrets).
    pub account_directory: std::sync::Arc<crate::account_directory::AccountDirectory>,
    /// ADR-008 automatic updates: the UI state machine plus the last
    /// fetched manifest (input for the download step).
    pub update: crate::updater::UpdateEngine,
    pub update_manifest: Mutex<Option<crate::updater::UpdateManifest>>,
}

type CmdResult<T> = Result<T, String>;

fn with_engine<T>(app: &AppHandle, f: impl FnOnce(&EngineHandle) -> CmdResult<T>) -> CmdResult<T> {
    let services = app.state::<AppServices>();
    let guard = services.engine.lock().expect("engine slot");
    let Some(handle) = guard.as_ref() else {
        return Err("engine not started (set the signaling URL and go online first)".into());
    };
    f(handle)
}

/// Create the engine thread (signaling connection + runtime). Idempotent.
#[tauri::command]
pub fn engine_start(app: AppHandle) -> CmdResult<EngineStatusDto> {
    start_engine(&app)
}

/// Shared engine-start path: the typed command above and the MCP bridge's
/// auto-start (ADR-004, RD-018) both call this.
pub(crate) fn start_engine(app: &AppHandle) -> CmdResult<EngineStatusDto> {
    // A dead engine thread (panic) must not zombie the app: the old code
    // reused the slot forever, so every later command failed "engine
    // stopped" until a manual restart (2026-10-28 incident). The slot is
    // now checked for LIVENESS; a dead handle is replaced and the
    // always-ready roles are replayed on the fresh engine.
    let replay = {
        let services = app.state::<AppServices>();
        let mut guard = services.engine.lock().expect("engine slot");
        match guard.as_ref() {
            Some(handle) if handle.is_alive() => {
                return Ok(handle.status().into());
            }
            Some(dead) => {
                let status = dead.status();
                let replay = (
                    status.controller_state != "Idle",
                    status.host_state != "Idle",
                );
                *guard = None; // drop the zombie handle
                Some(replay)
            }
            None => None,
        }
    };
    let (settings, metrics_dir) = {
        let services = app.state::<AppServices>();
        let store = services.store.lock().expect("store");
        (
            store.settings().clone(),
            app.path()
                .app_log_dir()
                .unwrap_or_else(|_| std::env::temp_dir()),
        )
    };
    if settings.signaling_base_url.trim().is_empty() {
        return Err(
            "No signaling server configured. Open Settings and set the service URL \
             (the deployed Vercel service, or the local dev server for testing)."
                .into(),
        );
    }
    let signaling = node_runtime::signaling_remote::RemoteSignaling::new(
        node_runtime::signaling_remote::RemoteSignalingConfig::new(
            &settings.signaling_base_url,
            &settings.device_id,
            &settings.device_token,
        ),
    );
    let quality = preset_from_name(&settings.default_quality)
        .unwrap_or(protocol::wire::QualityPreset::Balanced);
    let scale =
        scale_from_name(&settings.default_viewer_scale).unwrap_or(render_windows::ScaleMode::Fit);
    let cfg = EngineConfig {
        device_id: settings.device_id.clone(),
        signaling: Box::new(signaling),
        real_pipelines: true,
        real_input: true,
        auto_reonline: true,
        metrics_dir: Some(metrics_dir),
        status_file: None,
        viewer_title: "Remote Desktop".to_owned(),
        initial_quality: quality,
        initial_scale: scale,
        // Test-only chaos is never set by the product shell (E2E only).
        blackhole_remote_candidates: false,
        // ADR-009: rides the outgoing accept so the controller can label
        // its trusted-host entry.
        host_display_name: display_name(&settings),
    };
    let (mut handle, events) = engine::spawn(cfg);
    // Forwarder: engine events → webview events (metadata only).
    let forward_app = app.clone();
    std::thread::Builder::new()
        .name("engine-events".into())
        .spawn(move || {
            while let Ok(event) = events.recv() {
                if !forward_event(&forward_app, event) {
                    break;
                }
            }
        })
        .map_err(|e| format!("event forwarder spawn: {e}"))?;
    // Two callers can race a respawn (UI poll + assistant); the loser's
    // fresh engine is shut down and the winner's status returned.
    let status = {
        let services = app.state::<AppServices>();
        let mut slot = services.engine.lock().expect("engine slot");
        if let Some(existing) = slot.as_ref()
            && existing.is_alive()
        {
            let status = existing.status().into();
            drop(slot);
            handle.shutdown();
            return Ok(status);
        }
        *slot = Some(handle);
        let Some(live) = slot.as_ref() else {
            unreachable!("just stored");
        };
        live.status().into()
    };
    // Replay the always-ready roles the dead engine had (0.6.3): the
    // controller role for everyone, host presence when it was sharing.
    if let Some((controller, host)) = replay {
        let _ = with_engine(app, |handle| {
            if controller {
                let _ = handle.send(EngineCmd::ControllerStart);
            }
            if host {
                let _ = handle.send(EngineCmd::HostStart);
            }
            Ok(())
        });
        let _ = app.emit(
            events::INFO,
            Some(serde_json::json!({ "message":
                "The connection engine stopped unexpectedly and was restarted. If a session was live, it has ended — connect again."
            })),
        );
    }
    Ok(status)
}

/// Map one engine event onto a Tauri event. Returns false when the engine
/// event channel closed (forwarder exits).
fn forward_event(app: &AppHandle, event: EngineEvent) -> bool {
    let emit = |name: &str, payload: Option<serde_json::Value>| {
        let _ = app.emit(name, payload.unwrap_or(serde_json::Value::Null));
    };
    match event {
        EngineEvent::StateChanged {
            machine,
            state,
            session_id,
        } => {
            // ADR-006 B3: a host consent prompt that fell back to Online
            // without an accept or an explicit reject was a TIMEOUT — cool
            // the controller down so an unanswered prompt cannot be
            // re-spammed. The engine names the role with
            // `MachineKind::name()` (lowercase); comparing against "Host"
            // never matched, so the cooldown never fired until 2026-11-27.
            if machine == node_runtime::MachineKind::Host.name() && state == "Online" {
                let now = crate::chat::now_ms();
                let services = app.state::<AppServices>();
                let mut trust = services.trust.lock().expect("trust state");
                trust.note_host_back_online(now);
            }
            emit(
                events::STATE,
                Some(
                    serde_json::json!({ "machine": machine, "state": state, "session_id": session_id }),
                ),
            )
        }
        EngineEvent::ConsentRequested {
            controller_device_id,
            session_id,
            ai_session,
            pairing_proof_hex,
            requester_name,
            message_id,
            account_proof,
        } => {
            // ADR-006: silent auto-accept requires a VALID pairing proof.
            // The bare device id proves nothing — ids are claimable through
            // the presence-tombstone window minutes after a machine goes
            // offline — so a claimed-trusted request without a matching
            // proof falls back to the human prompt (with a warning flag);
            // fail open to the human, never to accept.
            let host_device_id = {
                let services = app.state::<AppServices>();
                let store = services.store.lock().expect("store");
                store.settings().device_id.clone()
            };
            let pairing = crate::chat::pairing_for(app, &controller_device_id);
            let paired = pairing.is_some();
            let verified = pairing
                .as_ref()
                .map(|p| {
                    node_runtime::pairing_proof::verify_pairing_proof(
                        &p.secret_hex,
                        &controller_device_id,
                        &host_device_id,
                        &session_id,
                        &message_id,
                        pairing_proof_hex.as_deref(),
                        crate::chat::now_ms(),
                    )
                })
                .unwrap_or(false);
            // ADR-013 P2: account-scope proof — the Ed25519 signature must
            // verify (self-certifying installation id, domain-bound,
            // fresh) AND the installation must be a machine of OUR account
            // (the directory poller's snapshot). Signature-valid-but-
            // unknown installations get NO upgrade — they fall through to
            // the ordinary unpaired prompt path.
            let account = account_proof.as_ref().and_then(|proof| {
                let signature_ok = node_runtime::account_proof::verify_account_proof(
                    Some(proof),
                    &controller_device_id,
                    &host_device_id,
                    &session_id,
                    &message_id,
                    crate::chat::now_ms(),
                );
                if !signature_ok {
                    return None;
                }
                app.state::<AppServices>()
                    .account_directory
                    .lookup(&proof.installation_id)
                    .map(|label| {
                        serde_json::json!({
                            "installation_id": proof.installation_id,
                            "label": label,
                        })
                    })
            });
            let mut proof_ok = false;
            if !verified
                && let Some(account_claim) = account.as_ref()
                && let Some(installation_id) = account_claim
                    .get("installation_id")
                    .and_then(|v| v.as_str())
                && crate::chat::has_account_intent(app, installation_id)
            {
                // Consent-once honored: a remembered account machine
                // connects silently (like a proven pairing). The accept's
                // remember choice also completes the pairing ceremony, so
                // later connects ride the stronger pairing proof.
                proof_ok = crate::chat::auto_accept_account(app);
            }
            if verified {
                // RD-023 (user decision 2, 2026-10-24) + ADR-006 proof:
                // proven-paired controllers are auto-accepted — silent full
                // control. The emitted event still fires; the state change
                // resolves any prompt within a tick. `proof_ok` in the
                // payload means "silent accept actually sent" — if the
                // engine send failed the UI must show the dialog, not a
                // decisionless passive card.
                proof_ok = crate::chat::auto_accept_if_paired(app, &controller_device_id);
            } else if !proof_ok {
                // (An account silent-accept already set proof_ok — it is a
                // VERIFIED requester and must not consume the untrusted
                // prompt budget or run the cooldown checks; security review
                // finding 4: doing both raced an accept against a budget
                // reject.)
                // ADR-006 B3 prompt-flood defense: a controller in cooldown
                // (explicit reject / unanswered timeout) is auto-rejected
                // without a prompt. 0.10.3 adds the GLOBAL prompt budget —
                // the cooldowns key on device ids an attacker rotates, so
                // the aggregate (unpaired prompts per hour, all ids) is
                // what actually bounds a flood. Account-verified requesters
                // (ADR-013 P2) ride the same defenses: a compromised
                // same-account machine must not be able to flood either.
                let now = crate::chat::now_ms();
                let services = app.state::<AppServices>();
                let mut trust = services.trust.lock().expect("trust state");
                trust.sweep(now);
                if trust.blocked(&controller_device_id, now) || !trust.prompt_budget_ok(now) {
                    drop(trust);
                    let _ = with_engine(app, |handle| handle.send(EngineCmd::ConsentReject));
                    return true;
                }
                trust.prompt = Some((controller_device_id.clone(), false, false));
                // The account prompt's Always/Decline keys on the PROVEN
                // installation id, not the (rotatable) signaling id.
                trust.prompt_account = account
                    .as_ref()
                    .and_then(|a| a.get("installation_id"))
                    .and_then(|v| v.as_str())
                    .map(str::to_owned);
                // The window must be VISIBLE for the consent moment: an
                // always-ready family host normally lives in the tray, and
                // an invisible prompt dies at the 30 s timeout.
                if let Some(window) = app.get_webview_window("shell") {
                    let _ = window.show();
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                }
            }
            emit(
                events::CONSENT,
                Some(serde_json::json!({
                    "controller_device_id": controller_device_id,
                    "session_id": session_id,
                    "ai_session": ai_session,
                    "paired": paired,
                    "pairing_proof_ok": proof_ok,
                    // ADR-009: the machine display name from the wire
                    // (advisory — the code beside it in the prompt is the
                    // identity; pre-0.10 controllers send none).
                    "requester_name": requester_name,
                    // ADR-013 P2: present on a VERIFIED account-scope
                    // proof — the prompt renders the account variant
                    // ("machine of your DeepMulti account", Always allow
                    // keyed to the installation id). Null on every other
                    // path, including signature-valid-but-unknown installs.
                    "account": account,
                })),
            );
        }
        EngineEvent::ConsentAccepted {
            controller_device_id,
            remember,
            requester_name,
        } => {
            // ADR-006: the owner's click IS the pairing ceremony — but the
            // controller's PairOffer arrives only after the session
            // establishes, so RECORD the decision now and apply it when the
            // offer lands (see PairOfferReceived below).
            let prompt_account = {
                let services = app.state::<AppServices>();
                let mut trust = services.trust.lock().expect("trust state");
                if let Some((_, accepted, _)) = trust.prompt.as_mut() {
                    *accepted = true;
                }
                trust.decision = Some((controller_device_id.clone(), remember, requester_name));
                // ADR-013 P2 (security review finding 1): the account claim
                // belongs to the PROMPT this accept answers — a pending
                // claim for a DIFFERENT controller (a timed-out prompt's
                // leftover, answered here by a paired auto-accept) is
                // dropped, never armed.
                let claim_is_for_this_prompt = trust
                    .prompt
                    .as_ref()
                    .is_some_and(|(c, _, _)| c == &controller_device_id);
                trust
                    .prompt_account
                    .take()
                    .filter(|_| claim_is_for_this_prompt)
            };
            // ADR-006 amendment (2026-10-28): "Always allow" is durable at
            // click time. The in-memory decision above dies with the
            // session — if the controller's PairOffer is lost to a short
            // session or a teardown race, the standing intent completes
            // the pairing in the next session the owner allows instead of
            // silently voiding the click (the "approved forever, asked
            // again" bug). "Allow once" neither arms nor revokes: a
            // standing Always survives it; only Decline or removing the
            // machine in Trusted machines revokes.
            if remember {
                crate::chat::remember_intent(app, &controller_device_id);
            }
            // ADR-013 P2: "Always allow" on an ACCOUNT prompt additionally
            // arms the standing account intent keyed to the proven
            // installation id (consumed here — one prompt, one decision).
            if remember && let Some(installation_id) = prompt_account.as_deref() {
                crate::chat::remember_account_intent(app, installation_id);
            }
        }
        EngineEvent::SessionEstablished {
            session_id,
            peer,
            peer_name,
        } => {
            // RD-023 + ADR-006 amendment (2026-10-28): offer pairing only
            // when THIS machine is the controller of the session. The owed
            // flag was set by our own connect command for this peer; a
            // host-side establish (we're being controlled) has none — the
            // host must never mint/offer pairings toward its controller
            // (spurious offers cross-wired the two sides' secrets and
            // could strand both at endless prompts).
            let controller_session = {
                let services = app.state::<AppServices>();
                let mut trust = services.trust.lock().expect("trust state");
                trust
                    .owed_pair_offer
                    .take()
                    .is_some_and(|owed| Some(owed) == peer)
            };
            if controller_session && let Some(peer) = peer.as_deref() {
                crate::chat::offer_pairing_if_new(app, peer);
            }
            // ADR-009: the controller caches the host's display name
            // (accept.host_name) onto its pairing row — the trusted-host
            // list's label. Absent for pre-0.10 hosts; set_pairing_name
            // no-ops without a row.
            if let (Some(peer), Some(name)) = (peer.as_deref(), peer_name.as_deref()) {
                crate::chat::set_pairing_name(app, peer, name);
            }
            emit(
                events::SESSION_ESTABLISHED,
                Some(serde_json::json!({ "session_id": session_id, "peer": peer })),
            );
        }
        EngineEvent::SessionEnded {
            cause,
            code,
            message,
            hint,
        } => {
            // ADR-006: the ceremony state dies with the session — an
            // un-applied decision or lingering prompt never crosses into
            // the next one (ADR-013 P2: the prompt's account claim too).
            {
                let services = app.state::<AppServices>();
                let mut trust = services.trust.lock().expect("trust state");
                trust.decision = None;
                trust.prompt = None;
                trust.prompt_account = None;
            }
            emit(
                events::SESSION_ENDED,
                Some(
                    serde_json::json!({ "cause": cause, "code": code, "message": message, "hint": hint }),
                ),
            )
        }
        EngineEvent::PeerOnline { device_id } => emit(
            events::PEER,
            Some(serde_json::json!({ "device_id": device_id, "online": true })),
        ),
        EngineEvent::PeerOffline { device_id } => emit(
            events::PEER,
            Some(serde_json::json!({ "device_id": device_id, "online": false })),
        ),
        EngineEvent::HostCaps { monitors } => emit(
            events::CAPS,
            Some(serde_json::json!({ "origin": "host", "monitors": monitors })),
        ),
        EngineEvent::PeerCaps { monitors } => emit(
            events::CAPS,
            Some(serde_json::json!({ "origin": "peer", "monitors": monitors })),
        ),
        EngineEvent::Diagnostics { snapshot } => emit(
            events::DIAGNOSTICS,
            Some(serde_json::json!({ "snapshot": snapshot })),
        ),
        EngineEvent::Error {
            code,
            message,
            hint,
        } => {
            // Pre-connection send failures about the TARGET are "that
            // machine is offline", not a direct-connection problem — the
            // raw code + NAT hint reads as breakage to family users.
            if message.contains("unknown_target") {
                emit(
                    events::ERROR,
                    Some(serde_json::json!({
                        "code": "host_offline",
                        "message": "That machine isn\u{2019}t online right now. Ask whoever uses it to open the app (it starts automatically when their PC is on), then try again.",
                        "hint": null
                    })),
                );
            } else {
                emit(
                    events::ERROR,
                    Some(serde_json::json!({ "code": code, "message": message, "hint": hint })),
                )
            }
        }
        EngineEvent::Info { message } => emit(
            events::INFO,
            Some(serde_json::json!({ "message": message })),
        ),
        // ADR-005 (RD-022/023): chat + pairing are persisted app-side (the
        // engine only transports), then forwarded to the webview.
        EngineEvent::ChatReceived {
            peer,
            id,
            ts_ms,
            sender,
            body,
        } => {
            crate::chat::record_incoming(app, &peer, id, ts_ms, &sender, &body);
            emit(
                events::CHAT,
                Some(serde_json::json!({
                    "peer": peer, "id": id, "ts_ms": ts_ms, "sender": sender, "body": body
                })),
            );
        }
        EngineEvent::PairOfferReceived {
            controller_device_id,
            secret_hex,
        } => {
            // ADR-006: apply the owner's "Always allow" when the offer
            // lands — this session's click (trust.decision) or a standing
            // intent from an earlier click whose offer was lost (2026-10-28
            // amendment; both are explicit human choices for this device
            // id). Anything else → drop un-acked (the controller's pending
            // offer expires client-side; nothing is stored).
            let (click_remembered, peer_name) = {
                let services = app.state::<AppServices>();
                let mut trust = services.trust.lock().expect("trust state");
                match trust
                    .decision
                    .take_if(|(controller, _, _)| controller == &controller_device_id)
                {
                    Some((_, remember, name)) => (remember, name),
                    None => (false, None),
                }
            };
            let remember =
                click_remembered || crate::chat::has_remember_intent(app, &controller_device_id);
            if remember {
                // Human-backed: a stale secret (controller reinstall, lost
                // ack) is replaced instead of refused, so one Always-click
                // re-pairs instead of prompting forever.
                let live =
                    crate::chat::record_pairing(app, &controller_device_id, &secret_hex, true);
                // ADR-009: label the host-role row with the controller's
                // machine display name from the consent prompt.
                if live && let Some(name) = peer_name.as_deref() {
                    crate::chat::set_pairing_name(app, &controller_device_id, name);
                }
                if live {
                    let _ = with_engine(app, |handle| handle.send(EngineCmd::SendPairAck));
                } else {
                    // Unreachable under the human-backed path, kept as the
                    // fail-safe copy for any future non-backed caller.
                    let _ = app.emit(
                        events::INFO,
                        Some(serde_json::json!({ "message": format!(
                            "Couldn't re-trust {controller_device_id} — remove it in Config → Trusted machines, then connect again to re-pair."
                        ) })),
                    );
                }
                emit(
                    events::PAIRING,
                    Some(serde_json::json!({ "device_id": controller_device_id, "paired": live })),
                );
            }
        }
        EngineEvent::PairAckReceived { host_device_id } => {
            crate::chat::pairing_ack(app, &host_device_id);
            // ADR-009: the host's display name was already cached onto the
            // controller-role row at SessionEstablished (accept.host_name)
            // — the pairing itself is the saved machine now.
            emit(
                events::PAIRING,
                Some(serde_json::json!({ "device_id": host_device_id, "paired": true })),
            );
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Identity / settings (local persistence)
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_identity(app: AppHandle) -> CmdResult<Identity> {
    let services = app.state::<AppServices>();
    let store = services.store.lock().expect("store");
    Ok(Identity {
        connection_code: store.settings().device_id.clone(),
        device_id: store.settings().device_id.clone(),
        device_name: display_name(store.settings()),
    })
}

pub(crate) fn display_name(settings: &AppSettings) -> String {
    if settings.device_name.trim().is_empty() {
        return hostname();
    }
    // 0.10.2 (security review): the name rides signaling envelopes that
    // the service validates (1-64 chars, no control characters) — a
    // nonconforming local name would get every outbound connect/accept
    // REJECTED. Clamp to the wire rule instead of failing later.
    wire_safe_name(&settings.device_name).unwrap_or_else(hostname)
}

/// Clamp a display name to the signaling wire rule: trimmed, control
/// characters stripped, at most 64 chars. `None` when nothing usable
/// remains (caller falls back).
pub(crate) fn wire_safe_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !crate::chat::is_invisible_char(*c))
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.chars().take(64).collect())
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "this-pc".into())
}

#[tauri::command]
pub fn get_settings(app: AppHandle) -> CmdResult<SettingsDto> {
    let services = app.state::<AppServices>();
    let store = services.store.lock().expect("store");
    let s = store.settings();
    Ok(SettingsDto {
        device_id: s.device_id.clone(),
        device_name: s.device_name.clone(),
        signaling_base_url: s.signaling_base_url.clone(),
        default_quality: s.default_quality.clone(),
        default_viewer_scale: s.default_viewer_scale.clone(),
        launch_at_login: s.launch_at_login,
        host_sharing: s.host_sharing,
        agent_admin: s.agent_admin,
        agent_download_domains: s.agent_download_domains.clone(),
        allow_remote_agent_instructions: s.allow_remote_agent_instructions,
        auto_update: s.auto_update,
    })
}

#[tauri::command]
pub fn set_settings(app: AppHandle, patch: SettingsPatch) -> CmdResult<SettingsDto> {
    // ADR-006: the login-autostart toggle drives the plugin immediately.
    set_launch_at_login(&app, patch.launch_at_login)?;
    let services = app.state::<AppServices>();
    let mut store = services.store.lock().expect("store");
    let next = AppSettings {
        device_id: store.settings().device_id.clone(),
        device_name: patch.device_name,
        // URL/token changes apply on next engine start (the signaling
        // connection is engine-lifetime).
        signaling_base_url: patch.signaling_base_url.trim().to_owned(),
        default_quality: patch.default_quality,
        default_viewer_scale: patch.default_viewer_scale,
        device_token: store.settings().device_token.clone(),
        launch_at_login: patch.launch_at_login,
        // ADR-009: host presence follows this at the next engine start
        // (the always-ready role replay reads it at launch). ADR-010: it
        // also gates the directory entry — republish/remove on the flip.
        host_sharing: patch.host_sharing,
        // ADR-011: applies on the next launch (the elevation gate in
        // lib.rs reads it at startup).
        agent_admin: patch.agent_admin,
        autostart_default_applied: store.settings().autostart_default_applied,
        // Assistant provider fields are managed via `agent_configure`,
        // not the settings patch — preserve them here.
        agent_base_url: store.settings().agent_base_url.clone(),
        agent_model: store.settings().agent_model.clone(),
        agent_download_domains: patch.agent_download_domains,
        // ADR-013 P3 slice 2: applies immediately — the inbox poller
        // reads it on every drain tick (no restart needed).
        allow_remote_agent_instructions: patch.allow_remote_agent_instructions,
        auto_update: patch.auto_update,
        // ADR-013 D4/P3: the human-chat room word is managed by the
        // human_chat service (rooms_join/rooms_leave), not the settings
        // patch — preserve it here (it never crosses the settings IPC).
        human_room_word: store.settings().human_room_word.clone(),
    };
    let sharing_flipped = store.settings().host_sharing != patch.host_sharing;
    let admin_flipped = store.settings().agent_admin != patch.agent_admin;
    store.update_settings(next)?;
    drop(store);
    if sharing_flipped {
        // Off the store lock before directory work (it re-locks inside);
        // network best-effort off-thread — the poller retries puts.
        let handle = app.clone();
        std::thread::spawn(move || crate::directory::sync_visibility(&handle));
    }
    if admin_flipped {
        // ADR-011: swap the autostart mechanism to match the posture
        // (scheduled task vs Run key). When turning admin ON from an
        // unelevated app the swap completes on the next (elevated)
        // launch — the startup gate in lib.rs handles the relaunch.
        let _ = set_launch_at_login(&app, patch.launch_at_login);
    }
    let s = app
        .state::<AppServices>()
        .store
        .lock()
        .expect("store")
        .settings()
        .clone();
    Ok(SettingsDto {
        device_id: s.device_id,
        device_name: s.device_name,
        signaling_base_url: s.signaling_base_url,
        default_quality: s.default_quality,
        default_viewer_scale: s.default_viewer_scale,
        launch_at_login: s.launch_at_login,
        host_sharing: s.host_sharing,
        agent_admin: s.agent_admin,
        agent_download_domains: s.agent_download_domains.clone(),
        allow_remote_agent_instructions: s.allow_remote_agent_instructions,
        auto_update: s.auto_update,
    })
}

// ---------------------------------------------------------------------------
// Engine commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn engine_status(app: AppHandle) -> CmdResult<EngineStatusDto> {
    // Self-heal (2026-10-28): the UI polls status every few seconds — a
    // dead engine (panic) is respawned here instead of erroring "engine
    // stopped" at the user forever.
    {
        let dead = app
            .state::<AppServices>()
            .engine
            .lock()
            .expect("engine slot")
            .as_ref()
            .is_some_and(|h| !h.is_alive());
        if dead {
            let _ = start_engine(&app);
        }
    }
    with_engine(&app, |handle| Ok(handle.status().into()))
}

#[tauri::command]
pub fn host_start(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::HostStart))
}

#[tauri::command]
pub fn host_stop(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::HostStop))
}

#[tauri::command]
pub fn controller_start(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::ControllerStart))
}

#[tauri::command]
pub fn controller_stop(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::ControllerStop))
}

/// Shut the engine down cleanly (an in-flight host session tells the
/// peer before the process dies), then exit. The File → Quit command and
/// the updater's install step share this path.
pub fn shutdown_and_exit(app: &AppHandle) {
    if let Some(services) = app.try_state::<AppServices>()
        && let Some(mut engine) = services.engine.lock().expect("engine slot").take()
    {
        engine.shutdown();
    }
    app.exit(0);
}

/// File → Quit: the same shutdown path as the tray's Quit item (engine
/// down, then process exit). Keeping the engine shutdown explicit means an
/// in-flight host session tells the peer before the process dies.
#[tauri::command]
pub fn quit_app(app: AppHandle) {
    shutdown_and_exit(&app);
}

#[tauri::command]
pub fn connect(app: AppHandle, args: ConnectArgs) -> CmdResult<()> {
    let code = args.code.trim().to_lowercase();
    if code.is_empty() {
        return Err("Enter the host machine's connection code.".into());
    }
    // UX review 0.10.2: a mistyped code used to sail through to the
    // service and come back as "machine isn't online" — a wrong-but-
    // confident diagnosis. Validate the shape here (defense; the rail
    // validates client-side for instant feedback).
    if !crate::store::is_machine_code(&code) {
        return Err(crate::store::BAD_CODE_COPY.to_owned());
    }
    // ADR-009: the connect_request carries this machine's display name so
    // the host's prompt says who is asking. The name is advisory — the
    // device id beside it stays the identity (ADR-007 §4 posture).
    let requester_name = {
        let services = app.state::<AppServices>();
        let store = services.store.lock().expect("store");
        display_name(store.settings())
    };
    // ADR-006: attach the pairing secret (when one is held with this host)
    // so the engine stamps the single-use pairing proof on the
    // connect_request — silent paired accept must prove the secret, not
    // just claim the (claimable) device id.
    let pairing_secret =
        crate::chat::pairing_for(&app, &code).map(|p| crate::chat::PairingSecret(p.secret_hex));
    // ADR-013 P2: a live swarm membership signs the connect_request with
    // the account proof — a host of the SAME account that knows this
    // installation in its directory trusts it (prompt once, then
    // silently). No membership = the field stays absent, as on pre-P2
    // controllers; a pairing proof still wins where one exists.
    let account_prover = {
        let services = app.state::<AppServices>();
        match services.swarm.current() {
            crate::swarm::SwarmState::Joined { .. } => {
                crate::swarm::SwarmIdentity::load_or_create(&crate::credstore::WindowsCredStore)
                    .ok()
                    .map(|identity| std::sync::Arc::new(identity.account_prover()))
            }
            _ => None,
        }
    };
    // ADR-006 amendment (2026-10-28): this connect owes the session an
    // outbound pairing offer — consumed at establishment to send it from
    // the CONTROLLER side only (see SessionEstablished).
    {
        let services = app.state::<AppServices>();
        services.trust.lock().expect("trust state").owed_pair_offer =
            Some(crate::store::normalize_machine_code(&code));
    }
    with_engine(&app, |handle| {
        handle.send(EngineCmd::Connect {
            code,
            pairing_secret,
            requester_name: Some(requester_name),
            agent: args.agent,
            account_prover,
        })
    })
}

/// The account directory (ADR-013 P2): this account's machines as the
/// heartbeat thread's poller last saw them (latest-wins snapshot; the
/// `app://account-directory` event mirrors every refresh).
#[tauri::command]
pub fn account_directory_machines(
    app: AppHandle,
) -> CmdResult<Vec<crate::account_directory::AccountMachineDto>> {
    Ok(app.state::<AppServices>().account_directory.machines())
}

/// Attach the viewer window to a live agent session ("show the screen"):
/// the same session keeps running — the visual is monitoring only, and
/// the host starts streaming again.
#[tauri::command]
pub fn viewer_show(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::ViewerShow))
}

/// Detach the viewer from a live agent session ("hide the screen"):
/// chat-only again, the host stops streaming. The session stays.
#[tauri::command]
pub fn viewer_hide(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::ViewerHide))
}

#[tauri::command]
pub fn cancel_connect(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::CancelConnect))
}

#[tauri::command]
pub fn disconnect(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::Disconnect))
}

#[tauri::command]
pub fn consent_accept(app: AppHandle, remember: bool) -> CmdResult<()> {
    with_engine(&app, |handle| {
        handle.send(EngineCmd::ConsentAccept { remember })
    })
}

#[tauri::command]
pub fn consent_reject(app: AppHandle) -> CmdResult<()> {
    // ADR-006 B3: an explicit reject puts the controller in cooldown —
    // repeat prompts from it are auto-rejected for REJECT_COOLDOWN_MS.
    let declined = {
        let services = app.state::<AppServices>();
        let mut trust = services.trust.lock().expect("trust state");
        let controller = trust.prompt.as_ref().map(|(c, _, _)| c.clone());
        if let Some(controller) = controller.as_deref() {
            if let Some((_, _, rejected)) = trust.prompt.as_mut() {
                *rejected = true;
            }
            let now = crate::chat::now_ms();
            trust.block(controller, now + crate::chat::REJECT_COOLDOWN_MS);
        }
        trust.decision = None;
        let account = trust.prompt_account.take();
        (controller, account)
    };
    // ADR-006 amendment (2026-10-28): Decline is the explicit un-trust —
    // it also revokes any standing "Always allow" intent for this machine
    // (ADR-013 P2: the account intent keyed to the installation id too).
    let (controller, account) = declined;
    if let Some(controller) = controller {
        crate::chat::revoke_intent(&app, &controller);
    }
    if let Some(installation_id) = account {
        crate::chat::revoke_account_intent(&app, &installation_id);
    }
    with_engine(&app, |handle| handle.send(EngineCmd::ConsentReject))
}

#[tauri::command]
pub fn set_quality(app: AppHandle, args: SetQualityArgs) -> CmdResult<()> {
    let Some(preset) = preset_from_name(&args.preset) else {
        return Err(format!("unknown quality preset {:?}", args.preset));
    };
    with_engine(&app, |handle| handle.send(EngineCmd::SetQuality(preset)))
}

#[tauri::command]
pub fn select_monitor(app: AppHandle, args: SelectMonitorArgs) -> CmdResult<()> {
    with_engine(&app, |handle| {
        handle.send(EngineCmd::SelectMonitor {
            monitor_id: args.monitor_id,
        })
    })
}

#[tauri::command]
pub fn viewer_set_scale(app: AppHandle, scale: String) -> CmdResult<()> {
    let Some(mode) = scale_from_name(&scale) else {
        return Err(format!("unknown scale mode {scale:?}"));
    };
    with_engine(&app, |handle| handle.send(EngineCmd::ViewerScale(mode)))
}

#[tauri::command]
pub fn viewer_toggle_fullscreen(app: AppHandle) -> CmdResult<()> {
    with_engine(&app, |handle| handle.send(EngineCmd::ViewerFullscreen))
}

#[tauri::command]
pub fn list_monitors(app: AppHandle) -> CmdResult<serde_json::Value> {
    with_engine(&app, |handle| {
        let status = handle.status();
        Ok(serde_json::json!({
            "host": status.host_monitors,
            "peer": status.peer_monitors,
        }))
    })
}

// -- machine chat + pairing (ADR-005, RD-022/RD-023) -----------------------

#[derive(serde::Deserialize)]
pub struct ChatSendArgs {
    pub code: String,
    pub text: String,
    /// True when the message addresses the peer machine's assistant (the
    /// Conversation pane's "their assistant" toggle). Sets the wire's
    /// agent bit so the peer wakes its assistant as an instruction turn.
    /// The local assistant has its own path (`agent::tools`) and never
    /// calls this command.
    #[serde(default)]
    pub agent: bool,
}

/// Send one chat message to a machine: in-session over the direct `chat`
/// channel, otherwise sealed through the signaling inbox.
#[tauri::command]
pub fn chat_send(app: AppHandle, args: ChatSendArgs) -> CmdResult<()> {
    let code = args.code.trim().to_lowercase();
    let text = args.text.trim();
    if text.is_empty() {
        return Err("empty message".to_owned());
    }
    // Local perspective: the human typed it, addressed to the peer's
    // assistant ("to-agent" renders as "you → their assistant"). The
    // local assistant authoring a message records "agent" on its own path.
    let sender = if args.agent { "to-agent" } else { "user" };
    crate::chat::record_outgoing(&app, &code, sender, text);
    let (in_session, base_url, token, me) = {
        let services = app.state::<AppServices>();
        let store = services.store.lock().expect("store");
        let in_session = services
            .engine
            .lock()
            .expect("engine slot")
            .as_ref()
            .is_some_and(|handle| {
                let s = handle.status();
                s.controller_state == "Connected" && s.session_id.is_some()
                    || s.host_state == "Connected"
            });
        let settings = store.settings().clone();
        (
            in_session,
            settings.signaling_base_url,
            settings.device_token,
            settings.device_id,
        )
    };
    if in_session {
        return with_engine(&app, |handle| {
            handle
                .send(EngineCmd::ChatSend {
                    body: text.to_owned(),
                    agent: args.agent,
                })
                .map_err(|e| e.to_string())
        });
    }
    // ADR-013 P3: the inbox CAN carry an agent bit (sealed v2 payload,
    // `inbox_send_agent`) — slice 3 wires it for fleet_run's correlated
    // fan-out. The human offline "to-agent" verb stays refused: waking a
    // peer's assistant from a casual offline ask is not a behavior this
    // command should grow silently. Refuse rather than mislead.
    if args.agent {
        return Err(
            "their assistant only answers during a session — connect to that machine first"
                .to_owned(),
        );
    }
    crate::chat::inbox_send(&app, &base_url, &token, &me, &code, text)
}

/// Chat history with one machine.
#[tauri::command]
pub fn chat_history(app: AppHandle, code: String) -> CmdResult<Vec<crate::chat::ChatLine>> {
    Ok(crate::chat::history(&app, &code.trim().to_lowercase()))
}

/// Established pairings (trusted machines: silent reconnect + chat keys).
#[tauri::command]
pub fn pairings_list(app: AppHandle) -> CmdResult<Vec<PairingDto>> {
    Ok(crate::chat::pairings(&app)
        .into_iter()
        .map(PairingDto::from)
        .collect())
}

/// ADR-010 discovery list (pull): the decrypted circle directory. Rows
/// carry metadata only — device id, nickname, presence, is_self.
#[tauri::command]
pub fn directory_machines(app: AppHandle) -> CmdResult<Vec<crate::directory::DirectoryMachineDto>> {
    Ok(crate::directory::machines(&app))
}

/// Force a directory refresh (the poller also refreshes every 30 s).
#[tauri::command]
pub fn directory_refresh(app: AppHandle) -> CmdResult<()> {
    crate::directory::refresh(&app)
}

/// Redacted pairing row for the webview (ADR-006): the shared secret never
/// crosses the IPC boundary (invariant-6 discipline).
#[derive(Debug, Clone, serde::Serialize)]
pub struct PairingDto {
    pub code: String,
    pub created_ms: u64,
    pub pending_ack: bool,
    pub role: String,
    /// ADR-009: cached display name of the peer machine.
    pub name: Option<String>,
}

impl From<crate::chat::Pairing> for PairingDto {
    fn from(p: crate::chat::Pairing) -> Self {
        Self {
            code: p.code,
            created_ms: p.created_ms,
            pending_ack: p.pending_ack,
            role: p.role,
            name: p.name,
        }
    }
}

/// Revoke a pairing: future connects prompt for consent again.
#[tauri::command]
pub fn pairing_remove(app: AppHandle, code: String) -> CmdResult<()> {
    crate::chat::remove_pairing(&app, &code);
    Ok(())
}

/// ADR-009: rename a trusted-host row (the label is local-only).
#[tauri::command]
pub fn pairing_rename(app: AppHandle, code: String, name: String) -> CmdResult<()> {
    match crate::chat::sanitize_local_name(&name) {
        Some(name) => {
            crate::chat::set_pairing_name(&app, &code, &name);
            Ok(())
        }
        None => Err("Enter a name up to 64 characters (letters, numbers, spaces).".into()),
    }
}

// ---------------------------------------------------------------------------
// Automatic updates (ADR-008)
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn update_state(app: AppHandle) -> CmdResult<crate::updater::UpdateUiState> {
    Ok(app.state::<AppServices>().update.state())
}

/// Help → Check for updates: force a check now (the automatic-toggle off
/// only silences the scheduled checks, never an explicit one). No-op
/// while an update is already downloading/staged/installed — a re-check
/// must not clobber that.
#[tauri::command]
pub fn update_check(app: AppHandle) -> CmdResult<()> {
    let services = app.state::<AppServices>();
    services.update.force_check_now(&app);
    Ok(())
}

/// Download the offered installer and verify it (ADR-008: the user
/// pressed Update; installing stays a second, deliberate press).
#[tauri::command]
pub fn update_download(app: AppHandle) -> CmdResult<()> {
    crate::updater::start_download(app)
}

/// Run the verified installer: silent NSIS, app restarts via the
/// detached wrapper. Refuses during a live remote session.
#[tauri::command]
pub fn update_install(app: AppHandle) -> CmdResult<()> {
    crate::updater::install(app)
}

/// "Later": quiet for this version until the app restarts.
#[tauri::command]
pub fn update_dismiss(app: AppHandle) -> CmdResult<()> {
    app.state::<AppServices>().update.dismiss(&app);
    Ok(())
}

// ---------------------------------------------------------------------------
// Login autostart (ADR-006 always-ready)
// ---------------------------------------------------------------------------

fn set_launch_at_login(app: &AppHandle, enabled: bool) -> CmdResult<()> {
    // ADR-011: in admin mode (and while actually elevated) the logon
    // autostart is a HIGHEST scheduled task — the registry Run key the
    // plugin manages would start the app unelevated and trigger a UAC
    // prompt on every boot. Otherwise (admin off, or not elevated right
    // now — e.g. the UAC was declined) the plugin path applies and any
    // stale admin task is removed so the two never double-start.
    let admin = app
        .state::<AppServices>()
        .store
        .lock()
        .map(|s| s.settings().agent_admin)
        .unwrap_or(false);
    if enabled && admin && crate::elevate::is_elevated() {
        match std::env::current_exe() {
            Ok(exe) => {
                if !crate::elevate::ensure_admin_autostart(&exe) {
                    eprintln!("[autostart] elevated scheduled task failed; falling back");
                    return plugin_autostart(app, true);
                }
                let _ = plugin_autostart(app, false);
                return Ok(());
            }
            Err(err) => {
                eprintln!("[autostart] no current exe: {err}; falling back");
                return plugin_autostart(app, true);
            }
        }
    }
    let _ = crate::elevate::remove_admin_autostart();
    plugin_autostart(app, enabled)
}

/// The registry Run-key autostart the plugin owns (unelevated starts).
pub(crate) fn plugin_autostart(app: &AppHandle, enabled: bool) -> CmdResult<()> {
    use tauri_plugin_autostart::ManagerExt;
    let autolaunch = app.autolaunch();
    let result = if enabled {
        autolaunch.enable()
    } else {
        autolaunch.disable()
    };
    // The plugin can fail on exotic setups — surface it but never block
    // saving the rest of the settings.
    if let Err(err) = result {
        eprintln!(
            "[autostart] {} failed: {err}",
            if enabled { "enable" } else { "disable" }
        );
    }
    Ok(())
}

/// One-time first-run default: login autostart on once (always-ready —
/// family machines are reachable at login; reversible in Settings).
pub fn enable_autostart_default(app: &AppHandle) {
    let services = app.state::<AppServices>();
    let (already, applied) = {
        let store = services.store.lock().expect("store");
        (
            store.settings().launch_at_login,
            store.settings().autostart_default_applied,
        )
    };
    if already || applied {
        return;
    }
    let _ = set_launch_at_login(app, true);
    if let Ok(mut store) = services.store.lock() {
        let mut next = store.settings().clone();
        next.launch_at_login = true;
        next.autostart_default_applied = true;
        let _ = store.update_settings(next);
    }
}
