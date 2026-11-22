//! Humans-only E2E chat (ADR-013 D4/P3, slice 6): the app's half of the
//! pinned OnlyHumans protocol (v1.2.0). A dedicated background thread owns
//! a tokio runtime and ONE `onlyhumans_core::net` node at a time; joining a
//! word room (re)spawns the node for that word's effective GK, leaving tears
//! it down. The node speaks the room protocol over QUIC/TCP (noise) with
//! relay v2 + DCUtR, and registers/dials through the tracker hub mounted at
//! `/api/hub/*` (pin deviation #6 — see `onlyhumans_core::hub`).
//!
//! Humans only, never agents (D4): this is a separate USER surface. No agent
//! tool reads or posts into rooms — the agent tool layer is untouched (slice
//! 7 enforces the wall structurally). The room word is admission material:
//! it lives in Rust state + the settings store ONLY, never in an IPC result
//! or event payload (the ipc_surface walk's credential discipline).
//!
//! Background-service shape follows the mcp.rs precedent (named thread + a
//! dedicated tokio runtime) and the swarm.rs state discipline (a mirrored
//! DTO pushed on `human-chat://state`, pull via `rooms_state`). The node's
//! own `NodeEvent` stream is translated into three Tauri events the UI
//! subscribes to: state, message, log.

use std::sync::Mutex;

use onlyhumans_core::net::{self, Command, NodeConfig, NodeEvent, NodeHandle};
use onlyhumans_core::rooms::{MemberInfo, normalize_passcode};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::commands::{AppServices, events};

// ---------------------------------------------------------------------------
// IPC DTOs (metadata only — walked by the ipc_surface test)
// ---------------------------------------------------------------------------

/// One room member as the node reports it (peer id + shared display name).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HumanMember {
    pub peer: String,
    pub name: String,
}

impl From<MemberInfo> for HumanMember {
    fn from(m: MemberInfo) -> Self {
        Self {
            peer: m.peer,
            name: m.name,
        }
    }
}

/// The human-chat room state for the webview, emitted on
/// `human-chat://state` and returned by `rooms_state`. The room WORD is
/// structurally absent (Rust state + settings only); `room` is the derived
/// room id hex, `epoch` the current key epoch.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HumanRoomState {
    /// A node is running for a joined word (false before join / after leave).
    pub joined: bool,
    /// The derived room id hex (None until the node reports RoomReady).
    pub room: Option<String>,
    /// Current key epoch (0 until ready; bumps on Rotated).
    pub epoch: u64,
    /// Whether this machine hosts the room (the only role that can rotate).
    pub we_are_host: bool,
    /// Join-flow status line: idle | connecting | searching | joining |
    /// founding | hosting | connected | sealed | failed.
    pub status: String,
    /// Room members (peer id + display name).
    pub peers: Vec<HumanMember>,
    /// This machine's peer id in the room (None until the node spawns).
    pub my_peer: Option<String>,
    /// Hub presence link + the site's live online count (advisory).
    pub presence_linked: bool,
    pub online: u64,
    /// Last fatal error (spawn failure), cleared on the next join.
    pub error: Option<String>,
}

impl Default for HumanRoomState {
    fn default() -> Self {
        Self {
            joined: false,
            room: None,
            epoch: 0,
            we_are_host: false,
            status: "idle".to_owned(),
            peers: Vec::new(),
            my_peer: None,
            presence_linked: false,
            online: 0,
            error: None,
        }
    }
}

/// One decrypted room message (the `human-chat://message` payload). `mine`
/// marks this machine's own lines so the UI can right-align them.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HumanRoomMessage {
    pub room: String,
    pub sender: String,
    pub body: String,
    pub epoch: u64,
    pub mine: bool,
    /// Delivered through the site mailbox rather than a direct connection.
    pub via_site: bool,
}

/// A non-fatal node log line (the `human-chat://log` payload): join
/// progress, hub/mailbox notes, protocol errors.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HumanRoomLog {
    pub message: String,
}

// ---------------------------------------------------------------------------
// Managed service + control channel
// ---------------------------------------------------------------------------

/// Control requests from the (sync) Tauri commands to the node thread. An
/// unbounded tokio channel: `send` is a sync method (no async context needed
/// on the command side), and the volume is user-driven (a few presses), so
/// it cannot grow without bound in practice.
enum Ctrl {
    Join { word: String },
    Send { text: String },
    Rotate,
    Leave,
}

/// Managed state: the control channel to the node thread (None until
/// [`spawn`] runs) plus the mirrored room state the commands read.
pub struct HumanChatService {
    ctrl: Mutex<Option<mpsc::UnboundedSender<Ctrl>>>,
    state: Mutex<HumanRoomState>,
}

impl Default for HumanChatService {
    fn default() -> Self {
        Self {
            ctrl: Mutex::new(None),
            state: Mutex::new(HumanRoomState::default()),
        }
    }
}

impl HumanChatService {
    /// Send a control request to the node thread. Errors when the runtime
    /// is absent (before [`spawn`]) or the thread has exited.
    fn send(&self, ctrl: Ctrl) -> Result<(), String> {
        let guard = self.ctrl.lock().expect("human-chat ctrl");
        let tx = guard
            .as_ref()
            .ok_or_else(|| "human chat is not running yet".to_owned())?;
        tx.send(ctrl).map_err(|_| "human chat stopped".to_owned())
    }

    /// The current mirrored state (pull; the `human-chat://state` push
    /// mirrors it).
    pub fn current(&self) -> HumanRoomState {
        self.state.lock().expect("human-chat state").clone()
    }

    /// Replace the mirror (node thread only).
    fn set_state(&self, next: HumanRoomState) {
        *self.state.lock().expect("human-chat state") = next;
    }
}

/// Apply + emit a state snapshot: the mirror is updated under its lock, the
/// emit happens outside it (the swarm.rs `apply_state` discipline).
fn push_state(app: &AppHandle, next: HumanRoomState) {
    app.state::<AppServices>()
        .human_chat
        .set_state(next.clone());
    let _ = app.emit(events::HUMAN_ROOM_STATE, next);
}

// ---------------------------------------------------------------------------
// Commands (sync; no network I/O on the WebView dispatch thread)
// ---------------------------------------------------------------------------

type CmdResult<T> = Result<T, String>;

/// Current human-chat room state (pull; the `human-chat://state` push
/// mirrors it).
#[tauri::command]
pub fn rooms_state(app: AppHandle) -> CmdResult<HumanRoomState> {
    Ok(app.state::<AppServices>().human_chat.current())
}

/// Join (or re-join) a word room: persists the word, then hands the join to
/// the node thread, which (re)spawns the node for that word's effective GK.
/// Returns immediately — progress arrives as `human-chat://state` events.
#[tauri::command]
pub fn rooms_join(app: AppHandle, word: String) -> CmdResult<()> {
    let word = normalize_passcode(&word);
    if word.is_empty() {
        return Err("enter a room word to join".to_owned());
    }
    // Persist the joined word (settings store pattern; never IPC).
    {
        let services = app.state::<AppServices>();
        let mut store = services.store.lock().expect("store");
        let next = crate::store::AppSettings {
            human_room_word: word.clone(),
            ..store.settings().clone()
        };
        store.update_settings(next).map_err(|e| e.to_string())?;
    }
    app.state::<AppServices>()
        .human_chat
        .send(Ctrl::Join { word })
}

/// Send a text message to the joined room. Errors before join.
#[tauri::command]
pub fn rooms_send(app: AppHandle, text: String) -> CmdResult<()> {
    let text = text.trim().to_owned();
    if text.is_empty() {
        return Err("nothing to send".to_owned());
    }
    let services = app.state::<AppServices>();
    if !services.human_chat.current().joined {
        return Err("join a room first".to_owned());
    }
    services.human_chat.send(Ctrl::Send { text })
}

/// Rotate the room key (host only — the node refuses for guests and logs
/// why). Errors before join.
#[tauri::command]
pub fn rooms_rotate(app: AppHandle) -> CmdResult<()> {
    let services = app.state::<AppServices>();
    if !services.human_chat.current().joined {
        return Err("join a room first".to_owned());
    }
    services.human_chat.send(Ctrl::Rotate)
}

/// Leave the room: tears the node down and clears the persisted word.
#[tauri::command]
pub fn rooms_leave(app: AppHandle) -> CmdResult<()> {
    {
        let services = app.state::<AppServices>();
        let mut store = services.store.lock().expect("store");
        let next = crate::store::AppSettings {
            human_room_word: String::new(),
            ..store.settings().clone()
        };
        store.update_settings(next).map_err(|e| e.to_string())?;
    }
    app.state::<AppServices>().human_chat.send(Ctrl::Leave)
}

// ---------------------------------------------------------------------------
// Background thread (mcp.rs precedent: named thread + dedicated runtime)
// ---------------------------------------------------------------------------

/// Spawn the human-chat node thread and restore a persisted room word (if
/// any). Idempotent-ish: called once from setup; a second call would replace
/// the control channel (the old thread exits when its receiver drops).
pub fn spawn(app: AppHandle) {
    let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<Ctrl>();
    *app.state::<AppServices>()
        .human_chat
        .ctrl
        .lock()
        .expect("human-chat ctrl") = Some(ctrl_tx);

    let handle = app.clone();
    std::thread::Builder::new()
        .name("human-chat".into())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("human-chat tokio runtime");
            rt.block_on(run_loop(handle, ctrl_rx));
        })
        .expect("spawn human-chat thread");

    // Restore a surviving room word (the swarm spawn_startup precedent): a
    // machine that joined a room rejoins it on launch. The word never left
    // Rust state + settings.
    let saved = app
        .state::<AppServices>()
        .store
        .lock()
        .expect("store")
        .settings()
        .human_room_word
        .clone();
    if !saved.trim().is_empty() {
        let _ = app.state::<AppServices>().human_chat.send(Ctrl::Join {
            word: normalize_passcode(&saved),
        });
    }
}

/// The node thread's run loop: owns the current node + its event forwarder,
/// pumps control requests out and translated node events in. A generation
/// counter tags every forwarded event so a torn-down node's late events can
/// never clobber a newer room's state (the swarm cycle discipline).
async fn run_loop(app: AppHandle, mut ctrl_rx: mpsc::UnboundedReceiver<Ctrl>) {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<(u64, NodeEvent)>();
    let mut node: Option<NodeHandle> = None;
    let mut forward: Option<JoinHandle<()>> = None;
    let mut generation: u64 = 0;
    let mut snap = HumanRoomState::default();

    loop {
        tokio::select! {
            ctrl = ctrl_rx.recv() => {
                let Some(ctrl) = ctrl else { break };
                match ctrl {
                    Ctrl::Join { word } => {
                        teardown(&mut node, &mut forward).await;
                        generation += 1;
                        snap = HumanRoomState {
                            joined: true,
                            status: "connecting".to_owned(),
                            ..HumanRoomState::default()
                        };
                        match spawn_node(&app, &word, generation, &event_tx).await {
                            Ok((handle, fwd)) => {
                                snap.my_peer = Some(handle.peer_id.to_string());
                                node = Some(handle);
                                forward = Some(fwd);
                                push_state(&app, snap.clone());
                            }
                            Err(reason) => {
                                snap.joined = false;
                                snap.status = "failed".to_owned();
                                snap.error = Some(reason);
                                push_state(&app, snap.clone());
                            }
                        }
                    }
                    Ctrl::Send { text } => {
                        if let Some(handle) = &node {
                            let room = snap.room.clone().unwrap_or_default();
                            let _ = handle
                                .cmd_tx
                                .send(Command::SendMessage { room, text })
                                .await;
                        }
                    }
                    Ctrl::Rotate => {
                        if let Some(handle) = &node {
                            let _ = handle.cmd_tx.send(Command::Rotate).await;
                        }
                    }
                    Ctrl::Leave => {
                        teardown(&mut node, &mut forward).await;
                        snap = HumanRoomState::default();
                        push_state(&app, snap.clone());
                    }
                }
            }
            ev = event_rx.recv() => {
                let Some((g, ev)) = ev else { continue };
                if g != generation {
                    continue; // a torn-down node's late event — drop it
                }
                translate(&app, &mut snap, ev);
            }
        }
    }
}

/// Stop the current node (best-effort graceful Shutdown so it drops its
/// presence token) and abort its event forwarder.
async fn teardown(node: &mut Option<NodeHandle>, forward: &mut Option<JoinHandle<()>>) {
    if let Some(handle) = node.take() {
        let _ = handle.cmd_tx.send(Command::Shutdown).await;
    }
    if let Some(fwd) = forward.take() {
        fwd.abort();
    }
}

/// Spawn a node for `word` and a forwarder that tags its events with
/// `generation`. The hub base is the app's tracker URL (the same
/// `DEEPFLUX_TRACKER_URL` mechanism swarm enrollment uses); the data dir is
/// `<app-data>/human-chat` so the identity + room store survive restarts.
async fn spawn_node(
    app: &AppHandle,
    word: &str,
    generation: u64,
    event_tx: &mpsc::UnboundedSender<(u64, NodeEvent)>,
) -> Result<(NodeHandle, JoinHandle<()>), String> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("human-chat");
    let username = {
        let services = app.state::<AppServices>();
        let store = services.store.lock().expect("store");
        crate::commands::display_name(store.settings())
    };
    let cfg = NodeConfig {
        data_dir,
        hub_base: Some(crate::swarm::tracker_url()),
        username: Some(username),
        passcode: Some(word.to_owned()),
        ..NodeConfig::default()
    };
    let (node_tx, mut node_rx) = mpsc::unbounded_channel::<NodeEvent>();
    let handle = net::spawn(cfg, node_tx).await.map_err(|e| e.to_string())?;
    let fwd_tx = event_tx.clone();
    let fwd = tokio::spawn(async move {
        while let Some(ev) = node_rx.recv().await {
            if fwd_tx.send((generation, ev)).is_err() {
                break;
            }
        }
    });
    Ok((handle, fwd))
}

/// Translate one node event into the mirrored state + the Tauri events the
/// UI subscribes to. State-shaped events update the snapshot and push it;
/// messages and logs ride their own channels.
fn translate(app: &AppHandle, snap: &mut HumanRoomState, ev: NodeEvent) {
    match ev {
        NodeEvent::RoomReady {
            room,
            we_are_host,
            epoch,
            ..
        } => {
            snap.room = Some(room);
            snap.we_are_host = we_are_host;
            snap.epoch = epoch;
            snap.status = if we_are_host { "hosting" } else { "connected" }.to_owned();
            push_state(app, snap.clone());
        }
        NodeEvent::JoinStatus { status } => {
            snap.status = status;
            push_state(app, snap.clone());
        }
        NodeEvent::MembersChanged { members, .. } => {
            snap.peers = members.into_iter().map(HumanMember::from).collect();
            push_state(app, snap.clone());
        }
        NodeEvent::Rotated { new_epoch, .. } => {
            snap.epoch = new_epoch;
            push_state(app, snap.clone());
        }
        NodeEvent::Presence { linked, online } => {
            snap.presence_linked = linked;
            snap.online = online;
            push_state(app, snap.clone());
        }
        NodeEvent::Message {
            room,
            sender,
            body,
            epoch,
            via_site,
        } => {
            let mine = snap.my_peer.as_deref() == Some(sender.as_str());
            let _ = app.emit(
                events::HUMAN_ROOM_MESSAGE,
                HumanRoomMessage {
                    room,
                    sender,
                    body,
                    epoch,
                    mine,
                    via_site,
                },
            );
        }
        NodeEvent::MessagesCleared { .. } => {
            // The node wiped history; tell the UI to drop its log.
            let _ = app.emit(
                events::HUMAN_ROOM_LOG,
                HumanRoomLog {
                    message: "history cleared".to_owned(),
                },
            );
        }
        NodeEvent::Log { message } => {
            let _ = app.emit(events::HUMAN_ROOM_LOG, HumanRoomLog { message });
        }
        // Listening / ConnectionStateChanged are transport detail the room
        // UI does not surface (presence rides the MembersChanged list).
        NodeEvent::Listening { .. } | NodeEvent::ConnectionStateChanged { .. } => {}
    }
}
