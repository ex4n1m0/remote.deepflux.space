//! The network node: a libp2p swarm speaking the room protocol over
//! request-response, plus address-hub registration and dialing.
//!
//! M1 scope: direct connections (QUIC + TCP, noise-encrypted). Circuit
//! relay v2 + DCUtR hole-punching are staged for the connectivity pass
//! (see README) — the swarm composition keeps a slot for them.

use crate::hub::HubClient;
use crate::identity::Identity;
use crate::rooms::{Envelope, RoomEvent, Rooms};
use crate::store::Store;
use futures::prelude::*;
use libp2p::request_response::{self, Codec as _, ProtocolSupport};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{dcutr, identify, multiaddr::Protocol, ping, relay, Multiaddr, PeerId, Swarm};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;

pub const ROOM_PROTOCOL: &str = "/onlyhumans/room/1";

// ---------------------------------------------------------------------------
// Wire codec: 4-byte big-endian length + JSON
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
pub struct EnvelopeCodec;

impl request_response::Codec for EnvelopeCodec {
    type Protocol = String;
    type Request = Envelope;
    type Response = Envelope;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_json(io).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        read_json(io).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_json(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        write_json(io, &res).await
    }
}

async fn read_json<T: futures::AsyncRead + Unpin + Send>(io: &mut T) -> std::io::Result<Envelope> {
    let mut len = [0u8; 4];
    io.read_exact(&mut len).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > 4 * 1024 * 1024 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; n];
    io.read_exact(&mut buf).await?;
    let env: Envelope = serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    tracing::info!("codec read ok: {} bytes: {}", buf.len(), String::from_utf8_lossy(&buf[..buf.len().min(90)]));
    Ok(env)
}

async fn write_json<T: futures::AsyncWrite + Unpin + Send>(
    io: &mut T,
    env: &Envelope,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(env)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    tracing::info!("codec write: {} bytes: {}", bytes.len(), String::from_utf8_lossy(&bytes[..bytes.len().min(90)]));
    io.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    io.write_all(&bytes).await?;
    io.close().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Behaviour
// ---------------------------------------------------------------------------

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    relay_client: relay::client::Behaviour,
    /// Relay service for other peers (any reachable node offers it).
    relay: relay::Behaviour,
    /// Hole-punching: upgrades relayed connections to direct when possible.
    dcutr: dcutr::Behaviour,
    rooms: request_response::Behaviour<EnvelopeCodec>,
}

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum Command {
    /// Direct dial by multiaddr (tests).
    Dial { addr: Multiaddr },
    /// Send a chat message to a room (main room hex or a DM hex).
    SendMessage { room: String, text: String },
    /// Open (or re-open) a private two-person room with `peer`.
    OpenDm { peer: String },
    /// Host-side key rotation.
    Rotate,
    /// Wipe the room's message history on every participant.
    ClearHistory,
    /// Forget this window's room state (key, epoch, host row) and
    /// rediscover the room from the hub — manual recovery for a
    /// split-brained or stuck room.
    ResetRoom,
    /// Explicitly reserve a relay circuit; `addr` is the relay's full
    /// address ending in /p2p/<relay_id> (tests, port-forwarded hosts).
    ReserveWith { addr: Multiaddr },
    /// Ask the node to re-emit a state snapshot (UI startup).
    RequestState,
    /// Stop the node task (releases ports + DB so a restart can rebind).
    Shutdown,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum NodeEvent {
    Listening { addr: String },
    /// Progress of the automatic join flow, for the UI status line.
    JoinStatus { status: String },
    RoomReady { room: String, peer: String, we_are_host: bool, epoch: u64 },
    Message { room: String, sender: String, body: String, epoch: u64, via_site: bool },
    MembersChanged { room: String, members: Vec<crate::rooms::MemberInfo> },
    MessagesCleared { room: String },
    Rotated { room: String, new_epoch: u64 },
    ConnectionStateChanged { peer: String, connected: bool },
    /// Site link: our anonymous presence beacon landed (the site's public
    /// counter now includes us) or failed. `online` is the count the hub
    /// reported (0 when unknown/rate-limited — still linked).
    Presence { linked: bool, online: u64 },
    Log { message: String },
}

#[derive(Clone)]
pub struct NodeHandle {
    pub cmd_tx: mpsc::Sender<Command>,
    pub peer_id: PeerId,
}

pub struct NodeConfig {
    pub data_dir: std::path::PathBuf,
    pub hub_base: Option<String>,
    pub listen_quic: Option<u16>,
    pub listen_tcp: Option<u16>,
    /// Offline mode: skip all hub traffic (tests).
    pub offline: bool,
    /// Offer relay service and reserve with reachable peers (default true).
    pub relay_enabled: bool,
    /// Force this node to accept relay reservations even without detected
    /// external addresses (port-forwarded hosts, tests).
    pub force_relay_hop: bool,
    /// Tests/offline: host the room immediately instead of consulting the
    /// hub (the founding member's shortcut).
    pub assume_host: bool,
    /// Tests/offline: this peer is known to host the room; join it once
    /// connected (skips hub room-record discovery).
    pub room_host: Option<String>,
    /// Display name shared with the room on join.
    pub username: Option<String>,
    /// Optional room passcode: when set (non-blank), the node derives a
    /// parallel room universe from (GK, word) instead of joining the
    /// main room. Same word + same binary -> same room.
    pub passcode: Option<String>,
    /// Mailbox-only member (what the web portal is): register with NO
    /// direct addresses and deliver exclusively through the site
    /// mailbox. Hosts still hold the room record; joiners reach them by
    /// mailing the Join. Also lets the live interop test stand in for a
    /// browser tab.
    pub mailbox_only: bool,
    /// Public address (IP or DNS name) to publish FIRST for port-forwarded
    /// hosts — the one address peers behind other NATs can dial.
    pub public_addr: Option<String>,
    /// Anonymous site-presence token (random per process start). Owned by
    /// the SHELL so it can drop the token on exit even if this task is
    /// busy mid-dial; the shell also passes it here for the heartbeats.
    pub presence_token: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: std::env::temp_dir().join("onlyhumans"),
            hub_base: None,
            listen_quic: Some(0),
            listen_tcp: Some(0),
            offline: false,
            relay_enabled: true,
            force_relay_hop: false,
            assume_host: false,
            room_host: None,
            username: None,
            passcode: None,
            mailbox_only: false,
            public_addr: None,
            presence_token: {
                use rand::RngCore;
                let mut b = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut b);
                hex::encode(b)
            },
        }
    }
}

pub async fn spawn(
    cfg: NodeConfig,
    mut event_tx: mpsc::UnboundedSender<NodeEvent>,
) -> anyhow::Result<NodeHandle> {
    let identity = Identity::load_or_create(&cfg.data_dir)?;
    let store = Store::open(&cfg.data_dir)?;
    let peer_id = identity.peer_id();
    let hub = HubClient::new(cfg.hub_base.as_deref().unwrap_or(crate::hub::DEFAULT_HUB));

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(identity.keypair().clone())
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default().nodelay(true),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_quic()
        .with_relay_client(
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key, relay_client| {
            let identify = identify::Behaviour::new(identify::Config::new(
                "onlyhumans/1".to_string(),
                key.public(),
            ));
            let ping = ping::Behaviour::new(ping::Config::new());
            let relay = relay::Behaviour::new(
                key.public().to_peer_id(),
                relay::Config::default(),
            );
            let dcutr = dcutr::Behaviour::new(key.public().to_peer_id());
            let rooms = request_response::Behaviour::with_codec(
                EnvelopeCodec,
                [(ROOM_PROTOCOL.to_string(), ProtocolSupport::Full)],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(30))
                    .with_max_concurrent_streams(64),
            );
            Behaviour {
                identify,
                ping,
                relay_client,
                relay,
                dcutr,
                rooms,
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(600)))
        .build();

    if let Some(port) = cfg.listen_quic {
        swarm.listen_on(
            Multiaddr::empty()
                .with(Protocol::from("0.0.0.0".parse::<std::net::Ipv4Addr>().unwrap()))
                .with(Protocol::Udp(port))
                .with(Protocol::QuicV1),
        )?;
    }
    if cfg.force_relay_hop {
        swarm
            .behaviour_mut()
            .relay
            .set_status(Some(relay::Status::Enable));
    }
    if let Some(port) = cfg.listen_tcp {
        swarm.listen_on(
            Multiaddr::empty()
                .with(Protocol::from("0.0.0.0".parse::<std::net::Ipv4Addr>().unwrap()))
                .with(Protocol::Tcp(port)),
        )?;
    }

    let (cmd_tx, mut cmd_rx) = mpsc::channel::<Command>(64);

    // 1.1.0: every room is a word room. A blank word means Earth — the
    // public room the site names — so there is no GK-only room anymore
    // and a leaked/extracted GK alone never admits anyone to anything.
    let room_word = cfg
        .passcode
        .as_deref()
        .map(crate::rooms::normalize_passcode)
        .filter(|w| !w.is_empty())
        .unwrap_or_else(|| "earth".to_string());

    let mut rooms = Rooms::new(
        crate::rooms::effective_gk(&crate::global_key(), Some(room_word.as_str())),
        identity.id_string(),
        cfg.username.clone().unwrap_or_default(),
    );
    let room_hex = rooms.room_hex().to_string();

    // Restore the room so chats and the key survive restarts.
    if let Ok(convs) = store.conversations() {
        if let Some(c) = convs.iter().find(|c| c.room_id_hex == room_hex) {
            if let Ok(host) = libp2p::PeerId::from_str(&c.peer_id) {
                let role = if c.is_host {
                    crate::rooms::Role::Host
                } else {
                    crate::rooms::Role::Guest
                };
                if let Ok(Some((key, epoch))) = store.room_state(&c.room_id_hex) {
                    rooms.restore(host, role, key, epoch);
                    // Rehydrate the member mesh from contacts so fan-out
                    // works immediately; the host's list re-converges as
                    // members re-join.
                    if let Ok(cs) = store.contacts() {
                        rooms.restore_members(cs.into_iter().map(|c| (c.peer_id, c.name)).collect());
                    }
                }
            }
        }
    }

    /// Direct addresses of peers we can potentially reserve with.
    let mut relay_candidates: HashMap<PeerId, Multiaddr> = HashMap::new();
    /// Full circuit addresses from accepted reservations.
    let mut circuit_addrs: Vec<Multiaddr> = Vec::new();
    let mut outbox: HashMap<PeerId, VecDeque<Envelope>> = HashMap::new();
    let mut connected: HashMap<PeerId, bool> = HashMap::new();
    /// Consecutive ticks a peer's outbox went undelivered while offline;
    /// after two, the queue moves to the site mailbox.
    let mut mail_wait: HashMap<PeerId, u32> = HashMap::new();
    /// Shadow of envelopes handed to send_request (see track_inflight).
    let mut inflight: HashMap<PeerId, VecDeque<Envelope>> = HashMap::new();

    // Automatic join orchestration.
    let mut join_target: Option<PeerId> = None;
    // Host we last queued a Join envelope for, and when. The fresh-guest
    // path must also MAIL Joins (a mailbox-only host such as the web
    // portal publishes no addresses and can never be dialed) — the latch
    // keeps the 5 s tick from queueing one on every pass.
    let mut join_mail: Option<(PeerId, std::time::Instant)> = None;
    // When the room-sealed latch flipped (re-arms discovery after 5 min:
    // sealed rooms die with their hosts and get re-founded).
    let mut sealed_since: Option<std::time::Instant> = None;
    // Ready-guest record check: (last check, consecutive empty lookups).
    let mut guest_check: Option<(std::time::Instant, u32)> = None;
    let mut host_record_ok = false;
    let mut grace_left: Option<u32> = if cfg.assume_host { Some(0) } else { Some(12) };
    let mut announced = false;
    // Public IP the hub observed for us (mini-STUN); captured on one
    // registration cycle, published as a same-port guess on the next.
    let mut observed_ip: Option<std::net::Ipv4Addr> = None;

    // The interval's first tick races listener binding, so retry fast until
    // the first successful registration, then refresh on the slow cadence.
    let mut hub_fast = tokio::time::interval(Duration::from_secs(2));
    hub_fast.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut hub_interval = tokio::time::interval(Duration::from_secs(120));
    hub_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut hub_registered = false;
    // Mailbox drain rides its own, faster cadence: a mailbox-only peer
    // (the web portal) can only answer through the site, so app↔web
    // visibility is bounded by how often we drain — 30 s, independent of
    // the 120 s registration cycle. Drains are signed GETs of an usually
    // empty inbox; the hub rate-limits pushes, not drains.
    let mut mail_interval = tokio::time::interval(Duration::from_secs(30));
    mail_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut room_tick = tokio::time::interval(Duration::from_secs(5));
    // Presence beacon token from the config (shell-owned so exit cleanup
    // can't race this task): random per app start, never derived from the
    // identity — the site's counter learns "an app", nothing more.
    let presence_token = cfg.presence_token.clone();

    // rusqlite's Connection is !Sync; a std Mutex makes the task Send.
    let store = std::sync::Mutex::new(store);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(cmd) = cmd_rx.recv() => {
                    if matches!(cmd, Command::Shutdown) {
                        // Drop our presence token so the site's counter
                        // forgets us immediately instead of at TTL expiry.
                        if !cfg.offline {
                            let _ = hub.presence_leave(&presence_token).await;
                        }
                        break;
                    }
                    if matches!(cmd, Command::ResetRoom) {
                        // Needs the run-loop latches, so it lives here
                        // instead of handle_command: drop the room and
                        // every discovery latch so the next tick starts
                        // the join/found flow over from scratch.
                        rooms.reset();
                        rooms.sealed = false;
                        let _ = store.lock().unwrap().clear_conversation(&room_hex);
                        announced = false;
                        host_record_ok = false;
                        grace_left = None;
                        join_target = None;
                        join_mail = None;
                        sealed_since = None;
                        guest_check = None;
                        let _ = event_tx.send(NodeEvent::JoinStatus { status: "connecting".into() });
                        let _ = event_tx.send(NodeEvent::Log {
                            message: "room state reset — rediscovering the room".into(),
                        });
                        continue;
                    }
                    handle_command(
                        &mut swarm,
                        &mut rooms,
                        &store,
                        &mut relay_candidates,
                        &mut circuit_addrs,
                        &cmd,
                        &identity,
                        &hub,
                        &mut outbox,
                        &mut inflight,
                        &cfg,
                        &mut event_tx,
                    ).await;
                }
                _ = hub_fast.tick(), if !cfg.offline && !hub_registered => {
                    match register_with_hub(&mut swarm, &identity, &hub, &circuit_addrs, cfg.public_addr.as_deref(), cfg.mailbox_only, &mut observed_ip).await {
                        Ok(()) => {
                            hub_registered = true;
                            // The slow interval's immediate first tick would
                            // re-register within the hub's 30s per-peer
                            // rate limit; reset pushes the next refresh a
                            // full period out. The mail interval resets
                            // alongside so its own immediate first tick
                            // doesn't fire a redundant drain.
                            hub_interval.reset();
                            mail_interval.reset();
                            beat_presence(&hub, &presence_token, &event_tx).await;
                            // Fresh start: pick up anything that queued
                            // for us while we were away.
                            drain_mailbox(&mut swarm, &mut rooms, &store, &mut outbox, &mut inflight, &identity, &hub, &event_tx).await;
                        }
                        Err(e) => {
                            let _ = event_tx.send(NodeEvent::Log { message: format!("hub register: {e}") });
                        }
                    }
                }
                _ = hub_interval.tick(), if !cfg.offline && hub_registered => {
                    tracing::debug!("tick: hub interval (register + presence + record refresh)");
                    if let Err(e) = register_with_hub(&mut swarm, &identity, &hub, &circuit_addrs, cfg.public_addr.as_deref(), cfg.mailbox_only, &mut observed_ip).await {
                        let _ = event_tx.send(NodeEvent::Log { message: format!("hub register: {e}") });
                    }
                    beat_presence(&hub, &presence_token, &event_tx).await;
                    // Hosts refresh their room record alongside addresses
                    // so the election pointer never silently expires while
                    // they are alive.
                    if rooms.is_host() {
                        // The record is NX-owned: a restored host cannot
                        // steal a LIVE record from its current holder. If
                        // one is held by someone else, yield our (stale)
                        // room state and rejoin through normal discovery —
                        // otherwise two computers each host their own copy
                        // of the room forever.
                        let foreign_live = match hub.lookup_room(&room_hex).await {
                            Ok(Some(rec)) => rec.host_peer_id != identity.peer_id().to_string(),
                            _ => false,
                        };
                        if foreign_live {
                            rooms.reset();
                            let _ = store.lock().unwrap().clear_conversation(&room_hex);
                            announced = false;
                            host_record_ok = false;
                            grace_left = None;
                            join_target = None;
                            join_mail = None;
                            let _ = event_tx.send(NodeEvent::Log {
                                message: "another live host holds the room record — yielding, rejoining".into(),
                            });
                        } else if let Err(e) = hub.register_room(&identity, &room_hex).await {
                            let _ = event_tx.send(NodeEvent::Log { message: format!("room record: {e}") });
                        }
                    }
                }
                _ = mail_interval.tick(), if !cfg.offline && hub_registered => {
                    // The dedicated drain cadence (see mail_interval above):
                    // mailbox-only peers answer only through the site.
                    drain_mailbox(&mut swarm, &mut rooms, &store, &mut outbox, &mut inflight, &identity, &hub, &event_tx).await;
                }
                _ = room_tick.tick() => {
                    tracing::debug!("tick: room orchestration");
                    room_orchestration(
                        &mut swarm,
                        &mut rooms,
                        &hub,
                        &identity,
                        &cfg,
                        &room_hex,
                        &mut join_target,
                        &mut join_mail,
                        &mut sealed_since,
                        &mut guest_check,
                        &mut host_record_ok,
                        &mut grace_left,
                        &mut announced,
                        &mut outbox,
                        &mut inflight,
                        &store,
                        &mut event_tx,
                    ).await;
                    // Retry hub-based dials for peers with undelivered
                    // envelopes (messages queue up while a member is
                    // offline). A peer still unreachable after a couple
                    // of ticks gets its queue handed to the site mailbox
                    // instead — sealed envelopes wait there until its
                    // next drain, so delivery no longer depends on both
                    // sides being simultaneously reachable.
                    //
                    // All due peers ship as ONE batched push per tick
                    // (mixed recipients, capped at the hub's 16-item
                    // limit): the hub throttles per SENDER to one push
                    // every 4 s, so per-peer requests would 429 each
                    // other, and a >16-item queue could never drain.
                    // Leftovers stay queued for the next tick.
                    if !cfg.offline {
                        let mut batch: Vec<(PeerId, Envelope)> = Vec::new();
                        for peer in outbox.keys().copied().collect::<Vec<_>>() {
                            if batch.len() >= 16 {
                                break;
                            }
                            if !swarm.is_connected(&peer) {
                                dial_peer(&mut swarm, &hub, &identity, peer, &cfg, &mut event_tx).await;
                                if !swarm.is_connected(&peer) {
                                    let waited = mail_wait.entry(peer).or_insert(0);
                                    *waited += 1;
                                    if *waited >= 2 {
                                        while batch.len() < 16 {
                                            match outbox.get_mut(&peer) {
                                                Some(q) => match q.pop_front() {
                                                    Some(env) => batch.push((peer, env)),
                                                    None => break,
                                                },
                                                None => break,
                                            }
                                        }
                                    }
                                } else {
                                    mail_wait.remove(&peer);
                                }
                            } else {
                                mail_wait.remove(&peer);
                            }
                        }
                        if !batch.is_empty() {
                            let n = batch.len();
                            let peers_n = batch
                                .iter()
                                .map(|(p, _)| *p)
                                .collect::<std::collections::HashSet<_>>()
                                .len();
                            let items: Vec<(String, Envelope)> =
                                batch.iter().map(|(p, e)| (p.to_string(), e.clone())).collect();
                            match hub.mail_push_many(&identity, &items).await {
                                Ok(()) => {
                                    let pushed: std::collections::HashSet<PeerId> =
                                        batch.iter().map(|(p, _)| *p).collect();
                                    for peer in pushed {
                                        let empty =
                                            outbox.get(&peer).map_or(true, |q| q.is_empty());
                                        if empty {
                                            mail_wait.remove(&peer);
                                        }
                                    }
                                    let _ = event_tx.send(NodeEvent::Log {
                                        message: format!(
                                            "mailbox: {n} sealed envelope(s) queued via site for {peers_n} peer(s)"
                                        ),
                                    });
                                }
                                Err(e) => {
                                    // Keep the envelopes queued; retry next tick.
                                    for (peer, env) in batch {
                                        enqueue(&mut outbox, peer, env);
                                    }
                                    let _ = event_tx.send(NodeEvent::Log {
                                        message: format!("mailbox push: {e}"),
                                    });
                                }
                            }
                        }
                    }
                }
                ev = swarm.select_next_some() => {
                    handle_swarm_event(
                        &mut swarm,
                        &mut rooms,
                        ev,
                        &store,
                        &mut outbox,
                        &mut inflight,
                        &mut connected,
                        &mut relay_candidates,
                        &mut circuit_addrs,
                        cfg.relay_enabled,
                        &mut event_tx,
                    );
                }
            }
        }
    });

    Ok(NodeHandle { cmd_tx, peer_id })
}

fn enqueue(outbox: &mut HashMap<PeerId, VecDeque<Envelope>>, peer: PeerId, env: Envelope) {
    let q = outbox.entry(peer).or_default();
    // Bound queues for peers that are gone: stale member entries would
    // otherwise accumulate undelivered frames forever.
    if q.len() > 64 {
        q.pop_front();
    }
    q.push_back(env);
}

/// Envelopes handed to send_request but not yet proven delivered. A
/// send_request onto a connection that dies mid-flight FAILS silently
/// after popping from the outbox — the shadow lets us put failed sends
/// back (recipients' replay guards make the resulting duplicates
/// harmless). Bounded like the outbox itself.
fn track_inflight(inflight: &mut HashMap<PeerId, VecDeque<Envelope>>, peer: PeerId, env: Envelope) {
    let q = inflight.entry(peer).or_default();
    if q.len() > 64 {
        q.pop_front();
    }
    q.push_back(env);
}

fn flush_outbox(
    swarm: &mut Swarm<Behaviour>,
    outbox: &mut HashMap<PeerId, VecDeque<Envelope>>,
    inflight: &mut HashMap<PeerId, VecDeque<Envelope>>,
    peer: PeerId,
) {
    if !swarm.is_connected(&peer) {
        return;
    }
    if let Some(q) = outbox.get_mut(&peer) {
        while let Some(env) = q.pop_front() {
            track_inflight(inflight, peer, env.clone());
            swarm
                .behaviour_mut()
                .rooms
                .send_request(&peer, env);
        }
    }
}

/// Flush pending envelopes to `peer` — or, when we are not connected,
/// start a hub-based redial immediately instead of letting them sit in
/// the outbox until the 90 s tick. Reconnection flushes via
/// ConnectionEstablished.
async fn flush_or_redial(
    swarm: &mut Swarm<Behaviour>,
    hub: &HubClient,
    identity: &Identity,
    cfg: &NodeConfig,
    event_tx: &mpsc::UnboundedSender<NodeEvent>,
    outbox: &mut HashMap<PeerId, VecDeque<Envelope>>,
    inflight: &mut HashMap<PeerId, VecDeque<Envelope>>,
    peer: PeerId,
) {
    if swarm.is_connected(&peer) {
        flush_outbox(swarm, outbox, inflight, peer);
    } else {
        dial_peer(swarm, hub, identity, peer, cfg, event_tx).await;
    }
}

/// One presence beat: tell the site "a running app exists" and surface the
/// result as a Presence event for the UI's site-link indicator. Rides the
/// registration cadence (the beacon is meaningless if we can't reach the
/// hub at all).
async fn beat_presence(
    hub: &HubClient,
    token: &str,
    event_tx: &mpsc::UnboundedSender<NodeEvent>,
) {
    match hub.presence(token).await {
        Ok(n) => {
            let _ = event_tx.send(NodeEvent::Presence { linked: true, online: n });
        }
        Err(e) => {
            let _ = event_tx.send(NodeEvent::Presence { linked: false, online: 0 });
            let _ = event_tx.send(NodeEvent::Log { message: format!("presence: {e}") });
        }
    }
}

/// Drain our site mailbox and process every verified item exactly like a
/// direct request. Outgoing replies land in the outbox; if the peer is
/// still unreachable the tick's mailbox handoff delivers them the same
/// way (join-over-mailbox completes end to end).
#[allow(clippy::too_many_arguments)]
async fn drain_mailbox(
    swarm: &mut Swarm<Behaviour>,
    rooms: &mut Rooms,
    store: &std::sync::Mutex<Store>,
    outbox: &mut HashMap<PeerId, VecDeque<Envelope>>,
    inflight: &mut HashMap<PeerId, VecDeque<Envelope>>,
    identity: &Identity,
    hub: &HubClient,
    event_tx: &mpsc::UnboundedSender<NodeEvent>,
) {
    let items = match hub.mail_drain(identity).await {
        Ok(items) => items,
        Err(e) => {
            let _ = event_tx.send(NodeEvent::Log { message: format!("mailbox drain: {e}") });
            return;
        }
    };
    if items.is_empty() {
        return;
    }
    let _ = event_tx.send(NodeEvent::Log {
        message: format!("mailbox: drained {} item(s) from the site", items.len()),
    });
    for item in items {
        let from = match crate::hub::verify_mail_item(&item) {
            Ok(p) => p,
            Err(e) => {
                let _ = event_tx.send(NodeEvent::Log { message: format!("mailbox item rejected: {e}") });
                continue;
            }
        };
        let env: Envelope = match serde_json::from_str(&item.env_json) {
            Ok(e) => e,
            Err(e) => {
                let _ = event_tx.send(NodeEvent::Log { message: format!("mailbox item unparsable: {e}") });
                continue;
            }
        };
        tracing::info!("mailbox item from {from}: {}", &item.env_json[..item.env_json.len().min(60)]);
        let events = rooms.handle(from, env);
        process_room_events(rooms, store, &from, &events, event_tx);
        for ev in events {
            dispatch_room_event(swarm, outbox, inflight, &from, ev, true, event_tx);
        }
    }
}

async fn register_with_hub(
    swarm: &mut Swarm<Behaviour>,
    identity: &Identity,
    hub: &HubClient,
    circuit_addrs: &[Multiaddr],
    public_addr: Option<&str>,
    mailbox_only: bool,
    observed_ip: &mut Option<std::net::Ipv4Addr>,
) -> anyhow::Result<()> {
    let my_ip = default_route_ip();
    let mut addrs: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    fn push(addrs: &mut Vec<String>, seen: &mut std::collections::HashSet<String>, ma: Multiaddr) {
        let s = ma.to_string();
        if seen.insert(s.clone()) {
            addrs.push(s);
        }
    }
    // Ports of our QUIC/TCP listeners, reused for the public guesses below.
    let mut quic_port: Option<u16> = None;
    let mut tcp_port: Option<u16> = None;
    let mut local: Vec<Multiaddr> = Vec::new();
    for l in swarm.listeners() {
        // Rewrite 0.0.0.0 placeholders to our best local address; skip
        // loopback entirely — a remote peer can never dial it.
        let components: Vec<libp2p::multiaddr::Protocol<'_>> = l.iter().collect();
        let mut ma = Multiaddr::empty();
        let mut skip = false;
        for c in components {
            match c {
                Protocol::Ip4(ip) if ip.is_unspecified() => {
                    ma.push(Protocol::from(my_ip));
                }
                Protocol::Ip4(ip) if ip.is_loopback() => skip = true,
                Protocol::Udp(p) => {
                    quic_port = Some(p);
                    ma.push(Protocol::Udp(p));
                }
                Protocol::Tcp(p) => {
                    tcp_port = Some(p);
                    ma.push(Protocol::Tcp(p));
                }
                other => ma.push(other),
            }
        }
        if !skip {
            local.push(ma);
        }
    }

    // Explicit public address (port-forwarded hosts) goes FIRST — it is
    // the one address a peer behind another NAT can actually dial.
    if let Some(pa) = public_addr.map(str::trim).filter(|s| !s.is_empty()) {
        let host = pa.trim_start_matches("//").split(':').next().unwrap_or("").to_string();
        if !host.is_empty() {
            let host_proto = host
                .parse::<std::net::Ipv4Addr>()
                .ok()
                .map(Protocol::from)
                .unwrap_or_else(|| Protocol::Dns4(host.clone().into()));
            if let Some(p) = quic_port {
                push(&mut addrs, &mut seen, Multiaddr::empty().with(host_proto.clone()).with(Protocol::Udp(p)).with(Protocol::QuicV1));
            }
            if let Some(p) = tcp_port {
                push(&mut addrs, &mut seen, Multiaddr::empty().with(host_proto).with(Protocol::Tcp(p)));
            }
        }
    }
    for ma in local {
        push(&mut addrs, &mut seen, ma);
    }
    for c in circuit_addrs {
        push(&mut addrs, &mut seen, c.clone());
    }
    // Mini-STUN: on a PREVIOUS registration the hub told us the public IP
    // our HTTPS socket came from. That socket is not our QUIC/TCP
    // listener, so the port mapping through the NAT is a GUESS (same
    // port) — full-cone NATs accept inbound on an existing mapping and
    // peers re-dial every few seconds, so it is worth publishing and
    // costs nothing when wrong. The reg endpoint rate-limits to one
    // write per 30s, so the guess rides the NEXT registration cycle
    // (120s) rather than an immediate second PUT.
    if let Some(ip) = *observed_ip {
        if let Some(p) = quic_port {
            push(&mut addrs, &mut seen, Multiaddr::empty().with(Protocol::from(ip)).with(Protocol::Udp(p)).with(Protocol::QuicV1));
        }
        if let Some(p) = tcp_port {
            push(&mut addrs, &mut seen, Multiaddr::empty().with(Protocol::from(ip)).with(Protocol::Tcp(p)));
        }
    }
    if addrs.is_empty() && !mailbox_only {
        anyhow::bail!("no listening addresses yet");
    }
    let observed = hub.register(identity, addrs).await?;
    if let Some(ip) = observed.as_deref().and_then(|s| s.trim().parse::<std::net::Ipv4Addr>().ok()) {
        let o = ip.octets();
        let link_local = o[0] == 169 && o[1] == 254; // 169.254.0.0/16
        if !ip.is_private() && !ip.is_loopback() && !link_local {
            *observed_ip = Some(ip);
        }
    }
    Ok(())
}

fn circuit_addrs_contain(list: &[Multiaddr], addr: &Multiaddr) -> bool {
    list.iter().any(|a| a == addr)
}

fn default_route_ip() -> std::net::Ipv4Addr {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => "127.0.0.1".parse().unwrap(),
        })
        .unwrap_or_else(|_| "127.0.0.1".parse().unwrap())
}

#[allow(clippy::too_many_arguments)]
async fn handle_command(
    swarm: &mut Swarm<Behaviour>,
    rooms: &mut Rooms,
    store: &std::sync::Mutex<Store>,
    relay_candidates: &mut HashMap<PeerId, Multiaddr>,
    circuit_addrs: &mut Vec<Multiaddr>,
    cmd: &Command,
    identity: &Identity,
    hub: &HubClient,
    outbox: &mut HashMap<PeerId, VecDeque<Envelope>>,
    inflight: &mut HashMap<PeerId, VecDeque<Envelope>>,
    cfg: &NodeConfig,
    event_tx: &mpsc::UnboundedSender<NodeEvent>,
) {
    match cmd {
        // Handled by the run loop (breaks the select); unreachable here.
        Command::Shutdown => {}
        // Intercepted in the run loop (needs the discovery latches).
        Command::ResetRoom => {}
        Command::Dial { addr } => {
            if let Err(e) = swarm.dial(addr.clone()) {
                let _ = event_tx.send(NodeEvent::Log { message: format!("dial failed: {e}") });
            }
        }
        Command::SendMessage { room, text } => {
            if let Some(frame) = rooms.seal_chat(&room, text.as_bytes()) {
                // The main room persists history; DMs are memory-only.
                if room == rooms.room_hex() {
                    let epoch = rooms.state().map(|st| st.crypto.epoch).unwrap_or(1);
                    let _ = store
                        .lock()
                        .unwrap()
                        .append_message(&room, &identity.id_string(), text.as_str(), epoch, true);
                }
                // DM frames go only to the peer; main room fans out.
                if let Some(dm) = rooms.dm(&room) {
                    let peer = dm.peer;
                    enqueue(outbox, peer, Envelope::Chat { frame });
                    flush_or_redial(swarm, hub, identity, cfg, event_tx, outbox, inflight, peer).await;
                    return;
                }
                for peer in rooms.member_peers() {
                    if peer == identity.peer_id() {
                        continue;
                    }
                    enqueue(outbox, peer, Envelope::Chat { frame: frame.clone() });
                    flush_or_redial(swarm, hub, identity, cfg, event_tx, outbox, inflight, peer).await;
                }
            } else {
                let _ = event_tx.send(NodeEvent::Log {
                    message: "cannot send: still joining the room".into(),
                });
            }
        }
        Command::Rotate => {
            if let Some(frame) = rooms.rotate() {
                persist_room(rooms, store);
                // The host is a participant too: apply its own rotation to
                // its UI (epoch display) like everyone else.
                if let Some(st) = rooms.state() {
                    let _ = event_tx.send(NodeEvent::Rotated {
                        room: rooms.room_hex().to_string(),
                        new_epoch: st.crypto.epoch,
                    });
                }
                for peer in rooms.member_peers() {
                    if peer == identity.peer_id() {
                        continue;
                    }
                    enqueue(outbox, peer, Envelope::Rotate { frame: frame.clone() });
                    flush_or_redial(swarm, hub, identity, cfg, event_tx, outbox, inflight, peer).await;
                }
            } else {
                let _ = event_tx.send(NodeEvent::Log {
                    message: "only the host can rotate".into(),
                });
            }
        }
        Command::OpenDm { peer } => {
            let Ok(pid) = PeerId::from_str(&peer) else {
                let _ = event_tx.send(NodeEvent::Log { message: format!("invalid peer id: {peer}") });
                return;
            };
            let (hex, invite) = rooms.open_dm(pid);
            let _ = event_tx.send(NodeEvent::RoomReady {
                room: hex.clone(),
                peer: pid.to_string(),
                we_are_host: true,
                epoch: 1,
            });
            enqueue(outbox, pid, invite);
            flush_or_redial(swarm, hub, identity, cfg, event_tx, outbox, inflight, pid).await;
        }
        Command::ClearHistory => {
            if let Some(frame) = rooms.clear_envelope() {
                // Local wipe first, then fan the sealed request out.
                let room = rooms.room_hex().to_string();
                let _ = store.lock().unwrap().clear_messages(&room);
                let _ = event_tx.send(NodeEvent::MessagesCleared { room: room.clone() });
                for peer in rooms.member_peers() {
                    if peer == identity.peer_id() {
                        continue;
                    }
                    enqueue(outbox, peer, Envelope::Clear { frame: frame.clone() });
                    flush_or_redial(swarm, hub, identity, cfg, event_tx, outbox, inflight, peer).await;
                }
            } else {
                let _ = event_tx.send(NodeEvent::Log {
                    message: "cannot clear: still joining the room".into(),
                });
            }
        }
        Command::ReserveWith { addr } => {
            if let Some(Protocol::P2p(relay_id)) = addr.iter().last() {
                let mut base = addr.clone();
                base.pop(); // drop /p2p/<relay>
                try_reserve(swarm, relay_candidates, circuit_addrs, relay_id, base);
            } else {
                let _ = event_tx.send(NodeEvent::Log {
                    message: "ReserveWith requires an address ending in /p2p/<relay_id>".into(),
                });
            }
        }
        Command::RequestState => {
            let status = if rooms.is_host() {
                "hosting"
            } else if rooms.is_ready() {
                "connected"
            } else if join_status_hint(cfg) {
                "founding"
            } else {
                "searching"
            };
            let _ = event_tx.send(NodeEvent::JoinStatus { status: status.to_string() });
            if rooms.is_ready() {
                let st = rooms.state().expect("ready implies state");
                let _ = event_tx.send(NodeEvent::RoomReady {
                    room: rooms.room_hex().to_string(),
                    peer: st.host.to_string(),
                    we_are_host: rooms.is_host(),
                    epoch: st.crypto.epoch,
                });
                let _ = event_tx.send(NodeEvent::MembersChanged {
                    room: rooms.room_hex().to_string(),
                    members: rooms.members(),
                });
            }
        }
    }
}

fn join_status_hint(cfg: &NodeConfig) -> bool {
    cfg.assume_host
}

/// The automatic join/host election state machine, ticked every 5 s.
#[allow(clippy::too_many_arguments)]
async fn room_orchestration(
    swarm: &mut Swarm<Behaviour>,
    rooms: &mut Rooms,
    hub: &HubClient,
    identity: &Identity,
    cfg: &NodeConfig,
    room_hex: &str,
    join_target: &mut Option<PeerId>,
    join_mail: &mut Option<(PeerId, std::time::Instant)>,
    sealed_since: &mut Option<std::time::Instant>,
    guest_check: &mut Option<(std::time::Instant, u32)>,
    host_record_ok: &mut bool,
    grace_left: &mut Option<u32>,
    announced: &mut bool,
    outbox: &mut HashMap<PeerId, VecDeque<Envelope>>,
    inflight: &mut HashMap<PeerId, VecDeque<Envelope>>,
    store: &std::sync::Mutex<Store>,
    event_tx: &mpsc::UnboundedSender<NodeEvent>,
) {
    // Ready nodes announce themselves once (founding, joining, or restored
    // from the store), then maintain the mesh: stay connected to every
    // member so fan-out delivery works.
    if rooms.is_ready() {
        if !*announced {
            // A restored host must not blindly re-announce: if a LIVE
            // record names a different host, the election already chose
            // them — yield immediately instead of hosting a fork.
            if rooms.is_host() && !cfg.offline {
                if let Ok(Some(rec)) = hub.lookup_room(room_hex).await {
                    if rec.host_peer_id != identity.peer_id().to_string() {
                        rooms.reset();
                        *join_mail = None;
                        let _ = store.lock().unwrap().clear_conversation(room_hex);
                        let _ = event_tx.send(NodeEvent::Log {
                            message: "another live host holds the room record — yielding, rejoining".into(),
                        });
                        return;
                    }
                }
            }
            *announced = true;
            let st = rooms.state().expect("ready implies state");
            let _ = event_tx.send(NodeEvent::JoinStatus {
                status: if rooms.is_host() { "hosting".into() } else { "connected".into() },
            });
            let _ = event_tx.send(NodeEvent::RoomReady {
                room: room_hex.to_string(),
                peer: st.host.to_string(),
                we_are_host: rooms.is_host(),
                epoch: st.crypto.epoch,
            });
            let _ = event_tx.send(NodeEvent::MembersChanged {
                room: room_hex.to_string(),
                members: rooms.members(),
            });
            // A restored guest re-joins once per start: the host
            // re-delivers the key with a fresh member list (display
            // names otherwise drift after restarts) and any missed
            // rotation is healed.
            if !rooms.is_host() {
                let host = st.host;
                rooms.set_join_target(&host);
                enqueue(outbox, host, rooms.join_envelope());
                flush_outbox(swarm, outbox, inflight, host);
            }
        }
        // A seated guest never re-enters the join flow below — but its
        // host can die or lose the record to a successor. Periodically
        // verify the record still names OUR host; if it names another
        // live host (takeover/fork) or has been gone for two consecutive
        // checks, drop our state and rejoin through normal discovery so
        // we adopt the live room instead of stranding in a dead one.
        // (One empty lookup alone can be a lapse window; two a minute
        // apart means the host is really gone.)
        if !rooms.is_host() && !cfg.offline {
            let due = guest_check.map_or(true, |(at, _)| at.elapsed() >= Duration::from_secs(60));
            if due {
                *guest_check = Some((std::time::Instant::now(), guest_check.map_or(0, |(_, m)| m)));
                let st_host = rooms.state().expect("ready implies state").host;
                let mut rejoin = false;
                match hub.lookup_room(room_hex).await {
                    Ok(Some(rec)) => {
                        if matches!(PeerId::from_str(&rec.host_peer_id), Ok(h) if h == st_host) {
                            if let Some((_, missing)) = guest_check.as_mut() {
                                *missing = 0;
                            }
                        } else {
                            rejoin = true;
                        }
                    }
                    Ok(None) => {
                        if let Some((_, missing)) = guest_check.as_mut() {
                            *missing += 1;
                            rejoin = *missing >= 2;
                        }
                    }
                    Err(_) => {} // transient hub error: check again next cycle
                }
                if rejoin {
                    if let Some((_, missing)) = guest_check.as_mut() {
                        *missing = 0;
                    }
                    rooms.reset();
                    let _ = store.lock().unwrap().clear_conversation(room_hex);
                    *announced = false;
                    *host_record_ok = false;
                    *grace_left = None;
                    *join_target = None;
                    *join_mail = None;
                    let _ = event_tx.send(NodeEvent::Log {
                        message: "the room record moved on — rejoining through discovery".into(),
                    });
                    return;
                }
            }
        }
        if !cfg.offline {
            for peer in rooms.member_peers() {
                if peer != identity.peer_id() && !swarm.is_connected(&peer) {
                    dial_peer(swarm, hub, identity, peer, cfg, event_tx).await;
                }
            }
        }
        return;
    }

    // Offline (tests): static topology knobs instead of hub discovery.
    if cfg.offline {
        if cfg.assume_host {
            rooms.become_host(None, 1);
            persist_room(rooms, store);
        }
        if let Some(host) = &cfg.room_host {
            if let Ok(host) = PeerId::from_str(host) {
                *join_target = Some(host);
                rooms.set_join_target(&host);
                if swarm.is_connected(&host) {
                    enqueue(outbox, host, rooms.join_envelope());
                    flush_outbox(swarm, outbox, inflight, host);
                }
            }
        }
        return;
    }

    // Sealed: the host told us the room rotated under a key we never held.
    // Don't re-attempt joins (or found a fork) — the UI shows why. Sealed
    // rooms die with their hosts and get re-founded, so re-arm discovery
    // after 5 minutes instead of staying locked out for the process
    // lifetime.
    if rooms.sealed {
        if sealed_since.is_none() {
            *sealed_since = Some(std::time::Instant::now());
        } else if sealed_since.unwrap().elapsed() >= Duration::from_secs(300) {
            rooms.sealed = false;
            *sealed_since = None;
            let _ = event_tx.send(NodeEvent::Log {
                message: "sealed-room latch expired — rediscovering the room".into(),
            });
        }
        if rooms.sealed {
            return;
        }
    }

    // Online: consult the room record. This is both join discovery and
    // the "first to join creates the room" election.
    match hub.lookup_room(room_hex).await {
        Ok(Some(rec)) => {
            let _ = event_tx.send(NodeEvent::JoinStatus { status: "joining".into() });
            if let Ok(host) = PeerId::from_str(&rec.host_peer_id) {
                *join_target = Some(host);
                // Always queue the Join for this host, not only when we
                // are already connected: a mailbox-only host (the web
                // portal registers no addresses) can never be dialed, so
                // the outbox's handoff to the site mailbox is the only
                // way in. Connected hosts flush immediately; otherwise
                // the mail handoff delivers it after a couple of failed
                // dial ticks. The 120 s cadence covers a lost Join (the
                // worst-case mail round trip is ~80 s) without flooding
                // the host's inbox with duplicate re-admits.
                let retry_due = match join_mail.as_ref() {
                    Some((sent_to, at)) => {
                        *sent_to != host || at.elapsed() >= Duration::from_secs(120)
                    }
                    None => true,
                };
                if retry_due {
                    rooms.set_join_target(&host);
                    enqueue(outbox, host, rooms.join_envelope());
                    *join_mail = Some((host, std::time::Instant::now()));
                }
                if swarm.is_connected(&host) {
                    flush_outbox(swarm, outbox, inflight, host);
                } else {
                    // Dial via the host's published addresses; retries on
                    // later ticks until the record or connection lands.
                    dial_peer(swarm, hub, identity, host, cfg, event_tx).await;
                }
            }
        }
        Ok(None) => {
            let left = grace_left.get_or_insert(12);
            if *left == 0 {
                // Nobody hosts: found the room. NX on the hub makes a
                // concurrent founding race resolve to one winner.
                let _ = event_tx.send(NodeEvent::JoinStatus { status: "founding".into() });
                rooms.become_host(None, 1);
                match hub.register_room(identity, room_hex).await {
                    Ok(true) => {
                        // Persist only after winning the election; a losing
                        // row would brand us a phantom host across restarts.
                        persist_room(rooms, store);
                        *host_record_ok = true;
                    }
                    Ok(false) => {
                        // Lost the race: someone else founded a moment
                        // earlier. Drop our mint and join them.
                        let _ = event_tx.send(NodeEvent::Log {
                            message: "room record taken by another peer; joining them".into(),
                        });
                        rooms.reset();
                        return;
                    }
                    Err(e) => {
                        // Could not publish: also drop the mint and retry
                        // the whole election on a later tick.
                        let _ = event_tx.send(NodeEvent::Log {
                            message: format!("room register: {e}"),
                        });
                        rooms.reset();
                        return;
                    }
                }
                let st = rooms.state().expect("hosted");
                let _ = event_tx.send(NodeEvent::Log {
                    message: format!("founding room, epoch {}", st.crypto.epoch),
                });
            } else {
                *left -= 1;
                let _ = event_tx.send(NodeEvent::JoinStatus { status: "searching".into() });
            }
        }
        Err(e) => {
            let _ = event_tx.send(NodeEvent::Log { message: format!("room lookup: {e}") });
        }
    }
}

/// Attempt a relay reservation with `relay_id` reachable at `base` (no /p2p suffix).
fn try_reserve(
    swarm: &mut Swarm<Behaviour>,
    relay_candidates: &mut HashMap<PeerId, Multiaddr>,
    circuit_addrs: &mut Vec<Multiaddr>,
    relay_id: PeerId,
    base: Multiaddr,
) {
    let circuit = base
        .clone()
        .with(Protocol::P2p(relay_id))
        .with(Protocol::P2pCircuit);
    // circuit_addrs doubles as the "attempted" set: a second listen_on for
    // the same circuit aborts the first reservation's in-flight request.
    if circuit_addrs_contain(circuit_addrs, &circuit) {
        return;
    }
    circuit_addrs.push(circuit.clone());
    relay_candidates.insert(relay_id, base);
    if let Err(e) = swarm.listen_on(circuit.clone()) {
        eprintln!("[onlyhumans] relay reservation not started: {e}");
    }
}

async fn dial_peer(
    swarm: &mut Swarm<Behaviour>,
    hub: &HubClient,
    identity: &Identity,
    pid: PeerId,
    cfg: &NodeConfig,
    event_tx: &mpsc::UnboundedSender<NodeEvent>,
) {
    if swarm.is_connected(&pid) {
        return;
    }
    if !cfg.offline {
        if let Ok(Some(reg)) = hub.lookup(&pid.to_string()).await {
            for a in &reg.addrs {
                if let Ok(ma) = a.parse::<Multiaddr>() {
                    let mut ma = ma;
                    // A peer's published circuit address is
                    // .../p2p/<relay>/p2p-circuit; dialing THEM through it
                    // requires appending /p2p/<target>.
                    let is_bare_circuit = ma.iter().last() == Some(Protocol::P2pCircuit);
                    if is_bare_circuit {
                        ma = ma.with(Protocol::P2p(pid));
                    }
                    let _ = swarm.dial(ma);
                }
            }
            let _ = identity; // signature already verified inside lookup
        }
    }
    let _ = event_tx;
}

#[allow(clippy::too_many_arguments)]
fn handle_swarm_event(
    swarm: &mut Swarm<Behaviour>,
    rooms: &mut Rooms,
    ev: SwarmEvent<BehaviourEvent>,
    store: &std::sync::Mutex<Store>,
    outbox: &mut HashMap<PeerId, VecDeque<Envelope>>,
    inflight: &mut HashMap<PeerId, VecDeque<Envelope>>,
    connected: &mut HashMap<PeerId, bool>,
    relay_candidates: &mut HashMap<PeerId, Multiaddr>,
    circuit_addrs: &mut Vec<Multiaddr>,
    relay_enabled: bool,
    event_tx: &mpsc::UnboundedSender<NodeEvent>,
) {
    match ev {
        SwarmEvent::NewListenAddr { address, .. } => {
            if address.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                eprintln!("[onlyhumans] circuit listener up: {address}");
            }
            let _ = event_tx.send(NodeEvent::Listening { addr: address.to_string() });
        }
        SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
            tracing::info!("connection established: {peer_id} via {endpoint:?}");
            connected.insert(peer_id, true);
            let _ = event_tx.send(NodeEvent::ConnectionStateChanged {
                peer: peer_id.to_string(),
                connected: true,
            });
            flush_outbox(swarm, outbox, inflight, peer_id);
        }
        SwarmEvent::ConnectionClosed { peer_id, endpoint, num_established, cause, .. } => {
            tracing::info!("connection closed: {peer_id} via {endpoint:?} (remaining {num_established}) cause {cause:?}");
            connected.insert(peer_id, false);
            let _ = event_tx.send(NodeEvent::ConnectionStateChanged {
                peer: peer_id.to_string(),
                connected: false,
            });
        }
        SwarmEvent::Behaviour(BehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted {
            relay_peer_id,
            ..
        })) => {
            // Record the full dialable circuit address for the hub.
            // circuit_addrs already contains the attempted circuit from
            // try_reserve; nothing to add — just log the confirmation.
            let _ = event_tx.send(NodeEvent::Log {
                message: format!("relay reservation accepted via {relay_peer_id}"),
            });
        }
        SwarmEvent::Behaviour(BehaviourEvent::Relay(relay::Event::ReservationReqAccepted { src_peer_id, .. })) => {
            let _ = event_tx.send(NodeEvent::Log {
                message: format!("now relaying for {src_peer_id}"),
            });
        }
        SwarmEvent::Behaviour(BehaviourEvent::Relay(relay::Event::ReservationReqDenied { src_peer_id, status })) => {
            eprintln!("[onlyhumans] relay server: reservation DENIED from {src_peer_id}, status {status:?}");
        }
        SwarmEvent::Behaviour(BehaviourEvent::Rooms(rr_ev)) => match rr_ev {
            request_response::Event::Message { peer, message, .. } => {
                match message {
                    request_response::Message::Request { request, channel, .. } => {
                        let events = rooms.handle(peer, request);
                        process_room_events(rooms, &store, &peer, &events, event_tx);
                        for ev in events {
                            dispatch_room_event(swarm, outbox, inflight, &peer, ev, false, event_tx);
                        }
                        // Always acknowledge requests.
                        let _ = swarm
                            .behaviour_mut()
                            .rooms
                            .send_response(channel, Envelope::Ack);
                    }
                    request_response::Message::Response { response, .. } => {
                        let events = rooms.handle(peer, response);
                        process_room_events(rooms, &store, &peer, &events, event_tx);
                        for ev in events {
                            dispatch_room_event(swarm, outbox, inflight, &peer, ev, false, event_tx);
                        }
                    }
                }
            }
            request_response::Event::OutboundFailure { peer, error, .. } => {
                // The failed request consumed its envelope when it left
                // the outbox — put the shadowed copies back so the tick
                // retries (directly, or via the site mailbox while the
                // peer is unreachable). Recipients dedupe by sequence.
                if let Some(q) = inflight.remove(&peer) {
                    let o = outbox.entry(peer).or_default();
                    for env in q {
                        o.push_front(env);
                    }
                }
                let _ = event_tx.send(NodeEvent::Log {
                    message: format!("outbound to {peer} failed: {error}"),
                });
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                let _ = event_tx.send(NodeEvent::Log {
                    message: format!("inbound from {peer} failed: {error}"),
                });
            }
            _ => {}
        },
        SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            // Learning our own observed address is what auto-enables our
            // relay service (HOP) once we are publicly reachable — the
            // official relay-server pattern.
            let observed = info.observed_addr.clone();
            if swarm.external_addresses().all(|a| a != &observed) {
                swarm.add_external_address(observed);
            }
            // Learn addresses for future dials and relay reservations.
            for ma in info.listen_addrs {
                let usable = ma.iter().any(|p| {
                    matches!(p, Protocol::Ip4(ip) if !ip.is_loopback() && !ip.is_unspecified())
                });
                if !usable {
                    continue;
                }
                if !swarm.is_connected(&peer_id) {
                    let _ = swarm.dial(ma.clone().with(Protocol::P2p(peer_id)));
                }
                if relay_enabled {
                    try_reserve(swarm, relay_candidates, circuit_addrs, peer_id, ma);
                }
            }
        }
        _ => {}
    }
}

/// Persist the room (key/epoch/host/role) so it survives restarts.
fn persist_room(rooms: &Rooms, store: &std::sync::Mutex<Store>) {
    let Some(st) = rooms.state() else { return };
    let _ = store.lock().unwrap().upsert_conversation(
        rooms.room_hex(),
        &st.host.to_string(),
        st.role == crate::rooms::Role::Host,
        st.crypto.room_key(),
        st.crypto.epoch,
    );
}

/// Side effects of a batch of room events: persist state transitions and
/// keep the member list mirrored into contacts (so names apply).
fn process_room_events(
    rooms: &mut Rooms,
    store: &std::sync::Mutex<Store>,
    _from: &libp2p::PeerId,
    events: &[RoomEvent],
    event_tx: &mpsc::UnboundedSender<NodeEvent>,
) {
    for ev in events {
        match ev {
            RoomEvent::RoomReady { .. } | RoomEvent::Rotated { .. } => persist_room(rooms, store),
            RoomEvent::MessagesCleared { room_id_hex } => {
                let _ = store.lock().unwrap().clear_messages(room_id_hex);
            }
            RoomEvent::Message { room_id_hex, sender, body, epoch } => {
                // Persist inbound history in the core (UI-independent);
                // DMs are memory-only by design.
                if room_id_hex == rooms.room_hex() {
                    let outgoing = sender == rooms.my_id();
                    let text = String::from_utf8_lossy(body).into_owned();
                    let _ = store
                        .lock()
                        .unwrap()
                        .append_message(room_id_hex, sender, &text, *epoch, outgoing);
                }
            }
            RoomEvent::MembersChanged { members, .. } => {
                let mut s = store.lock().unwrap();
                for m in members {
                    if m.peer != rooms.my_id() {
                        let _ = s.set_shared_name(&m.peer, &m.name);
                    }
                }
            }            _ => {}
        }
    }
    let _ = event_tx;
}

fn dispatch_room_event(
    swarm: &mut Swarm<Behaviour>,
    outbox: &mut HashMap<PeerId, VecDeque<Envelope>>,
    inflight: &mut HashMap<PeerId, VecDeque<Envelope>>,
    from: &PeerId,
    ev: RoomEvent,
    via_site: bool,
    event_tx: &mpsc::UnboundedSender<NodeEvent>,
) {
    match ev {
        RoomEvent::Send { peer, envelope } => {
            enqueue(outbox, peer, envelope);
            flush_outbox(swarm, outbox, inflight, peer);
        }
        RoomEvent::RoomReady { room_id_hex, host, role, epoch } => {
            let _ = event_tx.send(NodeEvent::RoomReady {
                room: room_id_hex,
                peer: host.to_string(),
                we_are_host: role == crate::rooms::Role::Host,
                epoch,
            });
        }
        RoomEvent::Message { room_id_hex, sender, body, epoch } => {
            let _ = event_tx.send(NodeEvent::Message {
                room: room_id_hex,
                sender,
                body: String::from_utf8_lossy(&body).into_owned(),
                epoch,
                via_site,
            });
        }
        RoomEvent::MembersChanged { room_id_hex, members } => {
            let _ = event_tx.send(NodeEvent::MembersChanged { room: room_id_hex, members });
        }
        RoomEvent::MessagesCleared { room_id_hex } => {
            let _ = event_tx.send(NodeEvent::MessagesCleared { room: room_id_hex });
        }
        RoomEvent::Rotated { room_id_hex, new_epoch } => {
            let _ = event_tx.send(NodeEvent::Rotated { room: room_id_hex, new_epoch });
        }
        RoomEvent::ProtocolError { context } => {
            let _ = event_tx.send(NodeEvent::Log { message: context });
        }
        RoomEvent::Sealed => {
            let _ = event_tx.send(NodeEvent::JoinStatus { status: "sealed".into() });
        }
    }
    let _ = from;
    let _ = (swarm, outbox);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The UI switches on `kind` with camelCase fields (the wire-format
    /// contract); assert the exact JSON shape every consumer sees.
    #[test]
    fn presence_event_serializes_camel_case() {
        let ev = NodeEvent::Presence { linked: true, online: 3 };
        let j = serde_json::to_string(&ev).unwrap();
        assert_eq!(j, r#"{"kind":"presence","linked":true,"online":3}"#);
    }
}
