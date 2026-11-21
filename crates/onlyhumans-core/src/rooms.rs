//! Room protocol: ONE global community room per global key.
//!
//! - The room id is deterministic: SHA256("OH1-room-v1" | gk). Dev and
//!   production global keys therefore address separate rooms.
//! - The first member HOSTS: it mints a random room key and registers a
//!   signed, TTL'd host record on the hub (`/api/room`). Membership is
//!   granted to anyone proving knowledge of the GK — that is the entire
//!   admission ceremony.
//! - The host delivers the room key (GK-sealed per guest) plus the member
//!   list, broadcasts membership updates on join/leave, and is the only
//!   role that can rotate the key.
//! - Delivery is a mesh: every member seals one frame and the transport
//!   sends it to each member directly. The host going offline pauses new
//!   joins (until a key-holding member takes the record over) but not
//!   chat between connected members.

use crate::crypto::{self, Key, RoomCrypto, RoomId, Sealed};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Envelope {
    /// Guest -> host: admission request with GK proof for the global room.
    Join {
        room_id_hex: String,
        guest_id: String,
        guest_nonce_b64: String,
        guest_proof_b64: String,
        /// Display name the joiner wants to be known by.
        name: String,
    },
    /// Host -> guest: the room key GK-sealed for the recipient, plus the
    /// current member list (peer ids, including the recipient).
    KeyDelivery {
        room_id_hex: String,
        epoch: u64,
        key_ct_b64: String,
        members: Vec<MemberInfo>,
    },
    /// Host -> members: the current member list, sealed under the room key
    /// (only members may learn membership).
    Members { frame: Sealed },
    /// Any member: a sealed chat frame (main room: sent to every member;
    /// DMs: sent only to the peer).
    Chat { frame: Sealed },
    /// Peer -> peer: open (or re-open) a private two-person room. The key
    /// is GK-sealed for the recipient only; delivered directly, never
    /// fanned out, so other members learn nothing.
    DmInvite {
        room_id_hex: String,
        key_ct_b64: String,
    },
    /// Host -> members: rotation payload sealed under the current key.
    Rotate { frame: Sealed },
    /// Any member: request that everyone wipes their local message history
    /// for this room. Sealed like a chat frame (kind `clear`) so only room
    /// members can issue it.
    Clear { frame: Sealed },
    /// Member -> members: leaving the room.
    Leave { room_id_hex: String },
    Ack,
    Error { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Host,
    Guest,
}

pub struct RoomState {
    pub crypto: RoomCrypto,
    pub role: Role,
    /// Who currently hosts the room (ourselves when we host).
    pub host: PeerId,
    /// Known members: peer id -> display name (including ourselves).
    /// Maintained by the host authoritatively; guests apply host-sent
    /// lists.
    pub members: HashMap<String, String>,
    /// Outgoing sequence numbers are wall-clock seeded so they survive
    /// restarts without persistence (receiver replay guard).
    pub my_seq: u64,
    /// Highest sequence seen per sender (anti-replay).
    seen_seq: HashMap<String, u64>,
    /// A real room key has been installed (vs. the pre-join placeholder).
    has_key: bool,
}

impl RoomState {
    fn new(crypto: RoomCrypto, role: Role, host: PeerId, my_id: &str, has_key: bool) -> Self {
        let mut members = HashMap::new();
        members.insert(my_id.to_string(), String::new());
        Self {
            crypto,
            role,
            host,
            members,
            my_seq: now_seed(),
            seen_seq: HashMap::new(),
            has_key,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemberInfo {
    pub peer: String,
    pub name: String,
}

/// An ephemeral two-person room. Memory-only by design: never persisted,
/// so it disappears when both sides are offline.
pub struct DmRoom {
    pub peer: PeerId,
    pub crypto: RoomCrypto,
    pub my_seq: u64,
    seen_seq: u64,
}

pub struct Rooms {
    gk: Key,
    my_id: String,
    my_name: String,
    room_hex: String,
    room: Option<RoomState>,
    dms: HashMap<String, DmRoom>,
    /// The host we last sent a Join to. A FIRST KeyDelivery is only
    /// accepted from this peer: the GK (public for the earth room) lets
    /// anyone seal a key, so an unrestricted handler would let a stranger
    /// hand us their own room key and hijack the session.
    expect_host: Option<PeerId>,
    /// Our join was refused because the room is sealed (rotated under a
    /// key we never held). Session latch: stops the join retry loop and
    /// tells the UI the door is closed.
    pub sealed: bool,
}

#[derive(Debug, Clone)]
pub enum RoomEvent {
    /// Outgoing envelope for the transport to deliver to `peer`.
    Send { peer: PeerId, envelope: Envelope },
    /// The room became usable (key installed / minted).
    RoomReady { room_id_hex: String, host: PeerId, role: Role, epoch: u64 },
    /// Plaintext chat message received.
    Message { room_id_hex: String, sender: String, body: Vec<u8>, epoch: u64 },
    /// The member list changed.
    MembersChanged { room_id_hex: String, members: Vec<MemberInfo> },
    /// Every participant should wipe its local message history.
    MessagesCleared { room_id_hex: String },
    /// A key rotation was applied.
    Rotated { room_id_hex: String, new_epoch: u64 },
    /// The host refused our join: the room was sealed by a key rotation
    /// and we are not one of its members.
    Sealed,
    ProtocolError { context: String },
}

/// Deterministic room id for a global key: hex(SHA256("OH1-room-v1" | gk)
/// truncated to the 16-byte RoomId).
pub fn global_room_hex(gk: &Key) -> String {
    let mut h = Sha256::new();
    h.update(b"OH1-room-v1|");
    h.update(gk);
    hex::encode(&h.finalize()[..16])
}

/// Canonical form of a passcode word: surrounding whitespace stripped,
/// Unicode-lowercased, so "Secret" and "secret " address the same room.
pub fn normalize_passcode(word: &str) -> String {
    word.trim().to_lowercase()
}

/// Effective community key for an optional room word.
///
/// Empty/blank word -> the GK unchanged. A word mixes into the
/// derivation, producing a parallel room universe: same word + same
/// binary -> same room, different word -> different room, and the word
/// itself never crosses the network (only hashes of it do). Since 1.1.0
/// the stretch is Argon2id (64 MiB, t=3, p=1) — memory-hard, so GPU/ASIC
/// dictionary scanning pays orders of magnitude more per candidate than
/// the old chained-SHA256 loop. Still convenience isolation rather than
/// strong access control: pick long random words (the app generates
/// them). The web portal mirrors these exact parameters.
pub fn effective_gk(gk: &Key, word: Option<&str>) -> Key {
    let Some(word) = word else { return *gk };
    let word = normalize_passcode(word);
    if word.is_empty() {
        return *gk;
    }
    let mut h = Sha256::new();
    h.update(b"OH1-pass-v2|");
    h.update(gk);
    h.update(word.as_bytes());
    let salt = h.finalize();
    let params =
        argon2::Params::new(65_536, 3, 1, Some(32)).expect("valid Argon2id parameters");
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Key::default();
    argon
        .hash_password_into(word.as_bytes(), &salt, &mut out)
        .expect("argon2 derives 32 bytes");
    out
}

#[derive(Serialize, Deserialize)]
struct MembersPayload {
    members: Vec<MemberInfo>,
}

impl Rooms {
    pub fn new(gk: Key, my_id: String, my_name: String) -> Self {
        let my_name = sanitize_name(&my_name);
        let room_hex = global_room_hex(&gk);
        Self { gk, my_id, my_name, room_hex, room: None, dms: HashMap::new(), expect_host: None, sealed: false }
    }

    /// Record the host a Join envelope is being sent to (gates the first
    /// KeyDelivery we accept).
    pub fn set_join_target(&mut self, host: &PeerId) {
        self.expect_host = Some(*host);
    }

    pub fn my_id(&self) -> &str {
        &self.my_id
    }

    pub fn room_hex(&self) -> &str {
        &self.room_hex
    }

    /// Deterministic private-room id for a pair: both sides compute the
    /// same hex without coordination.
    pub fn dm_hex(&self, other: &str) -> String {
        let (a, b) = if self.my_id.as_str() < other {
            (self.my_id.as_str(), other)
        } else {
            (other, self.my_id.as_str())
        };
        let mut h = Sha256::new();
        h.update(b"OH1-dm-v1|");
        h.update(&self.gk);
        h.update(a.as_bytes());
        h.update(b"|");
        h.update(b.as_bytes());
        hex::encode(&h.finalize()[..16])
    }

    pub fn dm(&self, room_hex: &str) -> Option<&DmRoom> {
        self.dms.get(room_hex)
    }

    pub fn dm_peers(&self) -> Vec<PeerId> {
        self.dms.values().map(|d| d.peer).collect()
    }

    pub fn state(&self) -> Option<&RoomState> {
        self.room.as_ref()
    }

    pub fn is_ready(&self) -> bool {
        self.room.as_ref().map(|st| st.has_key).unwrap_or(false)
    }

    pub fn is_host(&self) -> bool {
        self.room.as_ref().map(|st| st.role == Role::Host).unwrap_or(false)
    }

    pub fn members(&self) -> Vec<MemberInfo> {
        self.room
            .as_ref()
            .map(|st| {
                st.members
                    .iter()
                    .map(|(peer, name)| MemberInfo {
                        peer: peer.clone(),
                        // Our own entry always carries OUR name.
                        name: if peer == &self.my_id { self.my_name.clone() } else { name.clone() },
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Founding (or takeover): mint a random key for the fixed room id and
    /// host it. Takeover passes the existing key so members keep history.
    pub fn become_host(&mut self, existing_key: Option<Key>, epoch: u64) {
        let room_id: RoomId = match hex::decode(&self.room_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
        {
            Some(r) => r,
            None => return,
        };
        let key = existing_key.unwrap_or_else(|| {
            let mut k = Key::default();
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
            k
        });
        let mut crypto = RoomCrypto::from_delivered(room_id, key);
        crypto.epoch = epoch.max(1);
        let host_id = self
            .my_id
            .parse::<PeerId>()
            .expect("my_id is a valid peer id");
        self.room = Some(RoomState::new(crypto, Role::Host, host_id, &self.my_id, true));
    }

    /// Restore a member list (from the contacts store) into a restored
    /// room, so fan-out works immediately after a restart. The host's
    /// authoritative list re-converges as guests re-join.
    pub fn restore_members(&mut self, peers: Vec<(String, String)>) {
        if let Some(st) = self.room.as_mut() {
            for (p, name) in peers {
                if p.parse::<PeerId>().is_ok() {
                    st.members.insert(p, name);
                }
            }
        }
    }

    /// Drop in-memory room state (e.g. we minted a key but lost the
    /// host-record race before anyone joined us).
    pub fn reset(&mut self) {
        self.room = None;
        self.expect_host = None;
    }

    /// Open (or re-open) a private room with `peer`. Returns the room hex
    /// and the DmInvite envelope to deliver directly to them. Creating is
    /// idempotent: an existing room keeps its key; the invite is resent
    /// anyway so a peer that lost it (restart) re-syncs.
    pub fn open_dm(&mut self, peer: PeerId) -> (String, Envelope) {
        let hex = self.dm_hex(&peer.to_string());
        if !self.dms.contains_key(&hex) {
            let room_id: RoomId = hex::decode(&hex).ok().and_then(|v| v.try_into().ok()).expect("dm hex");
            let mut key = Key::default();
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
            self.dms.insert(
                hex.clone(),
                DmRoom { peer, crypto: RoomCrypto::from_delivered(room_id, key), my_seq: now_seed(), seen_seq: 0 },
            );
        }
        let dm = &self.dms[&hex];
        // DM rooms never rotate and the DmInvite envelope carries no epoch
        // field, so the delivery seal is pinned to epoch 1 on both sides.
        let ct = crypto::seal_room_key(&self.gk, &dm.crypto.room_id, 1, &peer.to_string(), dm.crypto.room_key());
        (hex.clone(), Envelope::DmInvite { room_id_hex: hex, key_ct_b64: crypto::base64_encode(&ct) })
    }

    /// Build the Join envelope with a fresh GK proof.
    pub fn join_envelope(&self) -> Envelope {
        let mut gnonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut gnonce);
        let gproof = crypto::admission_proof(&self.gk, &self.my_id, &gnonce);
        Envelope::Join {
            room_id_hex: self.room_hex.clone(),
            guest_id: self.my_id.clone(),
            guest_nonce_b64: crypto::base64_encode(&gnonce),
            guest_proof_b64: crypto::base64_encode(&gproof),
            name: self.my_name.clone(),
        }
    }

    /// Seal a chat message for a room we are in (one frame; the transport
    /// decides fan-out: members for the main room, the peer for DMs).
    pub fn seal_chat(&mut self, room_hex: &str, body: &[u8]) -> Option<Sealed> {
        if room_hex == self.room_hex {
            let st = self.room.as_mut()?;
            if !st.has_key {
                return None; // still joining
            }
            st.my_seq += 1;
            return Some(st.crypto.seal(&self.my_id, st.my_seq, crypto::kinds::CHAT, body));
        }
        let dm = self.dms.get_mut(room_hex)?;
        dm.my_seq += 1;
        Some(dm.crypto.seal(&self.my_id, dm.my_seq, crypto::kinds::CHAT, body))
    }

    /// Build the sealed clear-history frame (one per member fan-out).
    pub fn clear_envelope(&mut self) -> Option<Sealed> {
        let st = self.room.as_mut()?;
        if !st.has_key {
            return None;
        }
        st.my_seq += 1;
        Some(st.crypto.seal(&self.my_id, st.my_seq, crypto::kinds::CLEAR, b""))
    }

    /// Host: rotate the room key. Returns the sealed rotation frame (to
    /// send to every member) after committing our own state.
    pub fn rotate(&mut self) -> Option<Sealed> {
        let st = self.room.as_mut()?;
        if st.role != Role::Host || !st.has_key {
            return None;
        }
        let secret = st.crypto.prepare_rotation();
        let payload = serde_json::to_vec(&secret).expect("serialize rotation");
        st.my_seq += 1;
        let frame = st.crypto.seal(&self.my_id, st.my_seq, crypto::kinds::ROTATE, &payload);
        st.crypto.commit_rotation(&secret).ok()?;
        Some(frame)
    }

    /// Restore a persisted room (startup). Guests re-join to resync.
    pub fn restore(&mut self, host: PeerId, role: Role, key: Key, epoch: u64) {
        if self.room.is_some() {
            return;
        }
        let room_id: RoomId = match hex::decode(&self.room_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
        {
            Some(r) => r,
            None => return,
        };
        let mut crypto = RoomCrypto::from_delivered(room_id, key);
        crypto.epoch = epoch.max(1);
        self.room = Some(RoomState::new(crypto, role, host, &self.my_id, true));
    }

    /// Process an incoming envelope from `from`.
    pub fn handle(&mut self, from: PeerId, env: Envelope) -> Vec<RoomEvent> {
        let mut out = Vec::new();
        match env {
            Envelope::Join {
                room_id_hex,
                guest_id,
                guest_nonce_b64,
                guest_proof_b64,
                name,
            } => {
                if room_id_hex != self.room_hex {
                    out.push(RoomEvent::Send {
                        peer: from,
                        envelope: Envelope::Error { message: "unknown room".into() },
                    });
                    return out;
                }
                let is_host = self.room.as_ref().map(|st| st.role == Role::Host).unwrap_or(false);
                if !is_host {
                    out.push(RoomEvent::Send {
                        peer: from,
                        envelope: Envelope::Error {
                            message: "not the host (record expired?)".into(),
                        },
                    });
                    return out;
                }
                let nonce: [u8; 16] = match crypto::base64_decode(&guest_nonce_b64)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                {
                    Some(n) => n,
                    None => {
                        out.push(err("malformed join nonce"));
                        return out;
                    }
                };
                let proof: Key = match crypto::base64_decode(&guest_proof_b64)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                {
                    Some(p) => p,
                    None => {
                        out.push(err("malformed join proof"));
                        return out;
                    }
                };
                if guest_id != from.to_string() {
                    out.push(err("join guest id does not match connection"));
                    return out;
                }
                if !crypto::verify_admission_proof(&self.gk, &guest_id, &nonce, &proof) {
                    out.push(err(&format!("join GK proof failed from {from}")));
                    return out;
                }
                // The first rotation seals the room. Rotation frames travel
                // only under the current key, so from epoch 2 onward the
                // membership is closed: a valid GK proof no longer mints a
                // seat. People already on the member list (restarts,
                // returns after a missed rotation) still re-join freely.
                if let Some(st) = self.room.as_ref() {
                    if st.crypto.epoch > 1 && !st.members.contains_key(&from.to_string()) {
                        out.push(RoomEvent::Send {
                            peer: from,
                            envelope: Envelope::Error {
                                message: "room-sealed: the room key was rotated — only current members keep access".into(),
                            },
                        });
                        return out;
                    }
                }
                out.extend(self.admit(from, &name));
            }
            Envelope::KeyDelivery {
                room_id_hex,
                epoch,
                key_ct_b64,
                members,
            } => {
                if room_id_hex != self.room_hex {
                    out.push(err("key delivery for unknown room"));
                    return out;
                }
                // Only the host we deliberately contacted may seat or
                // re-key us. Seated: our recorded host. First delivery:
                // the peer we mailed our Join to. Anything else (a GK
                // holder racing the real host) is ignored.
                if let Some(st) = self.room.as_ref() {
                    if st.has_key && st.host != from {
                        out.push(err("key delivery from a peer that is not our host"));
                        return out;
                    }
                } else if self.expect_host != Some(from) {
                    out.push(err("key delivery from an unexpected host"));
                    return out;
                }
                if epoch < 1 {
                    out.push(err("key delivery with invalid epoch"));
                    return out;
                }
                let ct = match crypto::base64_decode(&key_ct_b64) {
                    Ok(c) => c,
                    Err(_) => {
                        out.push(err("malformed key delivery"));
                        return out;
                    }
                };
                let room_id: RoomId = match hex::decode(&room_id_hex)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                {
                    Some(r) => r,
                    None => {
                        out.push(err("bad room id in delivery"));
                        return out;
                    }
                };
                // The seal was made for OUR id — we are the joiner here.
                let key = match crypto::open_room_key(&self.gk, &room_id, epoch, &self.my_id, &ct) {
                    Ok(k) => k,
                    Err(e) => {
                        out.push(err(&format!("key delivery failed: {e}")));
                        return out;
                    }
                };
                // Re-delivery to a seated member: the host is
                // authoritative — adopt a newer epoch or a changed key
                // (missed rotation, takeover fork) and always apply the
                // fresh member list; never regress.
                if let Some(st) = self.room.as_mut() {
                    if st.has_key {
                        let current_key = *st.crypto.room_key();
                        if epoch > st.crypto.epoch || key != current_key {
                            st.crypto = RoomCrypto::from_delivered(room_id, key);
                            st.crypto.epoch = epoch.max(1);
                        }
                        st.members = sanitize_members(members, &self.my_id);
                        out.push(RoomEvent::MembersChanged {
                            room_id_hex: room_id_hex.clone(),
                            members: self.members(),
                        });
                        return out;
                    }
                }
                self.room = Some(RoomState::new(
                    RoomCrypto::from_delivered(room_id, key),
                    Role::Guest,
                    from,
                    &self.my_id,
                    true,
                ));
                if let Some(st) = self.room.as_mut() {
                    st.crypto.epoch = epoch.max(1);
                    st.members = sanitize_members(members, &self.my_id);
                }
                out.push(RoomEvent::RoomReady {
                    room_id_hex: room_id_hex.clone(),
                    host: from,
                    role: Role::Guest,
                    epoch,
                });
                out.push(RoomEvent::MembersChanged {
                    room_id_hex,
                    members: self.members(),
                });
            }
            Envelope::Members { frame } => {
                let room_hex = frame.room_id_hex.clone();
                match self.open_frame(&frame, crypto::kinds::MEMBERS) {
                    Ok((body, _, _)) => {
                        match serde_json::from_slice::<MembersPayload>(&body) {
                            Ok(p) => {
                                if let Some(st) = self.room.as_mut() {
                                    st.members = sanitize_members(p.members, &self.my_id);
                                }
                                out.push(RoomEvent::MembersChanged {
                                    room_id_hex: room_hex,
                                    members: self.members(),
                                });
                            }
                            Err(e) => out.push(err(&format!("bad members payload: {e}"))),
                        }
                    }
                    Err(e) => out.push(err(&format!("members: {e}"))),
                }
            }
            Envelope::Chat { frame } => {
                let room_hex = frame.room_id_hex.clone();
                match self.open_frame(&frame, crypto::kinds::CHAT) {
                    Ok((body, epoch, sender)) => out.push(RoomEvent::Message {
                        room_id_hex: room_hex,
                        sender,
                        body,
                        epoch,
                    }),
                    Err(e) => {
                        // A frame for a room we don't hold: for DMs this
                        // means the peer lost it (restart) — tell them so
                        // they re-invite us.
                        if e.to_string().contains("unknown room") || e.to_string().contains("no room state") {
                            out.push(RoomEvent::Send {
                                peer: from,
                                envelope: Envelope::Error {
                                    message: format!("unknown-room:{room_hex}"),
                                },
                            });
                        }
                        out.push(err(&format!("chat: {e}")));
                    }
                }
            }
            Envelope::DmInvite { room_id_hex, key_ct_b64 } => {
                if room_id_hex == self.room_hex {
                    return out; // never via DM mechanics
                }
                let ct = match crypto::base64_decode(&key_ct_b64) {
                    Ok(c) => c,
                    Err(_) => return out,
                };
                let room_id: RoomId = match hex::decode(&room_id_hex).ok().and_then(|v| v.try_into().ok()) {
                    Some(r) => r,
                    None => return out,
                };
                // The seal was made for OUR id — only the intended peer
                // can open it. DMs pin epoch 1 (see the invite builder).
                let key = match crypto::open_room_key(&self.gk, &room_id, 1, &self.my_id, &ct) {
                    Ok(k) => k,
                    Err(_) => {
                        out.push(err("dm invite failed GK authentication"));
                        return out;
                    }
                };
                if self.dms.contains_key(&room_id_hex) {
                    return out; // already have (or had) this DM — keep our state
                }
                self.dms.insert(
                    room_id_hex.clone(),
                    DmRoom { peer: from, crypto: RoomCrypto::from_delivered(room_id, key), my_seq: now_seed(), seen_seq: 0 },
                );
                out.push(RoomEvent::RoomReady {
                    room_id_hex,
                    host: from,
                    role: Role::Guest,
                    epoch: 1,
                });
            }
            Envelope::Rotate { frame } => {
                let room_hex = frame.room_id_hex.clone();
                match self.open_frame(&frame, crypto::kinds::ROTATE) {
                    Ok((body, _, sender)) => {
                        // Only the host may rotate.
                        if let Some(st) = self.room.as_ref() {
                            if sender != st.host.to_string() {
                                out.push(err("rotation from non-host rejected"));
                                return out;
                            }
                        }
                        match serde_json::from_slice::<crypto::RotationSecret>(&body) {
                            Ok(secret) => {
                                if let Some(st) = self.room.as_mut() {
                                    let new_epoch = secret.next_epoch;
                                    if st.crypto.apply_rotation(&secret).is_ok() {
                                        out.push(RoomEvent::Rotated { room_id_hex: room_hex, new_epoch });
                                    } else {
                                        out.push(err("rotation rejected (epoch mismatch?)"));
                                    }
                                }
                            }
                            Err(e) => out.push(err(&format!("bad rotation payload: {e}"))),
                        }
                    }
                    Err(e) => out.push(err(&format!("rotate: {e}"))),
                }
            }
            Envelope::Clear { frame } => {
                let room_hex = frame.room_id_hex.clone();
                match self.open_frame(&frame, crypto::kinds::CLEAR) {
                    Ok(_) => out.push(RoomEvent::MessagesCleared { room_id_hex: room_hex }),
                    Err(e) => out.push(err(&format!("clear: {e}"))),
                }
            }
            Envelope::Leave { room_id_hex } => {
                if room_id_hex == self.room_hex {
                    if let Some(st) = self.room.as_mut() {
                        st.members.remove(&from.to_string());
                    }
                    if self.is_host() {
                        out.extend(self.broadcast_members());
                    }
                    out.push(RoomEvent::MembersChanged {
                        room_id_hex,
                        members: self.members(),
                    });
                }
            }
            Envelope::Ack => {}
            Envelope::Error { message } => {
                // A peer could not decrypt a DM frame (they lost the room
                // to a restart): re-invite them with our existing key.
                if let Some(hex) = message.strip_prefix("unknown-room:") {
                    if self.dms.contains_key(hex) {
                        let dm = &self.dms[hex];
                        let ct = crypto::seal_room_key(
                            &self.gk,
                            &dm.crypto.room_id,
                            1, // DM deliveries pin epoch 1
                            &from.to_string(),
                            dm.crypto.room_key(),
                        );
                        out.push(RoomEvent::Send {
                            peer: from,
                            envelope: Envelope::DmInvite {
                                room_id_hex: hex.to_string(),
                                key_ct_b64: crypto::base64_encode(&ct),
                            },
                        });
                    }
                }
                // Our join was refused because the room rotated under a key
                // we never held: latch it so the join retry loop stops and
                // the UI can say why.
                if message.starts_with("room-sealed") {
                    self.sealed = true;
                    out.push(RoomEvent::Sealed);
                }
            }
        }
        out
    }

    /// Host: admit `guest` — record membership (with their display
    /// name), deliver the key + member list, and tell existing members
    /// about the newcomer.
    fn admit(&mut self, guest: PeerId, name: &str) -> Vec<RoomEvent> {
        let Some(st) = self.room.as_ref() else {
            return vec![err("admit: no room")];
        };
        if st.role != Role::Host {
            return vec![err("admit: not host")];
        }
        let key = *st.crypto.room_key();
        let room_id: RoomId = st.crypto.room_id;
        let epoch = st.crypto.epoch;
        let members: Vec<MemberInfo> = {
            let st = self.room.as_mut().unwrap();
            st.members.insert(guest.to_string(), sanitize_name(name));
            self.members()
        };
        let ct = crypto::seal_room_key(&self.gk, &room_id, epoch, &guest.to_string(), &key);
        let mut out = vec![
            RoomEvent::Send {
                peer: guest,
                envelope: Envelope::KeyDelivery {
                    room_id_hex: self.room_hex.clone(),
                    epoch,
                    key_ct_b64: crypto::base64_encode(&ct),
                    members: members.clone(),
                },
            },
            RoomEvent::MembersChanged {
                room_id_hex: self.room_hex.clone(),
                members: members.clone(),
            },
        ];
        out.extend(self.broadcast_members());
        out
    }

    /// Host: seal the current member list for every member (the freshly
    /// admitted guest gets the list in KeyDelivery already, but a single
    /// uniform broadcast keeps everyone in sync).
    fn broadcast_members(&mut self) -> Vec<RoomEvent> {
        let Some(st) = self.room.as_ref() else { return vec![] };
        if st.role != Role::Host || !st.has_key {
            return vec![];
        }
        let _ = st;
        let payload = MembersPayload { members: self.members() };
        let body = serde_json::to_vec(&payload).expect("serialize members");
        // borrow gymnastics: seal needs &self.crypto, events need member ids
        let frame = {
            let st = self.room.as_mut().unwrap();
            st.my_seq += 1;
            st.crypto.seal(&self.my_id, st.my_seq, crypto::kinds::MEMBERS, &body)
        };
        let peers: Vec<PeerId> = self
            .room
            .as_ref()
            .unwrap()
            .members
            .keys()
            // Never address ourselves: a self-addressed broadcast would
            // queue forever offline (and, via the site mailbox, be mailed
            // back to our own inbox).
            .filter(|m| m.as_str() != self.my_id())
            .filter_map(|m| m.parse().ok())
            .collect();
        peers
            .into_iter()
            .map(|peer| RoomEvent::Send { peer, envelope: Envelope::Members { frame: frame.clone() } })
            .collect()
    }

    /// The mesh send set: every member's PeerId.
    pub fn member_peers(&self) -> Vec<PeerId> {
        self.members().iter().filter_map(|m| m.peer.parse().ok()).collect()
    }

    fn open_frame(
        &mut self,
        frame: &Sealed,
        kind: &[u8; 8],
    ) -> anyhow::Result<(Vec<u8>, u64, String)> {
        if frame.room_id_hex != self.room_hex {
            // Private room frame.
            let dm = self
                .dms
                .get_mut(&frame.room_id_hex)
                .ok_or_else(|| anyhow::anyhow!("frame for unknown room"))?;
            let sender = frame.sender.clone();
            let seq = frame.seq;
            let epoch = frame.epoch;
            let body = dm.crypto.open(frame, kind)?;
            if seq <= dm.seen_seq {
                anyhow::bail!("replayed sequence {seq} from {sender}");
            }
            dm.seen_seq = seq;
            return Ok((body, epoch, sender));
        }
        let st = self
            .room
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no room state"))?;
        let sender = frame.sender.clone();
        let seq = frame.seq;
        let epoch = frame.epoch;
        let body = st.crypto.open(frame, kind)?;
        let last = st.seen_seq.get(&sender).copied().unwrap_or(0);
        if seq <= last {
            anyhow::bail!("replayed sequence {seq} from {sender}");
        }
        st.seen_seq.insert(sender.clone(), seq);
        Ok((body, epoch, sender))
    }
}

/// Keep the list sane: dedup, always include ourselves, parseable peers
/// only, sanitized names.
fn sanitize_members(list: Vec<MemberInfo>, my_id: &str) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = list
        .into_iter()
        .filter(|m| m.peer.parse::<PeerId>().is_ok() && m.peer != my_id)
        .map(|m| (m.peer, sanitize_name(&m.name)))
        .collect();
    map.insert(my_id.to_string(), String::new());
    map
}

/// Display names: trimmed, 32 chars max, no control characters.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control())
        .take(32)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Wall-clock seed for outgoing sequence numbers: strictly increasing
/// across restarts without persistence.
fn now_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn err(context: &str) -> RoomEvent {
    RoomEvent::ProtocolError { context: context.to_string() }
}

#[cfg(test)]
mod passcode_tests {
    use super::*;

    fn gk() -> Key {
        [7u8; 32]
    }

    #[test]
    fn empty_word_is_the_untouched_gk() {
        assert_eq!(effective_gk(&gk(), None), gk());
        assert_eq!(effective_gk(&gk(), Some("")), gk());
        assert_eq!(effective_gk(&gk(), Some("   \t ")), gk());
    }

    #[test]
    fn normalization_folds_case_and_whitespace() {
        assert_eq!(normalize_passcode("  Secret "), "secret");
        assert_eq!(normalize_passcode("SECRET"), "secret");
        assert_eq!(normalize_passcode("ÜBER"), normalize_passcode("über"));
        assert_eq!(
            effective_gk(&gk(), Some("Secret")),
            effective_gk(&gk(), Some(" secret\t"))
        );
    }

    #[test]
    fn words_partition_the_room_universe() {
        let base = gk();
        // Determinism.
        assert_eq!(effective_gk(&base, Some("lair")), effective_gk(&base, Some("lair")));
        // Different words, different keys and room ids; neither is the
        // main room.
        let lair = effective_gk(&base, Some("lair"));
        let cave = effective_gk(&base, Some("cave"));
        assert_ne!(lair, cave);
        assert_ne!(lair, base);
        assert_ne!(cave, base);
        assert_ne!(global_room_hex(&lair), global_room_hex(&cave));
        assert_ne!(global_room_hex(&lair), global_room_hex(&base));
        // A different binary (GK) with the same word is a different
        // universe: per-clone isolation holds inside passcode rooms.
        let other_base = [8u8; 32];
        assert_ne!(
            effective_gk(&other_base, Some("lair")),
            effective_gk(&base, Some("lair"))
        );
    }
}

#[cfg(test)]
mod seal_tests {
    use super::*;
    use libp2p::identity::Keypair;
    use std::str::FromStr;

    fn gk() -> Key {
        [7u8; 32]
    }

    fn node(name: &str) -> (Rooms, PeerId) {
        let pid = Keypair::generate_ed25519().public().to_peer_id();
        (Rooms::new(gk(), pid.to_string(), name.into()), pid)
    }

    /// First Error envelope the host would send back, if any.
    fn sent_error(events: &[RoomEvent]) -> Option<String> {
        events.iter().find_map(|ev| match ev {
            RoomEvent::Send { envelope: Envelope::Error { message }, .. } => Some(message.clone()),
            _ => None,
        })
    }

    fn delivered_key(events: &[RoomEvent]) -> Option<u64> {
        events.iter().find_map(|ev| match ev {
            RoomEvent::Send { envelope: Envelope::KeyDelivery { epoch, .. }, .. } => Some(*epoch),
            _ => None,
        })
    }

    #[test]
    fn rotation_seals_the_room_to_strangers() {
        let (mut host, _hpid) = node("host");
        host.become_host(None, 1);
        assert!(host.rotate().is_some()); // epoch 2 — the door closes

        let (mut stranger, spid) = node("stranger");
        let events = host.handle(spid, stranger.join_envelope());
        let err = sent_error(&events).expect("stranger must be refused");
        assert!(err.starts_with("room-sealed"), "got: {err}");
        assert!(delivered_key(&events).is_none(), "no key may leak to a stranger");
        assert!(stranger.sealed == false); // latch flips on the GUEST side, below
    }

    #[test]
    fn sealed_guest_latches_on_refusal() {
        let (mut host, _hpid) = node("host");
        host.become_host(None, 1);
        assert!(host.rotate().is_some());

        let (mut guest, gpid) = node("guest");
        // Guest receives the host's refusal the transport would deliver.
        let refusal = Envelope::Error {
            message: "room-sealed: the room key was rotated — only current members keep access".into(),
        };
        let events = guest.handle(host_id(&host), refusal);
        assert!(matches!(events.as_slice(), [RoomEvent::Sealed]));
        assert!(guest.sealed, "join retry loop must stop");
    }

    #[test]
    fn members_still_rejoin_after_rotation() {
        let (mut host, hpid) = node("host");
        host.become_host(None, 1);

        // A member joins at epoch 1, then the host rotates.
        let (mut member, mpid) = node("member");
        let events = host.handle(mpid, member.join_envelope());
        assert_eq!(delivered_key(&events), Some(1), "member must be admitted");

        assert!(host.rotate().is_some()); // epoch 2

        // The member restarts / missed the rotation: their re-join (valid
        // GK proof, already on the member list) must still be admitted.
        let events = host.handle(mpid, member.join_envelope());
        assert!(sent_error(&events).is_none(), "member re-join must not be refused");
        assert_eq!(delivered_key(&events), Some(2), "member gets the current key");
        let _ = hpid;
    }

    #[test]
    fn stranger_cannot_seat_a_fresh_guest() {
        // A first KeyDelivery is only accepted from the host we mailed our
        // Join to — anyone holding the GK (public for earth) could
        // otherwise hand us their own key and hijack the session.
        let (mut host, _hpid) = node("host");
        let (mut guest, gpid) = node("guest");
        let (stranger, spid) = node("stranger");

        host.become_host(None, 1);
        guest.set_join_target(&host_id(&host));

        // The stranger races the real host with their own (validly
        // GK-sealed) delivery.
        let key = [9u8; 32];
        let ct = crypto::seal_room_key(
            &host.gk,
            &hex::decode(host.room_hex()).unwrap().try_into().unwrap(),
            1,
            &guest.my_id().to_string(),
            &key,
        );
        let poison = Envelope::KeyDelivery {
            room_id_hex: host.room_hex().to_string(),
            epoch: 1,
            key_ct_b64: crypto::base64_encode(&ct),
            members: vec![MemberInfo { peer: stranger.my_id().to_string(), name: "evil".into() }],
        };
        let events = guest.handle(spid, poison);
        assert!(guest.state().is_none(), "stranger delivery must not install a room");
        assert!(events.iter().any(|ev| matches!(ev, RoomEvent::ProtocolError { .. })));

        // The REAL host's delivery still seats us.
        let events = host.handle(gpid, guest.join_envelope());
        let delivery = events
            .iter()
            .find_map(|ev| match ev {
                RoomEvent::Send { peer, envelope: env @ Envelope::KeyDelivery { .. } } => Some((*peer, env.clone())),
                _ => None,
            })
            .expect("host must deliver the key");
        assert_eq!(delivery.0, gpid);
        let events = guest.handle(host_id(&host), delivery.1);
        assert!(matches!(events.first(), Some(RoomEvent::RoomReady { .. })));
        assert!(guest.state().is_some());
    }

    #[test]
    fn seated_guest_ignores_non_host_rekey_and_members() {
        let (mut host, _hpid) = node("host");
        let (mut guest, gpid) = node("guest");
        let (stranger, spid) = node("stranger");
        host.become_host(None, 1);

        // Seat the guest via the host's real delivery.
        guest.set_join_target(&host_id(&host));
        let events = host.handle(gpid, guest.join_envelope());
        let delivery = events
            .iter()
            .find_map(|ev| match ev {
                RoomEvent::Send { envelope: env @ Envelope::KeyDelivery { .. }, .. } => Some(env.clone()),
                _ => None,
            })
            .unwrap();
        guest.handle(host_id(&host), delivery);

        let members_before = guest.members();
        let epoch_before = guest.state().unwrap().crypto.epoch;

        // A non-host GK holder tries to re-key us and poison the list.
        let key = [9u8; 32];
        let ct = crypto::seal_room_key(
            &host.gk,
            &hex::decode(host.room_hex()).unwrap().try_into().unwrap(),
            5,
            &guest.my_id().to_string(),
            &key,
        );
        let poison = Envelope::KeyDelivery {
            room_id_hex: host.room_hex().to_string(),
            epoch: 5,
            key_ct_b64: crypto::base64_encode(&ct),
            members: vec![MemberInfo { peer: stranger.my_id().to_string(), name: "evil".into() }],
        };
        guest.handle(spid, poison);
        assert_eq!(guest.members(), members_before, "non-host must not change members");
        assert_eq!(guest.state().unwrap().crypto.epoch, epoch_before);
    }

    #[test]
    fn guest_adopts_host_rekey_on_redelivery() {
        // Missed rotation: the guest re-joins and the host re-delivers the
        // CURRENT key/epoch — the guest must adopt it, not keep the stale
        // key forever.
        let (mut host, _hpid) = node("host");
        let (mut guest, gpid) = node("guest");
        host.become_host(None, 1);

        guest.set_join_target(&host_id(&host));
        let events = host.handle(gpid, guest.join_envelope());
        let delivery = events
            .iter()
            .find_map(|ev| match ev {
                RoomEvent::Send { envelope: env @ Envelope::KeyDelivery { .. }, .. } => Some(env.clone()),
                _ => None,
            })
            .unwrap();
        guest.handle(host_id(&host), delivery);
        assert_eq!(guest.state().unwrap().crypto.epoch, 1);

        assert!(host.rotate().is_some()); // epoch 2, new key

        // Re-join from the (still listed) guest -> host re-delivers epoch 2.
        let events = host.handle(gpid, guest.join_envelope());
        let redelivery = events
            .iter()
            .find_map(|ev| match ev {
                RoomEvent::Send { envelope: env @ Envelope::KeyDelivery { .. }, .. } => Some(env.clone()),
                _ => None,
            })
            .unwrap();
        guest.set_join_target(&host_id(&host));
        guest.handle(host_id(&host), redelivery);

        let st = guest.state().unwrap();
        assert_eq!(st.crypto.epoch, 2, "guest must adopt the rotated epoch");
        assert_eq!(st.crypto.room_key(), host.state().unwrap().crypto.room_key());
    }

    fn host_id(host: &Rooms) -> PeerId {
        PeerId::from_str(&host.my_id).expect("valid peer id")
    }
}
