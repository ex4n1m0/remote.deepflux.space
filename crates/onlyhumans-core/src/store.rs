//! Local encrypted storage (SQLite). Message bodies and room keys are
//! sealed at rest with a device-local key; the plaintext database never
//! contains conversation content.

use crate::crypto::{self, Key};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as AeadKey, XChaCha20Poly1305, XNonce};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub struct Store {
    conn: Connection,
    device_key: Key,
}

fn seal_local(key: &Key, what: &[u8], data: &[u8]) -> Vec<u8> {
    let derived = crate::crypto::admission_proof(key, "local-storage", &[0u8; 16]);
    let mut nonce = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(&derived));
    let mut aad = b"OH1-store".to_vec();
    aad.extend_from_slice(what);
    let mut out = nonce.to_vec();
    out.extend_from_slice(
        &cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload { msg: data, aad: &aad },
            )
            .expect("local seal"),
    );
    out
}

fn open_local(key: &Key, what: &[u8], blob: &[u8]) -> anyhow::Result<Vec<u8>> {
    let derived = crypto::admission_proof(key, "local-storage", &[0u8; 16]);
    // nonce is the first 24 bytes of the blob
    let (n, ct) = blob.split_at_checked(24).ok_or_else(|| anyhow::anyhow!("short blob"))?;
    let cipher = XChaCha20Poly1305::new(AeadKey::from_slice(&derived));
    let mut aad = b"OH1-store".to_vec();
    aad.extend_from_slice(what);
    cipher
        .decrypt(
            &XNonce::from(<[u8; 24]>::try_from(n).unwrap()),
            Payload { msg: ct, aad: &aad },
        )
        .map_err(|_| anyhow::anyhow!("local blob failed authentication"))
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Contact {
    pub peer_id: String,
    pub name: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Conversation {
    /// Wire names match the UI's expectations exactly.
    #[serde(rename = "room")]
    pub room_id_hex: String,
    #[serde(rename = "peer")]
    pub peer_id: String,
    /// Our role in this conversation.
    #[serde(rename = "isHost")]
    pub is_host: bool,
    #[serde(rename = "createdAt")]
    pub created_ts: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredMessage {
    pub id: i64,
    pub sender: String,
    pub body: String,
    pub ts: i64,
    /// true if we sent it
    pub outgoing: bool,
    pub epoch: u64,
}

impl Store {
    /// Open (or create) `onlyhumans.db` under `dir`, with a device key
    /// generated on first use.
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let keyfile = dir.join("device.key");
        let device_key: Key = if keyfile.exists() {
            let b = std::fs::read(&keyfile)?;
            b.try_into()
                .map_err(|_| anyhow::anyhow!("device.key must be 32 bytes"))?
        } else {
            let mut k = Key::default();
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
            std::fs::write(&keyfile, k)?;
            k
        };

        let conn = Connection::open(dir.join("onlyhumans.db"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS contacts(
                peer_id TEXT PRIMARY KEY,
                name TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS conversations(
                room_id_hex TEXT PRIMARY KEY,
                peer_id TEXT NOT NULL,
                is_host INTEGER NOT NULL,
                created_ts INTEGER NOT NULL,
                key_epoch INTEGER NOT NULL,
                room_key_sealed BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS messages(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id_hex TEXT NOT NULL,
                sender TEXT NOT NULL,
                body_sealed BLOB NOT NULL,
                ts INTEGER NOT NULL,
                epoch INTEGER NOT NULL);
             CREATE INDEX IF NOT EXISTS idx_messages_room
                ON messages(room_id_hex, id);",
        )?;
        Ok(Self { conn, device_key })
    }

    // -- contacts ---------------------------------------------------------

    pub fn add_contact(&self, peer_id: &str, name: &str) -> anyhow::Result<()> {
        self.conn
            .execute(
                "INSERT INTO contacts(peer_id, name) VALUES(?1, ?2)
                 ON CONFLICT(peer_id) DO UPDATE SET name=excluded.name",
                params![peer_id, name],
            )
            .map(|_| ())
            .map_err(Into::into)
    }

    pub fn remove_contact(&self, peer_id: &str) -> anyhow::Result<()> {
        self.conn
            .execute("DELETE FROM contacts WHERE peer_id=?1", params![peer_id])?;
        Ok(())
    }

    pub fn contacts(&self) -> anyhow::Result<Vec<Contact>> {
        let mut stmt = self.conn.prepare("SELECT peer_id, name FROM contacts ORDER BY name")?;
        let rows = stmt
            .query_map([], |r| Ok(Contact { peer_id: r.get(0)?, name: r.get(1)? }))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Delete every stored message of a room (the room itself survives).
    pub fn clear_messages(&self, room_id_hex: &str) -> anyhow::Result<()> {
        self.conn
            .execute("DELETE FROM messages WHERE room_id_hex=?1", params![room_id_hex])
            .map(|_| ())
            .map_err(Into::into)
    }

    /// Record a peer as a contact without clobbering a user-set name.
    pub fn add_contact_if_absent(&self, peer_id: &str) -> anyhow::Result<()> {
        self.conn
            .execute(
                "INSERT INTO contacts(peer_id, name) VALUES(?1, '')
                 ON CONFLICT(peer_id) DO NOTHING",
                params![peer_id],
            )
            .map(|_| ())
            .map_err(Into::into)
    }

    /// Store a room-shared display name for a peer, but never overwrite a
    /// name the local user chose manually (manual renames are non-empty).
    pub fn set_shared_name(&self, peer_id: &str, name: &str) -> anyhow::Result<()> {
        self.conn
            .execute(
                "INSERT INTO contacts(peer_id, name) VALUES(?1, ?2)
                 ON CONFLICT(peer_id) DO UPDATE SET name=excluded.name
                 WHERE contacts.name=''",
                params![peer_id, name],
            )
            .map(|_| ())
            .map_err(Into::into)
    }

    pub fn is_contact(&self, peer_id: &str) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM contacts WHERE peer_id=?1",
                params![peer_id],
                |_| Ok(()),
            )
            .optional()
            .ok()
            .flatten()
            .is_some()
    }

    // -- conversations ------------------------------------------------------

    pub fn upsert_conversation(
        &self,
        room_id_hex: &str,
        peer_id: &str,
        is_host: bool,
        room_key: &Key,
        epoch: u64,
    ) -> anyhow::Result<()> {
        let sealed = seal_local(&self.device_key, room_id_hex.as_bytes(), room_key);
        self.conn.execute(
            "INSERT INTO conversations(room_id_hex, peer_id, is_host, created_ts, key_epoch, room_key_sealed)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(room_id_hex) DO UPDATE SET
                key_epoch=excluded.key_epoch,
                room_key_sealed=excluded.room_key_sealed",
            params![
                room_id_hex,
                peer_id,
                is_host as i64,
                chrono_now_ms(),
                epoch as i64,
                sealed
            ],
        )?;
        Ok(())
    }

    pub fn conversations(&self) -> anyhow::Result<Vec<Conversation>> {
        let mut stmt = self
            .conn
            .prepare("SELECT room_id_hex, peer_id, is_host, created_ts FROM conversations")?;
        let rows = stmt
            .query_map([], |r| {
                Ok(Conversation {
                    room_id_hex: r.get(0)?,
                    peer_id: r.get(1)?,
                    is_host: r.get::<_, i64>(2)? != 0,
                    created_ts: r.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn conversation_by_peer(&self, peer_id: &str) -> anyhow::Result<Option<Conversation>> {
        self.conn
            .query_row(
                "SELECT room_id_hex, peer_id, is_host, created_ts FROM conversations
                 WHERE peer_id=?1 ORDER BY created_ts DESC LIMIT 1",
                params![peer_id],
                |r| {
                    Ok(Conversation {
                        room_id_hex: r.get(0)?,
                        peer_id: r.get(1)?,
                        is_host: r.get::<_, i64>(2)? != 0,
                        created_ts: r.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    /// Load (key, epoch) for a conversation.
    pub fn room_state(&self, room_id_hex: &str) -> anyhow::Result<Option<(Key, u64)>> {
        let row: Option<(Vec<u8>, i64)> = self
            .conn
            .query_row(
                "SELECT room_key_sealed, key_epoch FROM conversations WHERE room_id_hex=?1",
                params![room_id_hex],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((sealed, epoch)) => {
                let pt = open_local(&self.device_key, room_id_hex.as_bytes(), &sealed)?;
                let k: Key = pt
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("stored room key corrupt"))?;
                Ok(Some((k, epoch as u64)))
            }
        }
    }

    // -- messages -----------------------------------------------------------

    pub fn append_message(
        &self,
        room_id_hex: &str,
        sender: &str,
        body: &str,
        epoch: u64,
        outgoing: bool,
    ) -> anyhow::Result<i64> {
        let sealed = seal_local(&self.device_key, room_id_hex.as_bytes(), body.as_bytes());
        self.conn.execute(
            "INSERT INTO messages(room_id_hex, sender, body_sealed, ts, epoch)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![room_id_hex, sender, sealed, chrono_now_ms(), epoch as i64],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn messages(&self, room_id_hex: &str, limit: i64) -> anyhow::Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sender, body_sealed, ts, epoch FROM messages
             WHERE room_id_hex=?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let mut rows = stmt
            .query_map(params![room_id_hex, limit], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)? as u64,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.reverse();
        let my_id = self
            .conn
            .query_row(
                "SELECT peer_id FROM conversations WHERE room_id_hex=?1",
                params![room_id_hex],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_default();
        let _ = my_id;
        rows.into_iter()
            .map(|(id, sender, sealed, ts, epoch)| {
                let pt = open_local(&self.device_key, room_id_hex.as_bytes(), &sealed)?;
                Ok(StoredMessage {
                    id,
                    sender,
                    body: String::from_utf8_lossy(&pt).into_owned(),
                    ts,
                    outgoing: false, // filled by caller (needs our peer id)
                    epoch,
                })
            })
            .collect()
    }
}

fn chrono_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversations_and_messages_roundtrip_encrypted() {
        let dir = std::env::temp_dir().join(format!("oh-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::open(&dir).unwrap();

        s.add_contact("peerX", "Alice").unwrap();
        assert!(s.is_contact("peerX"));
        assert!(!s.is_contact("peerY"));
        assert_eq!(s.contacts().unwrap().len(), 1);

        let key = [9u8; 32];
        s.upsert_conversation("deadbeef", "peerX", true, &key, 1)
            .unwrap();
        let (k2, epoch) = s.room_state("deadbeef").unwrap().unwrap();
        assert_eq!(k2, key);
        assert_eq!(epoch, 1);

        // rotate: same room, new key/epoch
        let key2 = [8u8; 32];
        s.upsert_conversation("deadbeef", "peerX", true, &key2, 2)
            .unwrap();
        assert_eq!(s.room_state("deadbeef").unwrap().unwrap(), (key2, 2));

        s.append_message("deadbeef", "peerX", "hello world", 2, false)
            .unwrap();
        s.append_message("deadbeef", "me", "hi alice", 2, true).unwrap();
        let msgs = s.messages("deadbeef", 50).unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].body, "hello world");
        assert_eq!(msgs[1].body, "hi alice");

        // Plaintext must not appear in the raw database file.
        let raw = std::fs::read(dir.join("onlyhumans.db")).unwrap();
        let needle = b"hello world";
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "message plaintext leaked into the database file"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

impl Store {
    /// Drop a room's persisted state (key, epoch, host row). The node
    /// forgets it was ever in the room and rediscovers it from the hub —
    /// used when yielding to a live foreign host record and by the
    /// manual "reset room" recovery action.
    pub fn clear_conversation(&self, room_id_hex: &str) -> anyhow::Result<()> {
        self.conn
            .execute("DELETE FROM conversations WHERE room_id_hex = ?1", params![room_id_hex])?;
        Ok(())
    }
}
