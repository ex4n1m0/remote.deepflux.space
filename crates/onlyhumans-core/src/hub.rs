//! Address-hub client. The hub (Vercel + Upstash) is a dumb, signed
//! {peer_id -> addresses} directory with TTL; clients verify every record
//! they fetch and trust nothing beyond reachability hints.

use crate::identity::Identity;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registration {
    pub peer_id: String,
    pub public_key_b64: String,
    pub addrs: Vec<String>,
    pub ts_ms: u64,
    pub sig_b64: String,
}

/// Who currently hosts a room: a signed, TTL-scoped pointer so joiners can
/// find the host through the hub. First writer wins (the endpoint stores
/// with NX), which is the room-creation election.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomHostRecord {
    pub room_id: String,
    pub host_peer_id: String,
    pub host_public_key_b64: String,
    pub ts_ms: u64,
    pub sig_b64: String,
}

#[derive(Debug, Serialize)]
struct PresencePing<'a> {
    token: &'a str,
    leave: bool,
}

#[derive(Debug, Default, Deserialize)]
struct PresenceResp {
    #[serde(default)]
    online: u64,
}

/// One queued envelope in the site mailbox: an opaque, end-to-end sealed
/// Envelope JSON plus the sender's signature. The hub verifies the
/// signature before storing; the recipient verifies it AGAIN and checks
/// that the included key derives the claimed sender id, so the hub
/// remains untrusted storage for mail exactly as for addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailItem {
    pub to: String,
    pub from: String,
    pub public_key_b64: String,
    pub env_json: String,
    pub ts_ms: u64,
    pub sig_b64: String,
}

/// Canonical bytes a sender signs for one mailbox item.
pub fn mail_canonical(from: &str, to: &str, ts_ms: u64, env_json: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"OH1-mail-v1|");
    v.extend_from_slice(from.as_bytes());
    v.push(b'|');
    v.extend_from_slice(to.as_bytes());
    v.push(b'|');
    v.extend_from_slice(ts_ms.to_string().as_bytes());
    v.push(b'|');
    v.extend_from_slice(env_json.as_bytes());
    v
}

/// Canonical bytes a peer signs to authorize draining its own inbox.
fn drain_canonical(peer: &str, ts_ms: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"OH1-drain-v1|");
    v.extend_from_slice(peer.as_bytes());
    v.push(b'|');
    v.extend_from_slice(ts_ms.to_string().as_bytes());
    v
}

/// Full recipient-side verification of a drained item: the signature must
/// verify under the included libp2p public key, and that key must derive
/// exactly the claimed sender peer id. Returns the verified sender.
pub fn verify_mail_item(item: &MailItem) -> anyhow::Result<libp2p::PeerId> {
    let pub_bytes = crate::crypto::base64_decode(&item.public_key_b64)?;
    let sig = crate::crypto::base64_decode(&item.sig_b64)?;
    let key = libp2p::identity::PublicKey::try_decode_protobuf(&pub_bytes)
        .map_err(|_| anyhow::anyhow!("mail item: bad public key protobuf"))?;
    let derived = key.to_peer_id();
    if derived.to_string() != item.from {
        anyhow::bail!("mail item: key does not derive the claimed sender");
    }
    let canon = mail_canonical(&item.from, &item.to, item.ts_ms, &item.env_json);
    if !Identity::verify(&pub_bytes, &canon, &sig) {
        anyhow::bail!("mail item: signature verification failed");
    }
    Ok(derived)
}

fn room_canonical(room_id: &str, host: &str, pub_b64: &str, ts_ms: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"OH1-room|");
    v.extend_from_slice(room_id.as_bytes());
    v.push(b'|');
    v.extend_from_slice(host.as_bytes());
    v.push(b'|');
    v.extend_from_slice(pub_b64.as_bytes());
    v.push(b'|');
    v.extend_from_slice(ts_ms.to_string().as_bytes());
    v
}

/// Canonical bytes that get signed for registration.
fn canonical(peer_id: &str, pub_b64: &str, addrs: &[String], ts_ms: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"OH1-reg|");
    v.extend_from_slice(peer_id.as_bytes());
    v.push(b'|');
    v.extend_from_slice(pub_b64.as_bytes());
    v.push(b'|');
    v.extend_from_slice(addrs.join(",").as_bytes());
    v.push(b'|');
    v.extend_from_slice(ts_ms.to_string().as_bytes());
    v
}

pub struct HubClient {
    base: String,
    http: reqwest::Client,
}

pub const DEFAULT_HUB: &str = "https://onlyhumans.deepflux.space";

impl HubClient {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }

    /// Register our addresses. Returns the public IP the hub OBSERVED on
    /// its HTTPS socket (mini-STUN) when it reports one — advisory data
    /// from the response, never stored server-side.
    pub async fn register(&self, id: &Identity, addrs: Vec<String>) -> anyhow::Result<Option<String>> {
        let ts_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let pub_b64 = crate::crypto::base64_encode(&id.public_key_bytes());
        let canon = canonical(&id.id_string(), &pub_b64, &addrs, ts_ms);
        let sig = id.sign(&canon)?;
        let reg = Registration {
            peer_id: id.id_string(),
            public_key_b64: pub_b64,
            addrs,
            ts_ms,
            sig_b64: crate::crypto::base64_encode(&sig),
        };
        let resp = self
            .http
            .put(format!("{}/api/reg", self.base))
            .json(&reg)
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("hub register failed: {} {}", resp.status(), resp.text().await.unwrap_or_default());
        }
        #[derive(serde::Deserialize, Default)]
        struct RegResp {
            #[serde(default)]
            observed_ip: Option<String>,
            #[serde(rename = "observedIp", default)]
            observed_ip_camel: Option<String>,
        }
        let r: RegResp = resp.json().await.unwrap_or_default();
        Ok(r.observed_ip.or(r.observed_ip_camel).filter(|s| !s.trim().is_empty()))
    }

    /// Anonymous presence beacon for the site's live counter. The token is
    /// random per app start — deliberately NOT the peer id — so the hub can
    /// count running apps but never tie a count to an identity. Returns the
    /// current online count (including us).
    pub async fn presence(&self, token: &str) -> anyhow::Result<u64> {
        let resp = self
            .http
            .post(format!("{}/api/presence", self.base))
            .json(&PresencePing { token, leave: false })
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            // We beat at most every ~120s; a 429 means a beat landed <30s
            // ago, so the site still counts us.
            return Ok(0);
        }
        if !resp.status().is_success() {
            anyhow::bail!("presence failed: {} {}", resp.status(), resp.text().await.unwrap_or_default());
        }
        let r: PresenceResp = resp.json().await.unwrap_or_default();
        Ok(r.online)
    }

    /// Remove our presence token (best-effort graceful exit; the entry
    /// also expires on its own).
    pub async fn presence_leave(&self, token: &str) -> anyhow::Result<()> {
        let resp = self
            .http
            .post(format!("{}/api/presence", self.base))
            .json(&PresencePing { token, leave: true })
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("presence leave failed: {}", resp.status());
        }
        Ok(())
    }

    /// Queue sealed envelopes for peers we cannot reach directly, as ONE
    /// batched request carrying mixed recipients (the hub throttles per
    /// SENDER to one push every 4 s and caps a push at 16 items — callers
    /// pass at most 16 envelopes and at most one batch per few seconds).
    /// Items are signed by us; peers drain them on their next hub cycle.
    pub async fn mail_push_many(
        &self,
        id: &Identity,
        items: &[(String, crate::rooms::Envelope)],
    ) -> anyhow::Result<()> {
        assert!(items.len() <= 16, "the hub caps a mail push at 16 items");
        let ts_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let pub_b64 = crate::crypto::base64_encode(&id.public_key_bytes());
        let from = id.id_string();
        let mut out = Vec::with_capacity(items.len());
        for (to, env) in items {
            let env_json = serde_json::to_string(env)?;
            let sig = id.sign(&mail_canonical(&from, to, ts_ms, &env_json))?;
            out.push(MailItem {
                to: to.clone(),
                from: from.clone(),
                public_key_b64: pub_b64.clone(),
                env_json,
                ts_ms,
                sig_b64: crate::crypto::base64_encode(&sig),
            });
        }
        let resp = self
            .http
            .post(format!("{}/api/inbox", self.base))
            .json(&serde_json::json!({ "items": out }))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("mail push failed: {} {}", resp.status(), resp.text().await.unwrap_or_default());
        }
        Ok(())
    }

    /// Drain our mailbox (requires our signature, so only we can read it).
    pub async fn mail_drain(&self, id: &Identity) -> anyhow::Result<Vec<MailItem>> {
        let ts_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let peer = id.id_string();
        let sig = crate::crypto::base64_encode(&id.sign(&drain_canonical(&peer, ts_ms))?);
        let resp = self
            .http
            .get(format!("{}/api/inbox/{peer}?ts_ms={ts_ms}&sig_b64={sig}", self.base))
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!("mail drain failed: {} {}", resp.status(), resp.text().await.unwrap_or_default());
        }
        #[derive(serde::Deserialize, Default)]
        struct DrainResp {
            #[serde(default)]
            items: Vec<MailItem>,
        }
        let r: DrainResp = resp.json().await.unwrap_or_default();
        Ok(r.items)
    }

    /// Look up a peer; returns None if unknown/expired. Signatures are
    /// verified locally before returning (the hub is untrusted storage).
    pub async fn lookup(&self, peer_id: &str) -> anyhow::Result<Option<Registration>> {
        let resp = self
            .http
            .get(format!("{}/api/lookup/{peer_id}", self.base))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!("hub lookup failed: {}", resp.status());
        }
        let reg: Registration = resp.json().await?;
        let pub_bytes = crate::crypto::base64_decode(&reg.public_key_b64)?;
        let sig = crate::crypto::base64_decode(&reg.sig_b64)?;
        let canon = canonical(&reg.peer_id, &reg.public_key_b64, &reg.addrs, reg.ts_ms);
        if reg.peer_id != peer_id {
            anyhow::bail!("hub returned a different peer id than requested");
        }
        if !Identity::verify(&pub_bytes, &canon, &sig) {
            anyhow::bail!("hub record failed signature verification");
        }
        // The key must derive the claimed peer id — the hub is untrusted
        // storage, so the binding the server enforces is enforced here too.
        let key = libp2p::identity::PublicKey::try_decode_protobuf(&pub_bytes)
            .map_err(|_| anyhow::anyhow!("peer record: bad public key protobuf"))?;
        if key.to_peer_id().to_string() != reg.peer_id {
            anyhow::bail!("peer record: key does not derive the claimed peer id");
        }
        Ok(Some(reg))
    }

    /// Publish ourselves as the host of `room_id`. Returns false when the
    /// record already exists (someone else hosts — first-writer-wins
    /// election lost, so join them instead).
    pub async fn register_room(&self, id: &Identity, room_id: &str) -> anyhow::Result<bool> {
        let ts_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let pub_b64 = crate::crypto::base64_encode(&id.public_key_bytes());
        let canon = room_canonical(room_id, &id.id_string(), &pub_b64, ts_ms);
        let sig = id.sign(&canon)?;
        let rec = RoomHostRecord {
            room_id: room_id.to_string(),
            host_peer_id: id.id_string(),
            host_public_key_b64: pub_b64,
            ts_ms,
            sig_b64: crate::crypto::base64_encode(&sig),
        };
        let resp = self
            .http
            .put(format!("{}/api/room", self.base))
            .json(&rec)
            .send()
            .await?;
        match resp.status() {
            s if s.is_success() => Ok(true),
            reqwest::StatusCode::CONFLICT => Ok(false),
            s => anyhow::bail!("room register failed: {} {}", s, resp.text().await.unwrap_or_default()),
        }
    }

    /// Fetch (and verify) the current host record of a room.
    pub async fn lookup_room(&self, room_id: &str) -> anyhow::Result<Option<RoomHostRecord>> {
        let resp = self
            .http
            .get(format!("{}/api/room/{room_id}", self.base))
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!("room lookup failed: {}", resp.status());
        }
        let rec: RoomHostRecord = resp.json().await?;
        let pub_bytes = crate::crypto::base64_decode(&rec.host_public_key_b64)?;
        let sig = crate::crypto::base64_decode(&rec.sig_b64)?;
        let canon = room_canonical(&rec.room_id, &rec.host_peer_id, &rec.host_public_key_b64, rec.ts_ms);
        if rec.room_id != room_id {
            anyhow::bail!("hub returned a different room id than requested");
        }
        if !Identity::verify(&pub_bytes, &canon, &sig) {
            anyhow::bail!("room record failed signature verification");
        }
        // The key must derive the claimed host peer id (the server checks
        // this too; we don't take the hub's word for it).
        let key = libp2p::identity::PublicKey::try_decode_protobuf(&pub_bytes)
            .map_err(|_| anyhow::anyhow!("room record: bad public key protobuf"))?;
        if key.to_peer_id().to_string() != rec.host_peer_id {
            anyhow::bail!("room record: key does not derive the claimed host");
        }
        Ok(Some(rec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_signing_is_verifiable() {
        // Exercise canonical()+verify without a network.
        let dir = std::env::temp_dir().join(format!("oh-hub-{}", std::process::id()));
        let id = Identity::load_or_create(&dir).unwrap();
        let pub_b64 = crate::crypto::base64_encode(&id.public_key_bytes());
        let addrs = vec!["/ip4/1.2.3.4/udp/4001/quic-v1".to_string()];
        let ts = 1234567890u64;
        let canon = canonical(&id.id_string(), &pub_b64, &addrs, ts);
        let sig = id.sign(&canon).unwrap();
        assert!(Identity::verify(
            &id.public_key_bytes(),
            &canon,
            &sig
        ));
        // Tampered addrs must fail
        let canon2 = canonical(&id.id_string(), &pub_b64, &["/ip4/9.9.9.9".to_string()], ts);
        assert!(!Identity::verify(&id.public_key_bytes(), &canon2, &sig));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod mail_tests {
    use super::*;

    fn tmp_identity(tag: &str) -> (Identity, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("oh-mail-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (Identity::load_or_create(&dir).unwrap(), dir)
    }

    fn item_from(id: &Identity, to: &str, env_json: &str) -> MailItem {
        let ts = 1234567890u64;
        let from = id.id_string();
        let sig = id.sign(&mail_canonical(&from, to, ts, env_json)).unwrap();
        MailItem {
            to: to.to_string(),
            from,
            public_key_b64: crate::crypto::base64_encode(&id.public_key_bytes()),
            env_json: env_json.to_string(),
            ts_ms: ts,
            sig_b64: crate::crypto::base64_encode(&sig),
        }
    }

    #[test]
    fn mail_item_verifies_and_derives_sender() {
        let (id, dir) = tmp_identity("ok");
        let item = item_from(&id, "12D3KooWTargetTargetTargetTargetTargetTarge", r#"{"Ack":"Ack"}"#);
        let from = verify_mail_item(&item).unwrap();
        assert_eq!(from, id.peer_id());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tampered_envelope_fails() {
        let (id, dir) = tmp_identity("tamper");
        let mut item = item_from(&id, "12D3KooWTargetTargetTargetTargetTargetTarge", r#"{"Ack":"Ack"}"#);
        item.env_json = r#"{"Join":{}}"#.to_string();
        assert!(verify_mail_item(&item).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn foreign_key_claiming_an_id_fails() {
        // Signed by A, but claims to be B: the key must derive `from`.
        let (a, da) = tmp_identity("signer");
        let (b, db) = tmp_identity("claimed");
        let mut item = item_from(&a, "12D3KooWTargetTargetTargetTargetTargetTarge", r#"{"Ack":"Ack"}"#);
        item.from = b.id_string();
        assert!(verify_mail_item(&item).is_err());
        let _ = std::fs::remove_dir_all(da);
        let _ = std::fs::remove_dir_all(db);
    }

    #[test]
    fn mail_item_json_field_names_are_snake_case() {
        // The wire contract with api/inbox.ts (Rust->TS field gotcha).
        let (id, dir) = tmp_identity("serde");
        let item = item_from(&id, "peer-x", "{}");
        let j = serde_json::to_string(&item).unwrap();
        for f in ["\"to\"", "\"from\"", "\"public_key_b64\"", "\"env_json\"", "\"ts_ms\"", "\"sig_b64\""] {
            assert!(j.contains(f), "missing {f} in {j}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
