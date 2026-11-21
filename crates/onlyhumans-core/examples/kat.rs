//! Cross-implementation known-answer vectors for the web portal.
//!
//!   cargo run -p onlyhumans_core --example kat
//!
//! Prints one JSON object the portal's test suite must reproduce (hash /
//! derivation vectors) or successfully decrypt (sealed frames), proving
//! the browser crypto mirrors this core byte for byte.

use libp2p::identity::Keypair;
use onlyhumans_core::crypto::{self, kinds, RoomCrypto};
use onlyhumans_core::rooms::{effective_gk, global_room_hex};
use sha2::{Digest, Sha256};

fn main() {
    // Fixed test GK — independent of any release channel key.
    let gk: crypto::Key = Sha256::digest(b"kat-gk-v1").try_into().unwrap();

    // Fixed deterministic Ed25519 identity.
    let seed: [u8; 32] = Sha256::digest(b"kat-peer-seed").try_into().unwrap();
    let kp = Keypair::ed25519_from_bytes(seed).expect("fixed seed is valid");
    let peer_id = libp2p::PeerId::from(kp.public()).to_string();
    let pub_b64 = crypto::base64_encode(&kp.public().encode_protobuf());

    // Word derivations ("Secret" folds to "secret" — case-insensitive).
    let earth = effective_gk(&gk, Some("earth"));
    let secret = effective_gk(&gk, Some("Secret"));
    let room_hex = global_room_hex(&earth);

    // Admission proof for the Earth room.
    let nonce: [u8; 16] = Sha256::digest(b"kat-nonce")[..16].try_into().unwrap();
    let proof = crypto::admission_proof(&earth, &peer_id, &nonce);

    // Room key + host->guest delivery seal under the effective GK.
    let room_key: crypto::Key = Sha256::digest(b"kat-room-key").try_into().unwrap();
    let room_id: crypto::RoomId = hex::decode(&room_hex).unwrap().try_into().unwrap();
    let key_ct_epoch: u64 = 1;
    let key_ct = crypto::seal_room_key(&earth, &room_id, key_ct_epoch, &peer_id, &room_key);

    // A chat frame the portal must open with the delivered key.
    let rc = RoomCrypto::from_delivered(room_id, room_key);
    let sealed = rc.seal(&peer_id, 1_700_000_000_000, kinds::CHAT, b"hello from rust");

    // A mailbox-item signature the portal must verify with @noble/ed25519.
    let env_json = "{\"Ack\":{}}";
    let mail_msg = format!("OH1-mail-v1|{peer_id}|recipient|1700000000001|{env_json}");
    let mail_sig = kp.sign(mail_msg.as_bytes()).expect("sign");

    println!(
        "{}",
        serde_json::json!({
            "gk_hex": hex::encode(gk),
            "peer_id": peer_id,
            "public_key_b64": pub_b64,
            "earth_gk_hex": hex::encode(earth),
            "secret_gk_hex": hex::encode(secret),
            "room_hex": room_hex,
            "room_key_hex": hex::encode(room_key),
            "proof_nonce_hex": hex::encode(nonce),
            "admission_proof_hex": hex::encode(proof),
            "key_ct_epoch": key_ct_epoch,
            "key_ct_b64": crypto::base64_encode(&key_ct),
            "sealed": sealed,
            "chat_plaintext": "hello from rust",
            "mail_msg": mail_msg,
            "mail_sig_b64": crypto::base64_encode(&mail_sig),
            "argon2": {"m_kib": 65536, "t": 3, "p": 1, "len": 32},
        })
    );
}
