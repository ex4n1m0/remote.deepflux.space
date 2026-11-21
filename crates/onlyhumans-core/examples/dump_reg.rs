//! Dump a signed registration payload (for debugging hub verification).
//! cargo run -p onlyhumans_core --example dump_reg -- [output.json]

use onlyhumans_core::crypto;
use onlyhumans_core::hub::Registration; // re-export check
use onlyhumans_core::identity::Identity;

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join("oh-dump-reg");
    let _ = std::fs::remove_dir_all(&dir);
    let id = Identity::load_or_create(&dir)?;
    let addrs = vec!["/ip4/203.0.113.7/udp/4001/quic-v1".to_string()];
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64;
    let pub_b64 = crypto::base64_encode(&id.public_key_bytes());
    let sig = id.sign(&canonical(&id.id_string(), &pub_b64, &addrs, ts))?;

    let reg = Registration {
        peer_id: id.id_string(),
        public_key_b64: pub_b64,
        addrs,
        ts_ms: ts,
        sig_b64: crypto::base64_encode(&sig),
    };
    let out = std::env::args().nth(1).unwrap_or_else(|| "reg_dump.json".into());
    std::fs::write(&out, serde_json::to_string_pretty(&reg)?)?;
    println!("wrote {out} (peer {})", reg.peer_id);
    println!("canonical hex: {}", hex::encode(canonical(&reg.peer_id, &reg.public_key_b64, &reg.addrs, ts)));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
