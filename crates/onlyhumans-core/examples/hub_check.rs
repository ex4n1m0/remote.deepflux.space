//! End-to-end hub check against the LIVE deployment:
//! Rust client -> PUT /api/reg (TS verifies our Ed25519 signature)
//!             -> GET /api/lookup (Rust re-verifies the stored signature).
//! Run: cargo run -p onlyhumans_core --example hub_check

use onlyhumans_core::hub::HubClient;
use onlyhumans_core::identity::Identity;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join("oh-hub-check");
    let _ = std::fs::remove_dir_all(&dir);
    let id = Identity::load_or_create(&dir)?;

    let hub = HubClient::new("https://onlyhumans.deepflux.space");
    let addrs = vec![
        "/ip4/203.0.113.7/udp/4001/quic-v1".to_string(),
        "/ip4/203.0.113.7/tcp/4001".to_string(),
    ];

    println!("peer id : {}", id.id_string());
    println!("registering at the live hub...");
    let _observed = hub.register(&id, addrs.clone()).await?;
    println!("register: OK (hub verified our signature)");

    let got = hub.lookup(&id.id_string()).await?;
    assert!(got.is_some(), "record missing right after registration");
    let reg = got.unwrap();
    assert_eq!(reg.peer_id, id.id_string());
    assert_eq!(reg.addrs, addrs);
    println!("lookup  : OK ({} addrs, re-verified signature locally)", reg.addrs.len());

    // Tampering check: a lookup for someone else's id must be empty.
    let other = hub.lookup("12D3KooWNonexistentPeerIdForNegativeTest000000000000000").await?;
    assert!(other.is_none());
    println!("negative: OK (unknown peer -> None)");

    let _ = std::fs::remove_dir_all(&dir);
    println!("\nHUB END-TO-END: PASS");
    Ok(())
}
