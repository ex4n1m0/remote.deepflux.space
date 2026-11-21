//! Live mailbox round-trip against the production hub (the release ritual
//! companion to hub_check): register a throwaway identity, queue two
//! sealed items addressed to ourselves, drain them back, verify
//! signatures, and prove the drain is empty afterwards.
//!   cargo run -p onlyhumans_core --example mail_check
use onlyhumans_core::hub::{mail_canonical, verify_mail_item, HubClient, MailItem, DEFAULT_HUB};
use onlyhumans_core::identity::Identity;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dir = std::env::temp_dir().join(format!("oh-mailcheck-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let id = Identity::load_or_create(&dir)?;
    let hub = HubClient::new(DEFAULT_HUB);

    // Drain authorization checks the REGISTERED key, so register first.
    hub.register(&id, vec!["/ip4/127.0.0.1/tcp/1".to_string()]).await?;
    println!("registered {}", id.id_string());

    let to = id.id_string();
    let ts = 1789810000000u64;
    let envs = [r#"{"Ack":"Ack"}"#, r#"{"Error":{"message":"mail check"}}"#];
    let items: Vec<MailItem> = envs
        .iter()
        .map(|e| {
            let sig = id.sign(&mail_canonical(&to, &to, ts, e))?;
            Ok(MailItem {
                to: to.clone(),
                from: to.clone(),
                public_key_b64: onlyhumans_core::crypto::base64_encode(&id.public_key_bytes()),
                env_json: e.to_string(),
                ts_ms: ts,
                sig_b64: onlyhumans_core::crypto::base64_encode(&sig),
            })
        })
        .collect::<anyhow::Result<_>>()?;
    // Push through the real endpoint (client signs the same way the node does).
    let client = reqwest::Client::new();
    let url = format!("{DEFAULT_HUB}/api/inbox");
    let resp: serde_json::Value = client.post(&url).json(&serde_json::json!({ "items": items })).send().await?.json().await?;
    println!("push: {resp}");
    assert_eq!(resp["ok"], serde_json::json!(true), "push failed");

    let drained = hub.mail_drain(&id).await?;
    println!("drained {} item(s)", drained.len());
    assert_eq!(drained.len(), 2, "expected 2 items");
    for item in &drained {
        let from = verify_mail_item(item)?;
        assert_eq!(from, id.peer_id());
    }
    // Second drain must be empty (destructive).
    let again = hub.mail_drain(&id).await?;
    println!("second drain: {} item(s)", again.len());
    assert!(again.is_empty(), "drain is not destructive");

    let _ = std::fs::remove_dir_all(&dir);
    println!("MAIL CHECK PASSED");
    Ok(())
}
