//! Two-node network diagnosis against the LIVE hub: reproduces the
//! found->join handshake with full libp2p tracing (RUST_LOG).
//!   cargo run -p onlyhumans_core --example netdiag -- host <dir> <word>
//!   cargo run -p onlyhumans_core --example netdiag -- guest <dir> <word>
use onlyhumans_core::net::{spawn, NodeConfig, NodeEvent};
use std::time::Duration;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args: Vec<String> = std::env::args().collect();
    let (role, dir, word) = match args.as_slice() {
        [_, role, dir, word] => (role.clone(), dir.clone(), word.clone()),
        _ => {
            eprintln!("usage: netdiag <host|guest> <data-dir> <code-word>");
            std::process::exit(2);
        }
    };
    let cfg = NodeConfig {
        data_dir: dir.into(),
        username: Some(format!("diag-{role}")),
        passcode: Some(word),
        ..Default::default()
    };
    let (tx, mut rx) = mpsc::unbounded_channel();
    let node = spawn(cfg, tx).await.expect("spawn");
    println!("[{role}] peer {}", node.peer_id);
    let t0 = std::time::Instant::now();
    while let Some(ev) = rx.recv().await {
        let line = match &ev {
            NodeEvent::Log { message } => format!("LOG {message}"),
            NodeEvent::JoinStatus { status } => format!("STATUS {status}"),
            NodeEvent::RoomReady { room, peer, we_are_host, epoch } =>
                format!("READY {room} host={peer} we_host={we_are_host} epoch={epoch}"),
            NodeEvent::MembersChanged { members, .. } => format!(
                "MEMBERS {}",
                members.iter().map(|m| format!("{}:{}", &m.peer[..8.min(m.peer.len())], m.name)).collect::<Vec<_>>().join(",")
            ),
            NodeEvent::Message { sender, body, .. } => format!(
                "MSG {} {:?}",
                &sender[..8.min(sender.len())],
                body.clone()
            ),
            NodeEvent::ConnectionStateChanged { peer, connected } => format!(
                "CONN {} {}",
                &peer[..8.min(peer.len())],
                if *connected { "up" } else { "down" }
            ),
            NodeEvent::Presence { linked, online } => format!("PRESENCE linked={linked} online={online}"),
            _ => format!("{ev:?}"),
        };
        println!("[{role} +{:>5}s] {line}", t0.elapsed().as_secs());
        if t0.elapsed() > Duration::from_secs(300) {
            break;
        }
    }
    let _ = node.cmd_tx.send(onlyhumans_core::net::Command::Shutdown).await;
}
