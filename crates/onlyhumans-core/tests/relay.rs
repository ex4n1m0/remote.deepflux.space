//! Connectivity proof: a room join and chat delivered entirely through a
//! peer relay.
//!
//! Topology (all in-process, real libp2p transports):
//!
//!   R = relay node (offers HOP service)
//!   B = guest reachable ONLY via the relay (reserves a circuit through R)
//!   A = founding room host, dials B's circuit address
//!
//! A --(circuit via R)--> B must complete the full room lifecycle.

use onlyhumans_core::net::{spawn, Command, NodeConfig, NodeEvent};
use std::time::Duration;
use tokio::sync::mpsc;

async fn next_event(rx: &mut mpsc::UnboundedReceiver<NodeEvent>, want: &str) -> NodeEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("timed out waiting for event")
            .expect("node task died");
        let kind = match &ev {
            NodeEvent::Listening { .. } => "listening",
            NodeEvent::JoinStatus { .. } => "join_status",
            NodeEvent::RoomReady { .. } => "room_ready",
            NodeEvent::Message { .. } => "message",
            NodeEvent::MembersChanged { .. } => "members",
            NodeEvent::MessagesCleared { .. } => "messages_cleared",
            NodeEvent::Rotated { .. } => "rotated",
            NodeEvent::ConnectionStateChanged { .. } => "conn",
            NodeEvent::Log { .. } => "log",
            NodeEvent::Presence { .. } => "presence",
        };
        eprintln!("  [{want}] {kind}: {ev:?}");
        if kind == want {
            return ev;
        }
    }
}

async fn wait_for_log(
    rx: &mut mpsc::UnboundedReceiver<NodeEvent>,
    needle: &str,
) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv()).await;
        match ev {
            Err(_) => return false,
            Ok(None) => return false,
            Ok(Some(NodeEvent::Log { message })) => {
                eprintln!("  [log] {message}");
                if message.contains(needle) {
                    return true;
                }
            }
            Ok(Some(other)) => {
                eprintln!("  [log-skipped] {other:?}");
            }
        }
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("oh-relay-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[tokio::test]
async fn chat_through_peer_relay() {
    // --- Relay node R: fixed TCP port, forced HOP service ---
    let (r_tx, mut r_rx) = mpsc::unbounded_channel();
    let r = spawn(
        NodeConfig {
            data_dir: temp_dir("r"),
            offline: true,
            force_relay_hop: true,
            listen_quic: None,
            ..Default::default()
        },
        r_tx,
    )
    .await
    .unwrap();
    let r_addr = loop {
        match next_event(&mut r_rx, "listening").await {
            NodeEvent::Listening { addr } => break addr,
            _ => continue,
        }
    };

    // --- A: founding host of the room ---
    let (a_tx, mut a_rx) = mpsc::unbounded_channel();
    let a = spawn(
        NodeConfig {
            data_dir: temp_dir("a"),
            offline: true,
            assume_host: true,
            username: Some("alice".into()),
            ..Default::default()
        },
        a_tx,
    )
    .await
    .unwrap();
    let room_hex = match next_event(&mut a_rx, "room_ready").await {
        NodeEvent::RoomReady { room, we_are_host: true, .. } => room,
        other => panic!("A should found the room, got {other:?}"),
    };

    // --- B: no reachable listener of its own; reserves through R ---
    let (b_tx, mut b_rx) = mpsc::unbounded_channel();
    let b = spawn(
        NodeConfig {
            data_dir: temp_dir("b"),
            offline: true,
            listen_quic: None,
            room_host: Some(a.peer_id.to_string()),
            username: Some("bob".into()),
            ..Default::default()
        },
        b_tx,
    )
    .await
    .unwrap();
    let dial = format!("{r_addr}/p2p/{}", r.peer_id);
    b.cmd_tx
        .send(Command::Dial { addr: dial.parse().unwrap() })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    b.cmd_tx
        .send(Command::ReserveWith { addr: dial.parse().unwrap() })
        .await
        .unwrap();
    assert!(
        wait_for_log(&mut b_rx, "relay reservation accepted").await,
        "B never obtained a relay reservation"
    );

    // --- A dials B through the circuit; B's tick then sends its Join ---
    let circuit = format!("{r_addr}/p2p/{}/p2p-circuit/p2p/{}", r.peer_id, b.peer_id);
    a.cmd_tx
        .send(Command::Dial { addr: circuit.parse().unwrap() })
        .await
        .unwrap();

    match next_event(&mut b_rx, "room_ready").await {
        NodeEvent::RoomReady { room, we_are_host: false, .. } => assert_eq!(room, room_hex),
        other => panic!("B should join via relay, got {other:?}"),
    }

    a.cmd_tx
        .send(Command::SendMessage { room: room_hex.clone(), text: "hello via relay".into() })
        .await
        .unwrap();
    match next_event(&mut b_rx, "message").await {
        NodeEvent::Message { body, .. } => assert_eq!(body, "hello via relay"),
        other => panic!("expected message, got {other:?}"),
    }
    b.cmd_tx
        .send(Command::SendMessage { room: room_hex, text: "relayed back".into() })
        .await
        .unwrap();
    match next_event(&mut a_rx, "message").await {
        NodeEvent::Message { body, .. } => assert_eq!(body, "relayed back"),
        other => panic!("expected reply, got {other:?}"),
    }
}
