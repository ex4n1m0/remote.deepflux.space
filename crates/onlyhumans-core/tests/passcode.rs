//! Passcode rooms: an optional word at startup derives a parallel room
//! universe from (GK, word). Same word + same binary -> same room with a
//! full working lifecycle; a different word -> a different room; the
//! passcode room is never the main room.

use onlyhumans_core::net::{spawn, Command, NodeConfig, NodeEvent};
use std::time::Duration;
use tokio::sync::mpsc;

async fn next_event(rx: &mut mpsc::UnboundedReceiver<NodeEvent>, want: &str) -> NodeEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
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
        if kind == want {
            return ev;
        }
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("oh-pass-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[tokio::test]
async fn same_word_meets_different_word_isolates() {
    // A founds the "lair" passcode room.
    let (a_tx, mut a_rx) = mpsc::unbounded_channel();
    let a = spawn(
        NodeConfig {
            data_dir: temp_dir("a"),
            offline: true,
            assume_host: true,
            username: Some("alice".into()),
            passcode: Some("  Lair ".into()), // case/whitespace folded
            ..Default::default()
        },
        a_tx,
    )
    .await
    .unwrap();
    let a_addr = loop {
        match next_event(&mut a_rx, "listening").await {
            NodeEvent::Listening { addr } if addr.contains("quic") => break addr,
            _ => continue,
        }
    };
    let lair_hex = match next_event(&mut a_rx, "room_ready").await {
        NodeEvent::RoomReady { room, we_are_host: true, .. } => room,
        other => panic!("A should found the lair, got {other:?}"),
    };

    // The lair is not the main room of this binary's GK.
    let main_hex = onlyhumans_core::rooms::global_room_hex(&onlyhumans_core::global_key());
    assert_ne!(lair_hex, main_hex, "passcode room must differ from the main room");

    // C founds the "cave": a different universe entirely.
    let (c_tx, mut c_rx) = mpsc::unbounded_channel();
    let _c = spawn(
        NodeConfig {
            data_dir: temp_dir("c"),
            offline: true,
            assume_host: true,
            username: Some("carol".into()),
            passcode: Some("cave".into()),
            ..Default::default()
        },
        c_tx,
    )
    .await
    .unwrap();
    let _ = next_event(&mut c_rx, "listening").await;
    let cave_hex = match next_event(&mut c_rx, "room_ready").await {
        NodeEvent::RoomReady { room, .. } => room,
        other => panic!("C should found the cave, got {other:?}"),
    };
    assert_ne!(cave_hex, lair_hex);
    assert_ne!(cave_hex, main_hex);

    // B joins the lair with the same word (typed differently) and the
    // full lifecycle works inside the passcode universe.
    let (b_tx, mut b_rx) = mpsc::unbounded_channel();
    let b = spawn(
        NodeConfig {
            data_dir: temp_dir("b"),
            offline: true,
            room_host: Some(a.peer_id.to_string()),
            username: Some("bob".into()),
            passcode: Some("lair".into()),
            ..Default::default()
        },
        b_tx,
    )
    .await
    .unwrap();
    // Offline mode has no hub: B learns A the way the loopback harness
    // does — an explicit dial of A's captured QUIC address.
    b.cmd_tx
        .send(Command::Dial { addr: a_addr.parse().unwrap() })
        .await
        .unwrap();
    let b_hex = match next_event(&mut b_rx, "room_ready").await {
        NodeEvent::RoomReady { room, we_are_host: false, .. } => room,
        other => panic!("B should join the lair, got {other:?}"),
    };
    assert_eq!(b_hex, lair_hex, "same word must address the same room");

    // Chat inside the lair.
    b.cmd_tx
        .send(Command::SendMessage { room: lair_hex.clone(), text: "who's there".into() })
        .await
        .unwrap();
    match next_event(&mut a_rx, "message").await {
        NodeEvent::Message { room, sender, body, .. } => {
            assert_eq!(room, lair_hex);
            assert_eq!(sender, b.peer_id.to_string());
            assert_eq!(body, "who's there");
        }
        other => panic!("A should receive lair chat, got {other:?}"),
    }

    // Rotation inside the lair reaches the guest.
    a.cmd_tx.send(Command::Rotate).await.unwrap();
    let (ra, rb) = tokio::join!(
        next_event(&mut a_rx, "rotated"),
        next_event(&mut b_rx, "rotated")
    );
    assert_eq!(
        match ra {
            NodeEvent::Rotated { new_epoch, .. } => new_epoch,
            _ => 0,
        },
        match rb {
            NodeEvent::Rotated { new_epoch, .. } => new_epoch,
            _ => 1,
        }
    );
}
