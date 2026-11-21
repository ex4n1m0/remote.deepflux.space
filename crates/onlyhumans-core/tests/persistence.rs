//! Restart proof: the founding host stops and restarts (same data dir) and
//! restores the room from the encrypted store — same identity, same room
//! key — so the chat continues without a new join round.

use onlyhumans_core::net::{spawn, Command, NodeConfig, NodeEvent};
use std::time::Duration;
use tokio::sync::mpsc;

async fn next_event(rx: &mut mpsc::UnboundedReceiver<NodeEvent>, want: &str) -> NodeEvent {
    // Generous deadline: on slow shared CI runners the restarted guest's
    // reconnect (re-observe + re-dial past QUIC idle) can outlive 30s
    // while being perfectly healthy — this flaked CI more than once.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
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
        eprintln!("  [{want}] got {kind}: {ev:?}");
        if kind == want {
            return ev;
        }
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("oh-persist-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

#[tokio::test]
async fn host_room_survives_restart() {
    // A: founding host, profile reused across the restart below.
    let a_dir = temp_dir("a");
    let (a_tx, mut a_rx) = mpsc::unbounded_channel();
    let a = spawn(
        NodeConfig {
            data_dir: a_dir.clone(),
            offline: true,
            assume_host: true,
            username: Some("alice".into()),
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
    let room_hex = match next_event(&mut a_rx, "room_ready").await {
        NodeEvent::RoomReady { room, we_are_host: true, .. } => room,
        other => panic!("A should found the room, got {other:?}"),
    };

    // B joins.
    let (b_tx, mut b_rx) = mpsc::unbounded_channel();
    let b = spawn(
        NodeConfig {
            data_dir: temp_dir("b"),
            offline: true,
            room_host: Some(a.peer_id.to_string()),
            username: Some("bob".into()),
            ..Default::default()
        },
        b_tx,
    )
    .await
    .unwrap();
    b.cmd_tx
        .send(Command::Dial {
            addr: format!("{a_addr}/p2p/{}", a.peer_id).parse().unwrap(),
        })
        .await
        .unwrap();
    match next_event(&mut b_rx, "room_ready").await {
        NodeEvent::RoomReady { room, .. } => assert_eq!(room, room_hex),
        other => panic!("B should join the same room, got {other:?}"),
    }

    a.cmd_tx
        .send(Command::SendMessage { room: room_hex.clone(), text: "before restart".into() })
        .await
        .unwrap();
    match next_event(&mut b_rx, "message").await {
        NodeEvent::Message { body, room, .. } => {
            assert_eq!(body, "before restart");
            assert_eq!(room, room_hex);
        }
        other => panic!("expected message, got {other:?}"),
    }

    // --- A stops (clean shutdown releases ports + DB) and comes back ---
    a.cmd_tx.send(Command::Shutdown).await.unwrap();
    // Determinism across platforms: wait until B actually OBSERVES the
    // host going away (QUIC keepalive/ping timeout) before re-dialing —
    // on Linux the stale connection can otherwise outlive the restart
    // and race the rejoin.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "B never saw A leave");
        let ev = tokio::time::timeout(Duration::from_secs(5), b_rx.recv())
            .await
            .expect("timed out waiting for b events")
            .expect("node task died");
        if let NodeEvent::ConnectionStateChanged { peer, connected: false } = &ev {
            if *peer == a.peer_id.to_string() {
                break;
            }
        }
    }
    tokio::time::sleep(Duration::from_secs(1)).await;

    let (a2_tx, mut a2_rx) = mpsc::unbounded_channel();
    let a2 = spawn(
        NodeConfig {
            data_dir: a_dir.clone(),
            offline: true,
            assume_host: true,
            username: Some("alice".into()),
            ..Default::default()
        },
        a2_tx,
    )
    .await
    .unwrap();
    assert_eq!(
        a2.peer_id, a.peer_id,
        "same data dir must restore the same identity"
    );
    // Event order after a restart is NOT guaranteed: the restored room's
    // room_ready can arrive before the first listening event (or after),
    // so capture whichever comes first instead of assuming an order.
    let mut a2_ready_seen = false;
    let a2_addr = loop {
        match next_event(&mut a2_rx, "listening").await {
            NodeEvent::Listening { addr } if addr.contains("quic") => break addr,
            NodeEvent::RoomReady { room, we_are_host: true, epoch, .. } => {
                assert_eq!(room, room_hex, "restart must restore the same room");
                assert_eq!(epoch, 1);
                a2_ready_seen = true;
            }
            _ => continue,
        }
    };
    if !a2_ready_seen {
        match next_event(&mut a2_rx, "room_ready").await {
            NodeEvent::RoomReady { room, we_are_host: true, epoch, .. } => {
                assert_eq!(room, room_hex, "restart must restore the same room");
                assert_eq!(epoch, 1);
            }
            other => panic!("A2 should restore as host, got {other:?}"),
        }
    }

    // B reconnects to A's new listener; its message decrypts with the
    // key both sides restored/persisted — no new join round.
    b.cmd_tx
        .send(Command::SendMessage { room: room_hex.clone(), text: "after restart".into() })
        .await
        .unwrap();
    b.cmd_tx
        .send(Command::Dial {
            addr: format!("{a2_addr}/p2p/{}", a2.peer_id).parse().unwrap(),
        })
        .await
        .unwrap();
    match next_event(&mut a2_rx, "message").await {
        NodeEvent::Message { room, body, sender, .. } => {
            assert_eq!(room, room_hex);
            assert_eq!(body, "after restart");
            assert_eq!(sender, b.peer_id.to_string());
        }
        other => panic!("expected restored-room message, got {other:?}"),
    }

    a2.cmd_tx
        .send(Command::SendMessage { room: room_hex, text: "host back".into() })
        .await
        .unwrap();
    match next_event(&mut b_rx, "message").await {
        NodeEvent::Message { body, .. } => assert_eq!(body, "host back"),
        other => panic!("expected reply, got {other:?}"),
    }
}
