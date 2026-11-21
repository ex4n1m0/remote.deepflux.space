//! Group-room milestone proof: three full nodes in one process, over real
//! libp2p QUIC on localhost, completing the entire protocol:
//! A founds the room (host) -> B and C join on GK proof -> key delivered
//! with member list -> chat fans out to everyone -> host rotation applies
//! everywhere (including the host's own UI) -> membership lists agree ->
//! DMs stay private -> clear wipes every store.

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
        eprintln!("  [{want}] got {kind}: {ev:?}");
        if kind == want {
            return ev;
        }
    }
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let d = temp_path(name);
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Same path, without the destructive cleanup (for re-opening stores of
/// already-spawned nodes).
fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("oh-group-{name}-{}", std::process::id()))
}

/// Wait until the members list equals `expect` (by peer id).
async fn wait_members(rx: &mut mpsc::UnboundedReceiver<NodeEvent>, expect: &[String], tag: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("timed out waiting for members")
            .expect("node task died");
        if let NodeEvent::MembersChanged { members, .. } = &ev {
            let mut got: Vec<String> = members.iter().map(|m| m.peer.clone()).collect();
            let mut want = expect.to_vec();
            got.sort();
            want.sort();
            if got == want {
                eprintln!("  [{tag}] members settled");
                return;
            }
        }
        eprintln!("  [{tag}/members] skip: {ev:?}");
    }
}

async fn wait_clear(rx: &mut mpsc::UnboundedReceiver<NodeEvent>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "clear never arrived");
        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out mid-wait")
            .expect("node task died");
        if matches!(ev, NodeEvent::MessagesCleared { .. }) {
            return;
        }
    }
}

#[tokio::test]
async fn three_nodes_one_room_full_lifecycle() {
    // Node A: founding host.
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

    let a_addr = loop {
        match next_event(&mut a_rx, "listening").await {
            NodeEvent::Listening { addr } if addr.contains("quic") => break addr,
            _ => continue,
        }
    };
    let room_hex = match next_event(&mut a_rx, "room_ready").await {
        NodeEvent::RoomReady { room, we_are_host: true, epoch, .. } => {
            assert_eq!(epoch, 1);
            room
        }
        other => panic!("A should be founding host, got {other:?}"),
    };

    // Nodes B and C: join A.
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
    let (c_tx, mut c_rx) = mpsc::unbounded_channel();
    let c = spawn(
        NodeConfig {
            data_dir: temp_dir("c"),
            offline: true,
            room_host: Some(a.peer_id.to_string()),
            username: Some("carol".into()),
            ..Default::default()
        },
        c_tx,
    )
    .await
    .unwrap();

    // Capture addresses BEFORE any waiter drains the channels — listening
    // events never repeat.
    let c_addr = loop {
        match next_event(&mut c_rx, "listening").await {
            NodeEvent::Listening { addr } if addr.contains("quic") => break addr,
            _ => continue,
        }
    };

    // Offline mode: guests dial the host explicitly (the tick sends Join
    // once connected).
    for h in [&b, &c] {
        h.cmd_tx
            .send(Command::Dial {
                addr: format!("{a_addr}/p2p/{}", a.peer_id).parse().unwrap(),
            })
            .await
            .unwrap();
    }

    next_event(&mut b_rx, "room_ready").await;
    next_event(&mut c_rx, "room_ready").await;

    // Membership settles on all three nodes.
    let all = vec![a.peer_id.to_string(), b.peer_id.to_string(), c.peer_id.to_string()];
    wait_members(&mut a_rx, &all, "A").await;
    wait_members(&mut b_rx, &all, "B").await;
    wait_members(&mut c_rx, &all, "C").await;

    // B and C learn about each other through the member list; offline
    // mode needs one explicit mesh dial between them.
    b.cmd_tx
        .send(Command::Dial {
            addr: format!("{c_addr}/p2p/{}", c.peer_id).parse().unwrap(),
        })
        .await
        .unwrap();

    // --- Chat: A -> everyone (mesh fan-out) ---
    a.cmd_tx
        .send(Command::SendMessage { room: room_hex.clone(), text: "hello room".into() })
        .await
        .unwrap();
    for (name, rx) in [("b", &mut b_rx), ("c", &mut c_rx)] {
        match next_event(rx, "message").await {
            NodeEvent::Message { body, sender, epoch, .. } => {
                assert_eq!(body, "hello room", "{name} must receive the host message");
                assert_eq!(sender, a.peer_id.to_string());
                assert_eq!(epoch, 1);
            }
            other => panic!("expected message, got {other:?}"),
        }
    }

    // --- Chat: B -> everyone (guest sends to the mesh) ---
    b.cmd_tx
        .send(Command::SendMessage { room: room_hex.clone(), text: "hi from b".into() })
        .await
        .unwrap();
    for (name, rx) in [("a", &mut a_rx), ("c", &mut c_rx)] {
        match next_event(rx, "message").await {
            NodeEvent::Message { body, sender, .. } => {
                assert_eq!(body, "hi from b");
                assert_eq!(sender, b.peer_id.to_string(), "{name} sees sender B");
            }
            other => panic!("expected message at {name}, got {other:?}"),
        }
    }

    // --- Host rotation applies everywhere (and to the host's own UI) ---
    a.cmd_tx.send(Command::Rotate).await.unwrap();
    for (name, rx) in [("a", &mut a_rx), ("b", &mut b_rx), ("c", &mut c_rx)] {
        match next_event(rx, "rotated").await {
            NodeEvent::Rotated { new_epoch, .. } => assert_eq!(new_epoch, 2, "{name} epoch"),
            other => panic!("expected rotation at {name}, got {other:?}"),
        }
    }

    a.cmd_tx
        .send(Command::SendMessage { room: room_hex.clone(), text: "epoch 2".into() })
        .await
        .unwrap();
    match next_event(&mut c_rx, "message").await {
        NodeEvent::Message { body, epoch, .. } => {
            assert_eq!(body, "epoch 2");
            assert_eq!(epoch, 2, "message must carry the new epoch");
        }
        other => panic!("expected post-rotation message, got {other:?}"),
    }

    // Guests cannot rotate.
    b.cmd_tx.send(Command::Rotate).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut saw_refusal = false;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(500), b_rx.recv()).await {
            if let NodeEvent::Log { message } = ev {
                if message.contains("only the host") {
                    saw_refusal = true;
                    break;
                }
            }
        }
    }
    assert!(saw_refusal, "guest rotate must be refused");

    // --- Private rooms: A clicks B -----------------------------------
    a.cmd_tx.send(Command::OpenDm { peer: b.peer_id.to_string() }).await.unwrap();
    let dm_ready = next_event(&mut b_rx, "room_ready").await;
    let dm_hex = match dm_ready {
        NodeEvent::RoomReady { room, .. } => room,
        other => panic!("B should get a dm RoomReady, got {other:?}"),
    };
    assert_ne!(dm_hex, room_hex, "dm must be a separate room");
    let _ = next_event(&mut a_rx, "room_ready").await;

    a.cmd_tx.send(Command::SendMessage { room: dm_hex.clone(), text: "private hello".into() }).await.unwrap();
    match next_event(&mut b_rx, "message").await {
        NodeEvent::Message { room, body, .. } => {
            assert_eq!(room, dm_hex);
            assert_eq!(body, "private hello");
        }
        other => panic!("expected dm message at B, got {other:?}"),
    }
    b.cmd_tx.send(Command::SendMessage { room: dm_hex.clone(), text: "private back".into() }).await.unwrap();
    match next_event(&mut a_rx, "message").await {
        NodeEvent::Message { room, body, .. } => {
            assert_eq!(room, dm_hex);
            assert_eq!(body, "private back");
        }
        other => panic!("expected dm reply at A, got {other:?}"),
    }
    {
        let mut leaked = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Some(ev)) = tokio::time::timeout(Duration::from_millis(200), c_rx.recv()).await {
                if let NodeEvent::Message { room, .. } = ev {
                    if room == dm_hex { leaked = true; }
                }
            }
        }
        assert!(!leaked, "C must not receive dm frames");
    }
    use onlyhumans_core::store::Store;
    for name in ["a", "b", "c"] {
        let st = Store::open(&temp_path(name)).unwrap();
        let dm_rows = st.messages(&dm_hex, 100).unwrap().len();
        assert_eq!(dm_rows, 0, "dm rows must never be persisted ({name})");
    }

    // --- Anyone can clear the room history for everyone ---
    let msg_count = |name: &str| {
        let st = Store::open(&temp_path(name)).unwrap();
        st.messages(&room_hex, 500).unwrap().len()
    };
    assert!(msg_count("a") > 0 && msg_count("b") > 0 && msg_count("c") > 0,
        "all three must have history before the clear");
    b.cmd_tx.send(Command::ClearHistory).await.unwrap();
    wait_clear(&mut a_rx).await;
    wait_clear(&mut c_rx).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(msg_count("a"), 0, "A's store must be wiped");
    assert_eq!(msg_count("b"), 0, "B's store must be wiped");
    assert_eq!(msg_count("c"), 0, "C's store must be wiped");
}
