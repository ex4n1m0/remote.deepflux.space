//! Live-hub room election + join: A founds THE room (registers the host
//! record on the production Vercel hub); B discovers the record, dials A
//! via the hub, joins on GK proof, and the two chat. No Dial commands.
//! Requires network and mutates the real hub (records are TTL-scoped), so
//! it is ignored in the default suite:
//!
//! cargo test -p onlyhumans_core --test hub_live -- --ignored --nocapture

use onlyhumans_core::net::{spawn, Command, NodeConfig, NodeEvent};
use std::time::Duration;
use tokio::sync::mpsc;

async fn next_event(rx: &mut mpsc::UnboundedReceiver<NodeEvent>, want: &str) -> NodeEvent {
    next_event_within(rx, want, 60).await
}

/// Mailbox-delivery rounds wait on the 120 s drain cadence on BOTH sides,
/// so a single exchange can take several minutes.
async fn next_event_within(
    rx: &mut mpsc::UnboundedReceiver<NodeEvent>,
    want: &str,
    secs: u64,
) -> NodeEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
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
    let d = std::env::temp_dir().join(format!("oh-hubroom-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

async fn wait_members(
    rx: &mut mpsc::UnboundedReceiver<NodeEvent>,
    expect: &[String],
    secs: u64,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "members never settled");
        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timed out waiting for members")
            .expect("node task died");
        if let NodeEvent::MembersChanged { members, .. } = &ev {
            let mut got: Vec<String> = members.iter().map(|m| m.peer.clone()).collect();
            let mut want = expect.to_vec();
            got.sort();
            want.sort();
            if got == want {
                return;
            }
        }
    }
}

#[tokio::test]
#[ignore = "touches the production hub (network)"]
async fn room_election_and_join_through_live_hub() {
    // A: online founding host (skips the empty-record grace period).
    let (a_tx, mut a_rx) = mpsc::unbounded_channel();
    let a = spawn(
        NodeConfig {
            data_dir: temp_dir("a"),
            assume_host: true,
            username: Some("alice".into()),
            ..Default::default()
        },
        a_tx,
    )
    .await
    .unwrap();

    let a_room = match next_event(&mut a_rx, "room_ready").await {
        NodeEvent::RoomReady { room, we_are_host: true, .. } => room,
        other => panic!("A should found the room, got {other:?}"),
    };
    eprintln!("  room = {a_room}");

    // B: online joiner — discovers the host record and dials via the hub.
    let (b_tx, mut b_rx) = mpsc::unbounded_channel();
    let b = spawn(
        NodeConfig {
            data_dir: temp_dir("b"),
            username: Some("bob".into()),
            ..Default::default()
        },
        b_tx,
    )
    .await
    .unwrap();

    match next_event(&mut b_rx, "room_ready").await {
        NodeEvent::RoomReady { room, we_are_host: false, .. } => {
            assert_eq!(room, a_room, "B must land in the same global room");
        }
        other => panic!("B should join via the hub record, got {other:?}"),
    }

    let both = vec![a.peer_id.to_string(), b.peer_id.to_string()];
    wait_members(&mut a_rx, &both, 120).await;
    wait_members(&mut b_rx, &both, 360).await;

    a.cmd_tx.send(Command::SendMessage { room: a_room.clone(), text: "from founder".into() }).await.unwrap();
    match next_event(&mut b_rx, "message").await {
        NodeEvent::Message { body, sender, .. } => {
            assert_eq!(body, "from founder");
            assert_eq!(sender, a.peer_id.to_string());
        }
        other => panic!("expected message, got {other:?}"),
    }
    b.cmd_tx.send(Command::SendMessage { room: a_room, text: "from joiner".into() }).await.unwrap();
    match next_event(&mut a_rx, "message").await {
        NodeEvent::Message { body, sender, .. } => {
            assert_eq!(body, "from joiner");
            assert_eq!(sender, b.peer_id.to_string());
        }
        other => panic!("expected message, got {other:?}"),
    }
}

/// Mailbox-only join: A hosts with no listeners and registers with NO
/// addresses — exactly what the web portal is — so B can never dial it and
/// the whole join, key delivery and both chats must travel through the site
/// mailbox. Regression test for the browser-interop deadlock where a fresh
/// guest only ever dialed the host. Real delivery latency: every hop waits
/// on a 120 s mailbox drain, so expect up to ~10 minutes:
///
/// cargo test -p onlyhumans_core --test hub_live join_listenerless -- --ignored --nocapture
#[tokio::test]
#[ignore = "touches the production hub (network, slow: mailbox cadence)"]
async fn join_listenerless_host_via_site_mailbox() {
    // A random word room: this test must never touch earth or a real room.
    let word = format!("probe-{}", std::process::id());
    let long = 360;

    // A: mailbox-only founding host (skips the empty-record grace period).
    let (a_tx, mut a_rx) = mpsc::unbounded_channel();
    let a = spawn(
        NodeConfig {
            data_dir: temp_dir("mb-a"),
            // No listeners + mailbox_only = a faithful portal stand-in:
            // registers with zero addresses, reachable only via the site
            // mailbox.
            listen_quic: None,
            listen_tcp: None,
            assume_host: true,
            username: Some("alice".into()),
            passcode: Some(word.clone()),
            mailbox_only: true,
            ..Default::default()
        },
        a_tx,
    )
    .await
    .unwrap();

    let a_room = match next_event(&mut a_rx, "room_ready").await {
        NodeEvent::RoomReady { room, we_are_host: true, .. } => room,
        other => panic!("A should found the room, got {other:?}"),
    };
    eprintln!("  room = {a_room} (word {word})");

    // B: mailbox-only joiner — no addresses on either side, so nothing can
    // bypass the site mailbox.
    let (b_tx, mut b_rx) = mpsc::unbounded_channel();
    let b = spawn(
        NodeConfig {
            data_dir: temp_dir("mb-b"),
            listen_quic: None,
            listen_tcp: None,
            username: Some("bob".into()),
            passcode: Some(word),
            mailbox_only: true,
            ..Default::default()
        },
        b_tx,
    )
    .await
    .unwrap();

    let b_room = match next_event_within(&mut b_rx, "room_ready", long).await {
        NodeEvent::RoomReady { room, we_are_host: false, .. } => room,
        other => panic!("B should join via the site mailbox, got {other:?}"),
    };
    assert_eq!(b_room, a_room, "B must land in A's word room");

    let both = vec![a.peer_id.to_string(), b.peer_id.to_string()];
    wait_members(&mut a_rx, &both, 120).await;
    wait_members(&mut b_rx, &both, 360).await;

    b.cmd_tx.send(Command::SendMessage { room: b_room.clone(), text: "from mailbox joiner".into() }).await.unwrap();
    match next_event_within(&mut a_rx, "message", long).await {
        NodeEvent::Message { body, sender, .. } => {
            assert_eq!(body, "from mailbox joiner");
            assert_eq!(sender, b.peer_id.to_string());
        }
        other => panic!("expected message at host, got {other:?}"),
    }
    a.cmd_tx.send(Command::SendMessage { room: b_room, text: "from mailbox host".into() }).await.unwrap();
    match next_event_within(&mut b_rx, "message", long).await {
        NodeEvent::Message { body, sender, .. } => {
            assert_eq!(body, "from mailbox host");
            assert_eq!(sender, a.peer_id.to_string());
        }
        other => panic!("expected message at joiner, got {other:?}"),
    }
}

/// Live web-portal interop: host a word room from a BROWSER TAB (/join),
/// then point the app node at the same word. Verifies the real scenario
/// "one from the app, one from the browser" end to end. The guest joins
/// mailbox-only, exactly like a portal peer, so delivery is mail-only.
///
///   OH_TEST_WORD=<word> cargo test -p onlyhumans_core --test hub_live \
///     join_portal_hosted_room -- --ignored --nocapture
///
/// Build against the same universe the portal uses (release GK), e.g.
/// `. secrets/release-gk.env && OH_GK_A=$OH_GK_A OH_GK_B=$OH_GK_B cargo test …`,
/// and serve a gk.json carrying the FINISHED GK (see tools/deploy-release.sh).
#[tokio::test]
#[ignore = "live browser interop: set OH_TEST_WORD to the word the portal tab hosts"]
async fn join_portal_hosted_room() {
    let word = std::env::var("OH_TEST_WORD").unwrap_or_else(|_| {
        panic!("set OH_TEST_WORD to the room word the browser tab is hosting")
    });
    let long = 360;

    let (g_tx, mut g_rx) = mpsc::unbounded_channel();
    let g = spawn(
        NodeConfig {
            data_dir: temp_dir("portal-guest"),
            username: Some("app-guest".into()),
            passcode: Some(word.clone()),
            mailbox_only: true,
            ..Default::default()
        },
        g_tx,
    )
    .await
    .unwrap();

    let room = match next_event_within(&mut g_rx, "room_ready", long).await {
        NodeEvent::RoomReady { room, we_are_host: false, .. } => room,
        other => panic!("app guest should join the portal-hosted room, got {other:?}"),
    };
    eprintln!("  joined portal-hosted room {room} (word {word})");

    match next_event_within(&mut g_rx, "members", long).await {
        NodeEvent::MembersChanged { members, .. } => {
            assert!(members.len() >= 2, "portal host and app guest must see each other, got {members:?}");
        }
        other => panic!("expected members, got {other:?}"),
    }

    // One message out; the human (or automation) on the portal tab replies,
    // which shows up as a Message event in this test's log.
    g.cmd_tx.send(Command::SendMessage { room, text: "hello from the desktop app".into() }).await.unwrap();
    match next_event_within(&mut g_rx, "message", long).await {
        NodeEvent::Message { body, sender, .. } => {
            assert_ne!(sender, g.peer_id.to_string(), "reply must come from the portal host");
            eprintln!("  portal replied: {body}");
        }
        other => panic!("expected a reply from the portal host, got {other:?}"),
    }
}
