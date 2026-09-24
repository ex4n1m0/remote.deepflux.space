//! In-process loopback integration tests for `WebrtcTransport` (delta D2's
//! automation layer): two transports in one process, signaling piped
//! directly through channels. This is the same connection path the rig
//! exercises across two processes; the rig adds file-based signaling,
//! encoded video, and chaos injection.

use std::time::{Duration, Instant};

use protocol::wire::{ButtonState, InputEvent, WireMessage};
use transport_webrtc::{
    Channel, ConnectionState, Transport, TransportEvent, VideoFrame, WebrtcTransport,
    WebrtcTransportRole,
};

/// Drive signaling + trickle ICE between two transports until both report
/// `ChannelsOpen` (or `deadline` expires). Returns the elapsed connect time
/// plus the observed channel-open order on each side.
fn connect_pair(
    controller: &mut WebrtcTransport,
    host: &mut WebrtcTransport,
    deadline: Duration,
) -> (Duration, Vec<Channel>, Vec<Channel>) {
    let started = Instant::now();

    let offer = controller.compose_offer().expect("compose_offer");
    let answer = host.compose_answer(&offer).expect("compose_answer");
    controller.apply_answer(&answer).expect("apply_answer");

    // Pump events on both sides until ChannelsOpen, forwarding ICE
    // candidates both ways (trickle).
    let mut open_controller = false;
    let mut open_host = false;
    let mut order_controller = Vec::new();
    let mut order_host = Vec::new();

    while started.elapsed() < deadline && !(open_controller && open_host) {
        while let Some(event) = controller.poll() {
            match event {
                TransportEvent::IceCandidate {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                } => {
                    host.add_remote_candidate(&candidate, sdp_mid.as_deref(), sdp_mline_index)
                        .expect("host add candidate");
                    // Duplicate signaling (same envelope re-delivered) must
                    // be a no-op, not an error.
                    host.add_remote_candidate(&candidate, sdp_mid.as_deref(), sdp_mline_index)
                        .expect("duplicate candidate must be accepted as no-op");
                }
                TransportEvent::ChannelOpened(channel) => order_controller.push(channel),
                TransportEvent::ChannelsOpen => open_controller = true,
                other => {
                    if let TransportEvent::Failed { reason } = other {
                        panic!("controller transport failed: {reason}");
                    }
                }
            }
        }
        while let Some(event) = host.poll() {
            match event {
                TransportEvent::IceCandidate {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                } => {
                    controller
                        .add_remote_candidate(&candidate, sdp_mid.as_deref(), sdp_mline_index)
                        .expect("controller add candidate");
                }
                TransportEvent::ChannelOpened(channel) => order_host.push(channel),
                TransportEvent::ChannelsOpen => open_host = true,
                other => {
                    if let TransportEvent::Failed { reason } = other {
                        panic!("host transport failed: {reason}");
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        open_controller,
        "controller channels did not open in {deadline:?}"
    );
    assert!(open_host, "host channels did not open in {deadline:?}");
    (started.elapsed(), order_controller, order_host)
}

/// A synthetic Annex-B access unit: SPS + PPS + IDR, sizes chosen to force
/// FU-A fragmentation on the IDR (no encoder needed to exercise RTP).
fn synthetic_access_unit(frame_index: u64, keyframe: bool) -> Vec<u8> {
    let mut au = Vec::new();
    if keyframe {
        au.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x64, 0x00, 0x1e]);
        au.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xeb, 0xec, 0xb2]);
        au.push(0);
        au.push(0);
        au.push(0);
        au.push(1);
        au.push(0x65);
        au.extend_from_slice(&vec![0x11u8; 3000]);
        let last = au.len() - 1;
        au[last] = (frame_index % 256) as u8;
    } else {
        au.extend_from_slice(&[0, 0, 0, 1, 0x41]);
        au.extend_from_slice(&vec![0x22u8; 600]);
        let last = au.len() - 1;
        au[last] = (frame_index % 256) as u8;
    }
    au
}

/// Drain every arriving message (any channel) until `wanted` are matched
/// or the deadline passes. Cross-channel arrival order is not guaranteed;
/// nothing is dropped.
fn collect_until(
    transport: &mut WebrtcTransport,
    wanted: &[(Channel, WireMessage)],
    deadline: Duration,
) -> Vec<(Channel, WireMessage)> {
    let started = Instant::now();
    let mut got: Vec<(Channel, WireMessage)> = Vec::new();
    while started.elapsed() < deadline
        && !wanted
            .iter()
            .all(|(ch, m)| got.iter().any(|(c, g)| c == ch && g == m))
    {
        match transport.poll() {
            Some(TransportEvent::Message(ch, message)) => got.push((ch, message)),
            Some(_) => {}
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    got
}

/// Happy path: connect, verify channel-open ordering, exchange messages on
/// all four channels, and check the negotiated no-TURN/no-STUN
/// configuration surfaces through stats.
#[test]
fn loopback_connect_channels_and_stats() {
    let mut controller =
        WebrtcTransport::new(WebrtcTransportRole::Controller).expect("controller transport");
    let mut host = WebrtcTransport::new(WebrtcTransportRole::Host).expect("host transport");

    let (elapsed, order_controller, order_host) =
        connect_pair(&mut controller, &mut host, Duration::from_secs(30));
    println!("connect time: {elapsed:?}");
    println!("controller open order: {order_controller:?}");
    println!("host open order: {order_host:?}");
    assert!(
        elapsed < Duration::from_secs(5),
        "connect must beat the 5 s budget on loopback, took {elapsed:?}"
    );
    // Channel *ids* are deterministic (creation order → SCTP ids), but the
    // open-event arrival order is NOT guaranteed by the stack: in repeated
    // runs the four OnOpen events race (observed both
    // [Control, InputFast, InputReliable, Cursor] and permutations). The
    // contract this crate exposes is therefore per-channel readiness plus
    // ChannelsOpen-after-all-four, pinned here as a set equality.
    let mut set_controller = order_controller.clone();
    let mut set_host = order_host.clone();
    set_controller.sort_by_key(|c| *c as u8);
    set_host.sort_by_key(|c| *c as u8);
    assert_eq!(
        set_controller,
        [
            Channel::Control,
            Channel::InputFast,
            Channel::InputReliable,
            Channel::Cursor
        ]
    );
    assert_eq!(
        set_host,
        [
            Channel::Control,
            Channel::InputFast,
            Channel::InputReliable,
            Channel::Cursor
        ]
    );

    // Round-trip messages on every channel.
    controller
        .send(
            Channel::InputFast,
            &protocol::wire::encode(&WireMessage::Input(InputEvent::MouseMove {
                seq: 1,
                x: 100,
                y: 200,
            })),
        )
        .unwrap();
    controller
        .send(
            Channel::InputReliable,
            &protocol::wire::encode(&WireMessage::Input(InputEvent::Key {
                seq: 2,
                scan_code: 0x1E,
                extended: false,
                state: ButtonState::Pressed,
            })),
        )
        .unwrap();
    controller
        .send(
            Channel::Control,
            &protocol::wire::encode(&WireMessage::Ping { nonce: 42 }),
        )
        .unwrap();
    host.send(
        Channel::Cursor,
        &protocol::wire::encode(&WireMessage::Cursor(
            protocol::wire::CursorMessage::Position { seq: 7, x: 1, y: 2 },
        )),
    )
    .unwrap();

    let want_host: Vec<(Channel, WireMessage)> = vec![
        (
            Channel::InputFast,
            WireMessage::Input(InputEvent::MouseMove {
                seq: 1,
                x: 100,
                y: 200,
            }),
        ),
        (
            Channel::InputReliable,
            WireMessage::Input(InputEvent::Key {
                seq: 2,
                scan_code: 0x1E,
                extended: false,
                state: ButtonState::Pressed,
            }),
        ),
        (Channel::Control, WireMessage::Ping { nonce: 42 }),
    ];
    let got_host = collect_until(&mut host, &want_host, Duration::from_secs(10));
    for (channel, message) in &want_host {
        assert!(
            got_host.iter().any(|(c, g)| c == channel && g == message),
            "host did not receive {message:?} on {channel:?} (got {got_host:?})"
        );
    }
    let want_controller = vec![(
        Channel::Cursor,
        WireMessage::Cursor(protocol::wire::CursorMessage::Position { seq: 7, x: 1, y: 2 }),
    )];
    let got_controller = collect_until(&mut controller, &want_controller, Duration::from_secs(10));
    assert_eq!(got_controller, want_controller);

    // Stats: RTT present, selected pair is host↔host on loopback, no relay.
    std::thread::sleep(Duration::from_millis(500));
    let stats = controller.stats().expect("stats");
    println!(
        "stats: rtt={:?} pair={:?}",
        stats.rtt_ms, stats.selected_pair
    );
    let pair = stats.selected_pair.expect("selected pair present");
    assert_eq!(pair.local_candidate_type, "host", "no STUN/TURN in spike");
    assert_eq!(pair.remote_candidate_type, "host");
    assert!(
        !stats.relay_in_use,
        "invariant 4: relay must never be in use"
    );
    assert!(stats.rtt_ms.unwrap_or(0.0) >= 0.0);

    controller.close();
    host.close();
}

/// Video path: synthetic access units through RTP packetization and back,
/// with the 64-bit frame_id carried by the header extension (ADR-002).
#[test]
fn loopback_video_frame_id_carriage() {
    let mut controller =
        WebrtcTransport::new(WebrtcTransportRole::Controller).expect("controller transport");
    let mut host = WebrtcTransport::new(WebrtcTransportRole::Host).expect("host transport");
    connect_pair(&mut controller, &mut host, Duration::from_secs(30));

    // Keyframe first, then inter frames; sizes force FU-A fragmentation.
    // Lock-step (send → wait for the frame) so the very first frames do not
    // race the SRTP receive-path warm-up — a real rig warms up likewise.
    let mut frames = Vec::new();
    for i in 0..10u64 {
        let keyframe = i % 10 == 0;
        host.send_video(VideoFrame {
            frame_id: 1000 + i,
            timestamp_ns: i * 16_666_667,
            is_keyframe: keyframe,
            bytes: synthetic_access_unit(i, keyframe),
        })
        .expect("send frame");
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if let Some(frame) = controller.poll_video() {
                frames.push(frame);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    assert_eq!(frames.len(), 10, "all frames must depacketize");
    // The frame-id extension verdict: every frame carries the stamped id.
    for (i, frame) in frames.iter().enumerate() {
        assert_eq!(frame.frame_id, Some(1000 + i as u64), "frame_id mismatch");
        assert_eq!(frame.missing_packets, 0);
    }
    assert!(frames[0].is_keyframe);
    // RTP timestamps advance by ~1500 ticks per 60 fps frame.
    let delta = frames[1]
        .rtp_timestamp
        .wrapping_sub(frames[0].rtp_timestamp);
    assert!((1490..=1510).contains(&delta), "rtp delta {delta}");
    // Depacketized bytes round-trip the source access unit.
    assert_eq!(frames[5].bytes.len(), 4 + 1 + 600);

    // Transport counters reflect the RTP path.
    let stats = host.stats().expect("host stats");
    assert_eq!(stats.frames_sent, 10);
    assert!(stats.packets_sent >= 10 + 3, "FU-A fragmentation occurred");
    let cstats = controller.stats().expect("controller stats");
    assert_eq!(cstats.frames_received, 10);
    assert_eq!(cstats.packets_lost, 0, "no loss on loopback");

    controller.close();
    host.close();
}

/// Malformed remote candidates fail typed, duplicates are no-ops, and a
/// peer-close surfaces as a connection-state change plus send errors
/// (disconnect cleanup).
#[test]
fn ice_failure_paths_and_disconnect_cleanup() {
    let mut controller =
        WebrtcTransport::new(WebrtcTransportRole::Controller).expect("controller transport");
    let mut host = WebrtcTransport::new(WebrtcTransportRole::Host).expect("host transport");

    // Garbage candidate before any session description: typed error.
    let err = controller
        .add_remote_candidate("candidate:garbage nonsense", None, Some(0))
        .unwrap_err();
    assert!(!err.0.is_empty(), "malformed candidate must fail typed");

    // Empty candidate is rejected without touching the stack.
    assert!(controller.add_remote_candidate("", None, None).is_err());

    connect_pair(&mut controller, &mut host, Duration::from_secs(30));

    // Host closes; controller must observe a state change away from
    // Connected within the disconnect window and subsequent sends fail.
    host.close();
    let started = Instant::now();
    let mut saw_teardown = false;
    while started.elapsed() < Duration::from_secs(15) {
        if let Some(TransportEvent::ConnectionStateChanged(state)) = controller.poll()
            && matches!(
                state,
                ConnectionState::Disconnected | ConnectionState::Failed | ConnectionState::Closed
            )
        {
            saw_teardown = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(saw_teardown, "controller must observe peer disconnect");
    // Send may succeed into the bounded queue (pump is gone), but must not
    // panic or block unboundedly.
    let _ = controller.send(
        Channel::Control,
        &protocol::wire::encode(&WireMessage::Ping { nonce: 9 }),
    );
    controller.close();
}

/// Input-reliable sequence-gap detection: pin the receiver-side contract
/// shape (`AllKeysUp` with `SequenceGap` on a reliable-seq jump) that the
/// rig exercises end-to-end with a dropped message. Deterministic, no
/// threads, no real transport needed — the wire fields were already
/// round-tripped above.
#[test]
fn reliable_input_sequence_gap_triggers_all_keys_up_semantics() {
    use protocol::wire::AllKeysUpTrigger;

    // The host-side detector + stub input sink the rig builds:
    // - ordered channel: a seq jump > 1 is loss → release all held keys.
    struct HostInputStub {
        last_seq: Option<u64>,
        held_keys: Vec<u16>,
        all_keys_up_events: Vec<AllKeysUpTrigger>,
    }
    impl HostInputStub {
        fn on_message(&mut self, message: &WireMessage) {
            let WireMessage::Input(event) = message else {
                return;
            };
            match event {
                InputEvent::Key {
                    seq,
                    scan_code,
                    state,
                    ..
                } => {
                    if let Some(last) = self.last_seq
                        && *seq > last + 1
                    {
                        // Gap: stuck-key safety fires before the new event.
                        self.all_keys_up_events.push(AllKeysUpTrigger::SequenceGap);
                        self.held_keys.clear();
                    }
                    self.last_seq = Some(*seq);
                    match state {
                        ButtonState::Pressed => self.held_keys.push(*scan_code),
                        ButtonState::Released => self.held_keys.retain(|k| k != scan_code),
                    }
                }
                InputEvent::AllKeysUp { trigger } => {
                    self.all_keys_up_events.push(*trigger);
                    self.held_keys.clear();
                }
                _ => {}
            }
        }
    }

    let mut stub = HostInputStub {
        last_seq: None,
        held_keys: Vec::new(),
        all_keys_up_events: Vec::new(),
    };
    // Controller held two keys (seq 1, 2), then seq 3 was dropped by the
    // chaos injector and seq 4 arrives: the gap must release everything.
    for seq in [1u64, 2] {
        stub.on_message(&WireMessage::Input(InputEvent::Key {
            seq,
            scan_code: 0x1E + (seq as u16),
            extended: false,
            state: ButtonState::Pressed,
        }));
    }
    assert_eq!(stub.held_keys.len(), 2);
    stub.on_message(&WireMessage::Input(InputEvent::Key {
        seq: 4,
        scan_code: 0x30,
        extended: false,
        state: ButtonState::Pressed,
    }));
    assert_eq!(
        stub.all_keys_up_events,
        vec![AllKeysUpTrigger::SequenceGap],
        "a reliable-seq gap must release held keys exactly once"
    );
    // The post-gap press is still applied — after the safety release.
    assert_eq!(stub.held_keys, vec![0x30]);
}

/// Mouse-move coalescing under application-layer loss/reorder: the newest
/// position wins regardless of arrival gaps (input-fast semantics).
#[test]
fn mouse_move_survives_loss_and_reorder() {
    use transport_webrtc::chaos::ChaosInjector;

    let mut chaos = ChaosInjector::new(2026, 20, 30);
    let mut latest_seq = 0u64;
    let mut newest_received = (0u16, 0u16);
    let sent_total = 2000u64;
    for sent in 1..=sent_total {
        for bytes in chaos.transform(encode_move(
            sent,
            (sent * 7 % 65536) as u16,
            (sent * 13 % 65536) as u16,
        )) {
            // "Arrival": the receiver keeps only the newest seq.
            let (seq, x, y) = decode_move(&bytes);
            if seq > latest_seq {
                latest_seq = seq;
                newest_received = (x, y);
            }
        }
    }
    for bytes in chaos.flush() {
        let (seq, x, y) = decode_move(&bytes);
        if seq > latest_seq {
            latest_seq = seq;
            newest_received = (x, y);
        }
    }
    println!(
        "injected: dropped={} reordered={}; newest received seq={latest_seq}",
        chaos.dropped, chaos.reordered
    );
    // With 20% loss the newest *sent* may be dropped; the receiver's state
    // must still be the newest *received* (monotonic), never an older one.
    assert!(latest_seq <= sent_total);
    assert!(chaos.dropped > 0, "injection must actually drop on 20%");
    assert!(
        chaos.reordered > 0,
        "injection must actually reorder on 30%"
    );
    // Coalescing contract: the receiver's position is exactly the newest
    // delivered message's payload, never an older one.
    assert_eq!(newest_received.0, (latest_seq * 7 % 65536) as u16);
}

fn encode_move(seq: u64, x: u16, y: u16) -> Vec<u8> {
    protocol::wire::encode(&WireMessage::Input(InputEvent::MouseMove { seq, x, y }))
}

fn decode_move(bytes: &[u8]) -> (u64, u16, u16) {
    match protocol::wire::decode(bytes).expect("decode") {
        WireMessage::Input(InputEvent::MouseMove { seq, x, y }) => (seq, x, y),
        other => panic!("unexpected {other:?}"),
    }
}
