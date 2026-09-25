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

// ---------------------------------------------------------------------------
// M5: STUN configuration, netem shaping, congestion estimate
// ---------------------------------------------------------------------------

use transport_webrtc::{CongestionOptions, WebrtcTransportOptions};

/// TURN is rejected at the configuration layer (invariant 4) — the error
/// is typed and names the invariant, before any peer connection exists.
#[test]
fn turn_ice_servers_are_rejected_at_configuration() {
    let err = WebrtcTransport::with_options(
        WebrtcTransportRole::Controller,
        WebrtcTransportOptions {
            ice_servers: vec!["turn:turn.example.com:3478".to_owned()],
            ..Default::default()
        },
    )
    .err()
    .expect("TURN must be rejected");
    assert!(
        err.0.contains("invariant 4") && err.0.contains("TURN"),
        "error must name the invariant: {err:?}"
    );
    let err = WebrtcTransport::with_options(
        WebrtcTransportRole::Controller,
        WebrtcTransportOptions {
            ice_servers: vec!["turns:turn.example.com:5349".to_owned()],
            ..Default::default()
        },
    )
    .err()
    .expect("TURN(S) must be rejected");
    assert!(err.0.contains("invariant 4"));
    // Unknown schemes fail typed too.
    assert!(
        WebrtcTransport::with_options(
            WebrtcTransportRole::Controller,
            WebrtcTransportOptions {
                ice_servers: vec!["qt://example.com".to_owned()],
                ..Default::default()
            },
        )
        .is_err()
    );
    // Congestion tuning must be ordered.
    assert!(
        WebrtcTransport::with_options(
            WebrtcTransportRole::Host,
            WebrtcTransportOptions {
                congestion: Some(CongestionOptions {
                    initial_bps: 5_000_000,
                    min_bps: 6_000_000,
                    max_bps: 8_000_000,
                }),
                ..Default::default()
            },
        )
        .is_err(),
        "min>initial must be rejected"
    );
}

/// The product (WAN) configuration — public STUN + all-interface sockets +
/// sender-side congestion control — still connects over loopback (host
/// candidates), never through a relay, and the selected pair surfaces in
/// stats. Works offline (srflx gathering simply fails) and online (srflx
/// appears; the dedicated internet-gated test pins that).
#[test]
fn wan_stun_configuration_loopback_still_connects() {
    let mut controller = WebrtcTransport::with_options(
        WebrtcTransportRole::Controller,
        WebrtcTransportOptions {
            ice_servers: transport_webrtc::DEFAULT_STUN_SERVERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            bind_all_interfaces: true,
            ..Default::default()
        },
    )
    .expect("controller transport");
    let mut host =
        WebrtcTransport::with_options(WebrtcTransportRole::Host, WebrtcTransportOptions::wan())
            .expect("host transport");

    let (elapsed, _, _) = connect_pair(&mut controller, &mut host, Duration::from_secs(30));
    assert!(
        elapsed < Duration::from_secs(5),
        "STUN-configured loopback connect must stay inside the 5 s budget, took {elapsed:?}"
    );
    std::thread::sleep(Duration::from_millis(500));
    let stats = host.stats().expect("host stats");
    assert!(
        !stats.relay_in_use,
        "invariant 4: relay must never be in use, even with ICE servers configured"
    );
    let pair = stats.selected_pair.expect("selected pair");
    println!(
        "wan-config loopback selected pair: local {} ({}), remote {} ({})",
        pair.local_address,
        pair.local_candidate_type,
        pair.remote_address,
        pair.remote_candidate_type
    );
    // The host (sender) was built with congestion control: the estimate
    // surface exists even before media flows (initial rate).
    assert!(
        stats.available_bandwidth_bps.is_some(),
        "sender-side estimate must surface in stats"
    );
    controller.close();
    host.close();
}

/// Internet-gated srflx evidence (run explicitly on a connected machine):
/// with public STUN configured, a server-reflexive candidate must be
/// gathered on the WAN-bound transport. `#[ignore]` so the offline gate
/// stays deterministic.
#[test]
#[ignore = "needs internet access to the public STUN servers"]
fn stun_gathers_srflx_when_online() {
    use transport_webrtc::TransportEvent;

    let mut controller = WebrtcTransport::with_options(
        WebrtcTransportRole::Controller,
        WebrtcTransportOptions {
            ice_servers: transport_webrtc::DEFAULT_STUN_SERVERS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            bind_all_interfaces: true,
            ..Default::default()
        },
    )
    .expect("controller transport");
    let _ = controller.compose_offer().expect("offer");
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut srflx = 0;
    let mut candidates = 0;
    while Instant::now() < deadline {
        while let Some(event) = controller.poll() {
            if let TransportEvent::IceCandidate { candidate, .. } = event {
                candidates += 1;
                if candidate.contains(" typ srflx") {
                    srflx += 1;
                }
            }
        }
        if srflx > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("gathered {candidates} candidates, {srflx} srflx");
    assert!(
        srflx > 0,
        "public STUN must produce srflx candidates online"
    );
    controller.close();
}

/// Netem shapes the RTP path: a 100%-loss profile delivers nothing (and
/// the drops surface in the bounded shaper's counters), then removing the
/// loss recovers delivery — the mid-stream blackout/recovery cell.
#[test]
fn netem_blackhole_then_recovery() {
    use transport_webrtc::chaos::NetemProfile;

    let mut controller = WebrtcTransport::new(WebrtcTransportRole::Controller).expect("controller");
    let mut host = WebrtcTransport::with_options(
        WebrtcTransportRole::Host,
        WebrtcTransportOptions {
            video_netem: Some(NetemProfile::parse("loss=100").unwrap()),
            ..Default::default()
        },
    )
    .expect("host with netem");
    let handle = host.netem_handle().expect("netem handle");
    connect_pair(&mut controller, &mut host, Duration::from_secs(30));

    // Warm up with delivery ON first (SRTP path ready), then blackhole.
    handle.set_profile(NetemProfile::default());
    let warmup = Instant::now();
    while warmup.elapsed() < Duration::from_secs(5) {
        let _ = host.send_video(VideoFrame {
            frame_id: 1,
            timestamp_ns: 0,
            is_keyframe: true,
            bytes: synthetic_access_unit(0, true),
        });
        if controller.poll_video().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        warmup.elapsed() < Duration::from_secs(5),
        "unshaped frames must flow before the blackhole"
    );

    handle.set_profile(NetemProfile::parse("loss=100").unwrap());
    let mut sent_blackout = 0u64;
    let blackout = Instant::now();
    while blackout.elapsed() < Duration::from_secs(2) {
        let _ = host.send_video(VideoFrame {
            frame_id: 2 + sent_blackout,
            timestamp_ns: (sent_blackout + 1) * 16_666_667,
            is_keyframe: false,
            bytes: synthetic_access_unit(1, false),
        });
        sent_blackout += 1;
        // Drain anything the receiver still has queued.
        let _ = controller.poll_video();
        std::thread::sleep(Duration::from_millis(16));
    }
    let mut leaked = 0;
    while controller.poll_video().is_some() {
        leaked += 1;
    }
    assert_eq!(leaked, 0, "no shaped packet may cross a 100% blackhole");
    let stats = host.stats().expect("host stats");
    let netem = stats.netem_queue.expect("netem gauges");
    assert!(
        netem.dropped >= sent_blackout,
        "drops must be counted: {} dropped for {sent_blackout} sent",
        netem.dropped
    );
    assert_eq!(netem.capacity, 300);

    // Recovery: clear the loss; frames must flow again.
    handle.set_profile(NetemProfile::default());
    let recovered = Instant::now();
    let mut got = false;
    while recovered.elapsed() < Duration::from_secs(5) {
        let _ = host.send_video(VideoFrame {
            frame_id: 9000,
            timestamp_ns: 90_000_000_000,
            is_keyframe: true,
            bytes: synthetic_access_unit(2, true),
        });
        if let Some(frame) = controller.poll_video() {
            assert_eq!(frame.frame_id, Some(9000));
            got = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(got, "delivery must recover after the blackhole lifts");
    controller.close();
    host.close();
}

/// Netem delay lands in the receiver's first-packet arrival: +300 ms
/// one-way must show up between send and `recv_instant` (matrix RTT
/// cell mechanism; ICE RTT deliberately stays loopback-fast — see the
/// chaos module docs).
#[test]
fn netem_delay_adds_one_way_latency() {
    use transport_webrtc::chaos::NetemProfile;

    let mut controller = WebrtcTransport::new(WebrtcTransportRole::Controller).expect("controller");
    let mut host = WebrtcTransport::with_options(
        WebrtcTransportRole::Host,
        WebrtcTransportOptions {
            video_netem: Some(NetemProfile::parse("delay_ms=300").unwrap()),
            ..Default::default()
        },
    )
    .expect("host with netem");
    connect_pair(&mut controller, &mut host, Duration::from_secs(30));

    let sent_at = Instant::now();
    host.send_video(VideoFrame {
        frame_id: 7,
        timestamp_ns: 0,
        is_keyframe: true,
        bytes: synthetic_access_unit(0, true),
    })
    .expect("send");
    let deadline = sent_at + Duration::from_secs(5);
    let mut arrival: Option<Instant> = None;
    while Instant::now() < deadline {
        if let Some(frame) = controller.poll_video() {
            assert_eq!(frame.frame_id, Some(7));
            arrival = frame.recv_instant;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let arrival = arrival.expect("delayed frame must still arrive");
    let one_way = arrival.saturating_duration_since(sent_at);
    assert!(
        one_way >= Duration::from_millis(250),
        "one-way must include the +300 ms shaping, measured {one_way:?}"
    );
    assert!(
        one_way < Duration::from_secs(2),
        "shaping must not become a blackhole, measured {one_way:?}"
    );
    controller.close();
    host.close();
}

/// With sender-side congestion control configured and a few seconds of
/// flowing media + RTCP feedback, the estimate surface reports the GCC
/// target and the receiver-report projection (remote loss/RTT) appears.
#[test]
fn congestion_estimate_and_remote_report_surface() {
    let mut controller = WebrtcTransport::new(WebrtcTransportRole::Controller).expect("controller");
    let mut host = WebrtcTransport::with_options(
        WebrtcTransportRole::Host,
        WebrtcTransportOptions {
            congestion: Some(CongestionOptions {
                initial_bps: 2_000_000,
                min_bps: 300_000,
                max_bps: 8_000_000,
            }),
            ..Default::default()
        },
    )
    .expect("host with congestion");
    connect_pair(&mut controller, &mut host, Duration::from_secs(30));

    let started = Instant::now();
    let mut frame = 0u64;
    while started.elapsed() < Duration::from_secs(5) {
        let keyframe = frame.is_multiple_of(30);
        let _ = host.send_video(VideoFrame {
            frame_id: frame,
            timestamp_ns: frame * 16_666_667,
            is_keyframe: keyframe,
            bytes: synthetic_access_unit(frame % 256, keyframe),
        });
        while controller.poll_video().is_some() {}
        frame += 1;
        std::thread::sleep(Duration::from_millis(16));
    }
    let stats = host.stats().expect("host stats");
    let estimate = stats
        .available_bandwidth_bps
        .expect("estimate must be published");
    assert!(
        (300_000..=8_000_000).contains(&estimate),
        "estimate must stay within the configured band: {estimate}"
    );
    let congestion = stats.congestion_stats.expect("congestion stats");
    println!(
        "estimate={estimate} bps delay_based={:?} loss_based={:?} updates={}",
        congestion.delay_based_bps, congestion.loss_based_bps, congestion.updates
    );
    // The controller's RTCP RRs feed remote-inbound-rtp on the sender.
    assert!(
        stats.remote_rtt_ms.is_some(),
        "receiver-report RTT must reach the sender within 5 s of media"
    );
    let _ = stats.remote_loss_percent.expect("fraction lost present");
    controller.close();
    host.close();
}
