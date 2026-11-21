//! Integration tests over real loopback TCP sockets (ADR-018 Phase C gate).
//!
//! Coverage: (a) full request→deltas→completed flow with handshake signature
//! verification, (b) tampered handshake rejection, (c) oversized frames
//! refused before body allocation/read, (d) deadline expiry → Timeout + close,
//! (e) non-loopback bind refusal, (f) RTT stats sanity, (g) concurrent
//! sessions on one listener, (h) cancel delivery mid-stream, plus handshake
//! policy rejections (stale timestamp).

use std::collections::HashMap;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use modelswarm_identity::{canonical_json, InstallationIdentity};
use modelswarm_transport::{
    verify_handshake, Cancel, Cancelled, ChatMessage, Completed, Handshake, HandshakeError,
    InferenceRequest, Listener, Sampling, Session, SignedFrameTransport, TokenDelta,
    TransportError, Usage, WireMessage, MAX_FRAME_BYTES,
};
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::oneshot;

const D: Duration = Duration::from_secs(5);
const PROFILE: &str = "msp:sim-mock:v1";

fn ident(seed: u8) -> InstallationIdentity {
    InstallationIdentity::from_bytes(&[seed; 32])
}

fn handshake_for(identity: &InstallationIdentity) -> Handshake {
    Handshake::build(identity, PROFILE, "llama.cpp", "test-build")
}

fn sample_request(request_id: &str) -> InferenceRequest {
    InferenceRequest {
        request_id: request_id.to_string(),
        profile_id: PROFILE.to_string(),
        capability_token: "sim.capability.token".to_string(),
        messages: vec![ChatMessage {
            role: "user".to_string(),
            content: "Say hello".to_string(),
        }],
        sampling: Sampling {
            temperature: 0.7,
            top_p: 0.9,
            top_k: 40,
            seed: Some(42),
        },
        max_tokens: 32,
        deadline_ms: 5_000,
        stream: true,
    }
}

/// Re-signs an edited handshake with `identity`'s key (test-side mirror of
/// the crate-private signer; the payload form is the msp-v1 §2.2 canonical
/// JSON of the eight signed fields).
fn re_sign(handshake: &mut Handshake, identity: &InstallationIdentity) {
    let key = SigningKey::from_bytes(&identity.to_bytes());
    let payload = canonical_json(&json!({
        "protocol_version": handshake.protocol_version,
        "peer_id": handshake.peer_id,
        "installation_id": handshake.installation_id,
        "profile_id": handshake.profile_id,
        "runtime_name": handshake.runtime_name,
        "runtime_build": handshake.runtime_build,
        "ts": handshake.ts,
        "nonce": handshake.nonce,
    }))
    .expect("canonical json of string fields");
    handshake.signature = B64.encode(key.sign(payload.as_bytes()).to_bytes());
}

async fn make_listener() -> Listener {
    SignedFrameTransport::listen("127.0.0.1:0")
        .await
        .expect("loopback bind")
}

/// Serving side for happy-path flows: accept (verifying against `client`),
/// answer every InferenceRequest with two deltas + usage + completion. The
/// done channel fires `Ok` once at least one request was served and the
/// client went away, or carries the failure otherwise.
async fn spawn_responder(
    listener: Listener,
    client: &InstallationIdentity,
) -> oneshot::Receiver<Result<(), TransportError>> {
    let expected = client.verifying_key();
    let (done_tx, done_rx) = oneshot::channel();
    tokio::spawn(async move {
        let result = serve(listener, &expected).await;
        let _ = done_tx.send(result);
    });
    done_rx
}

async fn serve(
    listener: Listener,
    expected: &ed25519_dalek::VerifyingKey,
) -> Result<(), TransportError> {
    let mut session = listener.accept(expected, D).await?;
    let mut served = false;
    loop {
        let msg = match session.recv(D).await {
            Ok(msg) => msg,
            // Client closed after being served: normal termination.
            Err(_) if served => return Ok(()),
            Err(err) => return Err(err),
        };
        let WireMessage::InferenceRequest(req) = msg else {
            continue;
        };
        for (index, delta) in ["Hel", "lo"].iter().enumerate() {
            session
                .send(
                    WireMessage::TokenDelta(TokenDelta {
                        request_id: req.request_id.clone(),
                        delta: (*delta).to_string(),
                        index: index as u32,
                    }),
                    D,
                )
                .await?;
        }
        session
            .send(
                WireMessage::Usage(Usage {
                    prompt_tokens: 12,
                    completion_tokens: 2,
                    prefill_ms: 3,
                    decode_ms: 4,
                }),
                D,
            )
            .await?;
        session
            .send(
                WireMessage::Completed(Completed {
                    request_id: req.request_id.clone(),
                    finish_reason: "stop".to_string(),

                    job_receipt: None,
                }),
                D,
            )
            .await?;
        served = true;
    }
}

// (a) ----------------------------------------------------------------------

#[tokio::test]
async fn loopback_pair_full_flow_with_signature_checks() {
    let client = ident(1);
    let listener = make_listener().await;
    let addr = listener.local_addr().unwrap();
    let responder = spawn_responder(listener, &client).await;

    // The outbound handshake verifies against its own key before it is sent.
    let hs = handshake_for(&client);
    assert!(verify_handshake(&WireMessage::Handshake(hs.clone()), &client.verifying_key()).is_ok());

    let mut session: Session = SignedFrameTransport::connect(&addr.to_string(), hs, D)
        .await
        .expect("handshake exchange");
    session
        .send(WireMessage::InferenceRequest(sample_request("req-a-1")), D)
        .await
        .expect("send request");

    let mut text = String::new();
    let mut deltas = 0u32;
    let mut usage: Option<Usage> = None;
    let mut finish_reason: Option<String> = None;
    while let Ok(msg) = session.recv(D).await {
        match msg {
            WireMessage::TokenDelta(delta) => {
                assert_eq!(delta.request_id, "req-a-1");
                assert_eq!(delta.index, deltas, "deltas arrive in order");
                text.push_str(&delta.delta);
                deltas += 1;
            }
            WireMessage::Usage(u) => usage = Some(u),
            WireMessage::Completed(c) => {
                assert_eq!(c.request_id, "req-a-1");
                finish_reason = Some(c.finish_reason);
                break;
            }
            other => panic!("unexpected message in stream: {other:?}"),
        }
    }
    assert_eq!(text, "Hello");
    assert_eq!(deltas, 2);
    let usage = usage.expect("usage precedes completed");
    assert_eq!(usage.prompt_tokens, 12);
    assert_eq!(usage.completion_tokens, 2);
    assert_eq!(finish_reason.as_deref(), Some("stop"));
    session.close();
    responder
        .await
        .expect("responder finished")
        .expect("responder flow after clean client close");
}

// (b) ----------------------------------------------------------------------

#[tokio::test]
async fn tampered_handshake_signature_is_rejected() {
    let client = ident(2);
    let listener = make_listener().await;
    let addr = listener.local_addr().unwrap();
    let server_key = client.verifying_key();
    let server = tokio::spawn(async move { listener.accept(&server_key, D).await });

    // Tamper the signature value itself (still valid base64, wrong bytes —
    // the first char is never the '=' padding).
    let mut hs = handshake_for(&client);
    let flipped = if hs.signature.starts_with('A') {
        'B'
    } else {
        'A'
    };
    hs.signature.replace_range(0..1, &flipped.to_string());
    assert_eq!(
        verify_handshake(&WireMessage::Handshake(hs.clone()), &client.verifying_key()).unwrap_err(),
        HandshakeError::BadSignature
    );

    // The full exchange rejects it too: the peer's negative ack (§6.5 code)
    // turns into HandshakeFailed.
    let err = SignedFrameTransport::connect(&addr.to_string(), hs, D)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, TransportError::HandshakeFailed(code) if code == "handshake_failed"),
        "expected handshake_failed, got {err:?}"
    );
    assert_eq!(err.msp_code(), Some("handshake_failed"));

    let server_result = server.await.unwrap();
    assert!(
        server_result.is_err(),
        "server must reject the tampered handshake"
    );
}

#[tokio::test]
async fn handshake_tampering_a_signed_field_is_rejected() {
    let client = ident(3);
    // A field inside the signed payload is swapped for a different valid
    // value: the signature no longer matches the canonical payload.
    let mut hs = handshake_for(&client);
    hs.profile_id = "msp:someone-else:v1".to_string();
    assert_eq!(
        verify_handshake(&WireMessage::Handshake(hs), &client.verifying_key()).unwrap_err(),
        HandshakeError::BadSignature
    );
}

// (c) ----------------------------------------------------------------------

#[tokio::test]
async fn oversized_frame_rejected_before_body_read() {
    let listener = make_listener().await;
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio::spawn(async move {
        // The frame error must happen during the handshake read, before any
        // signature/peer logic runs.
        listener.accept_with(|_| None, D).await
    });

    let mut raw = TcpStream::connect(addr).await.expect("raw connect");
    // Announce MAX+1 bytes but never send a body. If the reader tried to
    // allocate/read the body first, it would block here (and hit EOF when
    // the socket closes) instead of returning TooLarge.
    raw.write_all(&(MAX_FRAME_BYTES as u32 + 1).to_be_bytes())
        .await
        .unwrap();
    raw.flush().await.unwrap();

    let started = std::time::Instant::now();
    let err = tokio::time::timeout(Duration::from_secs(3), acceptor)
        .await
        .expect("must reject without waiting for the body")
        .expect("acceptor finished")
        .unwrap_err();
    assert!(matches!(err, TransportError::TooLarge), "got {err:?}");
    assert_eq!(err.msp_code(), Some("payload_too_large"));
    assert!(started.elapsed() < Duration::from_secs(3));
    raw.shutdown().await.ok();
}

// (d) ----------------------------------------------------------------------

#[tokio::test]
async fn deadline_expiry_returns_timeout_and_closes() {
    let client = ident(4);
    let listener = make_listener().await;
    let addr = listener.local_addr().unwrap();

    // Responder completes the handshake, then goes silent.
    let expected = client.verifying_key();
    let responder = tokio::spawn(async move {
        let session = listener.accept(&expected, D).await?;
        // Hold the session open, send nothing, outlive the client deadline.
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        drop(session);
        Ok::<(), TransportError>(())
    });

    let mut session = SignedFrameTransport::connect(&addr.to_string(), handshake_for(&client), D)
        .await
        .expect("connect");

    let err = session.recv(Duration::from_millis(50)).await.unwrap_err();
    assert!(matches!(err, TransportError::Timeout), "got {err:?}");
    assert_eq!(err.msp_code(), Some("deadline_exceeded"));
    // The session is closed by the expiry: later calls report Closed, never
    // hang, never silently succeed.
    assert!(session.is_closed());
    assert!(matches!(
        session.recv(D).await.unwrap_err(),
        TransportError::Closed
    ));
    assert!(matches!(
        session
            .send(
                WireMessage::Control(modelswarm_transport::Control::ping()),
                D
            )
            .await
            .unwrap_err(),
        TransportError::Closed
    ));
    responder.await.unwrap().unwrap();
}

// (e) ----------------------------------------------------------------------

#[tokio::test]
async fn non_loopback_bind_is_refused() {
    let err = SignedFrameTransport::listen("0.0.0.0:0").await.unwrap_err();
    assert!(
        matches!(err, TransportError::NonLoopbackDenied),
        "got {err:?}"
    );
    assert_eq!(err.msp_code(), None);
    // The wildcard v6 form is equally refused.
    assert!(matches!(
        SignedFrameTransport::listen("[::]:12345")
            .await
            .unwrap_err(),
        TransportError::NonLoopbackDenied
    ));
    // And a specific LAN address.
    assert!(matches!(
        SignedFrameTransport::listen("192.168.1.10:9000")
            .await
            .unwrap_err(),
        TransportError::NonLoopbackDenied
    ));
}

// (f) ----------------------------------------------------------------------

#[tokio::test]
async fn rtt_stats_are_sane_over_loopback() {
    let client = ident(6);
    let listener = make_listener().await;
    let addr = listener.local_addr().unwrap();
    let expected = client.verifying_key();
    let responder = tokio::spawn(async move {
        let session = listener.accept(&expected, D).await?;
        // Pings are answered by the transport itself; just hold the session.
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        drop(session);
        Ok::<(), TransportError>(())
    });

    let mut session = SignedFrameTransport::connect(&addr.to_string(), handshake_for(&client), D)
        .await
        .unwrap();
    let stats = session.measure_rtt(20, D).await.expect("rtt probes");
    assert!(
        stats.p50_ms < 250.0,
        "loopback p50 must be far below 250 ms, got {}",
        stats.p50_ms
    );
    assert!(stats.p50_ms >= 0.0 && stats.p50_ms.is_finite());
    assert!(stats.p95_ms >= stats.p50_ms);
    assert!(stats.jitter_ms >= 0.0 && stats.jitter_ms.is_finite());
    session.close();
    responder.await.unwrap().unwrap();
}

// (g) ----------------------------------------------------------------------

#[tokio::test]
async fn four_concurrent_sessions_on_one_listener() {
    let seeds: [u8; 4] = [10, 11, 12, 13];
    let directory: HashMap<String, ed25519_dalek::VerifyingKey> = seeds
        .iter()
        .map(|&seed| {
            let identity = ident(seed);
            (identity.peer_id(), identity.verifying_key())
        })
        .collect();
    let listener = make_listener().await;
    let addr = listener.local_addr().unwrap();

    // Serving side: four accepts, each answering one request with delta+done.
    let server = {
        let directory = directory.clone();
        tokio::spawn(async move {
            for _ in 0..seeds.len() {
                let session = listener
                    .accept_with(|hs| directory.get(&hs.peer_id).copied(), D)
                    .await?;
                tokio::spawn(async move {
                    let mut session = session;
                    while let Ok(msg) = session.recv(D).await {
                        let WireMessage::InferenceRequest(req) = msg else {
                            continue;
                        };
                        session
                            .send(
                                WireMessage::TokenDelta(TokenDelta {
                                    request_id: req.request_id.clone(),
                                    delta: "ok".to_string(),
                                    index: 0,
                                }),
                                D,
                            )
                            .await?;
                        session
                            .send(
                                WireMessage::Completed(Completed {
                                    request_id: req.request_id.clone(),
                                    finish_reason: "stop".to_string(),

                                    job_receipt: None,
                                }),
                                D,
                            )
                            .await?;
                    }
                    Ok::<(), TransportError>(())
                });
            }
            Ok::<(), TransportError>(())
        })
    };

    let mut tasks = Vec::new();
    for (i, &seed) in seeds.iter().enumerate() {
        let addr = addr.to_string();
        tasks.push(tokio::spawn(async move {
            let client = ident(seed);
            let mut session =
                SignedFrameTransport::connect(&addr, handshake_for(&client), D).await?;
            session
                .send(
                    WireMessage::InferenceRequest(sample_request(&format!("req-g-{i}"))),
                    D,
                )
                .await?;
            let mut done = false;
            while let Ok(msg) = session.recv(D).await {
                if let WireMessage::Completed(c) = msg {
                    assert_eq!(c.request_id, format!("req-g-{i}"));
                    done = true;
                    break;
                }
            }
            assert!(done, "session {i} must complete");
            session.close();
            Ok::<(), TransportError>(())
        }));
    }
    for task in tasks {
        task.await.unwrap().expect("concurrent session flow");
    }
    server.await.unwrap().unwrap();
}

// (h) ----------------------------------------------------------------------

#[tokio::test]
async fn cancel_is_delivered_mid_stream() {
    let client = ident(20);
    let listener = make_listener().await;
    let addr = listener.local_addr().unwrap();

    let (cancel_seen_tx, cancel_seen_rx) = oneshot::channel();
    let expected = client.verifying_key();
    let responder = tokio::spawn(async move {
        let mut session = listener.accept(&expected, D).await?;
        // Wait for the request, emit one delta, then honor the cancel.
        let req = loop {
            match session.recv(D).await? {
                WireMessage::InferenceRequest(req) => break req,
                _ => continue,
            }
        };
        session
            .send(
                WireMessage::TokenDelta(TokenDelta {
                    request_id: req.request_id.clone(),
                    delta: "par".to_string(),
                    index: 0,
                }),
                D,
            )
            .await?;
        let cancel = loop {
            match session.recv(D).await? {
                WireMessage::Cancel(cancel) => break cancel,
                _ => continue,
            }
        };
        cancel_seen_tx
            .send(cancel)
            .map_err(|_| TransportError::Closed)?;
        session
            .send(
                WireMessage::Cancelled(Cancelled {
                    request_id: req.request_id.clone(),
                    reason: "server acknowledged cancel".to_string(),
                }),
                D,
            )
            .await?;
        Ok::<(), TransportError>(())
    });

    let mut session = SignedFrameTransport::connect(&addr.to_string(), handshake_for(&client), D)
        .await
        .unwrap();
    session
        .send(WireMessage::InferenceRequest(sample_request("req-h-1")), D)
        .await
        .unwrap();

    // First token arrives…
    match session.recv(D).await.unwrap() {
        WireMessage::TokenDelta(d) => assert_eq!(d.delta, "par"),
        other => panic!("expected first delta, got {other:?}"),
    }
    // …then the client cancels mid-stream…
    session
        .request_cancel("req-h-1")
        .await
        .expect("cancel send");

    // …the server saw the Cancel frame with the right id and reason…
    let cancel: Cancel = cancel_seen_rx.await.unwrap();
    assert_eq!(cancel.request_id, "req-h-1");
    assert_eq!(cancel.reason, "cancelled_by_peer");

    // …and the stream terminates with the server's Cancelled event.
    match session.recv(D).await.unwrap() {
        WireMessage::Cancelled(c) => assert_eq!(c.request_id, "req-h-1"),
        other => panic!("expected cancelled event, got {other:?}"),
    }
    session.close();
    responder.await.unwrap().unwrap();
}

// Extra: handshake policy rejection ----------------------------------------

#[tokio::test]
async fn stale_handshake_timestamp_is_refused() {
    let client = ident(30);
    let listener = make_listener().await;
    let addr = listener.local_addr().unwrap();
    let expected = client.verifying_key();
    let server = tokio::spawn(async move { listener.accept(&expected, D).await });

    // Valid signature, but ts is years outside the ±120 s window (§6.6).
    let mut stale = handshake_for(&client);
    stale.ts = "2020-01-01T00:00:00Z".to_string();
    re_sign(&mut stale, &client);
    assert!(
        verify_handshake(
            &WireMessage::Handshake(stale.clone()),
            &client.verifying_key()
        )
        .is_ok(),
        "control: the signature itself must be valid — only ts is stale"
    );

    let err = SignedFrameTransport::connect(&addr.to_string(), stale, D)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, TransportError::HandshakeFailed(c) if c.contains("handshake_failed")),
        "stale ts must be refused, got {err:?}"
    );
    assert!(server.await.unwrap().is_err());
}

#[tokio::test]
async fn unknown_peer_is_refused_by_resolver() {
    let client = ident(31);
    let listener = make_listener().await;
    let addr = listener.local_addr().unwrap();

    // The directory does not contain this peer: accept_with rejects with the
    // §6.5 code even though the signature itself is valid. The client sees
    // only the wire code; the server-side error carries the reason.
    let server = tokio::spawn(async move { listener.accept_with(|_| None, D).await });
    let err = SignedFrameTransport::connect(&addr.to_string(), handshake_for(&client), D)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, TransportError::HandshakeFailed(c) if c == "handshake_failed"),
        "got {err:?}"
    );
    let server_err = server.await.unwrap().unwrap_err();
    assert!(
        matches!(&server_err, TransportError::HandshakeFailed(c) if c.contains("unknown peer")),
        "got {server_err:?}"
    );
}

// Raw-JSON passthrough (extension namespaces, ADR-018 amended staging) -------

#[tokio::test]
async fn raw_json_passthrough_rides_the_authenticated_session() {
    let client = ident(40);
    let listener = make_listener().await;
    let addr = listener.local_addr().unwrap();
    let expected = client.verifying_key();
    let responder = tokio::spawn(async move {
        let mut session = listener.accept(&expected, D).await?;
        // Extension server: one raw JSON exchange, then the typed surface
        // keeps working on the same session.
        let value = session.recv_json(D).await?;
        let reply = serde_json::json!({
            "echo": value,
            "namespace": "/msp/extension-test/1.0.0",
        });
        session.send_json(&reply, D).await?;
        let typed: WireMessage = session.recv(D).await?;
        assert!(matches!(typed, WireMessage::Cancel(_)));
        Ok::<(), TransportError>(())
    });

    let mut session: Session =
        SignedFrameTransport::connect(&addr.to_string(), handshake_for(&client), D)
            .await
            .expect("connect");
    // The extension frame is NOT a WireMessage: a typed-only peer would have
    // failed to decode it (and closed); recv_json reads it verbatim.
    let ext = json!({"op": "hello", "round": 7});
    session.send_json(&ext, D).await.expect("send_json");
    let echoed = session.recv_json(D).await.expect("recv_json");
    assert_eq!(echoed["echo"], ext);
    assert_eq!(echoed["namespace"], "/msp/extension-test/1.0.0");
    // Typed traffic still flows both directions afterwards.
    session.request_cancel("raw-json-1").await.expect("cancel");
    session.close();
    responder.await.unwrap().expect("responder flow");
}
