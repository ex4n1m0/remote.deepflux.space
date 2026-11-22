//! Client integration against a minimal canned HTTP server (real loopback
//! sockets, real reqwest transport, real Ed25519 envelopes).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use modelswarm_identity::{InstallationIdentity, SignedEnvelope};
use modelswarm_tracker_api::{split_lease_token, TrackerClient, TrackerError};
use serde_json::json;
use sha2::Digest;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Request {
    method: String,
    path: String,
    authorization: Option<String>,
    session: Option<String>,
    body: Vec<u8>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Request {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos;
        }
        let n = stream.read(&mut tmp).await.expect("read");
        assert!(n > 0, "client closed early");
        buf.extend_from_slice(&tmp[..n]);
    };
    let headers_raw = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = headers_raw.lines();
    let request_line = lines.next().expect("request line");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap().to_string();
    let path = parts.next().unwrap().to_string();
    let mut content_length = 0usize;
    let mut authorization = None;
    let mut session = None;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            content_length = line[15..].trim().parse().unwrap_or(0);
        } else if lower.starts_with("authorization:") {
            authorization = Some(line[14..].trim().to_string());
        } else if lower.starts_with("x-msp-session:") {
            session = Some(line[14..].trim().to_string());
        }
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await.expect("body read");
        assert!(n > 0);
        body.extend_from_slice(&tmp[..n]);
    }
    Request {
        method,
        path,
        authorization,
        session,
        body,
    }
}

type Handler = Box<dyn FnOnce(&Request) -> (String, String) + Send>;

/// Serves exactly one request (owns everything it touches so tests can
/// spawn it before driving the client).
async fn serve_one(listener: tokio::net::TcpListener, handler: Handler) {
    let (mut sock, _) = listener.accept().await.unwrap();
    let req = read_request(&mut sock).await;
    let (status, body) = handler(&req);
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(resp.as_bytes()).await.unwrap();
    sock.flush().await.unwrap();
}

fn make_client(base: String) -> (TrackerClient, Arc<InstallationIdentity>) {
    let identity = Arc::new(InstallationIdentity::generate());
    let c = TrackerClient::new(base, identity.clone());
    c.set_session("sess-token-1".to_string());
    (c, identity)
}

#[tokio::test]
async fn register_envelope_verified() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, identity) = make_client(format!("http://{addr}"));
    let id = identity.clone();
    let handler = Box::new(move |req: &Request| {
        let auth = req.authorization.as_deref().expect("Authorization header");
        assert!(auth.starts_with("MSP1 "), "bad auth header: {auth}");
        let payload = B64URL
            .decode(auth.strip_prefix("MSP1 ").unwrap())
            .expect("b64url");
        let envelope: SignedEnvelope = serde_json::from_slice(&payload).expect("envelope");
        assert!(envelope.verify(&id.verifying_key()), "signature invalid");
        assert_eq!(envelope.method, "POST");
        assert_eq!(envelope.path, "/api/v1/peers/register");
        assert_eq!(envelope.installation_id, id.installation_id());
        let expect = format!("sha256:{}", hex::encode(sha2::Sha256::digest(&req.body)));
        assert_eq!(envelope.body_digest, expect, "digest must match raw body");
        assert_eq!(req.session.as_deref(), Some("sess-token-1"));
        (
            "200 OK".into(),
            r#"{"leaseId":"L1","leaseExpiresAt":"2026-10-05T12:00:00Z"}"#.to_string(),
        )
    }) as Handler;
    let server = tokio::spawn(serve_one(listener, handler));
    let out = client
        .register(
            "peer-1",
            &["/ip4/127.0.0.1/tcp/5001".into()],
            &["msp1:aa".into()],
            2,
            json!({"name":"llama.cpp","version":"b0","build_hash":"ff"}),
        )
        .await
        .expect("register ok");
    server.await.unwrap();
    assert_eq!(out["leaseId"], "L1");
}

#[tokio::test]
async fn heartbeat_parses_notices() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, _id) = make_client(format!("http://{addr}"));
    let handler = Box::new(|_req: &Request| {
        (
            "200 OK".to_string(),
            r#"{"leaseExpiresAt":"2026-10-05T12:01:15Z","notices":[{"type":"revoked_peers","peerIds":["p9"]}]}"#.to_string(),
        )
    }) as Handler;
    let server = tokio::spawn(serve_one(listener, handler));
    let hb = client
        .heartbeat("L1", &["msp1:aa".into()], 1, 5, false)
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(hb.notices.len(), 1);
    assert_eq!(hb.notices[0].kind, "revoked_peers");
    assert_eq!(hb.notices[0].peer_ids, vec!["p9".to_string()]);
}

#[tokio::test]
async fn lookup_signs_get_and_parses_entries() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, identity) = make_client(format!("http://{addr}"));
    let id = identity.clone();
    let handler = Box::new(move |req: &Request| {
        assert_eq!(req.method, "GET");
        assert!(
            req.path.starts_with("/api/v1/peers?profile_id=") && req.path.contains("limit=10"),
            "path: {}",
            req.path
        );
        let auth = req.authorization.as_deref().expect("signed GET");
        let payload = B64URL.decode(auth.strip_prefix("MSP1 ").unwrap()).unwrap();
        let envelope: SignedEnvelope = serde_json::from_slice(&payload).unwrap();
        assert!(envelope.verify(&id.verifying_key()));
        (
            "200 OK".to_string(),
            r#"{"peers":[{"peerId":"p1","addresses":["/ip4/127.0.0.1/tcp/9"],"queueMs":3,"freeSlots":1,"leaseExpiresAt":"t","lastSeenAt":"t","capacityClass":"gpu_mid"}]}"#.to_string(),
        )
    }) as Handler;
    let server = tokio::spawn(serve_one(listener, handler));
    let peers = client.lookup("msp1:aa", 10).await.unwrap();
    server.await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].capacity_class.as_deref(), Some("gpu_mid"));
}

#[tokio::test]
async fn api_errors_map_typed() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, _id) = make_client(format!("http://{addr}"));
    let handler = Box::new(|_req: &Request| {
        (
            "429 Too Many Requests".to_string(),
            r#"{"error":{"code":"rate_limited","message":"slow down","retryable":true}}"#
                .to_string(),
        )
    }) as Handler;
    let server = tokio::spawn(serve_one(listener, handler));
    let err = client.drain("L1").await.unwrap_err();
    server.await.unwrap();
    match err {
        TrackerError::Api {
            status,
            code,
            retryable,
            ..
        } => {
            assert_eq!(status, 429);
            assert_eq!(code, "rate_limited");
            assert!(retryable);
        }
        other => panic!("expected Api error, got {other}"),
    }
}

#[tokio::test]
async fn lease_token_from_endpoint_parses() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client, _id) = make_client(format!("http://{addr}"));
    let payload = B64URL.encode(br#"{"peerId":"p1","profileId":"msp1:aa"}"#);
    let sig = B64URL.encode([7u8; 64]);
    // The real route returns the wire token as `token` (plus an echoed
    // `lease` field object we deliberately ignore).
    let body = format!(r#"{{"token":"{payload}.{sig}","lease":{{"peer_id":"p1"}}}}"#);
    let handler = Box::new(move |_req: &Request| ("200 OK".to_string(), body.clone())) as Handler;
    let server = tokio::spawn(serve_one(listener, handler));
    let lease = client.request_lease("L1", "msp1:aa").await.unwrap();
    server.await.unwrap();
    assert_eq!(lease.lease, format!("{payload}.{sig}"));
    let parsed = split_lease_token(&lease.lease).unwrap();
    assert_eq!(parsed["peerId"], "p1");
}
