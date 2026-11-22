//! The advisory transport seam (ADR-033 as amended by the 2026-10-15
//! owner directive): an injectable trait — the state machine's doubles
//! implement it; the pinned LOCAL-GATEWAY adapter is the production
//! implementation.
//!
//! The provider client is GONE. The directive ("how about we remove
//! this deepseek key completely, and make the helper use the hosted
//! model when hosted") deleted `ReqwestTransport`, the https-endpoint
//! arming, and every key surface: the assistant's only production
//! backing is THIS machine's loopback gateway — the SAME
//! OpenAI-compatible path chat uses, so queueing/governor fairness
//! applies to assistant turns exactly as it does to chat turns.
//!
//! Transport pinning (the RC-9 discipline, retargeted to loopback):
//! **loopback-only, redirects NEVER followed**. The adapter is
//! constructed from a bound loopback `SocketAddr` and refuses anything
//! else; the HTTP client does not follow redirects — a 3xx response is
//! `HttpStatus(3xx)` (gap `http_error`) and the request is never
//! re-sent anywhere. There is no Authorization header to protect
//! anymore, and no key exists anywhere in the plane.

use async_trait::async_trait;
use std::net::SocketAddr;

use super::state::{ProviderRequest, TransportFailure};

/// One assistant-plane call. Implementations return the model's reply
/// CONTENT bytes on HTTP 2xx (the gateway's OpenAI envelope is stripped
/// by the implementation; the pure state machine parses only the strict
/// `advisory-assistant/v1` schema).
#[async_trait]
pub trait AdvisoryTransport: Send + Sync + std::fmt::Debug {
    async fn send(&self, request: &ProviderRequest) -> Result<Vec<u8>, TransportFailure>;
}

/// The pinned reqwest client: **no redirects** (a 3xx comes back as the
/// response; the caller maps it to gap `http_error`). The SAME builder
/// serves the adapter and the redirect test, so the pin cannot drift
/// between them.
pub fn pinned_client() -> reqwest::Client {
    modelswarm_dns::apply(reqwest::Client::builder())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client")
}

/// The production transport: the machine's OWN local loopback gateway
/// (ADR-002 posture — loopback only), serving the hosted profile
/// through the same OpenAI-compatible path chat uses. The gateway
/// address and the profile id are pinned HERE at construction from the
/// RUNNING node's bound address — a request cannot name another host,
/// another port, or another model.
#[derive(Debug)]
pub struct LocalGatewayTransport {
    http: reqwest::Client,
    endpoint: String,
    model: String,
}

impl LocalGatewayTransport {
    /// Fails for any non-loopback address (the assistant never leaves
    /// this machine — the owner directive's whole point). IPv4 and IPv6
    /// loopback are both accepted; everything else is refused.
    pub fn new(gateway_addr: SocketAddr, hosted_profile: &str) -> Result<Self, TransportFailure> {
        if !gateway_addr.ip().is_loopback() {
            return Err(TransportFailure::Network(format!(
                "the assistant backing is the LOCAL gateway; refusing non-loopback {gateway_addr}"
            )));
        }
        Ok(Self {
            http: pinned_client(),
            endpoint: format!("http://{gateway_addr}/v1/chat/completions"),
            model: hosted_profile.to_string(),
        })
    }
}

#[async_trait]
impl AdvisoryTransport for LocalGatewayTransport {
    async fn send(&self, request: &ProviderRequest) -> Result<Vec<u8>, TransportFailure> {
        // The system prompt is a repo-versioned constant pinned to the
        // plane — never caller text.
        let system = request
            .system_prompt
            .unwrap_or(crate::advisory::assistant::ASSISTANT_SYSTEM_PROMPT);
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": request.body},
            ],
            "max_tokens": request.max_completion_tokens,
            "stream": false,
        });
        let result = self
            .http
            .post(&self.endpoint)
            .timeout(std::time::Duration::from_millis(request.timeout_ms))
            .json(&body)
            .send()
            .await;
        let response = match result {
            Ok(r) => r,
            Err(e) if e.is_timeout() => return Err(TransportFailure::Deadline),
            Err(e) => return Err(TransportFailure::Network(e.to_string())),
        };
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            // 3xx included: no redirect is ever followed — the request
            // dies here (the RC-9 discipline, loopback form).
            return Err(TransportFailure::HttpStatus(status));
        }
        // Response body cap: stream and refuse to buffer beyond the
        // request's cap (the state machine re-checks the final bytes).
        let mut bytes = Vec::new();
        let mut stream = response;
        while let Some(chunk) = stream
            .chunk()
            .await
            .map_err(|e| TransportFailure::Network(e.to_string()))?
        {
            bytes.extend_from_slice(&chunk);
            if bytes.len() > request.max_response_bytes {
                return Err(TransportFailure::ResponseOversized);
            }
        }
        // The gateway's OpenAI envelope is stripped here:
        // choices[0].message.content — the hosted model's reply, which
        // must itself be the strict assistant JSON (the system prompt
        // says so; anything else fails the state machine's parse with
        // gap `schema`, fail-closed).
        let parsed: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| TransportFailure::Network(format!("gateway envelope: {e}")))?;
        let content = parsed
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .ok_or_else(|| TransportFailure::Network("gateway envelope: no content".into()))?;
        Ok(content.as_bytes().to_vec())
    }
}

/// A counting transport double (TEST-ONLY; the chat-wall and cadence
/// suites ride it — production code never constructs it). Records every
/// attempted call and replays a programmed outcome per call. There is
/// no key parameter to capture: no key exists in the plane anymore.
#[derive(Debug)]
pub struct CountingTransport {
    calls: std::sync::Mutex<Vec<ProviderRequest>>,
    /// Replayed per call in order; the last entry repeats.
    script: std::sync::Mutex<Vec<Result<Vec<u8>, TransportFailure>>>,
    /// When set, every call is answered with a valid assistant reply
    /// echoing the request's turn (overrides the script).
    assistant_echo: Option<String>,
}

impl CountingTransport {
    pub fn new(script: Vec<Result<Vec<u8>, TransportFailure>>) -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            script: std::sync::Mutex::new(script),
            assistant_echo: None,
        }
    }

    /// A double that always succeeds with a minimal valid digest reply
    /// echoing whatever cycle it is asked about (the parse happens in
    /// the state machine; content here is just bytes).
    pub fn always_ok() -> Self {
        Self::new(vec![Ok(br#"{"schema":"advisory-suggestion/v1"}"#.to_vec())])
    }

    /// A double that always fails at the network layer.
    pub fn always_erroring() -> Self {
        Self::new(vec![Err(TransportFailure::Network("double".into()))])
    }

    /// A double that answers every call with a VALID assistant reply
    /// (schema `advisory-assistant/v1`) echoing the request's
    /// conversation_id/turn — the assistant panel's success-path tests
    /// ride it (the plane's conversation id is internally generated, so
    /// a canned body could never echo it).
    pub fn assistant_echo(reply_text: String) -> Self {
        Self::new(vec![Err(TransportFailure::Network(
            "placeholder, replaced in send".into(),
        ))])
        .with_assistant_echo(reply_text)
    }

    fn with_assistant_echo(mut self, reply_text: String) -> Self {
        self.assistant_echo = Some(reply_text);
        self
    }

    /// Number of calls INITIATED through this double.
    pub fn count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    /// Every request body sent (chat-wall canary assertions walk these).
    pub fn bodies(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.body.clone())
            .collect()
    }
}

#[async_trait]
impl AdvisoryTransport for CountingTransport {
    async fn send(&self, request: &ProviderRequest) -> Result<Vec<u8>, TransportFailure> {
        self.calls.lock().unwrap().push(request.clone());
        if let Some(reply) = &self.assistant_echo {
            // Echo the request's own turn (a canned body could not know
            // the plane's internally-generated conversation id).
            let body: serde_json::Value = serde_json::from_str(&request.body)
                .map_err(|e| TransportFailure::Network(format!("echo double: {e}")))?;
            let turn = body
                .get("turn")
                .cloned()
                .ok_or_else(|| TransportFailure::Network("echo double: no turn".into()))?;
            return Ok(serde_json::json!({
                "schema": "advisory-assistant/v1",
                "conversation_id": turn["conversation_id"],
                "turn": turn["turn"],
                "reply": reply,
                "hints": [],
            })
            .to_string()
            .into_bytes());
        }
        let mut script = self.script.lock().unwrap();
        if script.is_empty() {
            return Err(TransportFailure::Network("script exhausted".into()));
        }
        if script.len() > 1 {
            script.remove(0)
        } else {
            script[0].clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adapter_refuses_non_loopback_backings() {
        let off_machine: std::net::SocketAddr = "192.168.1.9:11435".parse().unwrap();
        assert!(LocalGatewayTransport::new(off_machine, "msp1:x").is_err());
        let public: std::net::SocketAddr = "8.8.8.8:443".parse().unwrap();
        assert!(LocalGatewayTransport::new(public, "msp1:x").is_err());
        let v6_loopback: std::net::SocketAddr = "[::1]:11435".parse().unwrap();
        assert!(LocalGatewayTransport::new(v6_loopback, "msp1:x").is_ok());
    }

    /// A full round trip against a mock OpenAI-shaped loopback gateway:
    /// the request carries the pinned system prompt as the system
    /// message and the verified body as the user message; the reply's
    /// `choices[0].message.content` is what comes back; a non-2xx maps
    /// to `HttpStatus`; an over-cap body maps to `ResponseOversized`.
    #[tokio::test]
    async fn adapter_round_trips_through_the_loopback_gateway_shape() {
        use axum::routing::{get, post};
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<serde_json::Value>::new()));
        let seen_post = seen.clone();
        let app = axum::Router::new()
            .route(
                "/v1/chat/completions",
                post(move |body: String| {
                    let seen = seen_post.clone();
                    async move {
                        seen.lock().unwrap().push(
                            serde_json::from_str(&body)
                                .expect("the assistant posts a valid gateway body"),
                        );
                        axum::Json(serde_json::json!({
                            "choices": [{"message": {"role": "assistant",
                                "content": "{\"schema\":\"advisory-assistant/v1\"}"}}]
                        }))
                    }
                }),
            )
            .route(
                "/redirect",
                get(|| async move {
                    axum::response::Redirect::temporary("http://127.0.0.1:1/elsewhere")
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });

        let adapter =
            LocalGatewayTransport::new(addr, "msp1:hosted").expect("loopback backing accepted");
        let request = ProviderRequest {
            body: r#"{"context":{},"history":[],"turn":{"conversation_id":"0123456789abcdef","turn":1,"text":"q"}}"#.into(),
            timeout_ms: 5_000,
            max_completion_tokens: 64,
            max_response_bytes: 65_536,
            system_prompt: None,
        };
        let content = adapter.send(&request).await.expect("round trip");
        assert_eq!(
            String::from_utf8(content).unwrap(),
            "{\"schema\":\"advisory-assistant/v1\"}"
        );
        // The gateway request pinned the hosted model, carried the
        // assistant system prompt, and was non-streaming.
        let posted = seen.lock().unwrap().pop().unwrap();
        assert_eq!(posted["model"], "msp1:hosted");
        assert_eq!(posted["stream"], false);
        assert_eq!(
            posted["messages"][0]["role"], "system",
            "the system message leads"
        );
        assert_eq!(
            posted["messages"][0]["content"],
            crate::advisory::assistant::ASSISTANT_SYSTEM_PROMPT
        );
        assert_eq!(posted["messages"][1]["role"], "user");
        assert_eq!(posted["max_tokens"], 64);

        // The pinned client does NOT follow redirects — a 3xx comes
        // back as the 3xx (the loopback form of RC-9).
        let client = pinned_client();
        let response = client
            .get(format!("http://{addr}/redirect"))
            .send()
            .await
            .expect("redirect response arrives");
        assert_eq!(response.status().as_u16(), 307, "returned, not followed");
        assert!(response.headers().get("location").is_some());
    }

    /// The adapter maps a non-2xx gateway answer to `HttpStatus` and an
    /// over-cap body to `ResponseOversized` (the state machine turns
    /// these into the honest `http_error`/`response_oversized` gaps).
    #[tokio::test]
    async fn adapter_maps_gateway_failures_honestly() {
        use axum::routing::post;
        let app = axum::Router::new().route(
            "/v1/chat/completions",
            post(|| async {
                (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    axum::Json(serde_json::json!({"error": {"code": "no_peer"}})),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let adapter = LocalGatewayTransport::new(addr, "msp1:hosted").unwrap();
        let request = ProviderRequest {
            body: "{}".into(),
            timeout_ms: 5_000,
            max_completion_tokens: 8,
            max_response_bytes: 65_536,
            system_prompt: None,
        };
        assert_eq!(
            adapter.send(&request).await,
            Err(TransportFailure::HttpStatus(503))
        );

        // Response cap: a valid envelope whose content exceeds the
        // request's cap is refused while buffering.
        let huge = axum::Router::new().route(
            "/v1/chat/completions",
            post(|| async {
                axum::Json(serde_json::json!({
                    "choices": [{"message": {"content": "x".repeat(10_000)}}]
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, huge).await });
        let adapter = LocalGatewayTransport::new(addr, "msp1:hosted").unwrap();
        let request = ProviderRequest {
            body: "{}".into(),
            timeout_ms: 5_000,
            max_completion_tokens: 8,
            max_response_bytes: 512,
            system_prompt: None,
        };
        assert_eq!(
            adapter.send(&request).await,
            Err(TransportFailure::ResponseOversized)
        );
    }
}
