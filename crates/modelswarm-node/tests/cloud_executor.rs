//! ADR-040 C1 tests: the cloud executor against a real local SSE server
//! (axum) speaking the OpenAI-compatible wire shape — request mapping
//! (model, messages, sampling, stream+usage flags, bearer key), the
//! TokenDelta/Usage/Completed event sequence with honest wall-clock
//! timings, finish-reason mapping, the no-usage fallback, mid-stream
//! truncation surfacing as an Error (never a fabricated completion), and
//! the pre-token 429 → Retryable failover semantics.

use std::time::Duration;

use futures_util::StreamExt;
use modelswarm_gateway::{
    ExecutorEvent, FinishReason, InferenceExecutor, NormalizedMessage, NormalizedRequest,
};
use modelswarm_node::cloud_executor::{CloudApiConfig, CloudApiExecutor, CloudProvider};

fn config(base: &str) -> CloudApiConfig {
    CloudApiConfig {
        provider: CloudProvider::DeepSeek,
        model: "deepseek-chat".into(),
        api_key: "sk-test-key-never-real".into(),
        request_timeout: Duration::from_secs(10),
        base_url_override: Some(base.to_string()),
    }
}

fn request() -> NormalizedRequest {
    NormalizedRequest {
        request_id: "cloud-1".into(),
        profile_id: "msp1:cloud-test".into(),
        capability_token: None,
        messages: vec![NormalizedMessage {
            role: "user".into(),
            content: "say hi twice".into(),
        }],
        sampling: modelswarm_gateway::Sampling {
            temperature: 0.2,
            top_p: 1.0,
            top_k: 40,
            seed: None,
        },
        max_tokens: 32,
        deadline_ms: 10_000,
        stream: true,
    }
}

/// Spawns the SSE double; returns its base URL. `body` is the raw SSE
/// stream the server writes (after validating the request shape).
async fn spawn_double(
    validate: fn(serde_json::Value, Option<&str>) -> Result<(), String>,
    body: &'static str,
) -> String {
    use axum::extract::State;
    use axum::response::IntoResponse;
    #[derive(Clone)]
    struct Ctx {
        validate: fn(serde_json::Value, Option<&str>) -> Result<(), String>,
        body: &'static str,
    }
    async fn handler(
        State(ctx): State<Ctx>,
        headers: axum::http::HeaderMap,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> axum::response::Response {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        if let Err(e) = (ctx.validate)(body, auth.as_deref()) {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                format!("double rejected: {e}"),
            )
                .into_response();
        }
        axum::response::Response::builder()
            .header("content-type", "text/event-stream")
            .body(axum::body::Body::from(ctx.body))
            .unwrap()
    }
    let ctx = Ctx { validate, body };
    let app = axum::Router::new()
        .route("/chat/completions", axum::routing::post(handler))
        .with_state(ctx);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn expect_request_shape(body: serde_json::Value, auth: Option<&str>) -> Result<(), String> {
    if body["model"] != "deepseek-chat" {
        return Err("model".into());
    }
    if body["stream"] != true || body["stream_options"]["include_usage"] != true {
        return Err("stream flags".into());
    }
    if body["messages"][0]["role"] != "user" || body["messages"][0]["content"] != "say hi twice" {
        return Err("messages".into());
    }
    // f32 → f64 widening on the wire (0.2f32 renders with tail digits);
    // compare with tolerance.
    let temp = body["temperature"].as_f64().unwrap_or(f64::NAN);
    if (temp - 0.2).abs() > 1e-6 {
        return Err("temperature".into());
    }
    if auth == Some("Bearer sk-test-key-never-real") {
        Ok(())
    } else {
        Err(format!("auth {auth:?}"))
    }
}

const HAPPY_BODY: &str = "data: {\"choices\":[{\"delta\":{\"content\":\"hi \"}}]}\n\
                          \n\
                          data: {\"choices\":[{\"delta\":{\"content\":\"there\"}}]}\n\
                          \n\
                          data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\
                          \n\
                          data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2}}\n\
                          \n\
                          data: [DONE]\n\n";

#[tokio::test]
async fn happy_path_streams_deltas_usage_completion() {
    let base = spawn_double(expect_request_shape, HAPPY_BODY).await;
    let exec = CloudApiExecutor::new(config(&base)).unwrap();
    assert_eq!(exec.mode_label(), "cloud — deepseek deepseek-chat (API)");
    let mut events = match exec.execute(request()).await {
        Ok(s) => s,
        Err(e) => panic!("execute failed: {e:?}"),
    };
    let mut text = String::new();
    let mut usage = None;
    let mut completed = false;
    while let Some(ev) = events.next().await {
        match ev {
            ExecutorEvent::TokenDelta { delta, .. } => text.push_str(&delta),
            ExecutorEvent::Usage {
                completion_tokens,
                prefill_ms,
                decode_ms,
                ..
            } => {
                usage = Some((completion_tokens, prefill_ms, decode_ms));
            }
            ExecutorEvent::Completed { finish_reason } => {
                assert_eq!(finish_reason, FinishReason::Stop);
                completed = true;
            }
            ExecutorEvent::Error { code, .. } => panic!("unexpected error: {code}"),
            ExecutorEvent::Accepted { .. } => {}
        }
    }
    assert_eq!(text, "hi there");
    assert!(completed);
    let (tokens, prefill_ms, _decode_ms) = usage.expect("usage arrived");
    assert_eq!(tokens, 2);
    // Honest wall-clock timings: measured, so strictly non-negative; the
    // first token arrives after a real network round trip.
    assert!(prefill_ms >= 0.0);
}

#[tokio::test]
async fn length_finish_reason_maps() {
    let body = "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\
                \n\
                data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}]}\n\
                \n\
                data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\
                \n\
                data: [DONE]\n\n";
    let base = spawn_double(expect_request_shape, body).await;
    let exec = CloudApiExecutor::new(config(&base)).unwrap();
    let mut events = exec.execute(request()).await.unwrap();
    while let Some(ev) = events.next().await {
        if let ExecutorEvent::Completed { finish_reason } = ev {
            assert_eq!(finish_reason, FinishReason::Length);
            return;
        }
    }
    panic!("no completion event");
}

#[tokio::test]
async fn missing_usage_chunk_still_completes_with_measured_usage() {
    // Some providers omit the usage chunk — [DONE] must still emit Usage
    // (measured timings, zero counts) before Completed.
    let body = "data: {\"choices\":[{\"delta\":{\"content\":\"y\"}}]}\n\
                \n\
                data: [DONE]\n\n";
    let base = spawn_double(expect_request_shape, body).await;
    let exec = CloudApiExecutor::new(config(&base)).unwrap();
    let mut events = exec.execute(request()).await.unwrap();
    let mut saw_usage = false;
    let mut saw_completed = false;
    while let Some(ev) = events.next().await {
        match ev {
            ExecutorEvent::Usage { .. } => saw_usage = true,
            ExecutorEvent::Completed { .. } => saw_completed = true,
            _ => {}
        }
    }
    assert!(
        saw_usage && saw_completed,
        "usage={saw_usage} completed={saw_completed}"
    );
}

#[tokio::test]
async fn truncated_stream_is_an_honest_error_never_a_completion() {
    // Stream dies mid-generation without [DONE]: ADR-007 — an Error event,
    // never a fabricated continuation or completion.
    let body = "data: {\"choices\":[{\"delta\":{\"content\":\"par\"}}]}\n\
                \n";
    let base = spawn_double(expect_request_shape, body).await;
    let exec = CloudApiExecutor::new(config(&base)).unwrap();
    let mut events = exec.execute(request()).await.unwrap();
    let mut errored = false;
    while let Some(ev) = events.next().await {
        match ev {
            ExecutorEvent::Error {
                code, retryable, ..
            } => {
                assert_eq!(code, "cloud_stream_ended");
                assert!(!retryable);
                errored = true;
            }
            ExecutorEvent::Completed { .. } => panic!("fabricated completion"),
            _ => {}
        }
    }
    assert!(errored);
}

#[tokio::test]
async fn pre_token_http_429_is_retryable_failover() {
    async fn handler() -> (axum::http::StatusCode, &'static str) {
        (axum::http::StatusCode::TOO_MANY_REQUESTS, "rate limited")
    }
    let app = axum::Router::new().route("/chat/completions", axum::routing::post(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let exec = CloudApiExecutor::new(config(&format!("http://{addr}"))).unwrap();
    match exec.execute(request()).await {
        Err(modelswarm_gateway::ExecutorError::Retryable { .. }) => {}
        other => panic!(
            "expected Retryable, got {:?}",
            std::mem::discriminant(&other)
        ),
    }
}

#[tokio::test]
async fn pre_token_auth_failure_is_fatal_closed_vocabulary() {
    async fn handler() -> (axum::http::StatusCode, &'static str) {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            "{\"error\":\"bad key\"}",
        )
    }
    let app = axum::Router::new().route("/chat/completions", axum::routing::post(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let exec = CloudApiExecutor::new(config(&format!("http://{addr}"))).unwrap();
    match exec.execute(request()).await {
        Err(modelswarm_gateway::ExecutorError::Fatal { code }) => {
            // Closed vocabulary: status only — the provider's body text
            // ("bad key") and the API key never appear.
            assert_eq!(code, "cloud_http_401");
            assert!(!code.contains("sk-test"));
        }
        other => panic!("expected Fatal, got {:?}", std::mem::discriminant(&other)),
    }
}
