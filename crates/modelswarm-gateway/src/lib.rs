//! Local OpenAI-compatible gateway bound to `127.0.0.1:11435`
//! (`docs/architecture.md` §10, ADR-007).
//!
//! Normalizes chat-completion requests into the frozen P2P schema
//! (`protocol/msp-v1.md` §6.2), clamps requester-supplied limits
//! (clamp-don't-reject, §6.4, echoed via the `x-msp-clamped` header), then
//! drives an [`InferenceExecutor`] to produce SSE or full-JSON responses.
//!
//! # Retry semantics (ADR-007, frozen)
//!
//! Failover to another peer happens **only until the first `token_delta`
//! has been emitted** to the local client (at most
//! [`MAX_RETRIES_BEFORE_FIRST_TOKEN`] retries). After the first token, host
//! loss or stall terminates the stream with an explicit `interrupted` error
//! event — no fabricated continuation, no silent regeneration.
//!
//! # Privacy
//!
//! Message content is never logged. The audit channel ([`audit`]) records
//! `request_id` plus counts and timings only; tests assert no prompt text
//! appears in any captured line.
//!
//! # Executor trait-shape decisions (Phase D plugs in here)
//!
//! - One `Arc<dyn InferenceExecutor>` per gateway. Peer selection and
//!   advancement live inside the executor; the gateway re-invokes
//!   `execute(request)` unchanged on retry (the request stays §6.2-pure —
//!   there is no hint field to smuggle routing state).
//! - [`ExecutorError::Retryable`] carries a `peer_hint` for observability
//!   (which peer the executor moved to / failed on), not for routing.
//! - [`NormalizedRequest::capability_token`] is `Option`: absent until the
//!   Phase D transport executor supplies real tokens.

mod http;

#[cfg(any(test, feature = "test-doubles"))]
pub mod doubles;

#[cfg(any(test, feature = "test-doubles"))]
pub use doubles::{QueueStream, StaticExecutor};
pub use http::{
    assert_loopback, build_router, serve, spawn_loopback, GatewayError, GatewayHandle, GatewayState,
};

use std::pin::Pin;

use async_trait::async_trait;
use futures_util::Stream;
use serde::{Deserialize, Serialize};

/// Default loopback port (`docs/architecture.md`: 11435).
pub const DEFAULT_PORT: u16 = 11_435;
/// `deadlineMs` clamp bounds and default (msp-v1 §6.4).
pub const DEADLINE_MS_MIN: u32 = 1_000;
/// `deadlineMs` upper bound (msp-v1 §6.4).
pub const DEADLINE_MS_MAX: u32 = 120_000;
/// `deadlineMs` default when the client omits it (per-request deadline).
pub const DEADLINE_MS_DEFAULT: u32 = 120_000;
/// `temperature` clamp bound (msp-v1 §6.4: [0, 2]).
pub const TEMPERATURE_MAX: f32 = 2.0;
/// `top_k` clamp bounds (msp-v1 §6.4: [1, 200]).
pub const TOP_K_MIN: u32 = 1;
/// `top_k` upper bound (msp-v1 §6.4).
pub const TOP_K_MAX: u32 = 200;
/// `top_k` default mirroring the llama.cpp server default.
pub const TOP_K_DEFAULT: u32 = 40;
/// Maximum total prompt (message content) size in UTF-8 bytes (msp-v1 §6.4).
pub const MAX_PROMPT_BYTES: usize = 32 * 1024;
/// Failover budget before the first emitted token (ADR-007).
pub const MAX_RETRIES_BEFORE_FIRST_TOKEN: u32 = 2;
/// Fallback output cap when the requested model is unknown to the local
/// profile provider (documented default; env-tunable in the node).
pub const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 2_048;

/// Finish reason vocabulary of the P2P stream protocol (msp-v1 §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FinishReason {
    /// Natural stop.
    Stop,
    /// `maxTokens` reached.
    Length,
    /// Cancelled by either side.
    Cancelled,
    /// Stream errored.
    Error,
}

impl FinishReason {
    /// The wire string used by both the P2P protocol and OpenAI-style
    /// responses.
    pub fn as_str(&self) -> &'static str {
        match self {
            FinishReason::Stop => "stop",
            FinishReason::Length => "length",
            FinishReason::Cancelled => "cancelled",
            FinishReason::Error => "error",
        }
    }
}

/// Normalized request, field-for-field the frozen msp-v1 §6.2 shape
/// (camelCase serialization; `requestId` is a uuid v4 minted by the
/// gateway; `capabilityToken` is `null` until Phase D supplies real ones).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedRequest {
    /// uuid v4, single-use.
    pub request_id: String,
    /// Target profile id (`model` in the OpenAI body).
    pub profile_id: String,
    /// Hub-signed capability token; `None` until Phase D.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_token: Option<String>,
    /// Chat messages; the serving peer's runtime applies the chat template.
    pub messages: Vec<NormalizedMessage>,
    /// Sampling parameters (clamped §6.4 values).
    pub sampling: Sampling,
    /// Output budget (clamped §6.4).
    pub max_tokens: u32,
    /// Total wall budget in milliseconds (clamped §6.4).
    pub deadline_ms: u32,
    /// Whether the client asked for SSE.
    pub stream: bool,
}

/// One chat message (`{role, content}` per msp-v1 §6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedMessage {
    /// `system` | `user` | `assistant` (kept as a string: §6.2 freezes the
    /// shape `{role, content}`, not an enum).
    pub role: String,
    /// Message text.
    pub content: String,
}

/// Sampling sub-object of the normalized request.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sampling {
    /// `[0, 2]` after clamping.
    pub temperature: f32,
    /// `(0, 1]` after clamping.
    pub top_p: f32,
    /// `[1, 200]` after clamping.
    pub top_k: u32,
    /// Optional deterministic seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
}

/// Events yielded by an executor stream (msp-v1 §6.3 vocabulary).
#[derive(Debug, Clone, PartialEq)]
pub enum ExecutorEvent {
    /// Admission done: queue position and ETA.
    Accepted {
        /// Position in the serving queue.
        queue_position: u32,
        /// Estimated start in milliseconds.
        eta_ms: u64,
    },
    /// One output delta; the first flips the gateway into no-retry mode.
    TokenDelta {
        /// Detokenized delta text.
        delta: String,
        /// Zero-based output token index.
        index: u32,
    },
    /// Usage accounting, emitted once before [`ExecutorEvent::Completed`].
    Usage {
        /// Prompt token count.
        prompt_tokens: u32,
        /// Completion token count.
        completion_tokens: u32,
        /// Server-side prefill time in milliseconds.
        prefill_ms: f64,
        /// Server-side decode time in milliseconds.
        decode_ms: f64,
    },
    /// Successful end of generation.
    Completed {
        /// Why generation ended.
        finish_reason: FinishReason,
    },
    /// Mid-stream failure. `retryable` lets the gateway fail over **only if
    /// no token has been emitted yet** (ADR-007); `interrupted_after_tokens`
    /// reports how much output the client actually received.
    Error {
        /// Machine-readable code (msp-v1 §6.5 vocabulary).
        code: String,
        /// Whether a pre-first-token retry may be attempted.
        retryable: bool,
        /// Tokens already emitted when the failure happened, if known.
        interrupted_after_tokens: Option<u32>,
    },
}

/// Boxed event stream produced by [`InferenceExecutor::execute`].
pub type ExecutorStream = Pin<Box<dyn Stream<Item = ExecutorEvent> + Send>>;

/// Immediate (pre-stream) executor failures.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ExecutorError {
    /// No eligible peer for the request.
    #[error("no eligible peer for profile")]
    NoPeer,
    /// A transient failure; `peer_hint` names the peer to try next (or the
    /// one that just failed) for observability.
    #[error("retryable executor failure (peer hint: {peer_hint:?})")]
    Retryable {
        /// Peer the executor suggests or lost.
        peer_hint: Option<String>,
    },
    /// Unrecoverable failure with a machine-readable code.
    #[error("fatal executor failure: {code}")]
    Fatal {
        /// Machine-readable error code (msp-v1 §6.5 vocabulary).
        code: String,
    },
}

/// The execution backend the gateway drives. Phase D plugs the transport
/// executor in here; tests use [`doubles::StaticExecutor`].
#[async_trait]
pub trait InferenceExecutor: Send + Sync {
    /// Begins executing `request`, returning an event stream, or an
    /// immediate error (failover-eligible only via [`ExecutorError::Retryable`]
    /// and only before the gateway has emitted any token).
    async fn execute(&self, request: NormalizedRequest) -> Result<ExecutorStream, ExecutorError>;
}

/// Audit channel: the ONLY place gateway code logs. Lines carry request ids
/// and counts, never message content (asserted in tests).
pub mod audit {
    use std::sync::{LazyLock, Mutex};

    static LINES: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));

    /// Records one audit line.
    pub fn record(line: impl Into<String>) {
        if let Ok(mut lines) = LINES.lock() {
            const AUDIT_CAPACITY: usize = 4_096;
            if lines.len() >= AUDIT_CAPACITY {
                lines.remove(0);
            }
            lines.push(line.into());
        }
    }

    /// Drains and returns all recorded lines (test hook).
    pub fn take_lines() -> Vec<String> {
        LINES
            .lock()
            .map(|mut l| std::mem::take(&mut *l))
            .unwrap_or_default()
    }
}

/// Profile information served by `GET /v1/models`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelInfo {
    /// Profile id (`model` in OpenAI requests).
    pub id: String,
    /// Profile `maxOutputTokens` (clamp ceiling for `max_tokens`).
    pub max_output_tokens: u32,
}

/// Source of locally known profiles for `/v1/models` and clamping.
pub trait ProfileProvider: Send + Sync {
    /// The profiles this installation currently knows/serves.
    fn list(&self) -> Vec<ModelInfo>;
}

/// Trivial [`ProfileProvider`] over a fixed list.
#[derive(Debug, Clone)]
pub struct StaticProfiles {
    models: Vec<ModelInfo>,
}

impl StaticProfiles {
    /// Wraps a fixed profile list.
    pub fn new(models: Vec<ModelInfo>) -> Self {
        Self { models }
    }
}

impl ProfileProvider for StaticProfiles {
    fn list(&self) -> Vec<ModelInfo> {
        self.models.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doubles::StaticExecutor;
    use crate::http::X_MSP_CLAMPED;

    use axum::body::{Body, Bytes};
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    const MODEL: &str = "msp1:deadbeef";
    const MODEL_MAX_TOKENS: u32 = 512;

    fn router(executor: std::sync::Arc<StaticExecutor>) -> Router {
        let profiles = StaticProfiles::new(vec![ModelInfo {
            id: MODEL.to_string(),
            max_output_tokens: MODEL_MAX_TOKENS,
        }]);
        build_router(GatewayState::new(executor, std::sync::Arc::new(profiles)))
    }

    fn chat_request(body: Value) -> Request<Body> {
        Request::post("/v1/chat/completions")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn basic_body() -> Value {
        json!({
            "model": MODEL,
            "messages": [{ "role": "user", "content": "hello" }],
        })
    }

    async fn body_bytes(response: axum::response::Response) -> Bytes {
        response
            .into_body()
            .collect()
            .await
            .expect("body collects")
            .to_bytes()
    }

    /// Splits an SSE body into its `data:` payloads.
    fn sse_payloads(body: &str) -> Vec<String> {
        body.split("\n\n")
            .filter(|frame| !frame.is_empty())
            .map(|frame| frame.trim_start_matches("data: ").to_string())
            .collect()
    }

    #[tokio::test]
    async fn happy_sse_stream_chunk_sequence_is_exact() {
        let executor = StaticExecutor::happy(&["Hel", "lo ", "world"]);
        let response = router(std::sync::Arc::new(executor))
            .oneshot(chat_request({
                let mut b = basic_body();
                b["stream"] = json!(true);
                b
            }))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/event-stream"
        );
        assert!(response.headers().get(X_MSP_CLAMPED).is_none());
        let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
        let frames = sse_payloads(&body);
        assert_eq!(frames.len(), 6, "frames: {frames:?}");

        let role: Value = serde_json::from_str(&frames[0]).unwrap();
        assert_eq!(role["object"], "chat.completion.chunk");
        assert_eq!(role["model"], MODEL);
        assert_eq!(role["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(role["choices"][0]["finish_reason"], Value::Null);

        for (i, expected) in ["Hel", "lo ", "world"].iter().enumerate() {
            let chunk: Value = serde_json::from_str(&frames[1 + i]).unwrap();
            assert_eq!(chunk["choices"][0]["delta"]["content"], *expected);
            assert_eq!(chunk["choices"][0]["finish_reason"], Value::Null);
        }

        let finish: Value = serde_json::from_str(&frames[4]).unwrap();
        assert_eq!(finish["choices"][0]["delta"], json!({}));
        assert_eq!(finish["choices"][0]["finish_reason"], "stop");
        assert_eq!(finish["usage"]["prompt_tokens"], 10);
        assert_eq!(finish["usage"]["completion_tokens"], 3);

        assert_eq!(frames[5], "[DONE]");
    }

    #[tokio::test]
    async fn sse_content_chunks_arrive_before_the_executor_completes() {
        // P1 pin: with an executor that yields deltas over time, the SSE
        // body must surface each chunk as it is produced — not buffer the
        // whole completion. 7 events at 40 ms/event ≈ 280 ms total; the
        // first content chunk must be readable well before that.
        use std::time::{Duration, Instant};

        use futures_util::StreamExt;

        let executor =
            StaticExecutor::slow_consumer(&["alpha", "beta", "gamma"], Duration::from_millis(40));
        let response = router(std::sync::Arc::new(executor))
            .oneshot(chat_request({
                let mut b = basic_body();
                b["stream"] = json!(true);
                b
            }))
            .await
            .unwrap();
        let started = Instant::now();
        let mut stream = response.into_body().into_data_stream();
        let mut seen = Vec::new();
        let mut first_content_after = None;
        while let Some(frame) = stream.next().await {
            let frame = frame.expect("sse frame");
            seen.extend_from_slice(&frame);
            if first_content_after.is_none()
                && String::from_utf8_lossy(&seen).contains("\"content\":\"alpha\"")
            {
                first_content_after = Some(started.elapsed());
            }
        }
        let total = started.elapsed();
        let first = first_content_after.expect("first content chunk observed");
        assert!(
            first + Duration::from_millis(60) < total,
            "first content at {first:?} vs completion at {total:?} — SSE is buffering"
        );
    }

    #[tokio::test]
    async fn non_stream_response_shape_is_openai() {
        let executor = StaticExecutor::happy_with(&["Hel", "lo"], 7, FinishReason::Length);
        let response = router(std::sync::Arc::new(executor))
            .oneshot(chat_request(basic_body()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/json"
        );
        let body: Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(body["object"], "chat.completion");
        assert_eq!(body["model"], MODEL);
        assert_eq!(body["choices"][0]["message"]["role"], "assistant");
        assert_eq!(body["choices"][0]["message"]["content"], "Hello");
        assert_eq!(body["choices"][0]["finish_reason"], "length");
        assert_eq!(body["usage"]["prompt_tokens"], 7);
        assert_eq!(body["usage"]["completion_tokens"], 2);
        assert!(body["id"].as_str().unwrap().starts_with("chatcmpl-"));
    }

    #[tokio::test]
    async fn out_of_range_values_are_clamped_not_rejected_and_echoed() {
        let executor = std::sync::Arc::new(StaticExecutor::happy(&["ok"]));
        let response = router(executor.clone())
            .oneshot(chat_request(json!({
                "model": MODEL,
                "messages": [{ "role": "user", "content": "hi" }],
                "stream": true,
                "deadline_ms": 5,            // below 1000
                "temperature": 9.5,          // above 2
                "top_p": 0.0,                // outside (0,1]
                "top_k": 5_000,              // above 200
                "max_tokens": 100_000,       // above profile max
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let clamped = response
            .headers()
            .get(X_MSP_CLAMPED)
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        for expected in [
            "deadline_ms=1000",
            "temperature=2",
            "top_p=1",
            "top_k=200",
            "max_tokens=512",
        ] {
            assert!(
                clamped.contains(expected),
                "clamped header {clamped:?} must contain {expected:?}"
            );
        }
        // Drain the SSE body so the spawned stream task finishes executing.
        let _ = body_bytes(response).await;
        // The normalized request the executor received carries the clamps.
        let request = executor.last_request().unwrap();
        assert_eq!(request.deadline_ms, 1000);
        assert_eq!(request.max_tokens, 512);
        assert_eq!(request.sampling.temperature, 2.0);
        assert_eq!(request.sampling.top_p, 1.0);
        assert_eq!(request.sampling.top_k, 200);
    }

    #[tokio::test]
    async fn in_range_values_pass_without_clamp_header() {
        let response = router(std::sync::Arc::new(StaticExecutor::happy(&["ok"])))
            .oneshot(chat_request(json!({
                "model": MODEL,
                "messages": [{ "role": "user", "content": "hi" }],
                "stream": true,
                "deadline_ms": 30_000,
                "temperature": 0.5,
                "top_p": 0.9,
                "top_k": 40,
                "max_tokens": 64,
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(X_MSP_CLAMPED).is_none());
    }

    #[tokio::test]
    async fn retry_before_first_token_succeeds_after_two_failovers() {
        let executor = std::sync::Arc::new(StaticExecutor::fail_before_first_token(
            2,
            &["re", "covered"],
        ));
        let response = router(executor.clone())
            .oneshot(chat_request({
                let mut b = basic_body();
                b["stream"] = json!(true);
                b
            }))
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
        let frames = sse_payloads(&body);
        assert_eq!(frames.len(), 5, "frames: {frames:?}");
        let content: String = frames[1..3]
            .iter()
            .map(|f| {
                let v: Value = serde_json::from_str(f).unwrap();
                v["choices"][0]["delta"]["content"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(content, "recovered", "tokens must appear exactly once");
        assert_eq!(frames[4], "[DONE]");
        assert_eq!(executor.calls(), 3, "initial + 2 retries");
    }

    #[tokio::test]
    async fn retry_budget_exhaustion_reports_no_eligible_peer() {
        let executor = std::sync::Arc::new(StaticExecutor::fail_before_first_token(5, &["never"]));
        let response = router(executor.clone())
            .oneshot(chat_request({
                let mut b = basic_body();
                b["stream"] = json!(true);
                b
            }))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
        let frames = sse_payloads(&body);
        assert_eq!(frames.len(), 2, "role chunk + error event: {frames:?}");
        let error: Value = serde_json::from_str(&frames[1]).unwrap();
        assert_eq!(error["error"]["code"], "no_eligible_peer");
        assert_eq!(error["error"]["retryable"], true);
        assert_eq!(error["error"]["interrupted_after_tokens"], 0);
        assert_eq!(executor.calls(), 3, "initial + 2 retries only");
    }

    #[tokio::test]
    async fn mid_stream_failure_is_explicit_interruption_with_no_continuation() {
        // `retryable: true` must NOT trigger a retry after the first token.
        let executor = std::sync::Arc::new(StaticExecutor::fail_mid_stream(
            &["par", "tial"],
            "host_lost",
            true,
        ));
        let response = router(executor.clone())
            .oneshot(chat_request({
                let mut b = basic_body();
                b["stream"] = json!(true);
                b
            }))
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
        let frames = sse_payloads(&body);
        assert_eq!(frames.len(), 4, "role + 2 tokens + error: {frames:?}");
        // Exactly the two tokens the peer actually produced — no fabricated
        // continuation, no duplicated output.
        let seen: Vec<String> = frames[1..3]
            .iter()
            .map(|f| {
                let v: Value = serde_json::from_str(f).unwrap();
                v["choices"][0]["delta"]["content"]
                    .as_str()
                    .unwrap()
                    .to_string()
            })
            .collect();
        assert_eq!(seen, vec!["par".to_string(), "tial".to_string()]);
        let error: Value = serde_json::from_str(&frames[3]).unwrap();
        assert_eq!(error["error"]["code"], "interrupted");
        assert_eq!(error["error"]["interrupted_after_tokens"], 2);
        assert!(!body.contains("[DONE]"), "no DONE after an error event");
        assert_eq!(executor.calls(), 1, "no retry after the first token");
    }

    #[tokio::test]
    async fn mid_stream_failure_non_stream_maps_to_502_interrupted() {
        let executor = std::sync::Arc::new(StaticExecutor::fail_mid_stream(
            &["par", "tial"],
            "host_lost",
            true,
        ));
        let response = router(executor.clone())
            .oneshot(chat_request(basic_body()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body: Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(body["error"]["code"], "interrupted");
        assert_eq!(body["error"]["interrupted_after_tokens"], 2);
        assert_eq!(executor.calls(), 1);
    }

    #[tokio::test]
    async fn models_endpoint_lists_profiles() {
        let response = router(std::sync::Arc::new(StaticExecutor::happy(&["x"])))
            .oneshot(Request::get("/v1/models").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(body["object"], "list");
        assert_eq!(body["data"][0]["id"], MODEL);
        assert_eq!(body["data"][0]["object"], "model");
    }

    #[tokio::test]
    async fn oversized_prompt_is_rejected_with_msp_error_shape() {
        let executor = std::sync::Arc::new(StaticExecutor::happy(&["x"]));
        let huge = "x".repeat(MAX_PROMPT_BYTES + 1);
        let response = router(executor.clone())
            .oneshot(chat_request(json!({
                "model": MODEL,
                "messages": [{ "role": "user", "content": huge }],
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(body["error"]["code"], "payload_too_large");
        assert_eq!(body["error"]["retryable"], false);
        assert!(body["error"]["message"].as_str().unwrap().contains("32769"));
        assert_eq!(executor.calls(), 0, "rejected before any executor work");
    }

    #[tokio::test]
    async fn invalid_body_and_empty_messages_are_400() {
        let executor = std::sync::Arc::new(StaticExecutor::happy(&["x"]));
        let app = router(executor.clone());
        let bad_json = app
            .clone()
            .oneshot(
                Request::post("/v1/chat/completions")
                    .header("content-type", "application/json")
                    .body(Body::from("{not json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_json.status(), StatusCode::BAD_REQUEST);
        let body: Value = serde_json::from_slice(&body_bytes(bad_json).await).unwrap();
        assert_eq!(body["error"]["code"], "invalid_body");

        let no_messages = app
            .oneshot(chat_request(json!({ "model": MODEL, "messages": [] })))
            .await
            .unwrap();
        assert_eq!(no_messages.status(), StatusCode::BAD_REQUEST);
        assert_eq!(executor.calls(), 0);
    }

    #[tokio::test]
    async fn no_peer_maps_to_503() {
        let executor = std::sync::Arc::new(StaticExecutor::no_peer());
        let response = router(executor)
            .oneshot(chat_request(basic_body()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body: Value = serde_json::from_slice(&body_bytes(response).await).unwrap();
        assert_eq!(body["error"]["code"], "no_peer");
    }

    #[tokio::test]
    async fn slow_consumer_stream_delivers_every_token() {
        let executor = std::sync::Arc::new(StaticExecutor::slow_consumer(
            &["a", "b", "c", "d"],
            std::time::Duration::from_millis(5),
        ));
        let response = router(executor)
            .oneshot(chat_request({
                let mut b = basic_body();
                b["stream"] = json!(true);
                b
            }))
            .await
            .unwrap();
        let body = String::from_utf8(body_bytes(response).await.to_vec()).unwrap();
        let frames = sse_payloads(&body);
        assert_eq!(frames.len(), 7);
        assert_eq!(frames[6], "[DONE]");
        for i in 0..4 {
            let chunk: Value = serde_json::from_str(&frames[1 + i]).unwrap();
            assert_eq!(
                chunk["choices"][0]["delta"]["content"],
                ["a", "b", "c", "d"][i]
            );
        }
    }

    #[tokio::test]
    async fn message_content_never_appears_in_audit_logs() {
        const SENTINEL: &str = "SENTINEL-SECRET-PROMPT-NEVER-LOG-ME";
        let executor = std::sync::Arc::new(StaticExecutor::happy(&["SENTINEL-SECRET-COMPLETION"]));
        let response = router(executor)
            .oneshot(chat_request(json!({
                "model": MODEL,
                "messages": [
                    { "role": "system", "content": SENTINEL },
                    { "role": "user", "content": format!("prefix {SENTINEL} suffix") },
                ],
                "stream": true,
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let _ = body_bytes(response).await;
        let lines = audit::take_lines();
        assert!(!lines.is_empty(), "some audit lines must exist");
        for line in &lines {
            assert!(
                !line.contains(SENTINEL),
                "audit line leaked message content: {line:?}"
            );
        }
        assert!(
            lines.iter().any(|l| l.contains("request_id=")),
            "audit lines carry request ids: {lines:?}"
        );
    }

    #[tokio::test]
    async fn unknown_model_uses_documented_output_cap() {
        let executor = std::sync::Arc::new(StaticExecutor::happy(&["x"]));
        let response = router(executor.clone())
            .oneshot(chat_request(json!({
                "model": "msp1:unknown",
                "messages": [{ "role": "user", "content": "hi" }],
                "max_tokens": 999_999,
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let request = executor.last_request().unwrap();
        assert_eq!(request.max_tokens, DEFAULT_MAX_OUTPUT_TOKENS);
        let clamped = response
            .headers()
            .get(X_MSP_CLAMPED)
            .and_then(|v| v.to_str().ok())
            .unwrap()
            .to_string();
        assert!(clamped.contains(&format!("max_tokens={DEFAULT_MAX_OUTPUT_TOKENS}")));
    }

    #[test]
    fn loopback_guard_refuses_non_loopback_addresses() {
        assert_loopback("127.0.0.1".parse().unwrap()).unwrap();
        assert_loopback("::1".parse().unwrap()).unwrap();
        for refused in ["0.0.0.0", "192.168.1.5", "8.8.8.8", "::"] {
            let ip: std::net::IpAddr = refused.parse().unwrap();
            assert!(
                matches!(assert_loopback(ip), Err(GatewayError::NotLoopback(_))),
                "{refused} must be refused"
            );
        }
    }

    #[tokio::test]
    async fn spawned_gateway_binds_loopback_only() {
        let executor = std::sync::Arc::new(StaticExecutor::happy(&["x"]));
        let profiles = StaticProfiles::new(vec![ModelInfo {
            id: MODEL.to_string(),
            max_output_tokens: 64,
        }]);
        let handle = spawn_loopback(GatewayState::new(executor, std::sync::Arc::new(profiles)))
            .await
            .unwrap();
        assert!(handle.local_addr.ip().is_loopback());
        handle.shutdown();
    }

    #[test]
    fn normalized_request_serializes_to_the_frozen_6_2_shape() {
        let request = NormalizedRequest {
            request_id: "6f9619ff-8b86-d011-b42d-00c04fc964ff".to_string(),
            profile_id: "msp1:aa11".to_string(),
            capability_token: None,
            messages: vec![NormalizedMessage {
                role: "user".to_string(),
                content: "hi".to_string(),
            }],
            sampling: Sampling {
                temperature: 0.7,
                top_p: 0.9,
                top_k: 40,
                seed: Some(7),
            },
            max_tokens: 64,
            deadline_ms: 30_000,
            stream: true,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["requestId"], "6f9619ff-8b86-d011-b42d-00c04fc964ff");
        assert_eq!(json["profileId"], "msp1:aa11");
        assert_eq!(json["messages"][0]["role"], "user");
        assert_eq!(json["sampling"]["topK"], 40);
        assert_eq!(json["maxTokens"], 64);
        assert_eq!(json["deadlineMs"], 30_000);
        assert!(json.get("capabilityToken").is_none());
        // Round-trip preserves everything.
        let back: NormalizedRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, request);
    }

    #[test]
    fn finish_reason_wire_strings() {
        assert_eq!(FinishReason::Stop.as_str(), "stop");
        assert_eq!(FinishReason::Length.as_str(), "length");
        assert_eq!(FinishReason::Cancelled.as_str(), "cancelled");
        assert_eq!(FinishReason::Error.as_str(), "error");
        assert_eq!(
            serde_json::to_string(&FinishReason::Length).unwrap(),
            "\"length\""
        );
    }
}
