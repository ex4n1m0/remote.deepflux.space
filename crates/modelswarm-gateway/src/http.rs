//! Axum router, request normalization + clamping, SSE shaping, and the
//! ADR-007 retry state machine.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;

use crate::audit;
use crate::{
    FinishReason, InferenceExecutor, ModelInfo, NormalizedMessage, NormalizedRequest,
    ProfileProvider, Sampling,
};

/// Header echoing the applied (post-clamp) values as `field=value` pairs,
/// comma-separated. Present only when at least one field was clamped.
pub const X_MSP_CLAMPED: HeaderName = HeaderName::from_static("x-msp-clamped");

/// Shared gateway state: the executor plus the profile provider.
#[derive(Clone)]
pub struct GatewayState {
    executor: Arc<dyn InferenceExecutor>,
    profiles: Arc<dyn ProfileProvider>,
}

impl GatewayState {
    /// Assembles gateway state.
    pub fn new(executor: Arc<dyn InferenceExecutor>, profiles: Arc<dyn ProfileProvider>) -> Self {
        Self { executor, profiles }
    }
}

/// Error type for serving-loop failures.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// A non-loopback bind address was requested (loopback-only, enforced).
    #[error("refusing to bind non-loopback address {0}; the gateway is 127.0.0.1-only")]
    NotLoopback(IpAddr),
    /// Underlying bind/serve IO failure.
    #[error("gateway io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Rejects any address that is not loopback. The gateway never binds
/// `0.0.0.0`, `::`, or an external interface.
pub fn assert_loopback(ip: IpAddr) -> Result<(), GatewayError> {
    match ip.is_loopback() {
        true => Ok(()),
        false => Err(GatewayError::NotLoopback(ip)),
    }
}

fn loopback_socket(port: u16) -> Result<SocketAddr, GatewayError> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    assert_loopback(addr.ip())?;
    Ok(addr)
}

/// Serves the OpenAI-compatible API on `127.0.0.1:port` (default
/// [`crate::DEFAULT_PORT`]). Loopback-only is structural: the address is
/// constructed here, never caller-supplied.
pub async fn serve(state: GatewayState, port: u16) -> Result<(), GatewayError> {
    let listener = tokio::net::TcpListener::bind(loopback_socket(port)?).await?;
    axum::serve(listener, build_router(state))
        .await
        .map_err(GatewayError::Io)
}

/// Handle to a spawned loopback gateway (test/utility helper).
pub struct GatewayHandle {
    /// The bound loopback address.
    pub local_addr: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

impl GatewayHandle {
    /// Stops the gateway server task.
    pub fn shutdown(self) {
        let _ = self.shutdown.send(());
    }
}

/// Binds an ephemeral loopback port and spawns the server.
pub async fn spawn_loopback(state: GatewayState) -> Result<GatewayHandle, GatewayError> {
    let listener = tokio::net::TcpListener::bind(loopback_socket(0)?).await?;
    let local_addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(listener, build_router(state)).with_graceful_shutdown(async move {
        let _ = rx.await;
    });
    tokio::spawn(async move {
        let _ = server.await;
    });
    Ok(GatewayHandle {
        local_addr,
        shutdown: tx,
    })
}

/// Builds the OpenAI-compatible router (no transport concerns inside).
pub fn build_router(state: GatewayState) -> Router {
    Router::new()
        .route("/v1/models", get(list_models))
        .route("/v1/chat/completions", post(chat_completions))
        .with_state(state)
}

/// GET /v1/models.
async fn list_models(State(state): State<GatewayState>) -> Response {
    let data: Vec<Value> = state.profiles.list().iter().map(model_entry).collect();
    Json(json!({ "object": "list", "data": data })).into_response()
}

fn model_entry(m: &ModelInfo) -> Value {
    json!({
        "id": m.id,
        "object": "model",
        "created": 0,
        "owned_by": "modelswarm",
    })
}

/// Parsed OpenAI chat-completions body. Unknown OpenAI fields are ignored;
/// MSP-relevant fields are optional and clamped, never rejected (§6.4).
#[derive(Debug, Deserialize)]
struct ChatCompletionsBody {
    model: String,
    messages: Vec<IncomingMessage>,
    temperature: Option<f32>,
    top_p: Option<f32>,
    top_k: Option<u32>,
    max_tokens: Option<u32>,
    stream: Option<bool>,
    seed: Option<u64>,
    /// Non-OpenAI extension: total wall budget (msp-v1 §6.4 `deadlineMs`).
    deadline_ms: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct IncomingMessage {
    role: String,
    content: String,
}

/// One applied clamp, echoed via [`X_MSP_CLAMPED`].
#[derive(Debug, Clone, PartialEq)]
struct AppliedClamp {
    field: &'static str,
    applied: String,
}

impl AppliedClamp {
    fn new(field: &'static str, applied: impl std::fmt::Display) -> Self {
        Self {
            field,
            applied: applied.to_string(),
        }
    }
}

/// POST /v1/chat/completions.
async fn chat_completions(State(state): State<GatewayState>, body: Bytes) -> Response {
    let parsed: ChatCompletionsBody = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(error) => {
            return msp_error(
                StatusCode::BAD_REQUEST,
                "invalid_body",
                &format!("request body is not a valid chat.completions payload: {error}"),
                false,
            );
        }
    };

    // Prompt-size cap before any expensive work (msp-v1 §6.4: 32 KiB).
    let prompt_bytes: usize = parsed.messages.iter().map(|m| m.content.len()).sum();
    if prompt_bytes > crate::MAX_PROMPT_BYTES {
        audit::record(format!(
            "event=request.rejected code=payload_too_large prompt_bytes={prompt_bytes}"
        ));
        return msp_error(
            StatusCode::BAD_REQUEST,
            "payload_too_large",
            &format!(
                "prompt is {prompt_bytes} bytes; the maximum is {}",
                crate::MAX_PROMPT_BYTES
            ),
            false,
        );
    }
    if parsed.messages.is_empty() {
        return msp_error(
            StatusCode::BAD_REQUEST,
            "invalid_body",
            "messages must not be empty",
            false,
        );
    }

    let mut clamps: Vec<AppliedClamp> = Vec::new();

    // deadlineMs (§6.4: clamp to [1000, 120000], default 120000).
    let deadline_ms = parsed.deadline_ms.unwrap_or(crate::DEADLINE_MS_DEFAULT);
    let deadline_ms = match deadline_ms {
        value if value < crate::DEADLINE_MS_MIN => {
            clamps.push(AppliedClamp::new("deadline_ms", crate::DEADLINE_MS_MIN));
            crate::DEADLINE_MS_MIN
        }
        value if value > crate::DEADLINE_MS_MAX => {
            clamps.push(AppliedClamp::new("deadline_ms", crate::DEADLINE_MS_MAX));
            crate::DEADLINE_MS_MAX
        }
        value => value,
    };

    // Profile-known max_tokens ceiling; the documented default applies when
    // the local provider does not know the model.
    let profile = state
        .profiles
        .list()
        .into_iter()
        .find(|m| m.id == parsed.model);
    let profile_max = profile
        .as_ref()
        .map(|m| m.max_output_tokens)
        .unwrap_or(crate::DEFAULT_MAX_OUTPUT_TOKENS);
    let requested_max = parsed.max_tokens.unwrap_or(profile_max);
    let max_tokens = match requested_max {
        value if value < 1 => {
            clamps.push(AppliedClamp::new("max_tokens", 1));
            1
        }
        value if value > profile_max => {
            clamps.push(AppliedClamp::new("max_tokens", profile_max));
            profile_max
        }
        value => value,
    };

    // temperature ∈ [0, 2], default 1.0.
    let temperature = parsed.temperature.unwrap_or(1.0);
    let temperature = if temperature < 0.0 {
        clamps.push(AppliedClamp::new("temperature", 0));
        0.0
    } else if temperature > crate::TEMPERATURE_MAX {
        clamps.push(AppliedClamp::new("temperature", crate::TEMPERATURE_MAX));
        crate::TEMPERATURE_MAX
    } else {
        temperature
    };

    // top_p ∈ (0, 1], default 1.0; out-of-range (including 0 or negative)
    // clamps to the neutral full-distribution value 1.0.
    let top_p = parsed.top_p.unwrap_or(1.0);
    let top_p = if !(0.0 < top_p && top_p <= 1.0) {
        clamps.push(AppliedClamp::new("top_p", 1));
        1.0
    } else {
        top_p
    };

    // top_k ∈ [1, 200], default 40.
    let top_k = parsed.top_k.unwrap_or(crate::TOP_K_DEFAULT);
    let top_k = match top_k {
        value if value < crate::TOP_K_MIN => {
            clamps.push(AppliedClamp::new("top_k", crate::TOP_K_MIN));
            crate::TOP_K_MIN
        }
        value if value > crate::TOP_K_MAX => {
            clamps.push(AppliedClamp::new("top_k", crate::TOP_K_MAX));
            crate::TOP_K_MAX
        }
        value => value,
    };

    let request = NormalizedRequest {
        request_id: Uuid::new_v4().to_string(),
        profile_id: parsed.model.clone(),
        capability_token: None,
        messages: parsed
            .messages
            .into_iter()
            .map(|m| NormalizedMessage {
                role: m.role,
                content: m.content,
            })
            .collect(),
        sampling: Sampling {
            temperature,
            top_p,
            top_k,
            seed: parsed.seed,
        },
        max_tokens,
        deadline_ms,
        stream: parsed.stream.unwrap_or(false),
    };

    audit::record(format!(
        "event=request.normalized request_id={} model={} messages={} prompt_bytes={} max_tokens={} deadline_ms={} clamps={}",
        request.request_id,
        request.profile_id,
        request.messages.len(),
        prompt_bytes,
        request.max_tokens,
        request.deadline_ms,
        clamps.len()
    ));
    if !clamps.is_empty() {
        let fields = clamps
            .iter()
            .map(|c| format!("{}:{}", c.field, c.applied))
            .collect::<Vec<_>>()
            .join(",");
        audit::record(format!(
            "event=request.clamped request_id={} fields={fields}",
            request.request_id
        ));
    }

    let clamp_header = clamped_header_value(&clamps);
    if request.stream {
        stream_response(state, request, clamp_header).await
    } else {
        json_response(state, request, clamp_header).await
    }
}

fn clamped_header_value(clamps: &[AppliedClamp]) -> Option<HeaderValue> {
    if clamps.is_empty() {
        return None;
    }
    let joined = clamps
        .iter()
        .map(|c| format!("{}={}", c.field, c.applied))
        .collect::<Vec<_>>()
        .join(", ");
    HeaderValue::from_str(&joined).ok()
}

/// Usage snapshot from the executor's `usage` event.
#[derive(Debug, Clone, Copy, PartialEq)]
struct UsageSnapshot {
    prompt_tokens: u32,
    completion_tokens: u32,
    #[allow(dead_code)]
    prefill_ms: f64,
    #[allow(dead_code)]
    decode_ms: f64,
}

/// Terminal outcome of driving the executor under ADR-007 rules.
#[derive(Debug, Clone, PartialEq)]
enum RunStatus {
    Completed {
        finish_reason: FinishReason,
        usage: Option<UsageSnapshot>,
    },
    Error {
        code: String,
        retryable: bool,
        interrupted_after_tokens: u32,
    },
}

impl RunStatus {
    fn error(code: &str, retryable: bool, emitted: u32) -> Self {
        Self::Error {
            code: code.to_string(),
            retryable,
            interrupted_after_tokens: emitted,
        }
    }
}

/// Drives the executor with ADR-007 semantics:
/// - retries (≤ [`crate::MAX_RETRIES_BEFORE_FIRST_TOKEN`]) only while no
///   token has been emitted to the client;
/// - after the first token, any failure becomes an explicit `interrupted`
///   error — never a fabricated continuation, never a silent regeneration.
///
/// `on_token` is invoked per emitted delta (SSE forwards immediately; the
/// JSON path buffers).
async fn run_request(
    executor: &dyn InferenceExecutor,
    request: &NormalizedRequest,
    mut on_token: impl FnMut(&str, u32),
) -> RunStatus {
    let mut retries_left = crate::MAX_RETRIES_BEFORE_FIRST_TOKEN;
    let mut emitted_tokens: u32 = 0;
    'attempts: loop {
        match executor.execute(request.clone()).await {
            Err(crate::ExecutorError::NoPeer) => {
                audit::record(format!(
                    "event=executor.no_peer request_id={}",
                    request.request_id
                ));
                return RunStatus::error("no_peer", false, emitted_tokens);
            }
            Err(crate::ExecutorError::Fatal { code }) => {
                audit::record(format!(
                    "event=executor.fatal request_id={} code={code}",
                    request.request_id
                ));
                return RunStatus::error(&code, false, emitted_tokens);
            }
            Err(crate::ExecutorError::Retryable { peer_hint }) => {
                audit::record(format!(
                    "event=executor.retryable request_id={} peer_hint={peer_hint:?} emitted_tokens={emitted_tokens} retries_left={retries_left}",
                    request.request_id
                ));
                if emitted_tokens == 0 && retries_left > 0 {
                    retries_left -= 1;
                    continue;
                }
                let code = if emitted_tokens > 0 {
                    "interrupted"
                } else {
                    "no_eligible_peer"
                };
                return RunStatus::error(code, true, emitted_tokens);
            }
            Ok(mut stream) => {
                let mut usage: Option<UsageSnapshot> = None;
                loop {
                    let event = match stream.next().await {
                        Some(event) => event,
                        // Stream ended without `completed`: abnormal. Retry
                        // only if nothing was emitted and budget remains;
                        // otherwise an honest interruption.
                        None => {
                            audit::record(format!(
                                "event=stream.ended_early request_id={} emitted_tokens={emitted_tokens}",
                                request.request_id
                            ));
                            if emitted_tokens == 0 && retries_left > 0 {
                                retries_left -= 1;
                                continue 'attempts;
                            }
                            let code = if emitted_tokens > 0 {
                                "interrupted"
                            } else {
                                "stream_ended"
                            };
                            return RunStatus::error(code, false, emitted_tokens);
                        }
                    };
                    match event {
                        crate::ExecutorEvent::Accepted {
                            queue_position,
                            eta_ms,
                        } => {
                            audit::record(format!(
                                "event=stream.accepted request_id={} queue_position={queue_position} eta_ms={eta_ms}",
                                request.request_id
                            ));
                        }
                        crate::ExecutorEvent::TokenDelta { delta, index } => {
                            emitted_tokens += 1;
                            on_token(&delta, index);
                        }
                        crate::ExecutorEvent::Usage {
                            prompt_tokens,
                            completion_tokens,
                            prefill_ms,
                            decode_ms,
                        } => {
                            usage = Some(UsageSnapshot {
                                prompt_tokens,
                                completion_tokens,
                                prefill_ms,
                                decode_ms,
                            });
                        }
                        crate::ExecutorEvent::Completed { finish_reason } => {
                            audit::record(format!(
                                "event=stream.completed request_id={} finish_reason={} output_tokens={emitted_tokens}",
                                request.request_id,
                                finish_reason.as_str()
                            ));
                            return RunStatus::Completed {
                                finish_reason,
                                usage,
                            };
                        }
                        crate::ExecutorEvent::Error {
                            code,
                            retryable,
                            interrupted_after_tokens,
                        } => {
                            audit::record(format!(
                                "event=stream.error request_id={} code={code} retryable={retryable} server_interrupted_after={interrupted_after_tokens:?} emitted_tokens={emitted_tokens}",
                                request.request_id
                            ));
                            if emitted_tokens == 0 && retryable && retries_left > 0 {
                                retries_left -= 1;
                                continue 'attempts;
                            }
                            // ADR-007: after the first token, the client
                            // sees what it saw — explicit interruption.
                            let final_code = if emitted_tokens > 0 {
                                "interrupted"
                            } else {
                                code.as_str()
                            };
                            return RunStatus::error(final_code, retryable, emitted_tokens);
                        }
                    }
                }
            }
        }
    }
}

fn created_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn chunk_base(id: &str, model: &str) -> Value {
    json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created_now(),
        "model": model,
    })
}

fn sse_line(value: &Value) -> String {
    format!("data: {value}\n\n")
}

async fn stream_response(
    state: GatewayState,
    request: NormalizedRequest,
    clamp_header: Option<HeaderValue>,
) -> Response {
    // Unbounded: slow consumers must never drop content chunks (§6.4
    // backpressure is the client's read loop).
    let (tx, rx) = mpsc::unbounded_channel::<String>();
    let executor = state.executor;
    let request_id = request.request_id.clone();
    let model = request.profile_id.clone();
    tokio::spawn(async move {
        let id = format!("chatcmpl-{request_id}");
        // Role chunk first (metadata, safe before any executor outcome).
        let mut role = chunk_base(&id, &model);
        role["choices"] = json!([{
            "index": 0,
            "delta": { "role": "assistant", "content": "" },
            "finish_reason": null,
        }]);
        let _ = tx.send(sse_line(&role));

        let status = run_request(executor.as_ref(), &request, |delta, _index| {
            let mut chunk = chunk_base(&id, &model);
            chunk["choices"] = json!([{
                "index": 0,
                "delta": { "content": delta },
                "finish_reason": null,
            }]);
            let _ = tx.send(sse_line(&chunk));
        })
        .await;

        match status {
            RunStatus::Completed {
                finish_reason,
                usage,
            } => {
                let mut finish = chunk_base(&id, &model);
                finish["choices"] = json!([{
                    "index": 0,
                    "delta": {},
                    "finish_reason": finish_reason.as_str(),
                }]);
                if let Some(u) = usage {
                    finish["usage"] = json!({
                        "prompt_tokens": u.prompt_tokens,
                        "completion_tokens": u.completion_tokens,
                    });
                }
                let _ = tx.send(sse_line(&finish));
                let _ = tx.send("data: [DONE]\n\n".to_string());
            }
            RunStatus::Error {
                code,
                retryable,
                interrupted_after_tokens,
            } => {
                // Explicit error event; the stream terminates WITHOUT
                // `[DONE]` and without any fabricated continuation.
                let message = match code.as_str() {
                    "interrupted" => "stream interrupted after first token; no retry (ADR-007)",
                    "no_peer" | "no_eligible_peer" => "no eligible peer for the requested profile",
                    _ => "executor stream failed",
                };
                let error = json!({
                    "error": {
                        "code": code,
                        "message": message,
                        "retryable": retryable,
                        "interrupted_after_tokens": interrupted_after_tokens,
                    }
                });
                let _ = tx.send(sse_line(&error));
            }
        }
    });

    let body_stream = UnboundedReceiverStream::new(rx).map(Ok::<String, std::io::Error>);
    let mut response = Response::new(Body::from_stream(body_stream));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    if let Some(value) = clamp_header {
        response.headers_mut().insert(X_MSP_CLAMPED, value);
    }
    response
}

async fn json_response(
    state: GatewayState,
    request: NormalizedRequest,
    clamp_header: Option<HeaderValue>,
) -> Response {
    let mut deltas: Vec<String> = Vec::new();
    let status = run_request(state.executor.as_ref(), &request, |delta, _index| {
        deltas.push(delta.to_string());
    })
    .await;
    let id = format!("chatcmpl-{}", request.request_id);
    match status {
        RunStatus::Completed {
            finish_reason,
            usage,
        } => {
            let content: String = deltas.concat();
            let mut body = json!({
                "id": id,
                "object": "chat.completion",
                "created": created_now(),
                "model": request.profile_id,
                "choices": [{
                    "index": 0,
                    "message": { "role": "assistant", "content": content },
                    "finish_reason": finish_reason.as_str(),
                }],
            });
            if let Some(u) = usage {
                body["usage"] = json!({
                    "prompt_tokens": u.prompt_tokens,
                    "completion_tokens": u.completion_tokens,
                });
            }
            let mut response = Json(body).into_response();
            if let Some(value) = clamp_header {
                response.headers_mut().insert(X_MSP_CLAMPED, value);
            }
            response
        }
        RunStatus::Error {
            code,
            retryable,
            interrupted_after_tokens,
        } => {
            let status = match code.as_str() {
                "no_peer" | "no_eligible_peer" => StatusCode::SERVICE_UNAVAILABLE,
                "interrupted" => StatusCode::BAD_GATEWAY,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            let message = match code.as_str() {
                "interrupted" => format!(
                    "stream interrupted after {interrupted_after_tokens} tokens; no retry (ADR-007)"
                ),
                "no_peer" | "no_eligible_peer" => {
                    "no eligible peer for the requested profile".to_string()
                }
                other => format!("executor failed: {other}"),
            };
            // msp-v1 §3.4 error shape plus the ADR-007 visibility field for
            // how much output the client actually received.
            let body = json!({
                "error": {
                    "code": code,
                    "message": message,
                    "retryable": retryable,
                    "interrupted_after_tokens": interrupted_after_tokens,
                }
            });
            let mut response = (status, Json(body)).into_response();
            if let Some(value) = clamp_header {
                response.headers_mut().insert(X_MSP_CLAMPED, value);
            }
            response
        }
    }
}

/// msp error shape (msp-v1 §3.4): `{"error":{code,message,retryable}}`.
pub(crate) fn msp_error(
    status: StatusCode,
    code: &str,
    message: &str,
    retryable: bool,
) -> Response {
    let body = json!({
        "error": {
            "code": code,
            "message": message,
            "retryable": retryable,
        }
    });
    (status, Json(body)).into_response()
}
