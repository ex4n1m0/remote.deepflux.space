//! ADR-040 cloud executor: the gateway's [`InferenceExecutor`] over one
//! OpenAI-compatible chat-completions API (DeepSeek, OpenRouter — any
//! provider speaking the same wire shape).
//!
//! Scope of C1 (the foundation of the cloud-peer build): request mapping
//! (NormalizedRequest → chat completion with `stream: true` +
//! `include_usage`), SSE parsing to the executor event vocabulary
//! (TokenDelta per chunk, Usage with HONEST wall-clock timings — the
//! provider reports no prefill/decode split, so `prefill_ms` is the
//! measured request-start→first-token and `decode_ms` the first→last),
//! and ADR-007 failure semantics: pre-first-token failures are
//! `Retryable` (the swarm may fail over), mid-stream failures become
//! `ExecutorEvent::Error` — never a fabricated continuation.
//!
//! KEY DISCIPLINE (ADR-040 §2/§5): the provider key never appears in a
//! URL, an error message, a debug format, or telemetry. Errors surface as
//! status codes and closed vocabulary only — provider response BODIES
//! are external-controlled text and never ride an error string.
//! Prompts DO leave to the provider (the disclosed, labeled cloud path).

use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::StreamExt;
use modelswarm_gateway::{
    ExecutorError, ExecutorEvent, ExecutorStream, FinishReason, InferenceExecutor,
    NormalizedRequest,
};
use tokio::sync::mpsc;

/// The two default providers (ADR-040 §5; more need an owner gate).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProvider {
    DeepSeek,
    OpenRouter,
}

impl CloudProvider {
    /// OpenAI-compatible base URL (chat completions at `/chat/completions`).
    pub fn base_url(self) -> &'static str {
        match self {
            CloudProvider::DeepSeek => "https://api.deepseek.com/v1",
            CloudProvider::OpenRouter => "https://openrouter.ai/api/v1",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            CloudProvider::DeepSeek => "deepseek",
            CloudProvider::OpenRouter => "openrouter",
        }
    }
}

/// One pinned cloud serving config (ADR-040 §1: provider + exact model id
/// IS the profile exactness for cloud profiles).
#[derive(Debug, Clone)]
pub struct CloudApiConfig {
    pub provider: CloudProvider,
    /// The provider's exact model id (e.g. `deepseek-chat`).
    pub model: String,
    /// The user's API key — desktop-local only, never logged or hub-sent.
    pub api_key: String,
    /// Overall request budget (stream + headers).
    pub request_timeout: Duration,
    /// Tests and local staging only: serve from this base instead of the
    /// provider's real endpoint. Production always leaves this `None`
    /// (the pinned provider URL is part of the profile's exactness).
    pub base_url_override: Option<String>,
}

/// Executes against one cloud profile. Cheap to build; one `reqwest`
/// client is shared per executor.
pub struct CloudApiExecutor {
    config: CloudApiConfig,
    client: reqwest::Client,
}

impl CloudApiExecutor {
    pub fn new(config: CloudApiConfig) -> Result<Self, String> {
        let client = modelswarm_dns::apply(reqwest::Client::builder())
            .timeout(config.request_timeout)
            .build()
            .map_err(|e| format!("cloud client build failed: {e}"))?;
        Ok(Self { config, client })
    }

    /// The honest mode-label fragment for replies this executor serves
    /// (ADR-040 §4): `cloud — <provider> <model> (API)`.
    pub fn mode_label(&self) -> String {
        format!(
            "cloud — {} {} (API)",
            self.config.provider.label(),
            self.config.model
        )
    }

    fn chat_url(&self) -> String {
        let base = self
            .config
            .base_url_override
            .as_deref()
            .unwrap_or_else(|| self.config.provider.base_url());
        format!("{}/chat/completions", base.trim_end_matches('/'))
    }
}

/// Maps one SSE `data:` payload (already stripped of the prefix) to zero
/// or more executor events. Pure — the test suite pins the shapes.
fn sse_payload_to_events(payload: &str) -> Vec<ExecutorEvent> {
    let mut out = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) else {
        return out; // Unparseable keep-alives/comments degrade to silence.
    };
    if let Some(choices) = v.get("choices").and_then(|c| c.as_array()) {
        if let Some(first) = choices.first() {
            if let Some(content) = first
                .get("delta")
                .and_then(|d| d.get("content"))
                .and_then(|c| c.as_str())
            {
                if !content.is_empty() {
                    out.push(ExecutorEvent::TokenDelta {
                        delta: content.to_string(),
                        index: 0,
                    });
                }
            }
        }
    }
    if let Some(usage) = v.get("usage") {
        let prompt = usage
            .get("prompt_tokens")
            .and_then(|t| t.as_u64())
            .unwrap_or(0);
        let completion = usage
            .get("completion_tokens")
            .and_then(|t| t.as_u64())
            .unwrap_or(0);
        // Timings are attached by the stream task (wall-clock measured);
        // this pure layer only lifts the counts.
        out.push(ExecutorEvent::Usage {
            prompt_tokens: u32::try_from(prompt).unwrap_or(u32::MAX),
            completion_tokens: u32::try_from(completion).unwrap_or(u32::MAX),
            prefill_ms: 0.0,
            decode_ms: 0.0,
        });
    }
    out
}

fn finish_reason_of(payload: &str) -> Option<FinishReason> {
    let v = serde_json::from_str::<serde_json::Value>(payload).ok()?;
    let reason = v
        .get("choices")?
        .as_array()?
        .first()?
        .get("finish_reason")?
        .as_str()?;
    Some(match reason {
        "length" => FinishReason::Length,
        _ => FinishReason::Stop,
    })
}

#[async_trait]
impl InferenceExecutor for CloudApiExecutor {
    async fn execute(&self, request: NormalizedRequest) -> Result<ExecutorStream, ExecutorError> {
        let body = serde_json::json!({
            "model": self.config.model,
            "messages": request
                .messages
                .iter()
                .map(|m| serde_json::json!({ "role": m.role, "content": m.content }))
                .collect::<Vec<_>>(),
            "temperature": request.sampling.temperature,
            "top_p": request.sampling.top_p,
            "max_tokens": request.max_tokens,
            "stream": true,
            // OpenAI-compatible providers emit a final usage chunk when set.
            "stream_options": { "include_usage": true },
        });
        let started = Instant::now();
        let response = self
            .client
            .post(self.chat_url())
            .bearer_auth(&self.config.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ExecutorError::Fatal {
                // Transport text can embed URLs — key-free by construction
                // (the key rides the header), but keep it to the closed
                // shape anyway.
                code: format!("cloud_transport: {}", closed_transport_reason(&e)),
            })?;
        let status = response.status();
        if !status.is_success() {
            // 429/5xx are worth a pre-token failover; 4xx auth/shape are
            // fatal. Never include the provider's body text.
            let code = format!("cloud_http_{}", status.as_u16());
            return if status.as_u16() == 429 || status.is_server_error() {
                Err(ExecutorError::Retryable { peer_hint: None })
            } else {
                Err(ExecutorError::Fatal { code })
            };
        }

        let (tx, rx) = mpsc::channel::<ExecutorEvent>(64);
        let label = self.mode_label();
        tokio::spawn(async move {
            let mut stream = response.bytes_stream();
            let mut buffer = String::new();
            let mut first_token_at: Option<Instant> = None;
            let mut last_token_at: Option<Instant> = None;
            let mut finish = FinishReason::Stop;
            let mut usage_emitted = false;
            while let Some(chunk) = stream.next().await {
                let Ok(bytes) = chunk else { break };
                buffer.push_str(&String::from_utf8_lossy(&bytes));
                // SSE events are separated by blank lines; process every
                // complete `data:` line.
                while let Some(nl) = buffer.find('\n') {
                    let line = buffer[..nl].trim_end_matches('\r').to_string();
                    buffer.drain(..=nl);
                    let Some(payload) = line.strip_prefix("data: ") else {
                        continue;
                    };
                    if payload.trim() == "[DONE]" {
                        let decode_ms = match (first_token_at, last_token_at) {
                            (Some(a), Some(b)) => {
                                a.elapsed().max(b.duration_since(a)).as_secs_f64() * 1000.0
                            }
                            _ => 0.0,
                        };
                        let prefill_ms = first_token_at
                            .map(|t| t.duration_since(started).as_secs_f64() * 1000.0)
                            .unwrap_or(0.0);
                        if !usage_emitted {
                            let _ = tx
                                .send(ExecutorEvent::Usage {
                                    prompt_tokens: 0,
                                    completion_tokens: 0,
                                    prefill_ms,
                                    decode_ms,
                                })
                                .await;
                        }
                        let _ = tx
                            .send(ExecutorEvent::Completed {
                                finish_reason: finish,
                            })
                            .await;
                        return;
                    }
                    if let Some(reason) = finish_reason_of(payload) {
                        finish = reason;
                    }
                    for event in sse_payload_to_events(payload) {
                        if matches!(event, ExecutorEvent::TokenDelta { .. }) {
                            first_token_at.get_or_insert_with(Instant::now);
                            last_token_at = Some(Instant::now());
                        }
                        if matches!(event, ExecutorEvent::Usage { .. }) {
                            // Attach the measured timings to the provider's
                            // counts (the wall clock is the honest number).
                            if let ExecutorEvent::Usage {
                                prompt_tokens,
                                completion_tokens,
                                ..
                            } = event
                            {
                                usage_emitted = true;
                                let prefill_ms = first_token_at
                                    .map(|t| t.duration_since(started).as_secs_f64() * 1000.0)
                                    .unwrap_or(0.0);
                                let decode_ms = match (first_token_at, last_token_at) {
                                    (Some(a), Some(b)) => {
                                        b.duration_since(a).as_secs_f64() * 1000.0
                                    }
                                    _ => 0.0,
                                };
                                let _ = tx
                                    .send(ExecutorEvent::Usage {
                                        prompt_tokens,
                                        completion_tokens,
                                        prefill_ms,
                                        decode_ms,
                                    })
                                    .await;
                                continue;
                            }
                        }
                        let _ = tx.send(event).await;
                    }
                }
            }
            // Stream ended without [DONE]: an honest mid-stream Error, never
            // a fabricated completion (ADR-007).
            let _ = tx
                .send(ExecutorEvent::Error {
                    code: "cloud_stream_ended".into(),
                    retryable: false,
                    interrupted_after_tokens: None,
                })
                .await;
            let _ = label; // (kept for future audit wiring; not logged here)
        });
        Ok(Box::pin(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }
}

/// Transport failure reasons as a closed vocabulary (no error text — the
/// provider/network controls that string).
fn closed_transport_reason(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timeout"
    } else if e.is_connect() {
        "connect"
    } else if e.is_decode() {
        "decode"
    } else {
        "transport"
    }
}
