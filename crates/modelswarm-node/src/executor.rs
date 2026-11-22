//! Local single-peer executor: the gateway's [`InferenceExecutor`] over one
//! local [`InferenceRuntime`] (Phase G scope).
//!
//! This mirrors `modelswarm_session::spec::SpeculativeExecutor`'s event
//! batching — one [`ExecutorEvent::TokenDelta`] per batch of committed tokens
//! (round batch there, [`LOCAL_DELTA_BATCH_TOKENS`] chunk here), then
//! `Usage`, then `Completed` — so the gateway sees the same event shape today
//! and when the full swarm executor replaces this wiring. The full
//! cooperative/swarm executor (`SpeculativeExecutor` + peer rotation over
//! `modelswarm_transport`) is a documented later wiring; see the crate docs.
//!
//! Privacy: the request's message content is tokenized and passed to the
//! local runtime only. It is never logged: the executor's only logging is
//! a closed error-code table through the node telemetry sink (code, HTTP
//! status, byte lengths — never RuntimeError display text, which carries
//! external-process-controlled bodies), and the gateway's audit channel
//! records counts and ids only.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::StreamExt;
use modelswarm_gateway::{
    ExecutorError, ExecutorEvent, ExecutorStream, FinishReason, InferenceExecutor,
    NormalizedMessage, NormalizedRequest,
};
use modelswarm_runtime::{
    DecodeEvent, DecodeTimings, InferenceRuntime, RuntimeError, SamplingParams,
};
use tokio::sync::mpsc;

/// Tokens per [`ExecutorEvent::TokenDelta`] (batching parity with the session
/// executor's per-round batches).
pub const LOCAL_DELTA_BATCH_TOKENS: usize = 16;

/// Executes requests against one local runtime, or none.
pub struct SingleLocalExecutor {
    runtime: Option<Arc<dyn InferenceRuntime>>,
    profile_id: Option<String>,
    /// Node telemetry for redacted failure diagnostics (None in tests).
    telemetry: Option<Arc<modelswarm_telemetry::Telemetry>>,
}

impl SingleLocalExecutor {
    /// Wraps an optional local runtime serving `profile_id`. `None` in either
    /// position makes [`InferenceExecutor::execute`] return
    /// [`ExecutorError::NoPeer`] — an honest 503, never a fake answer.
    pub fn new(runtime: Option<Arc<dyn InferenceRuntime>>, profile_id: Option<String>) -> Self {
        Self {
            runtime,
            profile_id,
            telemetry: None,
        }
    }

    /// Routes decode-failure diagnostics to the node telemetry sink.
    pub fn with_telemetry(mut self, telemetry: Arc<modelswarm_telemetry::Telemetry>) -> Self {
        self.telemetry = Some(telemetry);
        self
    }
}

/// Closed error-code table for runtime failures (AGENTS.md rule 5): the
/// wire and audit surfaces see a stable code only — RuntimeError display
/// text never crosses them (engine error bodies can echo request
/// fragments). Returns `(code, http_status_or_0)`.
fn runtime_error_code(e: &RuntimeError) -> (&'static str, u16) {
    match e {
        RuntimeError::Api { status, .. } => ("engine_api_error", *status),
        RuntimeError::Http(_) => ("engine_transport", 0),
        RuntimeError::MalformedResponse(_) => ("engine_malformed_response", 0),
        RuntimeError::InvalidProfile(_) => ("engine_invalid_profile", 0),
        RuntimeError::TokenOutOfRange(_) => ("engine_token_out_of_range", 0),
        RuntimeError::NotLoaded(_) => ("engine_not_loaded", 0),
        RuntimeError::InvalidDescriptor(_) => ("engine_invalid_descriptor", 0),
        RuntimeError::Unsupported(_) => ("engine_unsupported", 0),
        RuntimeError::Timeout { .. } => ("deadline_exceeded", 0),
        RuntimeError::Cancelled(_) => ("cancelled", 0),
    }
}

fn fatal(code: &str) -> ExecutorError {
    ExecutorError::Fatal {
        code: code.to_string(),
    }
}

/// Renders the conversation in ChatML — the template family of every
/// catalog profile (Qwen, SmolLM2; evidenced by their chat_template_hash
/// inputs). The serving side owns template application (msp-v1 §6.2):
/// the raw `/v1/completions` endpoint applies nothing, and the previous
/// newline flattening made role-less text that tiny models answer with
/// immediate EOS (0-token replies). Non-ChatML profiles need template
/// metadata before they may join the catalog (ADR-025).
pub fn render_chatml(messages: &[NormalizedMessage]) -> String {
    let mut out = String::new();
    for message in messages {
        out.push_str("<|im_start|>");
        out.push_str(&message.role);
        out.push('\n');
        out.push_str(&message.content);
        out.push_str("<|im_end|>\n");
    }
    out.push_str("<|im_start|>assistant\n");
    out
}

#[async_trait]
impl InferenceExecutor for SingleLocalExecutor {
    async fn execute(&self, request: NormalizedRequest) -> Result<ExecutorStream, ExecutorError> {
        let runtime = self.runtime.as_ref().ok_or(ExecutorError::NoPeer)?.clone();
        let profile = self.profile_id.as_deref().ok_or(ExecutorError::NoPeer)?;
        if request.profile_id != profile {
            return Err(fatal("profile_mismatch"));
        }

        // The serving executor applies the chat template (ADR-025): clients
        // send plain {role, content} messages; ChatML is rendered exactly
        // once, here.
        let conversation = render_chatml(&request.messages);
        let prompt = runtime
            .tokenize(&conversation)
            .await
            .map_err(|_| fatal("tokenize_failed"))?;
        let handle = runtime
            .load(profile)
            .await
            .map_err(|_| fatal("load_failed"))?;

        let sampling = SamplingParams {
            temperature: request.sampling.temperature,
            top_p: request.sampling.top_p,
            top_k: request.sampling.top_k,
            seed: request.sampling.seed,
        };
        let budget = Duration::from_millis(u64::from(request.deadline_ms.max(1)));

        // Incremental execution (P1): a driver task forwards events as the
        // runtime produces them — Accepted immediately, one TokenDelta per
        // [`LOCAL_DELTA_BATCH_TOKENS`] committed tokens (detokenized in
        // batch, same event shape as before), Usage + Completed at the end.
        // The event sequence is unchanged from the materialized version;
        // only its timeliness changes. Mid-stream runtime failures become
        // `ExecutorEvent::Error` with the same stable code the pre-stream
        // `Err(Fatal)` carried (ADR-007: the gateway may fail over only
        // before the first token). Dropping the consumer drops the decode
        // stream with it, which aborts the engine-side request.
        let (tx, rx) = mpsc::unbounded_channel::<ExecutorEvent>();
        let telemetry = self.telemetry.clone();
        let max_tokens = request.max_tokens;
        let prompt_len = prompt.len() as u32;
        tokio::spawn(async move {
            let mut decode =
                runtime.decode_stream_events(&handle, &prompt, &sampling, max_tokens, budget);
            let _ = tx.send(ExecutorEvent::Accepted {
                queue_position: 0,
                eta_ms: 0,
            });
            let started = Instant::now();
            let mut batch: Vec<u32> = Vec::with_capacity(LOCAL_DELTA_BATCH_TOKENS);
            let mut batch_index: u32 = 0;
            let mut produced: u32 = 0;
            let mut timings: Option<DecodeTimings> = None;
            /// Detokenize failure → the same `detokenize_failed` code the
            /// pre-streaming executor's fatal path carried.
            fn detokenize_failure() -> ExecutorEvent {
                ExecutorEvent::Error {
                    code: "detokenize_failed".to_string(),
                    retryable: false,
                    interrupted_after_tokens: None,
                }
            }
            while let Some(event) = decode.next().await {
                match event {
                    Ok(DecodeEvent::Token(id)) => {
                        produced += 1;
                        batch.push(id);
                        if batch.len() >= LOCAL_DELTA_BATCH_TOKENS {
                            match runtime.detokenize(&batch).await {
                                Ok(delta) => {
                                    if tx
                                        .send(ExecutorEvent::TokenDelta {
                                            delta,
                                            index: batch_index,
                                        })
                                        .is_err()
                                    {
                                        return; // consumer gone: abort the decode
                                    }
                                }
                                Err(_) => {
                                    let _ = tx.send(detokenize_failure());
                                    return;
                                }
                            }
                            batch_index += 1;
                            batch.clear();
                        }
                    }
                    Ok(DecodeEvent::Timings(t)) => timings = Some(t),
                    Err(e) => {
                        // The cause must not vanish (a hidden engine failure
                        // is indistinguishable from "no peer" at the
                        // gateway) — but it must not leak either: a stable
                        // code on the event, redacted diagnostics
                        // (code/status/length only) in telemetry.
                        let (code, status) = runtime_error_code(&e);
                        if let Some(t) = &telemetry {
                            t.warn(
                                "executor.decode_failed",
                                &[
                                    ("code", code),
                                    ("status", &status.to_string()),
                                    ("detail_bytes", &e.to_string().len().to_string()),
                                ],
                            );
                        }
                        let _ = tx.send(ExecutorEvent::Error {
                            code: code.to_string(),
                            retryable: false,
                            interrupted_after_tokens: Some(produced),
                        });
                        return;
                    }
                }
            }
            if !batch.is_empty() {
                match runtime.detokenize(&batch).await {
                    Ok(delta) => {
                        let _ = tx.send(ExecutorEvent::TokenDelta {
                            delta,
                            index: batch_index,
                        });
                    }
                    Err(_) => {
                        let _ = tx.send(detokenize_failure());
                        return;
                    }
                }
            }
            let _ = tx.send(ExecutorEvent::Usage {
                prompt_tokens: prompt_len,
                completion_tokens: produced,
                prefill_ms: timings.map(|t| t.prompt_ms).unwrap_or(0.0),
                decode_ms: timings
                    .map(|t| t.decode_ms)
                    .unwrap_or_else(|| started.elapsed().as_secs_f64() * 1_000.0),
            });
            let finish_reason = if produced >= max_tokens {
                FinishReason::Length
            } else {
                FinishReason::Stop
            };
            let _ = tx.send(ExecutorEvent::Completed { finish_reason });
        });
        let stream = futures_util::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|event| (event, rx))
        });
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use modelswarm_gateway::{NormalizedMessage, Sampling};
    use modelswarm_runtime::MockRuntime;

    /// Test runtime whose `decode_stream_events` yields tokens with real
    /// wall delays (and can fail mid-stream): pins the executor's
    /// incremental behavior — deltas must reach the consumer as they are
    /// produced, not after the decode completes.
    struct SlowStreamRuntime {
        per_token: Duration,
        fail_after: Option<u32>,
    }

    #[async_trait]
    impl InferenceRuntime for SlowStreamRuntime {
        fn id(&self) -> modelswarm_runtime::RuntimeDescriptor {
            modelswarm_runtime::RuntimeDescriptor::new("slow-stream", "1", "a".repeat(64)).unwrap()
        }
        async fn load(&self, profile_id: &str) -> Result<modelswarm_runtime::Handle, RuntimeError> {
            Ok(modelswarm_runtime::Handle::new(profile_id, 1))
        }
        async fn tokenize(&self, text: &str) -> Result<Vec<u32>, RuntimeError> {
            Ok(text.as_bytes().iter().map(|b| u32::from(*b)).collect())
        }
        async fn detokenize(&self, ids: &[u32]) -> Result<String, RuntimeError> {
            let bytes: Vec<u8> = ids.iter().map(|t| *t as u8).collect();
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        }
        async fn prefill(
            &self,
            _handle: &modelswarm_runtime::Handle,
            _ids: &[u32],
        ) -> Result<modelswarm_runtime::KvCommitment, RuntimeError> {
            unreachable!("serving never calls prefill")
        }
        async fn decode_step(
            &self,
            _handle: &modelswarm_runtime::Handle,
            _prefix: &[u32],
            _sampling: &SamplingParams,
        ) -> Result<u32, RuntimeError> {
            unreachable!("streaming runtime under test")
        }
        fn metrics(&self) -> modelswarm_runtime::RuntimeMetrics {
            modelswarm_runtime::RuntimeMetrics::default()
        }
        fn cancel(&self, _task: modelswarm_runtime::TaskId) -> Result<(), RuntimeError> {
            Ok(())
        }
        fn decode_stream_events<'a>(
            &'a self,
            _handle: &'a modelswarm_runtime::Handle,
            _prefix: &'a [u32],
            _sampling: &SamplingParams,
            max_tokens: u32,
            _deadline: Duration,
        ) -> modelswarm_runtime::DecodeEventStream<'a> {
            let fail_after = self.fail_after;
            let per_token = self.per_token;
            Box::pin(futures_util::stream::unfold(
                0u32,
                move |count| async move {
                    if count >= max_tokens {
                        return None;
                    }
                    if let Some(fail_after) = fail_after {
                        if count >= fail_after {
                            return Some((
                                Err(RuntimeError::Http("engine died".into())),
                                count + 1,
                            ));
                        }
                    }
                    tokio::time::sleep(per_token).await;
                    Some((Ok(DecodeEvent::Token(65)), count + 1))
                },
            ))
        }
    }

    #[test]
    fn chatml_rendering_marks_roles_and_opens_assistant_turn() {
        let messages = vec![
            NormalizedMessage {
                role: "system".to_string(),
                content: "You are terse.".to_string(),
            },
            NormalizedMessage {
                role: "user".to_string(),
                content: "Hi".to_string(),
            },
            NormalizedMessage {
                role: "assistant".to_string(),
                content: "Hello.".to_string(),
            },
            NormalizedMessage {
                role: "user".to_string(),
                content: "Bye".to_string(),
            },
        ];
        assert_eq!(
            render_chatml(&messages),
            "<|im_start|>system\nYou are terse.<|im_end|>\n\
             <|im_start|>user\nHi<|im_end|>\n\
             <|im_start|>assistant\nHello.<|im_end|>\n\
             <|im_start|>user\nBye<|im_end|>\n\
             <|im_start|>assistant\n"
        );
    }

    fn request(profile: &str, max_tokens: u32) -> NormalizedRequest {
        NormalizedRequest {
            request_id: "selftest-req".to_string(),
            profile_id: profile.to_string(),
            capability_token: None,
            messages: vec![NormalizedMessage {
                role: "user".to_string(),
                content: "hello".to_string(),
            }],
            sampling: Sampling {
                temperature: 1.0,
                top_p: 1.0,
                top_k: 40,
                seed: None,
            },
            max_tokens,
            deadline_ms: 30_000,
            stream: true,
        }
    }

    #[tokio::test]
    async fn no_runtime_is_honest_no_peer() {
        let executor = SingleLocalExecutor::new(None, Some("msp1:x".to_string()));
        assert!(matches!(
            executor.execute(request("msp1:x", 4)).await,
            Err(ExecutorError::NoPeer)
        ));
    }

    #[tokio::test]
    async fn wrong_profile_is_fatal_mismatch() {
        let executor = SingleLocalExecutor::new(
            Some(Arc::new(MockRuntime::new(1, 1.0))),
            Some("msp1:x".to_string()),
        );
        match executor.execute(request("msp1:other", 4)).await {
            Err(ExecutorError::Fatal { code }) => assert_eq!(code, "profile_mismatch"),
            Err(other) => panic!("expected fatal profile_mismatch, got {other:?}"),
            Ok(_) => panic!("expected fatal profile_mismatch, got a stream"),
        }
    }

    #[tokio::test]
    async fn event_stream_shape_and_batching() {
        use futures_util::StreamExt;
        let executor = SingleLocalExecutor::new(
            Some(Arc::new(MockRuntime::new(7, 1.0))),
            Some("msp1:x".to_string()),
        );
        let stream = executor
            .execute(request("msp1:x", 40))
            .await
            .map_err(|e| format!("{e:?}"))
            .unwrap();
        let events: Vec<ExecutorEvent> = stream.collect().await;
        assert!(matches!(
            events.first(),
            Some(ExecutorEvent::Accepted { .. })
        ));
        assert!(matches!(
            events.last(),
            Some(ExecutorEvent::Completed { .. })
        ));
        let usage = events
            .iter()
            .rev()
            .find(|e| matches!(e, ExecutorEvent::Usage { .. }));
        let Some(ExecutorEvent::Usage {
            prompt_tokens,
            completion_tokens,
            ..
        }) = usage
        else {
            panic!("usage event missing: {events:?}");
        };
        assert_eq!(*completion_tokens, 40);
        assert!(*prompt_tokens > 0);
        // 40 tokens in batches of 16 → exactly 3 token deltas.
        let deltas = events
            .iter()
            .filter(|e| matches!(e, ExecutorEvent::TokenDelta { .. }))
            .count();
        assert_eq!(deltas, 3);
        let finish = events.last().unwrap();
        assert_eq!(
            *finish,
            ExecutorEvent::Completed {
                finish_reason: FinishReason::Length
            }
        );
    }

    #[tokio::test]
    async fn token_deltas_arrive_before_the_decode_completes() {
        use futures_util::StreamExt;
        // 40 tokens at 15 ms/token ≈ 600 ms decode; the first 16-token
        // delta must surface well before the completion event (~240 ms vs
        // ~600 ms — generous margins, the property is what matters).
        let runtime = Arc::new(SlowStreamRuntime {
            per_token: Duration::from_millis(15),
            fail_after: None,
        });
        let executor = SingleLocalExecutor::new(Some(runtime), Some("msp1:x".to_string()));
        let mut stream = executor.execute(request("msp1:x", 40)).await.unwrap();
        let started = Instant::now();
        let mut first_delta_after = None;
        let mut completion_after = None;
        while let Some(event) = stream.next().await {
            if matches!(event, ExecutorEvent::TokenDelta { .. }) && first_delta_after.is_none() {
                first_delta_after = Some(started.elapsed());
            }
            if matches!(event, ExecutorEvent::Completed { .. }) {
                completion_after = Some(started.elapsed());
            }
        }
        let first = first_delta_after.expect("at least one delta");
        let completed = completion_after.expect("completion event");
        assert!(
            first + Duration::from_millis(100) < completed,
            "first delta at {first:?} must precede completion at {completed:?}"
        );
    }

    #[tokio::test]
    async fn mid_stream_failure_becomes_an_error_event_with_deltas_intact() {
        use futures_util::StreamExt;
        // The engine dies after 20 tokens: one 16-token delta reached the
        // consumer, so ADR-007 forbids failover — the stream must end with
        // an explicit Error carrying the transport code, never a fake
        // completion and never a silent drop.
        let runtime = Arc::new(SlowStreamRuntime {
            per_token: Duration::from_millis(1),
            fail_after: Some(20),
        });
        let executor = SingleLocalExecutor::new(Some(runtime), Some("msp1:x".to_string()));
        let stream = executor.execute(request("msp1:x", 40)).await.unwrap();
        let events: Vec<ExecutorEvent> = stream.collect().await;
        let deltas = events
            .iter()
            .filter(|e| matches!(e, ExecutorEvent::TokenDelta { .. }))
            .count();
        assert_eq!(deltas, 1, "one 16-token delta before the failure");
        match events.last() {
            Some(ExecutorEvent::Error {
                code,
                retryable,
                interrupted_after_tokens,
            }) => {
                assert_eq!(code, "engine_transport");
                assert!(!*retryable, "local failures are not failover-eligible");
                assert_eq!(*interrupted_after_tokens, Some(20));
            }
            other => panic!("expected terminal Error event, got {other:?}"),
        }
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, ExecutorEvent::Completed { .. })),
            "no fabricated completion"
        );
    }
}
