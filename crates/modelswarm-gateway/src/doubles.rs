//! Test doubles for the gateway's [`InferenceExecutor`](crate::InferenceExecutor).
//! Compiled for this crate's own tests and whenever the `test-doubles`
//! feature is enabled (Phase D integration tests).

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::Stream;

use crate::{
    ExecutorError, ExecutorEvent, ExecutorStream, FinishReason, InferenceExecutor,
    NormalizedRequest,
};

/// Queue-backed event stream with an optional inter-event delay (the
/// slow-consumer double) — no channel, no spawn.
pub struct QueueStream {
    events: VecDeque<ExecutorEvent>,
    per_event_delay: Option<Duration>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl QueueStream {
    /// Immediate queue of events.
    pub fn from_events(events: Vec<ExecutorEvent>) -> Self {
        Self {
            events: VecDeque::from(events),
            per_event_delay: None,
            sleep: None,
        }
    }

    /// Queue with a delay inserted between events.
    pub fn delayed(events: Vec<ExecutorEvent>, per_event_delay: Duration) -> Self {
        Self {
            events: VecDeque::from(events),
            per_event_delay: Some(per_event_delay),
            sleep: None,
        }
    }
}

impl Stream for QueueStream {
    type Item = ExecutorEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<ExecutorEvent>> {
        // Finish the inter-event delay first, if one is pending.
        if let Some(sleep) = self.sleep.as_mut() {
            match sleep.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {
                    self.sleep = None;
                }
            }
        }
        match self.events.pop_front() {
            None => Poll::Ready(None),
            Some(event) => {
                if let Some(delay) = self.per_event_delay {
                    if !delay.is_zero() {
                        self.sleep = Some(Box::pin(tokio::time::sleep(delay)));
                    }
                }
                Poll::Ready(Some(event))
            }
        }
    }
}

/// Which stream a scripted run should produce.
#[derive(Debug, Clone)]
enum StreamKind {
    /// Accepted → tokens → usage → completed.
    Happy {
        deltas: Vec<String>,
        prompt_tokens: u32,
        finish_reason: FinishReason,
    },
    /// Accepted → K tokens → mid-stream error (ADR-007 after-first-token).
    FailMidStream {
        deltas_before_error: Vec<String>,
        code: String,
        retryable: bool,
    },
}

impl StreamKind {
    fn events(&self) -> Vec<ExecutorEvent> {
        match self {
            StreamKind::Happy {
                deltas,
                prompt_tokens,
                finish_reason,
            } => {
                let mut events = Vec::with_capacity(deltas.len() + 3);
                events.push(ExecutorEvent::Accepted {
                    queue_position: 0,
                    eta_ms: 12,
                });
                for (index, delta) in deltas.iter().enumerate() {
                    events.push(ExecutorEvent::TokenDelta {
                        delta: delta.clone(),
                        index: index as u32,
                    });
                }
                events.push(ExecutorEvent::Usage {
                    prompt_tokens: *prompt_tokens,
                    completion_tokens: deltas.len() as u32,
                    prefill_ms: 5.0,
                    decode_ms: 40.0,
                });
                events.push(ExecutorEvent::Completed {
                    finish_reason: *finish_reason,
                });
                events
            }
            StreamKind::FailMidStream {
                deltas_before_error,
                code,
                retryable,
            } => {
                let mut events = vec![ExecutorEvent::Accepted {
                    queue_position: 0,
                    eta_ms: 5,
                }];
                for (index, delta) in deltas_before_error.iter().enumerate() {
                    events.push(ExecutorEvent::TokenDelta {
                        delta: delta.clone(),
                        index: index as u32,
                    });
                }
                events.push(ExecutorEvent::Error {
                    code: code.clone(),
                    retryable: *retryable,
                    interrupted_after_tokens: Some(deltas_before_error.len() as u32),
                });
                events
            }
        }
    }
}

/// Deterministic scripted executor (gateway test double). Configurable
/// behavior: happy stream, fail-before-first-token (retryable errors N
/// times, then happy), fail-mid-stream, slow-consumer, or always-`NoPeer`.
/// Records the number of `execute` calls and the last request seen.
pub struct StaticExecutor {
    state: Mutex<ExecutorState>,
    calls: AtomicUsize,
    last_request: Mutex<Option<NormalizedRequest>>,
}

struct ExecutorState {
    remaining_failures: u32,
    kind: StreamKind,
    per_event_delay: Option<Duration>,
    always_no_peer: bool,
}

impl StaticExecutor {
    /// Happy-path stream double.
    pub fn happy(deltas: &[&str]) -> Self {
        Self::new(StreamKind::Happy {
            deltas: deltas.iter().map(|d| (*d).to_string()).collect(),
            prompt_tokens: 10,
            finish_reason: FinishReason::Stop,
        })
    }

    /// Happy path with an explicit finish reason and prompt size.
    pub fn happy_with(deltas: &[&str], prompt_tokens: u32, finish_reason: FinishReason) -> Self {
        Self::new(StreamKind::Happy {
            deltas: deltas.iter().map(|d| (*d).to_string()).collect(),
            prompt_tokens,
            finish_reason,
        })
    }

    /// Fails with `Retryable` exactly `retries` times (each failure hints
    /// the next peer), then runs the happy script.
    pub fn fail_before_first_token(retries: u32, deltas: &[&str]) -> Self {
        let executor = Self::happy(deltas);
        executor
            .state
            .lock()
            .expect("executor state")
            .remaining_failures = retries;
        executor
    }

    /// Emits deltas then dies mid-stream with `code`.
    pub fn fail_mid_stream(deltas_before_error: &[&str], code: &str, retryable: bool) -> Self {
        Self::new(StreamKind::FailMidStream {
            deltas_before_error: deltas_before_error
                .iter()
                .map(|d| (*d).to_string())
                .collect(),
            code: code.to_string(),
            retryable,
        })
    }

    /// Happy stream with `per_token_delay` between events.
    pub fn slow_consumer(deltas: &[&str], per_token_delay: Duration) -> Self {
        let executor = Self::happy(deltas);
        executor
            .state
            .lock()
            .expect("executor state")
            .per_event_delay = Some(per_token_delay);
        executor
    }

    /// Always fails with `NoPeer`.
    pub fn no_peer() -> Self {
        let executor = Self::happy(&[]);
        executor
            .state
            .lock()
            .expect("executor state")
            .always_no_peer = true;
        executor
    }

    /// Number of `execute` invocations so far.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// The last request handed to `execute`.
    pub fn last_request(&self) -> Option<NormalizedRequest> {
        self.last_request.lock().expect("last request").clone()
    }

    fn new(kind: StreamKind) -> Self {
        Self {
            state: Mutex::new(ExecutorState {
                remaining_failures: 0,
                kind,
                per_event_delay: None,
                always_no_peer: false,
            }),
            calls: AtomicUsize::new(0),
            last_request: Mutex::new(None),
        }
    }
}

#[async_trait]
impl InferenceExecutor for StaticExecutor {
    async fn execute(&self, request: NormalizedRequest) -> Result<ExecutorStream, ExecutorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.last_request.lock().expect("last request") = Some(request);
        let mut state = self.state.lock().expect("executor state");
        if state.always_no_peer {
            return Err(ExecutorError::NoPeer);
        }
        if state.remaining_failures > 0 {
            state.remaining_failures -= 1;
            return Err(ExecutorError::Retryable {
                peer_hint: Some(format!("peer-{}", state.remaining_failures + 1)),
            });
        }
        let events = state.kind.events();
        match state.per_event_delay {
            Some(delay) => Ok(Box::pin(QueueStream::delayed(events, delay))),
            None => Ok(Box::pin(QueueStream::from_events(events))),
        }
    }
}
