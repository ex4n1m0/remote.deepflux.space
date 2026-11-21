//! `LlamaCppAdapter`: the production-baseline runtime (ADR-002/019).
//!
//! A reqwest HTTP client against a llama.cpp-server base URL (loopback,
//! random internal bearer per ADR-002). The trait's load/tokenize/decode
//! paths map onto the server's OpenAI-compatible endpoints:
//!
//! | Trait call | Endpoint |
//! |---|---|
//! | `load` | `GET /v1/models` (reachability + auth check) |
//! | `tokenize` | `POST /tokenize` |
//! | `detokenize` | `POST /detokenize` |
//! | `prefill` | `POST /v1/completions` with `max_tokens: 1` (prompt token array) |
//! | `decode_step` | `POST /v1/completions` (1 token) + `POST /tokenize` for the id |
//! | `decode_stream_events` | one `POST /v1/completions` with `stream: true, logprobs: true` — SSE chunks parsed incrementally, exact id recovery per chunk (`id` first, `bytes` cross-check, fail-closed on disagreement, same as `decode_step`), EOS-terminated |
//! | `decode_stream` | folds `decode_stream_events` into the Vec API (single code path) |
//! | `cancel` | best-effort `POST /cancel`; 404/405 tolerated (the server also cancels on client abort) |
//!
//! `decode_step` keeps its one-POST-per-token shape deliberately: it is the
//! `propose()` building block (greedy self-continuation, ADR-021) and the
//! byte-for-byte fallback path pinned by the existing tests; serving traffic
//! flows through the SSE stream.
//!
//! Prefill/decode throughput metrics are derived from the streaming response
//! `timings` fields (`prompt_n`/`prompt_ms`/`predicted_n`/`predicted_ms` on
//! the final SSE chunk, b11407) with a client-observed fallback. Not
//! feature-gated: this adapter only ever talks HTTP; binary download and
//! process supervision live elsewhere (ADR-019).

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    DecodeEvent, DecodeEventStream, DecodeTimings, Handle, KvCommitment, RuntimeDescriptor,
    RuntimeError, RuntimeMetrics, SamplingParams, TaskId,
};

/// Pinned-engine identity (from `runtime-pins.json`): what `id()` reports so
/// telemetry/handshakes carry the true engine build.
#[derive(Debug, Clone)]
pub struct EngineIdentity {
    /// llama.cpp release tag, e.g. `b11407`.
    pub version: String,
    /// sha256 of the pinned engine zip (ADR-022 §6).
    pub build_hash: String,
}

/// Builder-style configuration for [`LlamaCppAdapter`].
#[derive(Debug, Clone)]
pub struct LlamaCppConfig {
    /// Base URL of the llama.cpp server, e.g. `http://127.0.0.1:8123`.
    pub base_url: String,
    /// Random internal bearer secret (ADR-002); sent as `Authorization: Bearer …`.
    pub bearer_token: String,
    /// Per-request timeout for adapter calls. Decode paths compute the
    /// remaining budget from the caller's deadline, bounded by this value.
    pub request_timeout: Duration,
    /// Pinned-engine identity for `id()`; when `None` a placeholder
    /// descriptor is reported (dev/test setups without a pin).
    pub engine: Option<EngineIdentity>,
    /// Exact bytes→id vocabulary from the model's GGUF (enables lossless
    /// token-id recovery via logprob byte sequences, incl. byte-fallback
    /// tokens that detokenized text cannot represent).
    pub vocab: Option<Arc<modelswarm_types::TokenVocab>>,
    /// Research determinism mode: when `true`, every per-token request
    /// carries `cache_prompt: false` so the server recomputes from the
    /// posted prefix alone — decode_step results stop depending on the
    /// slot's KV-cache history (the 9.6 pass-2 finding: a verify pattern
    /// that probes backward relative to the slot's furthest state makes
    /// cached-prefix reuse perturb greedy output). DEFAULT `false` =
    /// today's behavior (production keeps the server's prompt cache).
    /// Costs a full re-prefill per step — the honest structural
    /// wire-re-post cost, labeled by its users.
    pub no_prompt_cache: bool,
}

impl LlamaCppConfig {
    /// Configuration with defaults for everything but the endpoint identity.
    pub fn new(base_url: impl Into<String>, bearer_token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            bearer_token: bearer_token.into(),
            request_timeout: Duration::from_secs(60),
            engine: None,
            vocab: None,
            no_prompt_cache: false,
        }
    }

    /// Attaches a pinned-engine identity.
    pub fn with_engine(mut self, engine: EngineIdentity) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Attaches the exact token vocabulary.
    pub fn with_vocab(mut self, vocab: Arc<modelswarm_types::TokenVocab>) -> Self {
        self.vocab = Some(vocab);
        self
    }
}

#[derive(Debug)]
struct Shared {
    metrics: RwLock<RuntimeMetrics>,
    next_handle: AtomicU64,
}

/// HTTP-backed [`crate::InferenceRuntime`] for the pinned llama.cpp server.
#[derive(Debug)]
pub struct LlamaCppAdapter {
    config: LlamaCppConfig,
    client: reqwest::Client,
    shared: Arc<Shared>,
}

impl LlamaCppAdapter {
    /// Creates the adapter (loopback base URL + bearer secret).
    pub fn new(config: LlamaCppConfig) -> Result<Self, RuntimeError> {
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|e| RuntimeError::Http(format!("client build failed: {e}")))?;
        Ok(Self {
            config,
            client,
            shared: Arc::new(Shared {
                metrics: RwLock::new(RuntimeMetrics::default()),
                next_handle: AtomicU64::new(1),
            }),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.config.base_url.trim_end_matches('/'), path)
    }

    async fn post_json<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &serde_json::Value,
        timeout: Duration,
    ) -> Result<T, RuntimeError> {
        let started = Instant::now();
        let response = self
            .client
            .post(self.url(path))
            .bearer_auth(&self.config.bearer_token)
            .timeout(timeout)
            .json(body)
            .send()
            .await;
        let response = map_reqwest(response, started)?;
        let status = response.status();
        if !status.is_success() {
            let code = status.as_u16();
            let text = response.text().await.unwrap_or_default();
            return Err(RuntimeError::Api {
                status: code,
                code: extract_error_code(&text),
                message: text.chars().take(300).collect(),
            });
        }
        let raw = response
            .text()
            .await
            .map_err(|e| RuntimeError::Http(format!("body read failed: {e}")))?;
        serde_json::from_str(&raw)
            .map_err(|e| RuntimeError::MalformedResponse(format!("{path}: {e}")))
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, RuntimeError> {
        let started = Instant::now();
        let response = self
            .client
            .get(self.url(path))
            .bearer_auth(&self.config.bearer_token)
            .send()
            .await;
        let response = map_reqwest(response, started)?;
        let status = response.status();
        if !status.is_success() {
            let code = status.as_u16();
            let text = response.text().await.unwrap_or_default();
            return Err(RuntimeError::Api {
                status: code,
                code: extract_error_code(&text),
                message: text.chars().take(300).collect(),
            });
        }
        let raw = response
            .text()
            .await
            .map_err(|e| RuntimeError::Http(format!("body read failed: {e}")))?;
        serde_json::from_str(&raw)
            .map_err(|e| RuntimeError::MalformedResponse(format!("{path}: {e}")))
    }

    fn record_prefill_rate(&self, prompt_tokens: u64, elapsed: Duration) {
        if prompt_tokens > 0 {
            if let Some(rate) = tokens_per_ms(prompt_tokens, elapsed) {
                if let Ok(mut metrics) = self.shared.metrics.write() {
                    metrics.prefill_tokens_per_ms = rate;
                }
            }
        }
    }
}

fn map_reqwest(
    result: Result<reqwest::Response, reqwest::Error>,
    started: Instant,
) -> Result<reqwest::Response, RuntimeError> {
    match result {
        Ok(response) => Ok(response),
        Err(e) => Err(reqwest_error(e, started)),
    }
}

fn reqwest_error(e: reqwest::Error, started: Instant) -> RuntimeError {
    if e.is_timeout() {
        RuntimeError::Timeout {
            after_ms: crate::duration_ms_u64(started.elapsed()),
        }
    } else {
        RuntimeError::Http(e.to_string())
    }
}

/// Tokens per millisecond with sub-millisecond resolution; `None` when the
/// elapsed time is indistinguishable from zero.
fn tokens_per_ms(tokens: u64, elapsed: Duration) -> Option<f64> {
    let micros = elapsed.as_micros();
    if micros > 0 {
        Some(tokens as f64 / (micros as f64 / 1000.0))
    } else {
        None
    }
}

fn extract_error_code(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v["error"]["code"]
                .as_str()
                .map(str::to_string)
                .or_else(|| v["error"].as_str().map(str::to_string))
        })
        .unwrap_or_else(|| "unknown".to_string())
}

#[derive(Debug, Deserialize)]
struct ModelsResponse {
    #[serde(default)]
    #[allow(dead_code)] // shape verification only; ids are llama-internal names
    data: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenizeRequest {
    content: String,
}

#[derive(Debug, Deserialize)]
struct TokenizeResponse {
    tokens: Vec<u32>,
}

#[derive(Debug, Deserialize)]
struct DetokenizeResponse {
    content: String,
}

#[derive(Debug, Deserialize)]
struct CompletionsResponse {
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    text: String,
    #[serde(default)]
    logprobs: Option<ChoiceLogprobs>,
}

#[derive(Debug, Deserialize)]
struct ChoiceLogprobs {
    #[serde(default)]
    content: Vec<LogprobEntry>,
}

#[derive(Debug, Deserialize)]
struct LogprobEntry {
    /// The sampled token's id as the server itself reports it. b11407 always
    /// includes it — including for special tokens (EOS etc.) whose byte
    /// representation is empty, which is exactly where a bytes lookup fails.
    #[serde(default)]
    id: Option<u32>,
    /// Raw UTF-8 bytes of the generated token — exact id recovery including
    /// byte-fallback tokens that invalid-UTF-8 text cannot represent.
    #[serde(default)]
    bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct Usage {
    #[serde(default)]
    prompt_tokens: u64,
    /// Parsed for shape validation and future decode-rate attribution.
    #[serde(default)]
    #[allow(dead_code)]
    completion_tokens: u64,
}

/// Exact token-id recovery shared by `decode_step` and the SSE decode path:
/// the server-reported `id` is authoritative for the pinned artifact (its
/// sampler reads the same sha-verified GGUF), the pinned vocab's `bytes` map
/// is the independent cross-check, and a disagreement between the two means
/// vocabulary drift — fail closed rather than corrupt a token stream.
/// `Ok(None)` means the entry carries neither representation (caller falls
/// through to its documented approximation).
fn exact_token_id(
    vocab: &modelswarm_types::TokenVocab,
    entry: &LogprobEntry,
) -> Result<Option<u32>, RuntimeError> {
    if entry.id.is_none() && entry.bytes.is_none() {
        return Ok(None);
    }
    let bytes_id = vocab
        .bytes_to_id
        .get(entry.bytes.as_deref().unwrap_or_default())
        .copied();
    if let (Some(server_id), Some(bytes_id)) = (entry.id, bytes_id) {
        if server_id != bytes_id {
            return Err(RuntimeError::MalformedResponse(format!(
                "token id disagreement: server says {server_id}, pinned vocab says {bytes_id}"
            )));
        }
    }
    let id = entry.id.or(bytes_id);
    match id {
        Some(id) => Ok(Some(id)),
        None => Err(RuntimeError::MalformedResponse(format!(
            "generated token (id {:?}, bytes {:?}) not in the pinned vocabulary",
            entry.id, entry.bytes
        ))),
    }
}

// ---- SSE decode path (stream: true on the same /v1/completions endpoint) ----

/// One `data: {…}` SSE chunk of a streaming completion (b11407 shape,
/// probe-verified 2026-10-09: content chunks carry
/// `choices[0].logprobs.content[0]` with `id` + `bytes` per token — including
/// EOS, whose `bytes` is empty; the final chunk carries `finish_reason`,
/// `usage` and `timings`; the stream terminates with `data: [DONE]`).
#[derive(Debug, Deserialize)]
struct StreamChunk {
    #[serde(default)]
    choices: Vec<StreamChoice>,
    #[serde(default)]
    timings: Option<StreamTimings>,
    /// Generation failures surface as an SSE error event, not a status code.
    #[serde(default)]
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct StreamChoice {
    #[serde(default)]
    #[allow(dead_code)] // decoded for shape validation; ids come from logprobs
    text: String,
    #[serde(default)]
    logprobs: Option<ChoiceLogprobs>,
    #[serde(default)]
    #[allow(dead_code)] // the stop/length distinction is derived from tokens
    finish_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct StreamTimings {
    #[serde(default)]
    prompt_n: Option<u64>,
    #[serde(default)]
    prompt_ms: Option<f64>,
    #[serde(default)]
    predicted_n: Option<u64>,
    #[serde(default)]
    predicted_ms: Option<f64>,
}

impl StreamTimings {
    /// Phase split when the server reported the decode phase at all.
    fn decode_timings(self) -> Option<DecodeTimings> {
        let decode_ms = self.predicted_ms?;
        Some(DecodeTimings {
            prompt_tokens: self.prompt_n.unwrap_or(0),
            prompt_ms: self.prompt_ms.unwrap_or(0.0),
            completion_tokens: self.predicted_n.unwrap_or(0),
            decode_ms,
        })
    }
}

/// What one parsed SSE event told us.
enum SsePayload {
    /// Comment/keep-alive/empty event — nothing to act on.
    Ignore,
    /// `data: [DONE]` terminator.
    Done,
    /// A completion chunk.
    Chunk(Box<StreamChunk>),
}

/// Parses one raw SSE event (bytes between event separators) per the SSE
/// framing rules this server uses: `data:`-prefixed lines, `\n`-separated,
/// blank line ends the event. Multiple `data:` lines concatenate with `\n`
/// (spec behavior); anything else (comments, fields we do not speak) is
/// ignored. An unparsable `data:` payload fails closed.
fn parse_sse_event(raw: &[u8]) -> Result<SsePayload, RuntimeError> {
    let mut data_lines: Vec<&[u8]> = Vec::new();
    for line in raw.split(|b| *b == b'\n') {
        let line = strip_cr(line);
        if line.starts_with(b":") {
            continue; // comment / keep-alive
        }
        if let Some(payload) = line.strip_prefix(b"data:") {
            data_lines.push(payload.strip_prefix(b" ").unwrap_or(payload));
        }
    }
    if data_lines.is_empty() {
        return Ok(SsePayload::Ignore);
    }
    if data_lines.len() == 1 && data_lines[0] == b"[DONE]" {
        return Ok(SsePayload::Done);
    }
    let joined = data_lines.join(&b'\n');
    let chunk: StreamChunk = serde_json::from_slice(&joined)
        .map_err(|e| RuntimeError::MalformedResponse(format!("streaming completion chunk: {e}")))?;
    Ok(SsePayload::Chunk(Box::new(chunk)))
}

fn strip_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

type BodyChunkStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

/// State of one incremental decode; driven by [`next_decode_event`].
struct SseState {
    client: reqwest::Client,
    url: String,
    bearer: String,
    body: serde_json::Value,
    /// Total request budget (connect → body end); the reqwest per-request
    /// timeout enforces the caller's deadline across the whole stream.
    deadline: Duration,
    shared: Arc<Shared>,
    vocab: Option<Arc<modelswarm_types::TokenVocab>>,
    eos_id: Option<u32>,
    max_tokens: u32,
    produced: u32,
    /// Set when the vocab's EOS was sampled: remaining chunks are consumed
    /// (the final one carries `timings`) but their tokens are discarded.
    saw_eos: bool,
    started: Instant,
    phase: SsePhase,
    pending_timings: Option<DecodeTimings>,
    /// Terminal marker: polls after an error/end yield `None`.
    finished: bool,
    metrics_recorded: bool,
}

enum SsePhase {
    Connect,
    Body {
        stream: BodyChunkStream,
        buffer: Vec<u8>,
    },
    Done,
}

/// Advances the decode by one event. `Ok(None)` = stream over.
async fn next_decode_event(state: &mut SseState) -> Result<Option<DecodeEvent>, RuntimeError> {
    if state.finished {
        return Ok(None);
    }
    loop {
        match std::mem::replace(&mut state.phase, SsePhase::Done) {
            SsePhase::Connect => {
                let response = state
                    .client
                    .post(&state.url)
                    .bearer_auth(&state.bearer)
                    .timeout(state.deadline)
                    .json(&state.body)
                    .send()
                    .await;
                match map_reqwest(response, state.started) {
                    Ok(response) => {
                        let status = response.status();
                        if !status.is_success() {
                            let code = status.as_u16();
                            let text = response.text().await.unwrap_or_default();
                            state.finished = true;
                            return Err(RuntimeError::Api {
                                status: code,
                                code: extract_error_code(&text),
                                message: text.chars().take(300).collect(),
                            });
                        }
                        state.phase = SsePhase::Body {
                            stream: Box::pin(response.bytes_stream()),
                            buffer: Vec::new(),
                        };
                    }
                    Err(e) => {
                        state.finished = true;
                        return Err(e);
                    }
                }
            }
            SsePhase::Body {
                mut stream,
                mut buffer,
            } => {
                // One event per iteration: read until a blank-line separator
                // is complete, or the body ends/fails.
                enum Step {
                    Event(Vec<u8>),
                    BodyError(reqwest::Error),
                    Eof,
                }
                let step = loop {
                    if let Some((end, sep_len)) = find_event_end(&buffer) {
                        let mut raw: Vec<u8> = buffer.drain(..end + sep_len).collect();
                        raw.truncate(raw.len() - sep_len);
                        break Step::Event(raw);
                    }
                    match stream.next().await {
                        Some(Ok(chunk)) => buffer.extend_from_slice(&chunk),
                        Some(Err(e)) => break Step::BodyError(e),
                        None => break Step::Eof,
                    }
                };
                match step {
                    Step::Event(raw) => {
                        let outcome = consume_sse_event(state, &raw);
                        state.phase = SsePhase::Body { stream, buffer };
                        if let Some(event) = outcome? {
                            return Ok(Some(event));
                        }
                    }
                    Step::BodyError(e) => {
                        state.finished = true;
                        return Err(reqwest_error(e, state.started));
                    }
                    Step::Eof => return Ok(finish_stream(state)),
                }
            }
            SsePhase::Done => return Ok(finish_stream(state)),
        }
    }
}

/// Terminal transition: record fallback metrics if the server never sent
/// `timings`, then surface pending timings once (the next poll ends).
fn finish_stream(state: &mut SseState) -> Option<DecodeEvent> {
    if !state.metrics_recorded {
        state.metrics_recorded = true;
        if state.pending_timings.is_none() && state.produced > 0 {
            // No server timings: client-observed decode rate (documented
            // approximation, same as the pre-streaming adapter).
            record_decode_rate(
                &state.shared,
                u64::from(state.produced),
                state.started.elapsed(),
            );
        }
    }
    if let Some(timings) = state.pending_timings.take() {
        return Some(DecodeEvent::Timings(timings));
    }
    state.finished = true;
    None
}

fn record_decode_rate(shared: &Shared, tokens: u64, elapsed: Duration) {
    if let Some(rate) = tokens_per_ms(tokens, elapsed) {
        if let Ok(mut metrics) = shared.metrics.write() {
            metrics.decode_tokens_per_ms = rate;
        }
    }
}

fn record_prefill_rate(shared: &Shared, tokens: u64, elapsed_ms: f64) {
    if tokens > 0 && elapsed_ms > 0.0 {
        if let Ok(mut metrics) = shared.metrics.write() {
            metrics.prefill_tokens_per_ms = tokens as f64 / elapsed_ms;
        }
    }
}

/// Byte offset + separator length of the blank line ending the next SSE
/// event, if complete (`\n\n` or `\r\n\r\n`).
fn find_event_end(buffer: &[u8]) -> Option<(usize, usize)> {
    let lf = buffer.windows(2).position(|w| w == b"\n\n").map(|p| (p, 2));
    let crlf = buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| (p, 4));
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (a, b) => a.or(b),
    }
}

/// Acts on one parsed SSE event; `Ok(Some(event))` yields to the consumer.
fn consume_sse_event(
    state: &mut SseState,
    raw: &[u8],
) -> Result<Option<DecodeEvent>, RuntimeError> {
    match parse_sse_event(raw)? {
        SsePayload::Ignore => Ok(None),
        SsePayload::Done => {
            state.phase = SsePhase::Done;
            Ok(finish_stream(state))
        }
        SsePayload::Chunk(chunk) => {
            if let Some(error) = chunk.error.as_ref() {
                let code = error["code"].as_str().unwrap_or("generation_error");
                state.finished = true;
                return Err(RuntimeError::Api {
                    status: 200,
                    code: code.to_string(),
                    message: error
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("engine reported a streaming error")
                        .chars()
                        .take(300)
                        .collect(),
                });
            }
            if let Some(timings) = chunk.timings.and_then(|t| t.decode_timings()) {
                state.metrics_recorded = true;
                record_prefill_rate(&state.shared, timings.prompt_tokens, timings.prompt_ms);
                record_decode_rate(
                    &state.shared,
                    timings.completion_tokens,
                    Duration::from_secs_f64(timings.decode_ms / 1000.0),
                );
                state.pending_timings = Some(timings);
            }
            if state.saw_eos || state.produced >= state.max_tokens {
                return Ok(None);
            }
            let entry = chunk
                .choices
                .first()
                .and_then(|c| c.logprobs.as_ref())
                .and_then(|l| l.content.first());
            let Some(entry) = entry else {
                // Final chunk (finish_reason set, logprobs null): no token.
                return Ok(None);
            };
            let id = recover_stream_token_id(state, entry)?;
            if Some(id) == state.eos_id {
                state.saw_eos = true;
                return Ok(None);
            }
            state.produced += 1;
            Ok(Some(DecodeEvent::Token(id)))
        }
    }
}

/// Per-chunk id recovery. With the vocab attached this is the exact,
/// fail-closed path (identical rules to `decode_step`). Without a vocab
/// (dev/test setups) the server-reported `id` is used directly; a chunk that
/// reports neither id nor bytes is malformed for streaming.
fn recover_stream_token_id(state: &SseState, entry: &LogprobEntry) -> Result<u32, RuntimeError> {
    match &state.vocab {
        Some(vocab) => exact_token_id(vocab, entry)?.ok_or_else(|| {
            RuntimeError::MalformedResponse(
                "streaming chunk carried no token representation (id and bytes both absent)"
                    .to_string(),
            )
        }),
        None => entry.id.ok_or_else(|| {
            RuntimeError::MalformedResponse(
                "streaming chunk carried no token id and no vocab is attached".to_string(),
            )
        }),
    }
}

/// Sampling → request body per the determinism contract: `SamplingParams`
/// equal to the default maps to temperature 0 (greedy) — "the runtime's
/// default-sampling decode is a deterministic function of the prefix" —
/// while any explicit override is forwarded verbatim (with its seed).
fn sampling_body(sampling: &SamplingParams) -> serde_json::Value {
    if sampling == &SamplingParams::default() {
        json!({ "temperature": 0.0 })
    } else {
        let mut body = json!({
            "temperature": sampling.temperature,
            "top_p": sampling.top_p,
            "top_k": sampling.top_k,
        });
        if let Some(seed) = sampling.seed {
            body["seed"] = json!(seed);
        }
        body
    }
}

#[async_trait]
impl crate::InferenceRuntime for LlamaCppAdapter {
    fn id(&self) -> RuntimeDescriptor {
        match &self.config.engine {
            Some(engine) => {
                RuntimeDescriptor::new("llama.cpp", &engine.version, &engine.build_hash)
                    .expect("pinned descriptor is valid")
            }
            // Dev/test setups without a pin report a zero placeholder that
            // the node supervisor would re-stamp; never a claimed build.
            None => RuntimeDescriptor::new("llama.cpp", "adapter-http-v1", "0".repeat(64))
                .expect("static descriptor is valid"),
        }
    }

    async fn load(&self, profile_id: &str) -> Result<Handle, RuntimeError> {
        if profile_id.is_empty() {
            return Err(RuntimeError::InvalidProfile(profile_id.to_string()));
        }
        // Reachability + auth probe; the llama-internal model id is not the
        // MSP profile id, so we do not match on it here.
        let _models: ModelsResponse = self.get_json("/v1/models").await?;
        let handle_id = self.shared.next_handle.fetch_add(1, Ordering::Relaxed);
        Ok(Handle::new(profile_id, handle_id))
    }

    async fn tokenize(&self, text: &str) -> Result<Vec<u32>, RuntimeError> {
        let response: TokenizeResponse = self
            .post_json(
                "/tokenize",
                &json!(TokenizeRequest {
                    content: text.to_string()
                }),
                self.config.request_timeout,
            )
            .await?;
        Ok(response.tokens)
    }

    async fn detokenize(&self, ids: &[u32]) -> Result<String, RuntimeError> {
        let response: DetokenizeResponse = self
            .post_json(
                "/detokenize",
                &json!({ "tokens": ids }),
                self.config.request_timeout,
            )
            .await?;
        Ok(response.content)
    }

    async fn prefill(&self, _handle: &Handle, ids: &[u32]) -> Result<KvCommitment, RuntimeError> {
        if ids.is_empty() {
            return Err(RuntimeError::MalformedResponse(
                "prefill of empty token span".to_string(),
            ));
        }
        let started = Instant::now();
        let response: CompletionsResponse = self
            .post_json(
                "/v1/completions",
                &json!({
                    "prompt": ids,
                    "max_tokens": 1,
                    "stream": false,
                }),
                self.config.request_timeout,
            )
            .await?;
        let prompt_tokens = response
            .usage
            .as_ref()
            .map(|u| u.prompt_tokens)
            .unwrap_or(ids.len() as u64);
        self.record_prefill_rate(prompt_tokens, started.elapsed());
        Ok(KvCommitment::new(0, ids))
    }

    /// True streaming (P1): one `POST /v1/completions {stream:true,
    /// logprobs:true}` consumed incrementally. Exact token-id recovery per
    /// chunk follows the same fail-closed rules as `decode_step`
    /// (server `id` authoritative for the pinned artifact, pinned-vocab
    /// `bytes` as cross-check, disagreement = error); EOS terminates the
    /// stream without being emitted; the caller's deadline is enforced by the
    /// per-request timeout across the whole body. Dropping the stream aborts
    /// the connection, which the pinned server treats as cancellation.
    fn decode_stream_events<'a>(
        &'a self,
        _handle: &'a Handle,
        prefix: &'a [u32],
        sampling: &SamplingParams,
        max_tokens: u32,
        deadline: Duration,
    ) -> DecodeEventStream<'a> {
        if prefix.is_empty() {
            return Box::pin(futures_util::stream::once(async {
                Err(RuntimeError::MalformedResponse(
                    "decode_stream_events with empty prefix; prefill first".to_string(),
                ))
            }));
        }
        let mut body = json!({
            "prompt": prefix,
            "max_tokens": max_tokens,
            "stream": true,
        });
        if self.config.vocab.is_some() {
            body["logprobs"] = json!(true);
        }
        if let Some(sampling) = sampling_body(sampling).as_object() {
            for (key, value) in sampling {
                body[key] = value.clone();
            }
        }
        let state = SseState {
            client: self.client.clone(),
            url: self.url("/v1/completions"),
            bearer: self.config.bearer_token.clone(),
            body,
            deadline,
            shared: Arc::clone(&self.shared),
            vocab: self.config.vocab.clone(),
            eos_id: self.config.vocab.as_ref().and_then(|v| v.eos_id),
            max_tokens,
            produced: 0,
            saw_eos: false,
            started: Instant::now(),
            phase: SsePhase::Connect,
            pending_timings: None,
            finished: max_tokens == 0,
            metrics_recorded: false,
        };
        Box::pin(futures_util::stream::unfold(
            state,
            |mut state| async move {
                match next_decode_event(&mut state).await {
                    Ok(Some(event)) => Some((Ok(event), state)),
                    Ok(None) => None,
                    // Errors are terminal: mark finished so a stray extra poll
                    // cannot resurrect a half-consumed stream.
                    Err(e) => {
                        state.finished = true;
                        Some((Err(e), state))
                    }
                }
            },
        ))
    }

    async fn decode_step(
        &self,
        _handle: &Handle,
        prefix: &[u32],
        sampling: &SamplingParams,
    ) -> Result<u32, RuntimeError> {
        if prefix.is_empty() {
            return Err(RuntimeError::MalformedResponse(
                "decode_step with empty prefix; prefill first".to_string(),
            ));
        }
        let started = Instant::now();
        let mut body = json!({
            "prompt": prefix,
            "max_tokens": 1,
            "stream": false,
        });
        if self.config.no_prompt_cache {
            body["cache_prompt"] = json!(false);
        }
        // Exact id recovery needs the logprob byte sequence; harmless when
        // no vocab is attached (falls back to the text round-trip below).
        if self.config.vocab.is_some() {
            body["logprobs"] = json!(true);
        }
        if let Some(sampling) = sampling_body(sampling).as_object() {
            for (key, value) in sampling {
                body[key] = value.clone();
            }
        }
        let response: CompletionsResponse = self
            .post_json("/v1/completions", &body, self.config.request_timeout)
            .await?;
        let choice = response.choices.first().ok_or_else(|| {
            RuntimeError::MalformedResponse("completions response had no choices".to_string())
        })?;

        // Preferred path: exact id as the server reports it (see
        // [`exact_token_id`]; the server's `id` is the only representation
        // special tokens have — the Qwen2.5-7B `<|im_end|>` fix).
        if let (Some(vocab), Some(entries)) = (&self.config.vocab, choice.logprobs.as_ref()) {
            if let Some(entry) = entries.content.first() {
                if let Some(id) = exact_token_id(vocab, entry)? {
                    record_decode_rate(&self.shared, 1, started.elapsed());
                    return Ok(id);
                }
            }
        }

        // Fallback (no vocab attached): recover the id through the tokenizer.
        // Documented approximation — byte-fallback tokens are unrecoverable
        // from text; attach a vocab for the exact path.
        let text = &choice.text;
        if text.is_empty() {
            return Err(RuntimeError::MalformedResponse(
                "completions response produced empty text".to_string(),
            ));
        }
        let tokens: TokenizeResponse = self
            .post_json(
                "/tokenize",
                &json!(TokenizeRequest {
                    content: text.to_string()
                }),
                self.config.request_timeout,
            )
            .await?;
        record_decode_rate(&self.shared, 1, started.elapsed());
        tokens
            .tokens
            .first()
            .copied()
            .ok_or_else(|| RuntimeError::MalformedResponse("tokenize returned no ids".to_string()))
    }

    /// Materialized decode over the same single SSE connection as
    /// [`Self::decode_stream_events`] — one code path, two views.
    async fn decode_stream(
        &self,
        handle: &Handle,
        prefix: &[u32],
        sampling: &SamplingParams,
        max_tokens: u32,
        deadline: Duration,
    ) -> Result<Vec<u32>, RuntimeError> {
        let mut events = self.decode_stream_events(handle, prefix, sampling, max_tokens, deadline);
        let mut out = Vec::with_capacity(max_tokens.min(1024) as usize);
        while let Some(event) = events.next().await {
            match event? {
                DecodeEvent::Token(id) => out.push(id),
                DecodeEvent::Timings(_) => {}
            }
        }
        Ok(out)
    }

    /// Greedy self-continuation (ADR-021 salvageable unforked subset): the
    /// draft window is what this same model would greedily produce, so a
    /// proposer peer needs no separate draft model or server hooks.
    async fn propose(
        &self,
        handle: &Handle,
        prefix: &[u32],
        window: u32,
    ) -> Result<Vec<u32>, RuntimeError> {
        if window == 0 {
            return Ok(Vec::new());
        }
        let started = Instant::now();
        let default = SamplingParams::default();
        let deadline = self.config.request_timeout;
        let mut draft = Vec::with_capacity(window as usize);
        let mut prefix = prefix.to_vec();
        while draft.len() < window as usize {
            let elapsed = started.elapsed();
            if elapsed >= deadline {
                return Err(RuntimeError::Timeout {
                    after_ms: crate::duration_ms_u64(elapsed),
                });
            }
            let token = self.decode_step(handle, &prefix, &default).await?;
            if Some(token) == self.config.vocab.as_ref().and_then(|v| v.eos_id) {
                break;
            }
            prefix.push(token);
            draft.push(token);
        }
        Ok(draft)
    }

    fn metrics(&self) -> RuntimeMetrics {
        self.shared.metrics.read().map(|m| *m).unwrap_or_default()
    }

    fn cancel(&self, task: TaskId) -> Result<(), RuntimeError> {
        // Best-effort synchronous cancel: the pinned server also cancels
        // work when the requesting connection aborts, so 404/405 from builds
        // without POST /cancel is success for our purposes. The trait method
        // is sync, so the one-shot HTTP call runs on a helper thread with a
        // throwaway current-thread runtime (rare control-path call).
        let url = self.url("/cancel");
        let bearer = self.config.bearer_token.clone();
        let body = json!({ "task_id": task.0 });
        let outcome = std::thread::spawn(move || -> Result<(), RuntimeError> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|e| RuntimeError::Http(format!("cancel runtime: {e}")))?;
            runtime.block_on(async move {
                let started = Instant::now();
                // A fresh client is required here: the adapter's shared
                // client is bound to whichever async runtime created its
                // connection pool first, and this helper thread has its own.
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .map_err(|e| RuntimeError::Http(format!("cancel client: {e}")))?;
                let request = client
                    .post(url)
                    .bearer_auth(bearer)
                    .json(&body)
                    .build()
                    .map_err(|e| RuntimeError::Http(format!("cancel build failed: {e}")))?;
                match client.execute(request).await {
                    // 404/405 means this build has no POST /cancel: the
                    // server's abort-based cancellation applies, which is
                    // what dropping the request connection already achieved.
                    Ok(_) => Ok(()),
                    Err(e) => Err(reqwest_error(e, started)),
                }
            })
        })
        .join()
        .map_err(|_| RuntimeError::Http("cancel thread panicked".to_string()))?;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InferenceRuntime;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Canned answer for the mini llama.cpp mock server.
    #[derive(Debug, Clone)]
    struct Canned {
        status: u16,
        body: String,
        delay: Option<Duration>,
    }

    impl Canned {
        fn ok(body: impl Into<String>) -> Self {
            Self {
                status: 200,
                body: body.into(),
                delay: None,
            }
        }
        fn err(status: u16, body: impl Into<String>) -> Self {
            Self {
                status,
                body: body.into(),
                delay: None,
            }
        }
    }

    /// Responder closure type for the canned server.
    type CannedResponder = Arc<Mutex<dyn FnMut(&str) -> Canned + Send>>;

    /// A raw-socket HTTP/1.1 server serving canned responses chosen by a
    /// closure that sees the full request text. Lightest possible double:
    /// no axum, no hyper, one accept loop.
    async fn start_canned_server(
        responder: CannedResponder,
    ) -> std::io::Result<std::net::SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let responder = responder.clone();
                tokio::spawn(async move {
                    let mut buffer = Vec::with_capacity(8 * 1024);
                    let mut chunk = [0u8; 4 * 1024];
                    loop {
                        // Read one full request (headers + content-length body).
                        let request = loop {
                            let n = match socket.read(&mut chunk).await {
                                Ok(0) => return,
                                Ok(n) => n,
                                Err(_) => return,
                            };
                            buffer.extend_from_slice(&chunk[..n]);
                            if let Some(header_end) = find_header_end(&buffer) {
                                let headers =
                                    String::from_utf8_lossy(&buffer[..header_end]).to_uppercase();
                                let cl = headers
                                    .lines()
                                    .find_map(|l| l.strip_prefix("CONTENT-LENGTH:"))
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                                    .unwrap_or(0);
                                if buffer.len() >= header_end + 4 + cl {
                                    break buffer[..header_end + 4 + cl].to_vec();
                                }
                            }
                        };
                        let canned = (responder.lock().expect("responder"))(
                            &String::from_utf8_lossy(&request),
                        );
                        if let Some(delay) = canned.delay {
                            tokio::time::sleep(delay).await;
                        }
                        let reason = match canned.status {
                            200 => "OK",
                            401 => "Unauthorized",
                            404 => "Not Found",
                            500 => "Internal Server Error",
                            503 => "Service Unavailable",
                            _ => "Status",
                        };
                        let response = format!(
                            "HTTP/1.1 {} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                            canned.status,
                            reason,
                            canned.body.len(),
                            canned.body
                        );
                        if socket.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                        buffer.clear();
                    }
                });
            }
        });
        Ok(addr)
    }

    fn find_header_end(buf: &[u8]) -> Option<usize> {
        buf.windows(4).position(|w| w == b"\r\n\r\n")
    }

    /// One scripted raw SSE write (optional pre-write delay).
    #[derive(Debug, Clone)]
    struct SseFrame {
        bytes: String,
        delay: Option<Duration>,
    }

    impl SseFrame {
        fn data(json: &str) -> Self {
            Self {
                bytes: format!("data: {json}\n\n"),
                delay: None,
            }
        }
        fn token(id: u32, bytes: &[u8]) -> Self {
            // `{bytes:?}` renders `[65, 66]` — valid JSON for the byte array.
            Self::data(&format!(
                r#"{{"choices":[{{"text":"t","logprobs":{{"content":[{{"id":{id},"token":"t","bytes":{bytes:?}}}]}},"finish_reason":null}}]}}"#
            ))
        }
        fn done() -> Self {
            Self::data("[DONE]")
        }
        fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = Some(delay);
            self
        }
    }

    /// Final-chunk shape with timings (probe-verified b11407 wire format).
    fn sse_final_chunk(prompt_n: u64, predicted_n: u64) -> SseFrame {
        SseFrame::data(&format!(
            r#"{{"choices":[{{"text":"","logprobs":null,"finish_reason":"stop"}}],"usage":{{"prompt_tokens":{prompt_n},"completion_tokens":{predicted_n}}},"timings":{{"prompt_n":{prompt_n},"prompt_ms":2.0,"predicted_n":{predicted_n},"predicted_ms":8.0}}}}"#
        ))
    }

    type SseResponder = Arc<Mutex<dyn FnMut(&str) -> Vec<SseFrame> + Send>>;

    /// Raw-socket server speaking SSE: reads one request, answers
    /// `text/event-stream` with the scripted frames (delays between writes),
    /// then closes the connection (close-delimited body ends the stream).
    async fn start_sse_server(responder: SseResponder) -> std::io::Result<std::net::SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let responder = responder.clone();
                tokio::spawn(async move {
                    let mut buffer = Vec::with_capacity(8 * 1024);
                    let mut chunk = [0u8; 4 * 1024];
                    // One full request (headers + content-length body).
                    let request = loop {
                        let n = match socket.read(&mut chunk).await {
                            Ok(0) => return,
                            Ok(n) => n,
                            Err(_) => return,
                        };
                        buffer.extend_from_slice(&chunk[..n]);
                        if let Some(header_end) = find_header_end(&buffer) {
                            let headers =
                                String::from_utf8_lossy(&buffer[..header_end]).to_uppercase();
                            let cl = headers
                                .lines()
                                .find_map(|l| l.strip_prefix("CONTENT-LENGTH:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if buffer.len() >= header_end + 4 + cl {
                                break buffer[..header_end + 4 + cl].to_vec();
                            }
                        }
                    };
                    let frames =
                        (responder.lock().expect("responder"))(&String::from_utf8_lossy(&request));
                    let head =
                        "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n";
                    if socket.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    for frame in frames {
                        if let Some(delay) = frame.delay {
                            tokio::time::sleep(delay).await;
                        }
                        if socket.write_all(frame.bytes.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Ok(addr)
    }

    fn adapter_with_vocab(
        addr: std::net::SocketAddr,
        timeout: Duration,
        eos: Option<u32>,
    ) -> LlamaCppAdapter {
        let mut map = std::collections::HashMap::new();
        map.insert(vec![65u8], 72u32);
        map.insert(vec![66u8], 74u32);
        LlamaCppAdapter::new(LlamaCppConfig {
            base_url: format!("http://{addr}"),
            bearer_token: "internal-secret".to_string(),
            request_timeout: timeout,
            engine: None,
            vocab: Some(Arc::new(modelswarm_types::TokenVocab {
                bytes_to_id: map,
                eos_id: eos,
            })),
            no_prompt_cache: false,
        })
        .unwrap()
    }

    fn adapter(addr: std::net::SocketAddr, timeout: Duration) -> LlamaCppAdapter {
        LlamaCppAdapter::new(LlamaCppConfig {
            base_url: format!("http://{addr}"),
            bearer_token: "internal-secret".to_string(),
            request_timeout: timeout,
            engine: None,
            vocab: None,
            no_prompt_cache: false,
        })
        .unwrap()
    }

    const TOK_TOKENS: &str = r#"{"tokens":[72,101,108,108,111]}"#;
    const COMPLETIONS_A: &str =
        r#"{"choices":[{"text":"A"}],"usage":{"prompt_tokens":5,"completion_tokens":1}}"#;
    const MODELS: &str = r#"{"data":[{"id":"tiny.gguf"}]}"#;

    #[tokio::test]
    async fn load_tokenizes_and_steps_through_the_mock_server() {
        let seen_bearer = Arc::new(AtomicUsize::new(0));
        let seen_bearer_clone = seen_bearer.clone();
        let completions = Arc::new(Mutex::new(Vec::<Canned>::new()));
        let completions_for_server = completions.clone();
        // Queue: load(models), tokenize, prefill(completions), step(completions), step tokenize
        completions.lock().unwrap().push(Canned::ok(MODELS));
        completions.lock().unwrap().push(Canned::ok(TOK_TOKENS));
        completions.lock().unwrap().push(Canned::ok(COMPLETIONS_A));
        completions.lock().unwrap().push(Canned::ok(COMPLETIONS_A));
        completions.lock().unwrap().push(Canned::ok(TOK_TOKENS));

        let addr = start_canned_server(Arc::new(Mutex::new(move |request: &str| {
            if request
                .to_ascii_lowercase()
                .contains("authorization: bearer internal-secret")
            {
                seen_bearer_clone.fetch_add(1, Ordering::Relaxed);
            }
            completions_for_server.lock().unwrap().remove(0)
        })))
        .await
        .unwrap();

        let runtime = adapter(addr, Duration::from_secs(5));
        let handle = runtime.load("msp1:aa").await.unwrap();
        assert_eq!(handle.profile_id(), "msp1:aa");

        let ids = runtime.tokenize("Hello").await.unwrap();
        assert_eq!(ids, vec![72, 101, 108, 108, 111]);

        let commitment = runtime.prefill(&handle, &ids).await.unwrap();
        assert_eq!(commitment.token_span, (0, 5));
        assert_eq!(commitment.digest.len(), 64);

        let sampling = SamplingParams::default();
        let token = runtime.decode_step(&handle, &ids, &sampling).await.unwrap();
        assert_eq!(token, 72); // first token id of the canned "A"→tokenize reply

        let metrics = runtime.metrics();
        assert!(metrics.prefill_tokens_per_ms > 0.0);
        assert!(metrics.decode_tokens_per_ms > 0.0);
        assert!(seen_bearer.load(Ordering::Relaxed) >= 5);
    }

    #[tokio::test]
    async fn detokenize_round_trips_through_the_server() {
        let queue = Arc::new(Mutex::new(Vec::<Canned>::new()));
        queue
            .lock()
            .unwrap()
            .push(Canned::ok(r#"{"content":"Hello"}"#));
        let queue_server = queue.clone();
        let addr = start_canned_server(Arc::new(Mutex::new(move |_req: &str| {
            queue_server.lock().unwrap().remove(0)
        })))
        .await
        .unwrap();
        let runtime = adapter(addr, Duration::from_secs(5));
        assert_eq!(runtime.detokenize(&[72, 101]).await.unwrap(), "Hello");
    }

    #[tokio::test]
    async fn error_status_maps_to_api_error() {
        let addr = start_canned_server(Arc::new(Mutex::new(|_req: &str| {
            Canned::err(
                401,
                r#"{"error":{"code":"unauthorized","message":"bad bearer"}}"#,
            )
        })))
        .await
        .unwrap();
        let runtime = adapter(addr, Duration::from_secs(5));
        match runtime.load("msp1:aa").await.unwrap_err() {
            RuntimeError::Api { status, code, .. } => {
                assert_eq!(status, 401);
                assert_eq!(code, "unauthorized");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn malformed_body_maps_to_malformed_response() {
        let addr = start_canned_server(Arc::new(Mutex::new(|_req: &str| {
            Canned::ok("this is not json")
        })))
        .await
        .unwrap();
        let runtime = adapter(addr, Duration::from_secs(5));
        assert!(matches!(
            runtime.load("msp1:aa").await.unwrap_err(),
            RuntimeError::MalformedResponse(_)
        ));
    }

    #[tokio::test]
    async fn connection_refused_maps_to_http_error() {
        // Bind then immediately drop the listener to get a free-but-closed port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let runtime = adapter(addr, Duration::from_secs(2));
        let err = runtime.load("msp1:aa").await.unwrap_err();
        // On this Windows stack a closed loopback port can surface either as
        // a connect error or as a connect timeout; both are transport-class
        // failures and must not be Malformed/Api.
        assert!(
            matches!(err, RuntimeError::Http(_) | RuntimeError::Timeout { .. }),
            "expected transport-class error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn delayed_server_maps_to_timeout() {
        let addr = start_canned_server(Arc::new(Mutex::new(|_req: &str| Canned {
            status: 200,
            body: MODELS.to_string(),
            delay: Some(Duration::from_secs(3)),
        })))
        .await
        .unwrap();
        let runtime = adapter(addr, Duration::from_millis(150));
        let started = Instant::now();
        match runtime.load("msp1:aa").await.unwrap_err() {
            RuntimeError::Timeout { after_ms } => {
                assert!(after_ms >= 100, "timeout after {after_ms} ms");
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn decode_stream_uses_one_sse_request_and_recovers_ids_exactly() {
        // Script: id+bytes token, bytes-only token (cross-check path), EOS
        // (id, empty bytes — the <|im_end|> shape), final chunk with timings,
        // [DONE]. Exactly one POST /v1/completions whose body carries
        // stream/logprobs/prompt-ids/temperature 0 (default sampling).
        let bodies = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let bodies_server = bodies.clone();
        let addr = start_sse_server(Arc::new(Mutex::new(move |req: &str| {
            let body_start = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&req[body_start..]) {
                bodies_server.lock().unwrap().push(v);
            }
            vec![
                SseFrame::token(72, &[65]),
                SseFrame::data(
                    r#"{"choices":[{"text":"B","logprobs":{"content":[{"bytes":[66]}]}}]}"#,
                ),
                SseFrame::token(99, &[]),
                sse_final_chunk(3, 2),
                SseFrame::done(),
            ]
        })))
        .await
        .unwrap();

        let runtime = adapter_with_vocab(addr, Duration::from_secs(5), Some(99));
        let handle = Handle::new("msp1:aa", 1);
        let sampling = SamplingParams::default();
        let mut events = runtime.decode_stream_events(
            &handle,
            &[7, 8, 9],
            &sampling,
            10,
            Duration::from_secs(5),
        );
        use futures_util::StreamExt;
        let token_a = events.next().await.unwrap().unwrap();
        let token_b = events.next().await.unwrap().unwrap();
        let timings = events.next().await.unwrap().unwrap();
        assert!(events.next().await.is_none(), "stream ends after [DONE]");
        assert_eq!(token_a, DecodeEvent::Token(72));
        assert_eq!(token_b, DecodeEvent::Token(74));
        assert_eq!(
            timings,
            DecodeEvent::Timings(DecodeTimings {
                prompt_tokens: 3,
                prompt_ms: 2.0,
                completion_tokens: 2,
                decode_ms: 8.0,
            })
        );

        let bodies = bodies.lock().unwrap();
        assert_eq!(bodies.len(), 1, "one SSE POST per decode, not per token");
        assert_eq!(bodies[0]["stream"], serde_json::json!(true));
        assert_eq!(bodies[0]["logprobs"], serde_json::json!(true));
        assert_eq!(bodies[0]["temperature"], serde_json::json!(0.0));
        assert_eq!(bodies[0]["prompt"], serde_json::json!([7, 8, 9]));
        assert_eq!(bodies[0]["max_tokens"], serde_json::json!(10));
        // Server-reported timings feed the prefill/decode metric split (M2).
        let metrics = runtime.metrics();
        assert!(metrics.prefill_tokens_per_ms > 0.0);
        assert!(metrics.decode_tokens_per_ms > 0.0);
    }

    #[tokio::test]
    async fn decode_stream_stops_at_max_tokens() {
        let addr = start_sse_server(Arc::new(Mutex::new(|_req: &str| {
            vec![
                SseFrame::token(72, &[65]),
                SseFrame::token(72, &[65]),
                SseFrame::token(72, &[65]),
                SseFrame::token(72, &[65]),
                SseFrame::token(72, &[65]),
                sse_final_chunk(1, 5),
                SseFrame::done(),
            ]
        })))
        .await
        .unwrap();
        let runtime = adapter_with_vocab(addr, Duration::from_secs(5), None);
        let handle = Handle::new("msp1:aa", 1);
        let out = runtime
            .decode_stream(
                &handle,
                &[1, 2, 3],
                &SamplingParams::default(),
                4,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(out, vec![72, 72, 72, 72]);
    }

    #[tokio::test]
    async fn streaming_tokens_arrive_as_the_engine_produces_them() {
        // Frames 2 and 3 are server-delayed: the first token must arrive
        // BEFORE the script could have finished writing (true streaming,
        // the property the per-token loop destroyed).
        let addr = start_sse_server(Arc::new(Mutex::new(|_req: &str| {
            vec![
                SseFrame::token(72, &[65]),
                SseFrame::token(72, &[65]).with_delay(Duration::from_millis(60)),
                SseFrame::token(72, &[65]).with_delay(Duration::from_millis(60)),
                sse_final_chunk(1, 3),
                SseFrame::done(),
            ]
        })))
        .await
        .unwrap();
        let runtime = adapter_with_vocab(addr, Duration::from_secs(5), None);
        let handle = Handle::new("msp1:aa", 1);
        let started = tokio::time::Instant::now();
        let sampling = SamplingParams::default();
        let mut events =
            runtime.decode_stream_events(&handle, &[1], &sampling, 8, Duration::from_secs(5));
        let first = events.next().await.unwrap().unwrap();
        let first_after = started.elapsed();
        let rest: Vec<DecodeEvent> = events.map(|e| e.unwrap()).collect().await;
        assert_eq!(first, DecodeEvent::Token(72));
        assert_eq!(
            rest,
            vec![
                DecodeEvent::Token(72),
                DecodeEvent::Token(72),
                DecodeEvent::Timings(DecodeTimings {
                    prompt_tokens: 1,
                    prompt_ms: 2.0,
                    completion_tokens: 3,
                    decode_ms: 8.0,
                }),
            ]
        );
        // The full script needs >= 120 ms of server-side delay; the first
        // token must not wait for it (generous CI margins, property only).
        assert!(
            first_after < Duration::from_millis(100),
            "first event arrived after {first_after:?} — stream is not incremental"
        );
    }

    #[tokio::test]
    async fn streaming_disagreement_and_error_events_fail_closed() {
        // id/bytes disagreement → MalformedResponse.
        let addr = start_sse_server(Arc::new(Mutex::new(|_req: &str| {
            vec![SseFrame::token(70, &[65]), SseFrame::done()]
        })))
        .await
        .unwrap();
        let runtime = adapter_with_vocab(addr, Duration::from_secs(5), None);
        let handle = Handle::new("msp1:aa", 1);
        let err = runtime
            .decode_stream(
                &handle,
                &[1],
                &SamplingParams::default(),
                4,
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, RuntimeError::MalformedResponse(ref m) if m.contains("disagreement")),
            "got {err:?}"
        );

        // Engine-reported SSE error event → Api error, no tokens.
        let addr = start_sse_server(Arc::new(Mutex::new(|_req: &str| {
            vec![SseFrame::data(
                r#"{"error":{"code":"generation_error","message":"boom"}}"#,
            )]
        })))
        .await
        .unwrap();
        let runtime = adapter_with_vocab(addr, Duration::from_secs(5), None);
        let handle = Handle::new("msp1:aa", 1);
        match runtime
            .decode_stream(
                &handle,
                &[1],
                &SamplingParams::default(),
                4,
                Duration::from_secs(5),
            )
            .await
            .unwrap_err()
        {
            RuntimeError::Api { code, message, .. } => {
                assert_eq!(code, "generation_error");
                assert_eq!(message, "boom");
            }
            other => panic!("expected Api error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn streaming_deadline_maps_to_timeout() {
        let addr = start_sse_server(Arc::new(Mutex::new(|_req: &str| {
            vec![
                SseFrame::token(72, &[65]).with_delay(Duration::from_secs(3)),
                SseFrame::done(),
            ]
        })))
        .await
        .unwrap();
        let runtime = adapter_with_vocab(addr, Duration::from_secs(5), None);
        let handle = Handle::new("msp1:aa", 1);
        let started = Instant::now();
        match runtime
            .decode_stream(
                &handle,
                &[1],
                &SamplingParams::default(),
                4,
                Duration::from_millis(150),
            )
            .await
            .unwrap_err()
        {
            RuntimeError::Timeout { after_ms } => assert!(after_ms >= 100),
            other => panic!("expected Timeout, got {other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn streaming_without_vocab_uses_server_ids() {
        let addr = start_sse_server(Arc::new(Mutex::new(|_req: &str| {
            vec![
                SseFrame::token(555, &[1, 2, 3]),
                sse_final_chunk(1, 1),
                SseFrame::done(),
            ]
        })))
        .await
        .unwrap();
        let runtime = adapter(addr, Duration::from_secs(5));
        let handle = Handle::new("msp1:aa", 1);
        let out = runtime
            .decode_stream(
                &handle,
                &[1],
                &SamplingParams::default(),
                4,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(out, vec![555]);
    }

    #[tokio::test]
    async fn exact_id_recovery_uses_logprob_bytes_not_text() {
        // Vocab maps bytes [0xC3,0x80] ("À") to id 99 — the generated token
        // is recovered from logprobs.bytes without any /tokenize call.
        let completions_hits = Arc::new(AtomicUsize::new(0));
        let hits_server = completions_hits.clone();
        let tokenize_hits = Arc::new(AtomicUsize::new(0));
        let tokenize_server = tokenize_hits.clone();
        let addr = start_canned_server(Arc::new(Mutex::new(move |req: &str| {
            let first = req.split_whitespace().nth(1).unwrap_or("");
            if first.starts_with("/v1/completions") {
                hits_server.fetch_add(1, Ordering::Relaxed);
                Canned::ok(
                    r#"{"choices":[{"text":"?","logprobs":{"content":[{"token":"?","bytes":[195,128]}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
                )
            } else if first == "/tokenize" {
                tokenize_server.fetch_add(1, Ordering::Relaxed);
                Canned::ok(TOK_TOKENS)
            } else {
                Canned::ok(MODELS)
            }
        })))
        .await
        .unwrap();

        let mut vocab = modelswarm_types::TokenVocab {
            bytes_to_id: std::collections::HashMap::new(),
            eos_id: None,
        };
        vocab.bytes_to_id.insert(vec![0xC3, 0x80], 99);
        let runtime = LlamaCppAdapter::new(
            LlamaCppConfig::new(format!("http://{addr}"), "internal-secret")
                .with_vocab(Arc::new(vocab)),
        )
        .unwrap();
        let handle = runtime.load("msp1:aa").await.unwrap();
        let token = runtime
            .decode_step(&handle, &[1, 2], &SamplingParams::default())
            .await
            .unwrap();
        assert_eq!(token, 99);
        assert_eq!(completions_hits.load(Ordering::Relaxed), 1);
        assert_eq!(
            tokenize_hits.load(Ordering::Relaxed),
            0,
            "no text round-trip"
        );

        // An unknown byte sequence fails closed rather than guessing an id.
        let mut bad = modelswarm_types::TokenVocab {
            bytes_to_id: std::collections::HashMap::new(),
            eos_id: None,
        };
        bad.bytes_to_id.insert(vec![1, 2, 3], 5);
        let runtime = LlamaCppAdapter::new(
            LlamaCppConfig::new(format!("http://{addr}"), "internal-secret")
                .with_vocab(Arc::new(bad)),
        )
        .unwrap();
        let handle = runtime.load("msp1:aa").await.unwrap();
        assert!(matches!(
            runtime
                .decode_step(&handle, &[1, 2], &SamplingParams::default())
                .await
                .unwrap_err(),
            RuntimeError::MalformedResponse(_)
        ));
    }

    #[tokio::test]
    async fn special_token_with_empty_bytes_recovers_id_from_server() {
        // The Qwen2.5-7B chat failure: the reply's <|im_end|> (or any special
        // token) comes back with empty `token` AND empty `bytes` — the bytes
        // map can never contain the empty sequence — but b11407 reports the
        // sampled `id`, which is exact for the pinned artifact. The stream
        // must terminate on it (eos pinned) instead of erroring.
        let addr = start_canned_server(Arc::new(Mutex::new(|req: &str| {
            let first = req.split_whitespace().nth(1).unwrap_or("");
            if first.starts_with("/v1/completions") {
                Canned::ok(
                    r#"{"choices":[{"text":"","finish_reason":"stop","logprobs":{"content":[{"id":2,"token":"","bytes":[]}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
                )
            } else {
                Canned::ok(MODELS)
            }
        })))
        .await
        .unwrap();

        let mut vocab = modelswarm_types::TokenVocab {
            bytes_to_id: std::collections::HashMap::new(),
            eos_id: Some(2),
        };
        vocab.bytes_to_id.insert(vec![65], 72);
        let runtime = LlamaCppAdapter::new(
            LlamaCppConfig::new(format!("http://{addr}"), "internal-secret")
                .with_vocab(Arc::new(vocab)),
        )
        .unwrap();
        let handle = runtime.load("msp1:aa").await.unwrap();
        let token = runtime
            .decode_step(&handle, &[1, 2], &SamplingParams::default())
            .await
            .unwrap();
        assert_eq!(token, 2);

        // EOS-aware termination in streaming, not an error and not an
        // emitted token: the EOS chunk (id 2, empty bytes) then final + DONE.
        let sse_addr = start_sse_server(Arc::new(Mutex::new(|_req: &str| {
            vec![
                SseFrame::token(2, &[]),
                sse_final_chunk(1, 0),
                SseFrame::done(),
            ]
        })))
        .await
        .unwrap();
        let runtime = adapter_with_vocab(sse_addr, Duration::from_secs(5), Some(2));
        let handle = Handle::new("msp1:aa", 1);
        let out = runtime
            .decode_stream(
                &handle,
                &[1],
                &SamplingParams::default(),
                5,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn server_id_disagreeing_with_bytes_map_fails_closed() {
        let addr = start_canned_server(Arc::new(Mutex::new(|req: &str| {
            let first = req.split_whitespace().nth(1).unwrap_or("");
            if first.starts_with("/v1/completions") {
                Canned::ok(
                    r#"{"choices":[{"text":"A","logprobs":{"content":[{"id":70,"token":"A","bytes":[65]}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
                )
            } else {
                Canned::ok(MODELS)
            }
        })))
        .await
        .unwrap();

        // Vocab pins bytes [65] ("A") to id 72; the server claims 70 — vocab
        // drift must surface, never silently corrupt the token stream.
        let mut vocab = modelswarm_types::TokenVocab {
            bytes_to_id: std::collections::HashMap::new(),
            eos_id: None,
        };
        vocab.bytes_to_id.insert(vec![65], 72);
        let runtime = LlamaCppAdapter::new(
            LlamaCppConfig::new(format!("http://{addr}"), "internal-secret")
                .with_vocab(Arc::new(vocab)),
        )
        .unwrap();
        let handle = runtime.load("msp1:aa").await.unwrap();
        let err = runtime
            .decode_step(&handle, &[1, 2], &SamplingParams::default())
            .await
            .unwrap_err();
        assert!(
            matches!(err, RuntimeError::MalformedResponse(ref m) if m.contains("disagreement"))
        );
    }

    #[tokio::test]
    async fn default_sampling_maps_to_greedy_temperature_zero() {
        // The determinism contract: default sampling => temperature 0.
        let seen_bodies = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let bodies_server = seen_bodies.clone();
        let addr = start_canned_server(Arc::new(Mutex::new(move |req: &str| {
            let body_start = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
            let body = &req[body_start..];
            if req.starts_with("POST /v1/completions") {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                    bodies_server.lock().unwrap().push(v);
                }
                Canned::ok(COMPLETIONS_A)
            } else if req.starts_with("POST /tokenize") {
                Canned::ok(TOK_TOKENS)
            } else {
                Canned::ok(MODELS)
            }
        })))
        .await
        .unwrap();
        let runtime = adapter(addr, Duration::from_secs(5));
        let handle = runtime.load("msp1:aa").await.unwrap();
        runtime
            .decode_step(&handle, &[1], &SamplingParams::default())
            .await
            .unwrap();
        // Explicit sampling is forwarded verbatim.
        let explicit = SamplingParams {
            temperature: 0.7,
            top_p: 0.9,
            top_k: 50,
            seed: Some(42),
        };
        runtime.decode_step(&handle, &[1], &explicit).await.unwrap();

        let bodies = seen_bodies.lock().unwrap();
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0]["temperature"], serde_json::json!(0.0));
        assert_eq!(bodies[1]["temperature"].as_f64().unwrap() as f32, 0.7f32);
        assert_eq!(bodies[1]["seed"], serde_json::json!(42));
    }

    #[tokio::test]
    async fn propose_is_greedy_self_continuation_and_stream_stops_at_eos() {
        // Vocab: byte 0x41 -> id 72, eos -> 73. propose() keeps the
        // one-POST-per-token loop (3 steps); the streaming decode path uses
        // one SSE connection: five tokens at max_tokens 5, then the flip —
        // eos pinned to the emitted token makes the stream stop empty.
        fn vocab_with(eos: Option<u32>) -> Arc<modelswarm_types::TokenVocab> {
            let mut map = std::collections::HashMap::new();
            map.insert(vec![0x41], 72u32);
            map.insert(vec![0x49], 73u32);
            Arc::new(modelswarm_types::TokenVocab {
                bytes_to_id: map,
                eos_id: eos,
            })
        }

        let step = Arc::new(AtomicUsize::new(0));
        let step_server = step.clone();
        let addr = start_canned_server(Arc::new(Mutex::new(move |req: &str| {
            let first = req.split_whitespace().nth(1).unwrap_or("");
            if first.starts_with("/v1/completions") {
                step_server.fetch_add(1, Ordering::Relaxed);
                Canned::ok(
                    r#"{"choices":[{"text":"A","logprobs":{"content":[{"token":"A","bytes":[65]}]}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
                )
            } else {
                Canned::ok(MODELS)
            }
        })))
        .await
        .unwrap();

        let runtime = LlamaCppAdapter::new(
            LlamaCppConfig::new(format!("http://{addr}"), "internal-secret")
                .with_vocab(vocab_with(None)),
        )
        .unwrap();
        let handle = runtime.load("msp1:aa").await.unwrap();
        let draft = runtime.propose(&handle, &[1, 2], 3).await.unwrap();
        assert_eq!(draft, vec![72, 72, 72]);
        assert_eq!(step.load(Ordering::Relaxed), 3);

        // Streaming decode over the same ids: 5 A-tokens then finish.
        let sse_addr = start_sse_server(Arc::new(Mutex::new(|_req: &str| {
            vec![
                SseFrame::token(72, &[0x41]),
                SseFrame::token(72, &[0x41]),
                SseFrame::token(72, &[0x41]),
                SseFrame::token(72, &[0x41]),
                SseFrame::token(72, &[0x41]),
                sse_final_chunk(1, 5),
                SseFrame::done(),
            ]
        })))
        .await
        .unwrap();
        let runtime_sse = LlamaCppAdapter::new(
            LlamaCppConfig::new(format!("http://{sse_addr}"), "internal-secret")
                .with_vocab(vocab_with(None)),
        )
        .unwrap();
        let handle = Handle::new("msp1:aa", 1);
        let out = runtime_sse
            .decode_stream(
                &handle,
                &[1],
                &SamplingParams::default(),
                5,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(out, vec![72, 72, 72, 72, 72]);

        // EOS-awareness: with eos pinned to the emitted token, both propose
        // and the stream stop without emitting it.
        let runtime_eos = LlamaCppAdapter::new(
            LlamaCppConfig::new(format!("http://{addr}"), "internal-secret")
                .with_vocab(vocab_with(Some(72))),
        )
        .unwrap();
        let handle = runtime_eos.load("msp1:aa").await.unwrap();
        let draft = runtime_eos.propose(&handle, &[1, 2], 3).await.unwrap();
        assert!(draft.is_empty());

        let eos_addr = start_sse_server(Arc::new(Mutex::new(|_req: &str| {
            vec![
                SseFrame::token(72, &[0x41]),
                sse_final_chunk(1, 0),
                SseFrame::done(),
            ]
        })))
        .await
        .unwrap();
        let runtime_eos_sse = LlamaCppAdapter::new(
            LlamaCppConfig::new(format!("http://{eos_addr}"), "internal-secret")
                .with_vocab(vocab_with(Some(72))),
        )
        .unwrap();
        let handle = Handle::new("msp1:aa", 1);
        let out = runtime_eos_sse
            .decode_stream(
                &handle,
                &[1],
                &SamplingParams::default(),
                5,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert!(out.is_empty());
    }

    // Multi-thread flavor: `cancel` blocks the calling thread on a helper
    // OS thread doing the HTTP round-trip, and the canned server task runs
    // on this test's runtime — it must keep being driven meanwhile.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancel_tolerates_missing_endpoint() {
        let addr = start_canned_server(Arc::new(Mutex::new(|_req: &str| {
            Canned::err(404, r#"{"error":{"code":"not_found"}}"#)
        })))
        .await
        .unwrap();
        let runtime = adapter(addr, Duration::from_secs(5));
        runtime.cancel(TaskId(7)).unwrap();
    }

    #[tokio::test]
    async fn empty_choices_maps_to_malformed_response() {
        let queue = Arc::new(Mutex::new(Vec::<Canned>::new()));
        queue.lock().unwrap().push(Canned::ok(MODELS));
        queue.lock().unwrap().push(Canned::ok(r#"{"choices":[]}"#));
        let queue_server = queue.clone();
        let addr = start_canned_server(Arc::new(Mutex::new(move |_req: &str| {
            queue_server.lock().unwrap().remove(0)
        })))
        .await
        .unwrap();
        let runtime = adapter(addr, Duration::from_secs(5));
        let handle = runtime.load("msp1:aa").await.unwrap();
        assert!(matches!(
            runtime
                .decode_step(&handle, &[1], &SamplingParams::default())
                .await
                .unwrap_err(),
            RuntimeError::MalformedResponse(_)
        ));
    }
}
