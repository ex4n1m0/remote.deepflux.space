//! The assistant-plane client (ADR-037 §3.7, as rewired by the
//! 2026-10-15 owner directive: "how about we remove this deepseek key
//! completely, and make the helper use the hosted model when hosted"):
//! the user-facing setup helper riding the SAME pure injectable core
//! discipline — `step(state, input) -> (state, effects)` over an
//! injected clock and an injected transport (TR-RC-4/TR-AD-2), NO
//! reqwest, wall clock, or RNG inside the machine.
//!
//! States per the ADR's diagram: `IDLE → BUILD → SCRUB → CALL → PARSE →
//! RECORD → IDLE`. BUILD/SCRUB/PARSE/RECORD are pure computations inside
//! `step`; the waiting phases are `Idle` and `AwaitingCall`.
//!
//! The backing is the machine's OWN hosted model: when the node is
//! hosting, the CALL goes to the LOCAL loopback gateway — the same
//! OpenAI-compatible path chat uses, so queueing/governor fairness
//! applies to assistant turns exactly as to chat turns. When the
//! machine is not hosting there is NO backing: the surface renders the
//! frozen static-help corpus, honestly labeled (`not_hosting`). There
//! is no provider, no key, and no external egress anywhere in the
//! plane anymore.
//!
//! What may be sent (ADR-037 §3.5, the privacy contract, retargeted to
//! the local seam): the user's assistant-channel text (Redactor-scrubbed
//! and byte-capped) plus the TYPED context block (frozen field set in
//! the egress artifact) plus the trailing `history_turns_sent` completed
//! turns — to the machine's own gateway. This module is structurally
//! unable to name a swarm transcript, a serving frame, or a carrier
//! payload (W3 — pinned by the chat-wall suite's layer-2 scan).
//!
//! Caps (ADR-037 §3.4): 300/day, 60/hour, 40 turns/conversation, 15-min
//! idle reset, 12 history turns, 48 KiB request cap, 1024 completion
//! tokens, 45 s timeout. UTC-day and UTC-hour windows; failed calls
//! consume budget; NO in-turn retry — the next user turn is the retry.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use modelswarm_telemetry::redact::Redactor;
use modelswarm_telemetry::Telemetry;

use super::config::AdvisoryConfig;
use super::egress::{self, ContextField};
use super::state::{parse_one_suggestion, ProviderRequest, RecordedSuggestion, TransportFailure};
use super::transport::{AdvisoryTransport, LocalGatewayTransport};
use super::Gap;

/// The fixed, repo-versioned assistant system prompt (ADR-037 §3.2c
/// extended; retargeted to the hosted-model backing by the 2026-10-15
/// directive): the honesty contract to the model. The typed context gate
/// runs regardless of the prompt — the structural gate, not prompt
/// compliance, is the defense.
pub const ASSISTANT_SYSTEM_PROMPT: &str = "\
You are the setup and troubleshooting assistant of a decentralized \
inference swarm desktop app, running as the user's OWN hosted model on \
their own machine. You receive machine and setup metadata (a hardware \
profile, model-catalog rows, and status labels and counts) plus this \
conversation — never the user's swarm conversations, serving content, \
or secrets. Help with model choice for this machine, installation, and \
troubleshooting. Say \"I don't know\" when unsure. Never invent product \
behavior, version numbers, settings, or protocol rules; answer those \
only from the context block you are given. This app's deterministic \
rules decide everything — your advice never changes any decision and \
you must not claim otherwise. Reply with ONE JSON object exactly of the \
shape {\"schema\":\"advisory-assistant/v1\",\"conversation_id\":\"<echo \
the given conversation_id>\",\"turn\":<echo the given turn number>,\
\"reply\":\"<plain-text answer for the user>\",\"hints\":[{\"type\":\
\"triage_summary|catalog_note|digest\",\"target\":\"fleet or a 16-hex \
profile prefix\",\"confidence\":\"low|medium|high\",\"rationale\":\
\"short display text\"}]} where hints may be an empty array. The reply \
is display-only plain text.";

/// The shared response body cap (ADR-037 §3.7: `max_response_bytes`
/// 65 536).
pub const MAX_RESPONSE_BYTES: usize = 65_536;

// ---------------------------------------------------------------------------
// Caps and arming
// ---------------------------------------------------------------------------

/// The assistant-plane caps carried by the state (from
/// [`AdvisoryConfig::assistant`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AssistantRuntimeCaps {
    pub enabled: bool,
    pub max_calls_per_day: u32,
    pub max_calls_per_hour: u32,
    pub max_turns_per_conversation: u32,
    pub idle_reset_ms: u64,
    pub history_turns_sent: usize,
    pub max_request_bytes: usize,
    pub max_completion_tokens: u32,
    pub request_timeout_ms: u64,
    pub max_response_bytes: usize,
}

impl AssistantRuntimeCaps {
    /// The armed defaults used by tests: the nine ADR-037 §3.4 frozen
    /// defaults over a resolved hosted-model backing.
    pub fn armed_defaults() -> Self {
        Self {
            enabled: true,
            max_calls_per_day: 300,
            max_calls_per_hour: 60,
            max_turns_per_conversation: 40,
            idle_reset_ms: 900_000,
            history_turns_sent: 12,
            max_request_bytes: 49_152,
            max_completion_tokens: 1024,
            request_timeout_ms: 45_000,
            max_response_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

/// The hosted-model backing facts (the 2026-10-15 owner directive's
/// arming input): the RUNNING node's bound loopback gateway address and
/// the hosted profile id. Supplied by the composition when hosting is
/// on; absent while it is not.
#[derive(Debug, Clone)]
pub struct HostedBacking {
    pub gateway_addr: SocketAddr,
    pub profile: String,
}

/// The assistant-plane arming decision (the ADR-033 §3.1 shape,
/// collapsed by the 2026-10-15 directive — there is no key and no
/// endpoint anymore): `Hosted` while the machine hosts the model the
/// assistant runs on, the honest static floor otherwise. The §3.4
/// `assistant.enabled` master switch is INDEPENDENT of hosting: the
/// owner may pin the helper to the static corpus even while hosting.
#[derive(Debug, Clone, PartialEq)]
pub enum AssistantArm {
    /// Armed over the machine's own loopback gateway.
    Hosted,
    /// Not armed; `not_hosting` (no model backing) or `no_config`
    /// (malformed advisory.json — fail closed, never a guess).
    Static { reason: Gap },
    /// `assistant.enabled=false` (the shipped default): static-help mode,
    /// silent — the `disabled` gap fires only inside a driven machine.
    Disabled,
}

/// Resolves the assistant arming decision for a data dir plus the
/// caller-supplied hosting facts (reads `advisory.json` only; no
/// network, no key file — none exists).
pub fn assistant_arm(
    data_dir: &Path,
    backing: Option<&HostedBacking>,
) -> (AdvisoryConfig, AssistantArm) {
    let advisory = match AdvisoryConfig::load(data_dir) {
        Ok(cfg) => cfg,
        Err(_) => {
            return (
                AdvisoryConfig::default(),
                AssistantArm::Static {
                    reason: Gap::NoConfig,
                },
            )
        }
    };
    if !advisory.assistant.enabled {
        return (advisory, AssistantArm::Disabled);
    }
    match backing {
        // The transport is constructed by `spawn`; the arm decision
        // only needs the FACT of a hosted backing.
        Some(_) => (advisory, AssistantArm::Hosted),
        None => (
            advisory,
            AssistantArm::Static {
                reason: Gap::NotHosting,
            },
        ),
    }
}

// ---------------------------------------------------------------------------
// The pure state machine
// ---------------------------------------------------------------------------

/// One open conversation (ADR-037 §3.7): `conversation_id` is the first
/// 16 hex of a fresh runner-injected nonce (RC-8's generator pin,
/// reused); `turns` counts COMPLETED turns; `last_activity_ms` drives
/// the idle reset.
#[derive(Debug, Clone, PartialEq)]
pub struct Conversation {
    pub id: String,
    pub turns: u32,
    pub last_activity_ms: u64,
}

/// One completed exchange kept for context (bounded to
/// `history_turns_sent`).
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryTurn {
    pub user: String,
    pub reply: String,
}

/// The machine's waiting phase. The in-flight turn carries its own
/// (scrubbed) user text — the RESPONSE parser reads nothing user-typed
/// from the wire; RECORD files what this machine itself built.
#[derive(Debug, Clone, PartialEq)]
pub enum AssistantPhase {
    Idle,
    AwaitingCall {
        conversation_id: String,
        turn: u32,
        now_ms: u64,
        /// The SCRUBBED user text of the in-flight turn (what was sent).
        user_text: String,
    },
}

/// Effects the runner executes. Telemetry is counts and labels only
/// (`assistant.turn.sent` / `assistant.turn.gap`, the frozen plane_own
/// rows in the egress artifact).
#[derive(Debug, Clone, PartialEq)]
pub enum AssistantEffect {
    Gap {
        reason: Gap,
        conversation_id: Option<String>,
    },
    /// Execute one local-gateway call via the injected transport; feed
    /// the outcome back as [`AssistantInput::CallOutcome`]. This is the
    /// plane's ONE transport execution site (W2, pinned by the
    /// chat-wall suite).
    Call(ProviderRequest),
    /// `assistant.turn.sent` — RECORD's completed-turn summary; the
    /// reply and hints ride the effect (display-only; telemetry emits
    /// counts and labels derived from them, never the text).
    TurnSent {
        conversation_id: String,
        turn: u32,
        reply: String,
        hints: Vec<RecordedSuggestion>,
        hints_discarded: usize,
    },
    /// Count of context fields dropped at the gate this turn (a count,
    /// never content).
    ContextDropped { count: u64 },
}

/// The inputs. All time is virtual (`now_ms`); the turn nonce arrives
/// here so `step` stays RNG-free.
#[derive(Debug, Clone)]
pub enum AssistantInput {
    /// The user sent an assistant turn at `now_ms` with the typed
    /// context snapshot and a fresh 32-hex nonce.
    UserTurn {
        now_ms: u64,
        text: String,
        context: Vec<ContextField>,
        turn_nonce: String,
    },
    /// The transport outcome for the in-flight call.
    CallOutcome {
        conversation_id: String,
        turn: u32,
        outcome: Result<Vec<u8>, TransportFailure>,
    },
    /// A response arrived after its turn closed (late-discard path).
    LateResponse { conversation_id: String, turn: u32 },
}

/// The assistant-plane state. Pure data — no I/O, no clock, no RNG.
#[derive(Debug, Clone)]
pub struct AssistantState {
    pub caps: AssistantRuntimeCaps,
    pub armed: bool,
    pub phase: AssistantPhase,
    /// UTC day number the daily cap window counts.
    pub day: u64,
    pub calls_today: u32,
    /// UTC hour number the burst window counts.
    pub hour: u64,
    pub calls_this_hour: u32,
    pub conversation: Option<Conversation>,
    pub history: Vec<HistoryTurn>,
    /// Recently closed-with-timeout (conversation, turn) pairs (bounded)
    /// — the only late arrivals that may diagnose.
    timed_out: Vec<(String, u32)>,
}

fn utc_day(now_ms: u64) -> u64 {
    now_ms / 86_400_000
}

fn utc_hour(now_ms: u64) -> u64 {
    now_ms / 3_600_000
}

impl AssistantState {
    pub fn new(caps: AssistantRuntimeCaps, armed: bool, now_ms: u64) -> Self {
        Self {
            caps,
            armed,
            phase: AssistantPhase::Idle,
            day: utc_day(now_ms),
            calls_today: 0,
            hour: utc_hour(now_ms),
            calls_this_hour: 0,
            conversation: None,
            history: Vec::new(),
            timed_out: Vec::new(),
        }
    }

    fn close(&mut self) {
        self.phase = AssistantPhase::Idle;
    }

    fn conversation_id(&self) -> Option<String> {
        self.conversation.as_ref().map(|c| c.id.clone())
    }

    fn record_gap(
        &mut self,
        effects: &mut Vec<AssistantEffect>,
        reason: Gap,
        conversation_id: Option<String>,
    ) {
        if reason == Gap::Timeout {
            if let (Some(id), AssistantPhase::AwaitingCall { turn, .. }) =
                (conversation_id.clone(), &self.phase)
            {
                let turn = *turn;
                self.timed_out.retain(|t| t.0 != id);
                self.timed_out.push((id, turn));
                let len = self.timed_out.len();
                if len > 16 {
                    self.timed_out.drain(0..len - 16);
                }
            }
        }
        effects.push(AssistantEffect::Gap {
            reason,
            conversation_id,
        });
        self.close();
    }
}

/// The pure transition. Deterministic in `(state, input)` alone.
pub fn step(
    mut state: AssistantState,
    input: AssistantInput,
) -> (AssistantState, Vec<AssistantEffect>) {
    let mut effects = Vec::new();
    match input {
        AssistantInput::UserTurn {
            now_ms,
            text,
            context,
            turn_nonce,
        } => step_user_turn(&mut state, now_ms, text, context, turn_nonce, &mut effects),
        AssistantInput::CallOutcome {
            conversation_id,
            turn,
            outcome,
        } => step_call_outcome(&mut state, &conversation_id, turn, outcome, &mut effects),
        AssistantInput::LateResponse {
            conversation_id,
            turn,
        } => {
            // Diagnostic-only: permitted ONLY after a timeout gap for the
            // same (conversation, turn); every other late arrival is a
            // no-op discard (the gap was already recorded).
            if state
                .timed_out
                .iter()
                .any(|(id, t)| id == &conversation_id && *t == turn)
            {
                state
                    .timed_out
                    .retain(|(id, t)| !(id == &conversation_id && *t == turn));
                effects.push(AssistantEffect::Gap {
                    reason: Gap::Late,
                    conversation_id: Some(conversation_id),
                });
            }
        }
    }
    (state, effects)
}

fn step_user_turn(
    state: &mut AssistantState,
    now_ms: u64,
    text: String,
    context: Vec<ContextField>,
    turn_nonce: String,
    effects: &mut Vec<AssistantEffect>,
) {
    // Window rollovers: the UTC calendar day (midnight rollover
    // intended, pinned by test) and the UTC hour.
    let day = utc_day(now_ms);
    if day != state.day {
        state.day = day;
        state.calls_today = 0;
    }
    let hour = utc_hour(now_ms);
    if hour != state.hour {
        state.hour = hour;
        state.calls_this_hour = 0;
    }

    // IDLE gates (ADR-037 §3.7 diagram, first failure wins). The
    // provider-era `no_key`/`no_config` gates are GONE — arming is
    // hosting (the caller never constructs an unarmed machine with
    // `armed=true`).
    if !state.caps.enabled || !state.armed {
        state.record_gap(effects, Gap::Disabled, None);
        return;
    }
    if state.caps.max_calls_per_day == 0 || state.calls_today >= state.caps.max_calls_per_day {
        state.record_gap(effects, Gap::CapReached, state.conversation_id());
        return;
    }
    if state.caps.max_calls_per_hour == 0 || state.calls_this_hour >= state.caps.max_calls_per_hour
    {
        state.record_gap(effects, Gap::RateLimited, state.conversation_id());
        return;
    }

    // Conversation lifecycle: idle closes it (fresh turn budget next
    // time); the per-conversation turn cap then gates a STILL-ACTIVE
    // conversation only.
    let idle = state
        .conversation
        .as_ref()
        .is_some_and(|c| now_ms.saturating_sub(c.last_activity_ms) >= state.caps.idle_reset_ms);
    if idle {
        state.conversation = None;
    }
    if let Some(c) = &state.conversation {
        if state.caps.max_turns_per_conversation == 0
            || c.turns >= state.caps.max_turns_per_conversation
        {
            state.record_gap(effects, Gap::CapReached, state.conversation_id());
            return;
        }
    }

    // Open (or continue) the conversation. The conversation id is the
    // first 16 hex of the runner-injected nonce (RC-8's generator pin).
    let (conversation_id, turn) = match state.conversation.clone() {
        Some(c) => (c.id, c.turns + 1),
        None => {
            let id: String = turn_nonce.chars().take(16).collect();
            if id.len() != 16 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                // A malformed nonce is a caller-side defect: fail closed.
                state.record_gap(effects, Gap::EmptyAfterRedaction, None);
                return;
            }
            (id, 1)
        }
    };

    // BUILD: the typed context block through the ONE value-typed gate.
    let admitted = egress::admit_context(context);
    if admitted.dropped > 0 {
        effects.push(AssistantEffect::ContextDropped {
            count: admitted.dropped,
        });
    }

    // SCRUB: the user text through the Redactor net (keys, JWTs, Bearer,
    // hex runs >= 32) — the one free-text channel, scrubbed even though
    // it now only ever reaches the machine's own gateway (the same
    // discipline telemetry applies locally).
    let redactor = Redactor::default();
    let user_text = redactor.scrub_content(&text);
    if user_text.trim().is_empty() {
        state.record_gap(effects, Gap::EmptyAfterRedaction, Some(conversation_id));
        return;
    }

    // The request body: context + history + turn. History is bounded to
    // `history_turns_sent` and re-scrubbed (idempotent by construction).
    let history_value = |n: usize| -> serde_json::Value {
        let tail: Vec<_> = state
            .history
            .iter()
            .rev()
            .take(n)
            .rev()
            .flat_map(|turn| {
                [
                    serde_json::json!({"role": "user", "content": redactor.scrub_content(&turn.user)}),
                    serde_json::json!({"role": "assistant", "content": redactor.scrub_content(&turn.reply)}),
                ]
            })
            .collect();
        serde_json::Value::Array(tail)
    };
    let turn_value = serde_json::json!({
        "conversation_id": conversation_id,
        "turn": turn,
        "text": user_text,
    });
    let mut body = serde_json::json!({
        "context": admitted.body,
        "history": history_value(state.caps.history_turns_sent),
        "turn": turn_value,
    })
    .to_string();
    if body.len() > state.caps.max_request_bytes {
        // Context discipline yields: rebuild at ZERO history; if even
        // that is over the cap, the gap is `request_oversized` (§4.3)
        // and nothing is sent.
        body = serde_json::json!({
            "context": admitted.body,
            "history": history_value(0),
            "turn": turn_value,
        })
        .to_string();
        if body.len() > state.caps.max_request_bytes {
            state.record_gap(effects, Gap::RequestOversized, Some(conversation_id));
            return;
        }
    }
    // The choke-point re-scan on the FINAL serialized bytes (§3.5): the
    // context re-matches the frozen field set, the strings pass
    // scrub_content unchanged, the body is within the byte cap — else
    // nothing is sent.
    if egress::choke_point_rescan_assistant(&body, state.caps.max_request_bytes).is_err() {
        state.record_gap(effects, Gap::EmptyAfterRedaction, Some(conversation_id));
        return;
    }

    // CALL: consumes budget (calls INITIATED, not successes) and keeps
    // the conversation's activity clock. The conversation's COMPLETED
    // turn count is `turn - 1` until RECORD advances it.
    state.calls_today += 1;
    state.calls_this_hour += 1;
    state.conversation = Some(Conversation {
        id: conversation_id.clone(),
        turns: turn.saturating_sub(1),
        last_activity_ms: now_ms,
    });
    state.phase = AssistantPhase::AwaitingCall {
        conversation_id: conversation_id.clone(),
        turn,
        now_ms,
        user_text,
    };
    effects.push(AssistantEffect::Call(ProviderRequest {
        body,
        timeout_ms: state.caps.request_timeout_ms,
        max_completion_tokens: state.caps.max_completion_tokens,
        max_response_bytes: state.caps.max_response_bytes,
        system_prompt: Some(ASSISTANT_SYSTEM_PROMPT),
    }));
}

fn step_call_outcome(
    state: &mut AssistantState,
    conversation_id: &str,
    turn: u32,
    outcome: Result<Vec<u8>, TransportFailure>,
    effects: &mut Vec<AssistantEffect>,
) {
    let AssistantPhase::AwaitingCall {
        conversation_id: in_flight,
        turn: in_flight_turn,
        user_text,
        ..
    } = &state.phase
    else {
        return; // response after the turn closed: no-op discard
    };
    if in_flight.as_str() != conversation_id || *in_flight_turn != turn {
        return;
    }
    let user_text = user_text.clone();

    match outcome {
        Err(failure) => {
            let gap = match failure {
                TransportFailure::Deadline => Gap::Timeout,
                TransportFailure::HttpStatus(_) => Gap::HttpError,
                TransportFailure::ResponseOversized => Gap::ResponseOversized,
                TransportFailure::Network(_) => Gap::HttpError,
            };
            state.record_gap(effects, gap, Some(conversation_id.to_string()));
        }
        Ok(bytes) => {
            if bytes.len() > state.caps.max_response_bytes {
                state.record_gap(
                    effects,
                    Gap::ResponseOversized,
                    Some(conversation_id.to_string()),
                );
                return;
            }
            match parse_response(&bytes, conversation_id, turn) {
                Err(()) => {
                    // Bad JSON / unknown schema / echo mismatch / empty
                    // reply with no parseable hints: whole-body discard,
                    // no fabricated fallback text.
                    state.record_gap(effects, Gap::Schema, Some(conversation_id.to_string()));
                }
                Ok((reply, hints, hints_discarded)) => {
                    // RECORD: the completed exchange joins the bounded
                    // history; the conversation's turn count advances.
                    state.history.push(HistoryTurn {
                        user: user_text,
                        reply: reply.clone(),
                    });
                    let keep = state.caps.history_turns_sent;
                    if state.history.len() > keep {
                        let cut = state.history.len() - keep;
                        state.history.drain(0..cut);
                    }
                    if let Some(c) = &mut state.conversation {
                        c.turns = turn;
                    }
                    effects.push(AssistantEffect::TurnSent {
                        conversation_id: conversation_id.to_string(),
                        turn,
                        reply,
                        hints,
                        hints_discarded,
                    });
                    state.close();
                }
            }
        }
    }
}

/// PARSE (strict `advisory-assistant/v1` schema, first-failure-wins per
/// the §3.7 malformed table): `(reply, hints, hints_discarded)`.
/// Envelope failures ⇒ `Err(())` (whole-body discard, gap `schema`);
/// per-hint failures ⇒ discarded and counted, siblings parse.
fn parse_response(
    bytes: &[u8],
    conversation_id: &str,
    turn: u32,
) -> Result<(String, Vec<RecordedSuggestion>, usize), ()> {
    let parsed: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    let obj = parsed.as_object().ok_or(())?;
    if obj.get("schema").and_then(|s| s.as_str()) != Some("advisory-assistant/v1") {
        return Err(());
    }
    // RC-8 (reused): a response whose conversation_id or turn does not
    // echo the in-flight request is discarded whole.
    if obj.get("conversation_id").and_then(|s| s.as_str()) != Some(conversation_id) {
        return Err(());
    }
    if obj.get("turn").and_then(|t| t.as_u64()) != Some(u64::from(turn)) {
        return Err(());
    }
    let reply = obj
        .get("reply")
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_string();
    let mut hints = Vec::new();
    let mut hints_discarded = 0usize;
    if let Some(raw_hints) = obj.get("hints").and_then(|h| h.as_array()) {
        for raw in raw_hints {
            // §3.3's digest-plane-only rule: a model conversation must
            // not be able to mint tuning hints — that CLASS is discarded
            // and counted before any parsing; the reply still renders.
            let kind = raw.get("type").and_then(|t| t.as_str());
            if kind == Some("tuning_hint") {
                hints_discarded += 1;
                continue;
            }
            match parse_one_suggestion(raw) {
                Ok(hint) => hints.push(hint),
                Err(()) => hints_discarded += 1,
            }
        }
    }
    if reply.trim().is_empty() && hints.is_empty() {
        // No fabricated fallback text (§3.7 malformed table).
        return Err(());
    }
    Ok((reply, hints, hints_discarded))
}

// ---------------------------------------------------------------------------
// The plane handle (the user-triggered execution site — W2's one and
// only entry class)
// ---------------------------------------------------------------------------

/// One assistant turn's outcome, as the surface renders it.
#[derive(Debug, Clone, PartialEq)]
pub enum TurnOutcome {
    Reply {
        conversation_id: String,
        turn: u32,
        reply: String,
        hints: Vec<RecordedSuggestion>,
        hints_discarded: usize,
    },
    Gap {
        reason: Gap,
        conversation_id: Option<String>,
    },
}

/// The armed assistant plane: holds the loopback-pinned transport and
/// the pure machine's state. [`AssistantPlane::run_turn`] is the ONLY
/// assistant execution site of [`AdvisoryTransport::send`] (W2's
/// enumerated call sites).
pub struct AssistantPlane {
    transport: Arc<dyn AdvisoryTransport>,
    state: std::sync::Mutex<AssistantState>,
}

impl AssistantPlane {
    /// Arms the assistant plane for a data dir. `backing` is the
    /// hosted-model fact pair (the running node's gateway address +
    /// the hosted profile) — present while hosting, absent otherwise.
    /// `transport_override` is a TEST seam (the redaction/cadence
    /// suites inject a counting double that STANDS IN for the hosted
    /// model — never a real engine); production passes `None` and gets
    /// the pinned loopback adapter. Returns the plane plus the honest
    /// static-floor gap when the plane is absent (`not_hosting` |
    /// `disabled` | `no_config`).
    pub fn spawn(
        data_dir: &Path,
        backing: Option<&HostedBacking>,
        transport_override: Option<Arc<dyn AdvisoryTransport>>,
    ) -> (Option<Self>, Gap) {
        let (advisory, arm_result) = assistant_arm(data_dir, backing);
        match arm_result {
            AssistantArm::Disabled => return (None, Gap::Disabled),
            // A malformed advisory.json fails closed even for the test
            // seam — the caps would be guesses.
            AssistantArm::Static {
                reason: Gap::NoConfig,
            } => return (None, Gap::NoConfig),
            // Without a model backing there is no plane — unless the
            // TEST seam supplies the double that stands in for the
            // hosted model.
            AssistantArm::Static {
                reason: Gap::NotHosting,
            } if transport_override.is_none() => return (None, Gap::NotHosting),
            _ => {}
        }
        let transport: Arc<dyn AdvisoryTransport> = match transport_override {
            Some(double) => double,
            None => {
                let Some(backing) = backing else {
                    return (None, Gap::NotHosting);
                };
                match LocalGatewayTransport::new(backing.gateway_addr, &backing.profile) {
                    Ok(adapter) => Arc::new(adapter),
                    // The node's bound address is loopback by
                    // construction; a non-loopback backing is a
                    // composition defect — fail closed to the static
                    // floor with the honest label.
                    Err(_) => return (None, Gap::NoConfig),
                }
            }
        };
        let caps = AssistantRuntimeCaps {
            enabled: true,
            max_calls_per_day: advisory.assistant.max_calls_per_day,
            max_calls_per_hour: advisory.assistant.max_calls_per_hour,
            max_turns_per_conversation: advisory.assistant.max_turns_per_conversation,
            idle_reset_ms: advisory.assistant.idle_reset_ms,
            history_turns_sent: advisory.assistant.history_turns_sent as usize,
            max_request_bytes: advisory.assistant.max_request_bytes,
            max_completion_tokens: advisory.assistant.max_completion_tokens,
            request_timeout_ms: advisory.assistant.request_timeout_ms,
            // ADR-037 §3.7: the response cap is 65 536 — never the
            // request cap.
            max_response_bytes: MAX_RESPONSE_BYTES,
        };
        let now = system_now_ms();
        let plane = Self {
            transport,
            state: std::sync::Mutex::new(AssistantState::new(caps, true, now)),
        };
        (Some(plane), Gap::NotHosting)
    }

    /// Runs one user-triggered assistant turn end to end (BUILD → SCRUB
    /// → CALL → PARSE → RECORD), emitting only the frozen
    /// `assistant.turn.*` rows (counts and labels). NO in-turn retry:
    /// a failed turn is one gap; the next user turn is the retry.
    pub async fn run_turn(
        &self,
        telemetry: &Telemetry,
        user_text: &str,
        context: Vec<ContextField>,
    ) -> TurnOutcome {
        let now = system_now_ms();
        let input = AssistantInput::UserTurn {
            now_ms: now,
            text: user_text.to_string(),
            context,
            turn_nonce: modelswarm_identity::new_nonce(),
        };
        let (state, effects) = {
            let mut guard = self.state.lock().unwrap();
            let current = std::mem::replace(
                &mut *guard,
                AssistantState::new(AssistantRuntimeCaps::armed_defaults(), false, now),
            );
            let (state, effects) = step(current, input);
            *guard = state.clone();
            (state, effects)
        };
        let mut outcome: Option<TurnOutcome> = None;
        for effect in effects {
            match effect {
                AssistantEffect::Gap {
                    reason,
                    conversation_id,
                } => {
                    emit_gap(telemetry, reason, conversation_id.clone());
                    if outcome.is_none() {
                        outcome = Some(TurnOutcome::Gap {
                            reason,
                            conversation_id,
                        });
                    }
                }
                AssistantEffect::ContextDropped { count } => {
                    // Counted at the gate — a count, never content.
                    telemetry.info(
                        "assistant.turn.gap",
                        &[
                            ("reason", "context_dropped"),
                            ("dropped", &count.to_string()),
                        ],
                    );
                }
                AssistantEffect::Call(request) => {
                    let AssistantPhase::AwaitingCall {
                        conversation_id,
                        turn,
                        ..
                    } = &state.phase
                    else {
                        continue;
                    };
                    let (conversation_id, turn) = (conversation_id.clone(), *turn);
                    // The deadline wraps the injected transport (a late
                    // reply is a no-op discard; the machine's `late`
                    // diagnostic fires from the timed_out window).
                    let result = tokio::time::timeout(
                        std::time::Duration::from_millis(request.timeout_ms),
                        self.transport.send(&request),
                    )
                    .await
                    .map_err(|_| TransportFailure::Deadline)
                    .and_then(|r| r);
                    let outcome_input = AssistantInput::CallOutcome {
                        conversation_id: conversation_id.clone(),
                        turn,
                        outcome: result,
                    };
                    let outcome_effects = {
                        let mut guard = self.state.lock().unwrap();
                        let current = std::mem::replace(
                            &mut *guard,
                            AssistantState::new(AssistantRuntimeCaps::armed_defaults(), false, now),
                        );
                        let (state, effects) = step(current, outcome_input);
                        *guard = state;
                        effects
                    };
                    for e in outcome_effects {
                        match e {
                            AssistantEffect::TurnSent {
                                conversation_id,
                                turn,
                                reply,
                                hints,
                                hints_discarded,
                            } => {
                                telemetry.info(
                                    "assistant.turn.sent",
                                    &[
                                        ("conversation_id", conversation_id.as_str()),
                                        ("turn", &turn.to_string()),
                                        ("hints", &hints.len().to_string()),
                                        ("hints_discarded", &hints_discarded.to_string()),
                                    ],
                                );
                                outcome = Some(TurnOutcome::Reply {
                                    conversation_id,
                                    turn,
                                    reply,
                                    hints,
                                    hints_discarded,
                                });
                            }
                            AssistantEffect::Gap {
                                reason,
                                conversation_id,
                            } => {
                                emit_gap(telemetry, reason, conversation_id.clone());
                                if outcome.is_none() {
                                    outcome = Some(TurnOutcome::Gap {
                                        reason,
                                        conversation_id,
                                    });
                                }
                            }
                            _ => {}
                        }
                    }
                }
                AssistantEffect::TurnSent { .. } => {
                    // TurnSent is produced by the CallOutcome step, never
                    // the UserTurn step (there is no call-free turn).
                }
            }
        }
        outcome.unwrap_or(TurnOutcome::Gap {
            reason: Gap::EmptyAfterRedaction,
            conversation_id: None,
        })
    }

    /// Resets the conversation (the `assistant_reset` IPC): closes the
    /// open conversation and clears the local history. Never touches
    /// caps, budget windows, or any other plane.
    pub fn reset(&self) {
        if let Ok(mut guard) = self.state.lock() {
            guard.conversation = None;
            guard.history.clear();
        }
    }
}

fn emit_gap(telemetry: &Telemetry, reason: Gap, conversation_id: Option<String>) {
    telemetry.warn(
        "assistant.turn.gap",
        &[
            ("reason", reason.as_str()),
            (
                "conversation_id",
                conversation_id.as_deref().unwrap_or("none"),
            ),
        ],
    );
}

fn system_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    fn armed(now_ms: u64) -> AssistantState {
        AssistantState::new(AssistantRuntimeCaps::armed_defaults(), true, now_ms)
    }

    fn turn(now_ms: u64, text: &str) -> AssistantInput {
        AssistantInput::UserTurn {
            now_ms,
            text: text.to_string(),
            context: vec![ContextField {
                name: "hw.logical_cpus".to_string(),
                value: egress::ContextValue::Int(16),
            }],
            turn_nonce: NONCE.to_string(),
        }
    }

    fn in_flight(s: &AssistantState) -> (String, u32) {
        match &s.phase {
            AssistantPhase::AwaitingCall {
                conversation_id,
                turn,
                ..
            } => (conversation_id.clone(), *turn),
            _ => panic!("expected a call in flight"),
        }
    }

    fn ok_body(conversation_id: &str, turn: u32, reply: &str) -> Vec<u8> {
        format!(
            r#"{{"schema":"advisory-assistant/v1","conversation_id":"{conversation_id}","turn":{turn},"reply":"{reply}","hints":[]}}"#
        )
        .into_bytes()
    }

    fn backing() -> HostedBacking {
        HostedBacking {
            gateway_addr: "127.0.0.1:11435".parse().unwrap(),
            profile: "msp1:hosted".to_string(),
        }
    }

    #[test]
    fn golden_assistant_defaults_pin_adr037_section_3_4() {
        // ADR-037 §4.4 item (8) extension: the nine §3.4 defaults.
        let caps = AssistantRuntimeCaps::armed_defaults();
        assert_eq!(caps.max_calls_per_day, 300);
        assert_eq!(caps.max_calls_per_hour, 60);
        assert_eq!(caps.max_turns_per_conversation, 40);
        assert_eq!(caps.idle_reset_ms, 900_000);
        assert_eq!(caps.history_turns_sent, 12);
        assert_eq!(caps.max_request_bytes, 49_152);
        assert_eq!(caps.max_completion_tokens, 1024);
        assert_eq!(caps.request_timeout_ms, 45_000);
        assert_eq!(caps.max_response_bytes, 65_536);
    }

    #[test]
    fn a_turn_builds_scrubs_calls_and_records() {
        let s = armed(1_000);
        let (s, effects) = step(s, turn(1_000, "which model fits my machine?"));
        let (conversation_id, turn_no) = in_flight(&s);
        assert_eq!(conversation_id, "0123456789abcdef");
        assert_eq!(turn_no, 1);
        assert_eq!(s.calls_today, 1);
        assert_eq!(s.calls_this_hour, 1);
        match &effects[0] {
            AssistantEffect::Call(request) => {
                let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
                assert_eq!(body["context"]["hw.logical_cpus"], 16);
                assert_eq!(body["turn"]["text"], "which model fits my machine?");
                assert_eq!(body["turn"]["conversation_id"], "0123456789abcdef");
                assert_eq!(request.timeout_ms, 45_000);
                assert_eq!(request.max_completion_tokens, 1024);
                assert_eq!(request.system_prompt, Some(ASSISTANT_SYSTEM_PROMPT));
            }
            other => panic!("{other:?}"),
        }
        let (s2, effects) = step(
            s,
            AssistantInput::CallOutcome {
                conversation_id: conversation_id.clone(),
                turn: 1,
                outcome: Ok(ok_body(
                    &conversation_id,
                    1,
                    "the shortlist is hardware-scored",
                )),
            },
        );
        assert_eq!(s2.phase, AssistantPhase::Idle);
        assert_eq!(s2.history.len(), 1);
        assert_eq!(s2.history[0].reply, "the shortlist is hardware-scored");
        assert_eq!(s2.conversation.as_ref().unwrap().turns, 1);
        assert!(matches!(
            &effects[0],
            AssistantEffect::TurnSent { turn: 1, reply, .. }
                if reply == "the shortlist is hardware-scored"
        ));
        // The SECOND turn continues the same conversation.
        let (s3, effects) = step(s2, turn(2_000, "and why is the 27B partial?"));
        assert_eq!(in_flight(&s3).0, "0123456789abcdef");
        assert_eq!(in_flight(&s3).1, 2);
        let body = match &effects[0] {
            AssistantEffect::Call(request) => request.body.clone(),
            other => panic!("{other:?}"),
        };
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        let history = body["history"].as_array().unwrap();
        assert_eq!(history.len(), 2, "one user+one assistant entry");
        assert_eq!(history[0]["role"], "user");
        assert_eq!(history[1]["role"], "assistant");
        let _ = s3;
    }

    #[test]
    fn idle_reset_opens_a_fresh_conversation() {
        let s = armed(1_000);
        let (s, _) = step(s, turn(1_000, "hello"));
        let (s, _) = step(
            s,
            AssistantInput::CallOutcome {
                conversation_id: "0123456789abcdef".into(),
                turn: 1,
                outcome: Ok(ok_body("0123456789abcdef", 1, "hi")),
            },
        );
        // 15 minutes later: a NEW conversation id (different nonce), turn 1.
        let (s2, effects) = step(
            s,
            AssistantInput::UserTurn {
                now_ms: 1_000 + 900_000,
                text: "back again".into(),
                context: vec![],
                turn_nonce: "ffffffffffffffffffffffffffffffff".into(),
            },
        );
        let (id, turn_no) = in_flight(&s2);
        assert_eq!(id, "ffffffffffffffff");
        assert_eq!(turn_no, 1, "idle reset = fresh turn budget");
        let _ = id;
        match &effects[0] {
            AssistantEffect::Call(request) => {
                let body: serde_json::Value = serde_json::from_str(&request.body).unwrap();
                // History is the PLANE's bounded memory (the last N
                // completed turns, §3.5) — the idle reset closes the
                // CONVERSATION (fresh turn budget), it does not wipe
                // history; the bound keeps it small either way.
                assert_eq!(
                    body["history"].as_array().map(Vec::len),
                    Some(2),
                    "bounded history persists across the idle reset"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn conversation_turn_cap_gates_an_active_conversation() {
        let mut s = armed(0);
        s.caps.max_turns_per_conversation = 2;
        for t in 1..=2u32 {
            let (s2, effects) = step(s, turn(u64::from(t) * 1_000, "q"));
            let id = in_flight(&s2).0;
            let (s3, _) = step(
                s2,
                AssistantInput::CallOutcome {
                    conversation_id: id.clone(),
                    turn: t,
                    outcome: Ok(ok_body(&id, t, "a")),
                },
            );
            s = s3;
            let _ = effects;
        }
        // Turn 3 in the SAME conversation: cap_reached, no call.
        let (_, effects) = step(s, turn(3_000, "third"));
        assert!(matches!(
            effects.as_slice(),
            [AssistantEffect::Gap {
                reason: Gap::CapReached,
                ..
            }]
        ));
    }

    #[test]
    fn transport_failures_map_to_gaps_and_consume_budget() {
        for (failure, gap) in [
            (TransportFailure::Deadline, Gap::Timeout),
            (TransportFailure::HttpStatus(500), Gap::HttpError),
            (TransportFailure::HttpStatus(302), Gap::HttpError),
            (TransportFailure::HttpStatus(503), Gap::HttpError),
            (TransportFailure::Network("dial".into()), Gap::HttpError),
        ] {
            let s = armed(1_000);
            let (s, _) = step(s, turn(1_000, "q"));
            assert_eq!(s.calls_today, 1, "the failed call consumed budget");
            let (s2, effects) = step(
                s,
                AssistantInput::CallOutcome {
                    conversation_id: "0123456789abcdef".into(),
                    turn: 1,
                    outcome: Err(failure),
                },
            );
            assert_eq!(s2.phase, AssistantPhase::Idle);
            assert!(matches!(
                effects.as_slice(),
                [AssistantEffect::Gap { reason: g, .. }] if *g == gap
            ));
        }
    }

    #[test]
    fn hourly_burst_bound_is_rate_limited() {
        let mut s = armed(0);
        s.caps.max_calls_per_hour = 2;
        // Two calls in hour 0 (each completes).
        for t in 1..=2u32 {
            let (s2, _) = step(s.clone(), turn(u64::from(t), "q"));
            let (s3, _) = step(
                s2,
                AssistantInput::CallOutcome {
                    conversation_id: "0123456789abcdef".into(),
                    turn: t,
                    outcome: Ok(ok_body("0123456789abcdef", t, "a")),
                },
            );
            s = s3;
        }
        // A third call in the SAME hour: rate_limited.
        let (_, effects) = step(s, turn(3_000, "third"));
        assert!(matches!(
            effects.as_slice(),
            [AssistantEffect::Gap {
                reason: Gap::RateLimited,
                ..
            }]
        ));
        // After the UTC hour rolls over: allowed again.
        let s = armed(3_600_000);
        let (s2, effects) = step(s, turn(3_600_500, "next hour"));
        assert!(matches!(effects.as_slice(), [AssistantEffect::Call(_)]));
        assert_eq!(s2.calls_this_hour, 1);
    }

    #[test]
    fn utc_midnight_rolls_the_daily_window() {
        let midnight = 10 * 86_400_000u64;
        let mut s = armed(midnight - 2_000);
        s.caps.max_calls_per_day = 1;
        let (s, _) = step(s, turn(midnight - 2_000, "q"));
        let (s, effects) = step(s, turn(midnight - 1_000, "second"));
        assert!(matches!(
            effects.as_slice(),
            [AssistantEffect::Gap {
                reason: Gap::CapReached,
                ..
            }]
        ));
        let (s2, effects) = step(s, turn(midnight + 1_000, "after midnight"));
        assert!(matches!(effects.as_slice(), [AssistantEffect::Call(_)]));
        assert_eq!(s2.calls_today, 1, "the new day's first call");
        assert_eq!(s2.day, 10);
    }

    #[test]
    fn oversize_request_fails_as_request_oversized_even_at_zero_history() {
        let mut s = armed(1_000);
        s.caps.max_request_bytes = 32; // far too small for any body
        let (_, effects) = step(s, turn(1_000, "q"));
        assert!(
            matches!(
                effects.as_slice(),
                [AssistantEffect::Gap {
                    reason: Gap::RequestOversized,
                    ..
                }]
            ),
            "the §4.3 gap fires when even a zero-history body cannot fit"
        );
    }

    #[test]
    fn empty_after_scrub_never_sends() {
        let s = armed(1_000);
        // sk- shaped text scrubs to placeholders; a text that is ONLY
        // redactable material must not send a hollow turn.
        let (_, effects) = step(s, turn(1_000, ""));
        assert!(matches!(
            effects.as_slice(),
            [AssistantEffect::Gap {
                reason: Gap::EmptyAfterRedaction,
                ..
            }]
        ));
    }

    #[test]
    fn malformed_envelopes_discard_whole_body() {
        let s = armed(1_000);
        let (s, _) = step(s, turn(1_000, "q"));
        for bad in [
            b"{nope".to_vec(),
            br#"{"schema":"advisory-suggestion/v1","conversation_id":"0123456789abcdef","turn":1,"reply":"x"}"#.to_vec(),
            // Foreign conversation_id echo.
            br#"{"schema":"advisory-assistant/v1","conversation_id":"aaaabbbbccccdddd","turn":1,"reply":"x","hints":[]}"#.to_vec(),
            // Wrong turn echo.
            br#"{"schema":"advisory-assistant/v1","conversation_id":"0123456789abcdef","turn":7,"reply":"x","hints":[]}"#.to_vec(),
            // Empty reply with no parseable hints: schema (no fabricated
            // fallback text).
            br#"{"schema":"advisory-assistant/v1","conversation_id":"0123456789abcdef","turn":1,"reply":"","hints":[]}"#.to_vec(),
        ] {
            let (s2, effects) = step(
                s.clone(),
                AssistantInput::CallOutcome {
                    conversation_id: "0123456789abcdef".into(),
                    turn: 1,
                    outcome: Ok(bad),
                },
            );
            assert_eq!(s2.phase, AssistantPhase::Idle);
            assert!(
                matches!(effects.as_slice(), [AssistantEffect::Gap { reason: Gap::Schema, .. }]),
                "envelope failure must discard whole body"
            );
        }
    }

    #[test]
    fn response_over_shared_cap_is_response_oversized() {
        let s = armed(1_000);
        let (s, _) = step(s, turn(1_000, "q"));
        let huge = vec![b'x'; MAX_RESPONSE_BYTES + 1];
        let (_, effects) = step(
            s,
            AssistantInput::CallOutcome {
                conversation_id: "0123456789abcdef".into(),
                turn: 1,
                outcome: Ok(huge),
            },
        );
        assert!(matches!(
            effects.as_slice(),
            [AssistantEffect::Gap {
                reason: Gap::ResponseOversized,
                ..
            }]
        ));
    }

    #[test]
    fn tuning_hint_class_is_discarded_and_counted_the_reply_renders() {
        // §3.3's digest-plane-only rule + §3.7's malformed table: an
        // assistant reply can NEVER mint a tuning hint.
        let s = armed(1_000);
        let (s, _) = step(s, turn(1_000, "q"));
        let body = br#"{"schema":"advisory-assistant/v1","conversation_id":"0123456789abcdef","turn":1,"reply":"advice text","hints":[
            {"type":"tuning_hint","target":"fleet","confidence":"high","hint":{"MSP_SHADOW_QUEUE_CAP_MS":99999.0},"rationale":"must not mint"},
            {"type":"not_a_type","target":"fleet","confidence":"low","rationale":"unknown"},
            {"type":"catalog_note","target":"fleet","confidence":"low","rationale":"fine"},
            {"type":"digest","target":"fleet","confidence":"ultra","rationale":"bad confidence"}
        ]}"#
        .to_vec();
        let (s2, effects) = step(
            s,
            AssistantInput::CallOutcome {
                conversation_id: "0123456789abcdef".into(),
                turn: 1,
                outcome: Ok(body),
            },
        );
        assert!(matches!(
            &effects[0],
            AssistantEffect::TurnSent { reply, hints, hints_discarded, .. }
                if reply == "advice text" && hints.len() == 1 && *hints_discarded == 3
        ));
        assert_eq!(
            s2.history[0].reply, "advice text",
            "the reply still records"
        );
    }

    #[test]
    fn late_fires_only_after_timeout_for_the_same_turn() {
        let s = armed(1_000);
        let (s, _) = step(s, turn(1_000, "q"));
        let (s, _) = step(
            s,
            AssistantInput::CallOutcome {
                conversation_id: "0123456789abcdef".into(),
                turn: 1,
                outcome: Err(TransportFailure::Deadline),
            },
        );
        let (s, effects) = step(
            s,
            AssistantInput::LateResponse {
                conversation_id: "0123456789abcdef".into(),
                turn: 1,
            },
        );
        assert!(matches!(
            effects.as_slice(),
            [AssistantEffect::Gap {
                reason: Gap::Late,
                ..
            }]
        ));
        // Twice-late: no-op.
        let (_, effects) = step(
            s,
            AssistantInput::LateResponse {
                conversation_id: "0123456789abcdef".into(),
                turn: 1,
            },
        );
        assert!(effects.is_empty());
    }

    #[test]
    fn history_is_bounded_to_history_turns_sent() {
        let mut s = armed(0);
        s.caps.history_turns_sent = 2;
        for t in 1..=5u32 {
            let (s2, _) = step(s, turn(u64::from(t) * 1_000, &format!("q{t}")));
            let (s3, _) = step(
                s2,
                AssistantInput::CallOutcome {
                    conversation_id: "0123456789abcdef".into(),
                    turn: t,
                    outcome: Ok(ok_body("0123456789abcdef", t, "a")),
                },
            );
            s = s3;
        }
        assert_eq!(s.history.len(), 2);
        assert_eq!(s.history[0].user, "q4");
        assert_eq!(s.history[1].user, "q5");
    }

    /// ADR-037 §4.4 item (12): for any adversarial schedule, the caps
    /// hold — calls per UTC day <= 300, per UTC hour <= 60, and the
    /// conversation turn cap with idle reset bounds per-conversation
    /// turns; failures consume budget; no in-turn retry (each user turn
    /// produces at most ONE Call effect).
    #[test]
    fn adversarial_turn_flood_never_beats_caps_on_the_virtual_clock() {
        let mut s = armed(0);
        let mut calls = 0u64;
        let mut per_day: BTreeMap<u64, u64> = BTreeMap::new();
        let mut per_hour: BTreeMap<u64, u64> = BTreeMap::new();
        let mut seed = 0x9E3779B97F4A7C15u64;
        let mut now = 0u64;
        for i in 0..20_000 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            now += seed % 400_000; // sometimes sub-second, sometimes hours
            let text = format!("q{i}");
            let (s2, effects) = step(s, turn(now, &text));
            s = s2;
            let mut calls_this_input = 0;
            for effect in &effects {
                if let AssistantEffect::Call(_) = effect {
                    calls += 1;
                    calls_this_input += 1;
                    *per_day.entry(utc_day(now)).or_insert(0) += 1;
                    *per_hour.entry(utc_hour(now)).or_insert(0) += 1;
                }
            }
            assert!(
                calls_this_input <= 1,
                "no in-turn retry: one user turn, at most one call"
            );
            if calls_this_input == 1 {
                let (id, turn_no) = in_flight(&s);
                // Feed an outcome — adversarially failing: budget is
                // consumed, no retry this turn.
                let failure = if i % 3 == 0 {
                    TransportFailure::HttpStatus(503)
                } else {
                    TransportFailure::Deadline
                };
                let (s3, _) = step(
                    s,
                    AssistantInput::CallOutcome {
                        conversation_id: id,
                        turn: turn_no,
                        outcome: Err(failure),
                    },
                );
                s = s3;
                assert_eq!(s.phase, AssistantPhase::Idle);
            }
        }
        assert!(calls > 300, "the sweep must exercise calls ({calls})");
        for (day, count) in per_day {
            assert!(count <= 300, "day {day} saw {count} calls");
        }
        for (hour, count) in per_hour {
            assert!(count <= 60, "hour {hour} saw {count} calls");
        }
    }

    /// ADR-037 §4.4 item (11), node half: the user text is scrubbed
    /// before it is sent and the sent body passes `scrub_content`
    /// unchanged (the choke-point re-scan enforces it).
    #[test]
    fn adversarial_user_text_is_scrubbed_in_the_sent_body() {
        let redactor = Redactor::default();
        // The fake-key literals are concat!-split so the CI leak-guard
        // grep (`sk-<32 hex>` over tracked files) never sees them while
        // the runtime shape stays exactly key-like.
        for hostile in [
            concat!(
                "my key is sk-",
                "0123456789abcdef0123456789abcdef",
                " use it"
            ),
            "bearer abcdef0123456789abcdef0123456789 here",
            "jwt eyJhbGciOiJIUzI1NiJ9.e30.abcDEF0123456789 token",
            "hash 0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            let s = armed(1_000);
            let (s, effects) = step(s, turn(1_000, hostile));
            let _ = s;
            let body = match &effects[0] {
                AssistantEffect::Call(request) => request.body.clone(),
                other => panic!("{other:?}"),
            };
            assert!(
                redactor.scrub_content(&body) == body,
                "the sent body must already be scrubbed"
            );
            assert!(
                !body.contains(concat!("sk-", "0123456789abcdef0123456789abcdef")),
                "the raw key-shaped text never leaves"
            );
            // And a canary-shaped transcript marker is nowhere in the
            // body (the context block has no field that could carry it).
            assert!(!body.contains("CANARY"));
        }
    }

    /// The 2026-10-15 arming postures: the shipped default (no
    /// advisory.json, `assistant.enabled` on since the collapse) plus
    /// no hosting is the honest `not_hosting` static floor; hosting
    /// arms; an explicit opt-out is `disabled`; a malformed file is
    /// `no_config` — there is NO `no_key` path anymore (no key exists).
    #[test]
    fn arming_is_hosted_model_vs_static_floor() {
        let dir = tempfile::tempdir().unwrap();
        // No advisory.json + no hosting: the static floor with the
        // honest not_hosting label (the shipped default posture).
        let (_, arm) = assistant_arm(dir.path(), None);
        assert_eq!(
            arm,
            AssistantArm::Static {
                reason: Gap::NotHosting
            }
        );
        // Enabled + HOSTING: armed over the machine's own backing.
        std::fs::write(
            dir.path()
                .join(crate::advisory::config::ADVISORY_CONFIG_FILE),
            r#"{"assistant.enabled":true}"#,
        )
        .unwrap();
        let (_, arm) = assistant_arm(dir.path(), Some(&backing()));
        assert_eq!(arm, AssistantArm::Hosted);
        // Enabled but NOT hosting: the honest not_hosting floor.
        let (_, arm) = assistant_arm(dir.path(), None);
        assert_eq!(
            arm,
            AssistantArm::Static {
                reason: Gap::NotHosting
            }
        );
        // A malformed advisory.json: fail closed, never a guess.
        std::fs::write(
            dir.path()
                .join(crate::advisory::config::ADVISORY_CONFIG_FILE),
            "{bad",
        )
        .unwrap();
        let (_, arm) = assistant_arm(dir.path(), Some(&backing()));
        assert_eq!(
            arm,
            AssistantArm::Static {
                reason: Gap::NoConfig
            }
        );
        // And an OLD-ERA file (provider rows, enabled=true) parses and
        // arms over the hosted backing — the retired rows are inert.
        std::fs::write(
            dir.path().join(crate::advisory::config::ADVISORY_CONFIG_FILE),
            r#"{"enabled":true,"assistant.enabled":true,"endpoint_url":"https://old.invalid","model":"DeepSeek-V4.1-Flash","key_file":"C:/old.txt"}"#,
        )
        .unwrap();
        let (_, arm) = assistant_arm(dir.path(), Some(&backing()));
        assert_eq!(arm, AssistantArm::Hosted);
    }

    /// The spawn seam end to end over a counting double: enabled +
    /// double-backed = a live plane; not hosting without a double = the
    /// static floor with `not_hosting`.
    #[tokio::test]
    async fn spawn_arms_over_the_double_and_degrades_to_not_hosting() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path()
                .join(crate::advisory::config::ADVISORY_CONFIG_FILE),
            r#"{"assistant.enabled":true}"#,
        )
        .unwrap();
        let double = Arc::new(super::super::transport::CountingTransport::assistant_echo(
            "hosted advice".into(),
        ));
        let (plane, gap) = AssistantPlane::spawn(
            dir.path(),
            None,
            Some(double.clone() as Arc<dyn AdvisoryTransport>),
        );
        assert_eq!(
            gap.as_str(),
            "not_hosting",
            "spawn reports no degrade while armed"
        );
        let plane = plane.expect("the plane arms over the double");
        let (telemetry, _sink) = modelswarm_telemetry::Telemetry::memory();
        let outcome = plane.run_turn(&telemetry, "which model?", vec![]).await;
        assert!(matches!(outcome, TurnOutcome::Reply { .. }));
        assert_eq!(double.count(), 1, "the hosted-model double answered");

        // Without hosting and without a double: the static floor.
        let (plane, gap) = AssistantPlane::spawn(dir.path(), None, None);
        assert!(plane.is_none());
        assert_eq!(gap.as_str(), "not_hosting");
        // Disabled master switch: silent static floor.
        std::fs::write(
            dir.path()
                .join(crate::advisory::config::ADVISORY_CONFIG_FILE),
            r#"{"assistant.enabled":false}"#,
        )
        .unwrap();
        let (plane, gap) = AssistantPlane::spawn(dir.path(), Some(&backing()), None);
        assert!(plane.is_none());
        assert_eq!(gap.as_str(), "disabled");
    }
}
