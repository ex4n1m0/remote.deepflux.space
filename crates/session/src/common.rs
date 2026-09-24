//! Shared vocabulary for both state machines: configuration, actions,
//! timers, and the bounded dedupe log.

use std::collections::VecDeque;

use protocol::signaling::{
    DeviceId, MessageId, SIGNALING_PROTOCOL_VERSION, SessionId, SignalingBody, SignalingEnvelope,
};

/// Tunables for both machines. Timeouts are in logical milliseconds supplied
/// by the caller's virtual or real clock — the machines never read a clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    /// Controller: `connect_request` sent → `accept`/`reject` received.
    pub request_timeout_ms: u64,
    /// Host: consent prompt shown → user decision. The prompt auto-rejects
    /// after this.
    pub consent_timeout_ms: u64,
    /// Both: session accepted/answer exchanged → data channel open.
    pub connect_timeout_ms: u64,
    /// Presence heartbeat period while `Online`/`Connected`. The runtime
    /// raises `HeartbeatDue` on this cadence.
    pub heartbeat_period_ms: u64,
    /// Capacity of the bounded duplicate-`message_id` log (invariant 3).
    pub dedupe_capacity: usize,
    /// Reconnect attempt policy. **Placeholder for M5**: the MVP state
    /// machines never auto-reconnect; the user re-initiates. The struct
    /// exists so M5 can wire a real policy without changing the machines'
    /// signatures.
    pub reconnect: ReconnectPolicy,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            request_timeout_ms: 10_000,
            consent_timeout_ms: 30_000,
            connect_timeout_ms: 10_000,
            heartbeat_period_ms: 15_000,
            dedupe_capacity: 256,
            reconnect: ReconnectPolicy::default(),
        }
    }
}

/// Placeholder reconnect policy (M5 wires real behavior). MVP default is
/// zero automatic attempts — reconnect is an explicit user action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconnectPolicy {
    pub max_attempts: u32,
    pub backoff_base_ms: u64,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 0,
            backoff_base_ms: 1_000,
        }
    }
}

/// Timers a machine may schedule. The runtime fires the matching `*Timeout`
/// / `HeartbeatDue` event at `fire_at_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerId {
    /// Host: awaiting the consent decision.
    HostConsent,
    /// Host: accepted → data channel open.
    HostConnect,
    /// Controller: connect_request → accept/reject.
    ControllerRequest,
    /// Controller: accept → data channel open.
    ControllerConnect,
}

/// Why a session ended (local observable; also drives UX copy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectCause {
    User,
    Peer,
    Timeout,
    Rejected(protocol::signaling::RejectReason),
    Canceled,
    Collision,
    TransportError,
}

/// One unit of work the runtime must perform after a transition. Machines
/// never perform I/O themselves.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    /// Hand this envelope to the signaling client. Fully formed — the runtime
    /// only transports it.
    Send(SignalingEnvelope),
    ScheduleTimer {
        id: TimerId,
        fire_at_ms: u64,
    },
    CancelTimer {
        id: TimerId,
    },
    /// Host: show the accept/reject prompt for this controller.
    PromptConsent {
        controller_device_id: DeviceId,
        session_id: SessionId,
    },
    /// Host runtime: build an SDP answer for this offer (webrtc-rs lives
    /// behind the `Transport` trait in `transport-webrtc`; M2 wires this).
    ComposeAnswer {
        offer_sdp: String,
    },
    /// Controller runtime: build an SDP offer (M2 wires this).
    ComposeOffer,
    /// Hand a trickled ICE candidate to the local transport. No state change;
    /// listed as an action so the runtime stays dumb. `sdp_mid` is the JSEP
    /// string mid (signaling protocol version 1, QA F9).
    ForwardIce {
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
    },
    /// Host: start/stop the capture→encode→send pipeline.
    StartStreaming,
    StopStreaming,
    /// Controller: start/stop the receive→decode→present pipeline.
    StartRendering,
    StopRendering,
    /// Observable milestone for UI and tests.
    SessionEstablished {
        session_id: SessionId,
    },
    SessionEnded {
        cause: DisconnectCause,
    },
}

/// Typed rejection of an event that is not legal in the current state.
/// Legal pairs are documented in `docs/protocol/state-machines.md` and
/// exhaustively table-tested in each machine's unit tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IllegalTransition {
    pub state: &'static str,
    pub event: &'static str,
}

impl IllegalTransition {
    pub(crate) fn new(state: &'static str, event: &'static str) -> Self {
        Self { state, event }
    }
}

impl core::fmt::Display for IllegalTransition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "illegal transition: event {:?} in state {:?}",
            self.event, self.state
        )
    }
}

impl std::error::Error for IllegalTransition {}

/// Bounded LRU of recently seen `message_id`s for idempotent delivery.
/// Capacity comes from [`SessionConfig::dedupe_capacity`]; memory is O(cap).
#[derive(Debug)]
pub(crate) struct DedupeLog {
    capacity: usize,
    seen: VecDeque<MessageId>,
}

impl DedupeLog {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            seen: VecDeque::new(),
        }
    }

    /// Observe a message id. Returns `true` if it is new, `false` if it was
    /// already seen (duplicate delivery → caller must no-op).
    pub(crate) fn observe(&mut self, id: &str) -> bool {
        if self.seen.iter().any(|seen| seen == id) {
            return false;
        }
        if self.seen.len() == self.capacity {
            self.seen.pop_front();
        }
        self.seen.push_back(id.to_owned());
        true
    }
}

/// Which role a builder mints ids for. The product runs host and controller
/// of one device in the same process; the role tag keeps their ids disjoint
/// because the signaling service dedupes on `message_id` process-wide (QA
/// finding F1 — two builders both starting at `"{device}-1"` made the
/// controller's envelopes look like redeliveries of the host's).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdRole {
    Host,
    Controller,
}

impl IdRole {
    fn tag(self) -> &'static str {
        match self {
            IdRole::Host => "host",
            IdRole::Controller => "ctrl",
        }
    }
}

/// Builds envelopes with deterministic, unique `message_id`s
/// (`"{device}-{role}-{n}"`, e.g. `device-a-host-3`). One process runs both
/// roles, so uniqueness is per *device+role*; that is exactly the scope the
/// signaling service's `messageId` dedupe needs. Production runtimes may
/// substitute real UUIDs at the transport edge if they need global
/// uniqueness.
#[derive(Debug)]
pub(crate) struct EnvelopeBuilder {
    device_id: DeviceId,
    role: IdRole,
    counter: u64,
}

impl EnvelopeBuilder {
    pub(crate) fn new(device_id: DeviceId, role: IdRole) -> Self {
        Self {
            device_id,
            role,
            counter: 0,
        }
    }

    pub(crate) fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Allocate the next local id (`"{device}-{role}-{n}"`) without building
    /// an envelope. Used for session ids; shares the counter with envelope
    /// message ids so all ids from one device-role pair are unique.
    pub(crate) fn next_local_id(&mut self) -> MessageId {
        self.counter += 1;
        self.format_id()
    }

    fn format_id(&self) -> MessageId {
        format!("{}-{}-{}", self.device_id, self.role.tag(), self.counter)
    }

    pub(crate) fn envelope(
        &mut self,
        to: &str,
        session_id: Option<&str>,
        body: SignalingBody,
        now_ms: u64,
    ) -> SignalingEnvelope {
        self.counter += 1;
        SignalingEnvelope {
            protocol_version: SIGNALING_PROTOCOL_VERSION,
            message_id: self.format_id(),
            session_id: session_id.map(str::to_owned),
            from_device_id: self.device_id.clone(),
            to_device_id: to.to_owned(),
            timestamp_ms: now_ms,
            body,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::signaling::SIGNALING_SERVICE_ID;

    #[test]
    fn dedupe_log_detects_duplicates() {
        let mut log = DedupeLog::new(3);
        assert!(log.observe("a"));
        assert!(log.observe("b"));
        assert!(!log.observe("a"), "duplicate must be reported");
        assert!(log.observe("c"));
        assert!(log.observe("d"), "evicts oldest when at capacity");
        assert!(log.observe("a"), "evicted id is new again");
        assert!(!log.observe("d"));
    }

    #[test]
    fn dedupe_log_memory_is_bounded_by_capacity() {
        let mut log = DedupeLog::new(4);
        for i in 0..100 {
            assert!(log.observe(&format!("m{i}")));
        }
        assert!(log.seen.len() <= 4);
    }

    #[test]
    fn envelope_builder_produces_unique_deterministic_ids() {
        let mut builder = EnvelopeBuilder::new("device-a".to_owned(), IdRole::Host);
        let a = builder.envelope("device-b", None, SignalingBody::Heartbeat, 1_000);
        let b = builder.envelope("device-b", Some("s"), SignalingBody::Heartbeat, 1_001);
        assert_eq!(a.message_id, "device-a-host-1");
        assert_eq!(b.message_id, "device-a-host-2");
        assert_eq!(a.protocol_version, SIGNALING_PROTOCOL_VERSION);
        assert_eq!(a.from_device_id, "device-a");
        assert_eq!(a.to_device_id, "device-b");
        assert_eq!(a.timestamp_ms, 1_000);
    }

    /// QA F1: the two role machines of one device must never mint the same
    /// `message_id` — the signaling service dedupes on it process-wide.
    #[test]
    fn host_and_controller_builders_of_one_device_mint_disjoint_ids() {
        let mut host = EnvelopeBuilder::new("device-a".to_owned(), IdRole::Host);
        let mut ctrl = EnvelopeBuilder::new("device-a".to_owned(), IdRole::Controller);
        let mut ids = std::collections::HashSet::new();
        for _ in 0..50 {
            let h = host
                .envelope("device-b", None, SignalingBody::Heartbeat, 0)
                .message_id;
            let c = ctrl
                .envelope("device-b", None, SignalingBody::Heartbeat, 0)
                .message_id;
            assert!(ids.insert(h), "host id repeated");
            assert!(ids.insert(c), "controller id collided with a host id");
        }
        // And session ids share the same disjoint counter space.
        let s1 = ctrl.next_local_id();
        let s2 = ctrl.next_local_id();
        assert_ne!(s1, s2);
        assert!(ids.insert(s1), "session id collided with an envelope id");
    }

    #[test]
    fn envelope_builder_service_addressing() {
        let mut builder = EnvelopeBuilder::new("device-a".to_owned(), IdRole::Host);
        let env = builder.envelope(SIGNALING_SERVICE_ID, None, SignalingBody::Heartbeat, 5);
        assert_eq!(env.to_device_id, "signaling");
        assert_eq!(env.session_id, None);
    }
}
