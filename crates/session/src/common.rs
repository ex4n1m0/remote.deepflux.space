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
    /// listed as an action so the runtime stays dumb.
    ForwardIce {
        candidate: String,
        sdp_mid: Option<u16>,
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

/// Builds envelopes with deterministic, unique `message_id`s
/// (`"{device}-{n}"`). Production runtimes may substitute real UUIDs at the
/// transport edge if they need global uniqueness; within a device the counter
/// is unique for the process lifetime, which is all the signaling TTL needs.
#[derive(Debug)]
pub(crate) struct EnvelopeBuilder {
    device_id: DeviceId,
    counter: u64,
}

impl EnvelopeBuilder {
    pub(crate) fn new(device_id: DeviceId) -> Self {
        Self {
            device_id,
            counter: 0,
        }
    }

    pub(crate) fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Allocate the next local id (`"{device}-{n}"`) without building an
    /// envelope. Used for session ids; shares the counter with envelope
    /// message ids so all ids from one device are unique.
    pub(crate) fn next_local_id(&mut self) -> MessageId {
        self.counter += 1;
        format!("{}-{}", self.device_id, self.counter)
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
            message_id: format!("{}-{}", self.device_id, self.counter),
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
        let mut builder = EnvelopeBuilder::new("device-a".to_owned());
        let a = builder.envelope("device-b", None, SignalingBody::Heartbeat, 1_000);
        let b = builder.envelope("device-b", Some("s"), SignalingBody::Heartbeat, 1_001);
        assert_eq!(a.message_id, "device-a-1");
        assert_eq!(b.message_id, "device-a-2");
        assert_eq!(a.protocol_version, SIGNALING_PROTOCOL_VERSION);
        assert_eq!(a.from_device_id, "device-a");
        assert_eq!(a.to_device_id, "device-b");
        assert_eq!(a.timestamp_ms, 1_000);
    }

    #[test]
    fn envelope_builder_service_addressing() {
        let mut builder = EnvelopeBuilder::new("device-a".to_owned());
        let env = builder.envelope(SIGNALING_SERVICE_ID, None, SignalingBody::Heartbeat, 5);
        assert_eq!(env.to_device_id, "signaling");
        assert_eq!(env.session_id, None);
    }
}
