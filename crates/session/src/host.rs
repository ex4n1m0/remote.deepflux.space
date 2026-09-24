//! Host-side state machine (`Idle → Registering → Online → ConsentPrompted →
//! Exchanging → Connecting → Connected → Disconnected`).
//!
//! Deterministic: no clocks, no network. See `docs/protocol/state-machines.md`
//! for the diagram and the full legal-transition table; the table test at the
//! bottom of this file enforces that every illegal pair is rejected.

use protocol::capabilities::Capabilities;
use protocol::signaling::{
    CancelReason, DeviceId, DisconnectReason as SignalingDisconnectReason, MessageId, RejectReason,
    SIGNALING_SERVICE_ID, SessionId, SessionSecret, SignalingBody,
};

use crate::common::{Action, DisconnectCause, EnvelopeBuilder, IdRole};

use crate::common::{DedupeLog, IllegalTransition, SessionConfig, TimerId};

/// A pending consent prompt: which controller asked, for which session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    pub session_id: SessionId,
    pub controller_device_id: DeviceId,
}

/// Everything the host tracks about the session it is trying to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostSessionInfo {
    pub session_id: SessionId,
    pub peer_device_id: DeviceId,
    /// Present from `ConsentAccepted` on; checked again when the direct
    /// channel opens (M2). Never logged (invariant 6).
    pub secret: Option<SessionSecret>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HostState {
    /// Not hosting.
    Idle,
    /// `Register` sent, awaiting service ack.
    Registering,
    /// Presence established; waiting for a controller.
    Online,
    /// Consent prompt visible for exactly one controller request.
    ConsentPrompted { info: PendingRequest },
    /// Accepted; SDP answer pending (offer received or awaited).
    Exchanging { session: HostSessionInfo },
    /// Answer sent; awaiting the direct data channel.
    Connecting { session: HostSessionInfo },
    /// Streaming frames to the controller.
    Connected { session: HostSessionInfo },
    /// Terminal until an explicit `Start` restarts hosting.
    Disconnected { cause: DisconnectCause },
}

impl HostState {
    pub fn name(&self) -> &'static str {
        match self {
            HostState::Idle => "Idle",
            HostState::Registering => "Registering",
            HostState::Online => "Online",
            HostState::ConsentPrompted { .. } => "ConsentPrompted",
            HostState::Exchanging { .. } => "Exchanging",
            HostState::Connecting { .. } => "Connecting",
            HostState::Connected { .. } => "Connected",
            HostState::Disconnected { .. } => "Disconnected",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum HostEvent {
    /// User enabled the host role. Carries the capabilities to register.
    Start { capabilities: Capabilities },
    /// Service acknowledged registration.
    Registered,
    /// Service rejected registration (version, rate limit...).
    RegistrationFailed { reason: String },
    /// Runtime heartbeat cadence tick (presence keep-alive).
    HeartbeatDue,
    /// A controller sent `connect_request`. Deduplicated by `message_id`.
    IncomingRequest {
        message_id: MessageId,
        controller_device_id: DeviceId,
        session_id: SessionId,
    },
    /// Host user accepted the prompt; carries the one-time secret to hand over.
    ConsentAccepted { secret: SessionSecret },
    /// Host user declined the prompt.
    ConsentRejected,
    /// Consent prompt timer fired without a decision.
    ConsentTimeout,
    /// Controller's SDP offer arrived.
    OfferReceived { message_id: MessageId, sdp: String },
    /// Runtime produced the SDP answer (from `Action::ComposeAnswer`).
    AnswerComposed { sdp: String },
    /// Controller withdrew its request (`cancel`).
    CancelReceived {
        message_id: MessageId,
        reason: CancelReason,
    },
    /// Trickle ICE candidate from the controller (no state change).
    /// `sdp_mid` is the JSEP string mid (protocol version 1, QA F9).
    IceCandidateReceived {
        message_id: MessageId,
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
    },
    /// Connect-timeout timer fired (Exchanging/Connecting).
    ConnectTimeout,
    /// Direct data channel opened.
    DataChannelOpen,
    /// Controller ended the session (`disconnect`).
    DisconnectReceived {
        message_id: MessageId,
        reason: SignalingDisconnectReason,
    },
    /// Transport-level failure (ICE dead, DTLS error...).
    TransportFailed { reason: String },
    /// Host user stopped sharing.
    Stop,
}

impl HostEvent {
    pub fn name(&self) -> &'static str {
        match self {
            HostEvent::Start { .. } => "Start",
            HostEvent::Registered => "Registered",
            HostEvent::RegistrationFailed { .. } => "RegistrationFailed",
            HostEvent::HeartbeatDue => "HeartbeatDue",
            HostEvent::IncomingRequest { .. } => "IncomingRequest",
            HostEvent::ConsentAccepted { .. } => "ConsentAccepted",
            HostEvent::ConsentRejected => "ConsentRejected",
            HostEvent::ConsentTimeout => "ConsentTimeout",
            HostEvent::OfferReceived { .. } => "OfferReceived",
            HostEvent::AnswerComposed { .. } => "AnswerComposed",
            HostEvent::CancelReceived { .. } => "CancelReceived",
            HostEvent::IceCandidateReceived { .. } => "IceCandidateReceived",
            HostEvent::ConnectTimeout => "ConnectTimeout",
            HostEvent::DataChannelOpen => "DataChannelOpen",
            HostEvent::DisconnectReceived { .. } => "DisconnectReceived",
            HostEvent::TransportFailed { .. } => "TransportFailed",
            HostEvent::Stop => "Stop",
        }
    }

    /// Events carrying a signaling `message_id` participate in dedupe.
    pub fn message_id(&self) -> Option<&str> {
        match self {
            HostEvent::IncomingRequest { message_id, .. }
            | HostEvent::OfferReceived { message_id, .. }
            | HostEvent::CancelReceived { message_id, .. }
            | HostEvent::IceCandidateReceived { message_id, .. }
            | HostEvent::DisconnectReceived { message_id, .. } => Some(message_id),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct HostSession {
    state: HostState,
    cfg: SessionConfig,
    envelopes: EnvelopeBuilder,
    seen: DedupeLog,
}

impl HostSession {
    pub fn new(device_id: DeviceId, cfg: SessionConfig) -> Self {
        Self {
            state: HostState::Idle,
            seen: DedupeLog::new(cfg.dedupe_capacity),
            cfg,
            envelopes: EnvelopeBuilder::new(device_id, IdRole::Host),
        }
    }

    pub fn state(&self) -> &HostState {
        &self.state
    }

    /// Deterministic transition function. Duplicate `message_id` delivery is
    /// a no-op (`Ok(empty)`); events illegal in the current state are typed
    /// [`IllegalTransition`] errors and never mutate state.
    pub fn step(
        &mut self,
        event: HostEvent,
        now_ms: u64,
    ) -> Result<Vec<Action>, IllegalTransition> {
        if let Some(id) = event.message_id()
            && !self.seen.observe(id)
        {
            return Ok(Vec::new());
        }
        let state_name = self.state.name();
        let event_name = event.name();
        match self.state {
            HostState::Idle => match event {
                HostEvent::Start { capabilities } => {
                    self.state = HostState::Registering;
                    Ok(vec![Action::Send(self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        None,
                        SignalingBody::Register { capabilities },
                        now_ms,
                    ))])
                }
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            HostState::Registering => match event {
                HostEvent::Registered => {
                    self.state = HostState::Online;
                    Ok(Vec::new())
                }
                HostEvent::RegistrationFailed { .. } => {
                    self.state = HostState::Idle;
                    Ok(Vec::new())
                }
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            HostState::Online => match event {
                HostEvent::HeartbeatDue => {
                    let env = self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        None,
                        SignalingBody::Heartbeat,
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::IncomingRequest {
                    controller_device_id,
                    session_id,
                    ..
                } => {
                    self.state = HostState::ConsentPrompted {
                        info: PendingRequest {
                            session_id: session_id.clone(),
                            controller_device_id: controller_device_id.clone(),
                        },
                    };
                    Ok(vec![
                        Action::PromptConsent {
                            controller_device_id,
                            session_id,
                        },
                        Action::ScheduleTimer {
                            id: TimerId::HostConsent,
                            fire_at_ms: now_ms + self.cfg.consent_timeout_ms,
                        },
                    ])
                }
                HostEvent::Stop => {
                    self.state = HostState::Idle;
                    Ok(Vec::new())
                }
                // Tolerated no-op: signaling is a mailbox, so a controller's
                // `cancel` can race the delivery of its own request (or
                // arrive after we already returned to Online). Swallowing it
                // here keeps simultaneous-call resolution order-independent.
                HostEvent::CancelReceived { .. } => Ok(Vec::new()),
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            HostState::ConsentPrompted { ref info } => match event {
                HostEvent::HeartbeatDue => {
                    let info = info.clone();
                    let env = self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        Some(&info.session_id),
                        SignalingBody::Heartbeat,
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::IncomingRequest {
                    controller_device_id,
                    session_id,
                    ..
                } => {
                    // Busy rejection keyed to the incoming request's session
                    // id (QA F10), consistent with the other host states.
                    let env = self.envelopes.envelope(
                        &controller_device_id,
                        Some(&session_id),
                        SignalingBody::Reject {
                            reason: RejectReason::Busy,
                        },
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::ConsentAccepted { secret } => {
                    let info = info.clone();
                    let session = HostSessionInfo {
                        session_id: info.session_id.clone(),
                        peer_device_id: info.controller_device_id.clone(),
                        secret: Some(secret.clone()),
                    };
                    let env = self.envelopes.envelope(
                        &info.controller_device_id,
                        Some(&info.session_id),
                        SignalingBody::Accept {
                            session_secret: secret,
                        },
                        now_ms,
                    );
                    self.state = HostState::Exchanging { session };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::HostConsent,
                        },
                        Action::Send(env),
                        Action::ScheduleTimer {
                            id: TimerId::HostConnect,
                            fire_at_ms: now_ms + self.cfg.connect_timeout_ms,
                        },
                    ])
                }
                HostEvent::ConsentRejected => {
                    let info = info.clone();
                    let env = self.envelopes.envelope(
                        &info.controller_device_id,
                        Some(&info.session_id),
                        SignalingBody::Reject {
                            reason: RejectReason::Declined,
                        },
                        now_ms,
                    );
                    self.state = HostState::Online;
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::HostConsent,
                        },
                        Action::Send(env),
                    ])
                }
                HostEvent::ConsentTimeout => {
                    let info = info.clone();
                    let env = self.envelopes.envelope(
                        &info.controller_device_id,
                        Some(&info.session_id),
                        SignalingBody::Reject {
                            reason: RejectReason::Timeout,
                        },
                        now_ms,
                    );
                    self.state = HostState::Online;
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::CancelReceived { .. } => {
                    self.state = HostState::Online;
                    Ok(vec![Action::CancelTimer {
                        id: TimerId::HostConsent,
                    }])
                }
                HostEvent::DisconnectReceived { .. } => {
                    self.state = HostState::Online;
                    Ok(vec![Action::CancelTimer {
                        id: TimerId::HostConsent,
                    }])
                }
                HostEvent::Stop => {
                    self.state = HostState::Disconnected {
                        cause: DisconnectCause::User,
                    };
                    Ok(vec![Action::CancelTimer {
                        id: TimerId::HostConsent,
                    }])
                }
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            HostState::Exchanging { ref session } => match event {
                HostEvent::HeartbeatDue => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        Some(&session.session_id),
                        SignalingBody::Heartbeat,
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::IncomingRequest {
                    controller_device_id,
                    session_id,
                    ..
                } => {
                    // Busy rejection keyed to the *incoming* request's session
                    // so the refused controller can correlate it (QA F10 —
                    // every busy Reject carries the requester's session id).
                    let env = self.envelopes.envelope(
                        &controller_device_id,
                        Some(&session_id),
                        SignalingBody::Reject {
                            reason: RejectReason::Busy,
                        },
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::OfferReceived { sdp, .. } => {
                    Ok(vec![Action::ComposeAnswer { offer_sdp: sdp }])
                }
                HostEvent::AnswerComposed { sdp } => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Answer { sdp },
                        now_ms,
                    );
                    self.state = HostState::Connecting {
                        session: session.clone(),
                    };
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::IceCandidateReceived {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                    ..
                } => Ok(vec![Action::ForwardIce {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                }]),
                HostEvent::CancelReceived { .. } | HostEvent::DisconnectReceived { .. } => {
                    self.state = HostState::Online;
                    Ok(vec![Action::CancelTimer {
                        id: TimerId::HostConnect,
                    }])
                }
                HostEvent::ConnectTimeout => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Disconnect {
                            reason: SignalingDisconnectReason::Timeout,
                        },
                        now_ms,
                    );
                    self.state = HostState::Disconnected {
                        cause: DisconnectCause::Timeout,
                    };
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::TransportFailed { .. } => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Disconnect {
                            reason: SignalingDisconnectReason::TransportError,
                        },
                        now_ms,
                    );
                    self.state = HostState::Disconnected {
                        cause: DisconnectCause::TransportError,
                    };
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::Stop => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Disconnect {
                            reason: SignalingDisconnectReason::User,
                        },
                        now_ms,
                    );
                    self.state = HostState::Disconnected {
                        cause: DisconnectCause::User,
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::HostConnect,
                        },
                        Action::Send(env),
                    ])
                }
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            HostState::Connecting { ref session } => match event {
                HostEvent::HeartbeatDue => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        Some(&session.session_id),
                        SignalingBody::Heartbeat,
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::IncomingRequest {
                    controller_device_id,
                    session_id,
                    ..
                } => {
                    // Busy rejection keyed to the *incoming* request's session
                    // so the refused controller can correlate it (QA F10 —
                    // every busy Reject carries the requester's session id).
                    let env = self.envelopes.envelope(
                        &controller_device_id,
                        Some(&session_id),
                        SignalingBody::Reject {
                            reason: RejectReason::Busy,
                        },
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::DataChannelOpen => {
                    let session = session.clone();
                    self.state = HostState::Connected {
                        session: session.clone(),
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::HostConnect,
                        },
                        Action::StartStreaming,
                        Action::SessionEstablished {
                            session_id: session.session_id,
                        },
                    ])
                }
                HostEvent::IceCandidateReceived {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                    ..
                } => Ok(vec![Action::ForwardIce {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                }]),
                HostEvent::CancelReceived { .. } | HostEvent::DisconnectReceived { .. } => {
                    self.state = HostState::Online;
                    Ok(vec![Action::CancelTimer {
                        id: TimerId::HostConnect,
                    }])
                }
                HostEvent::ConnectTimeout | HostEvent::TransportFailed { .. } => {
                    let cause = match &event {
                        HostEvent::ConnectTimeout => DisconnectCause::Timeout,
                        _ => DisconnectCause::TransportError,
                    };
                    let reason = match &event {
                        HostEvent::ConnectTimeout => SignalingDisconnectReason::Timeout,
                        _ => SignalingDisconnectReason::TransportError,
                    };
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Disconnect { reason },
                        now_ms,
                    );
                    self.state = HostState::Disconnected { cause };
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::Stop => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Disconnect {
                            reason: SignalingDisconnectReason::User,
                        },
                        now_ms,
                    );
                    self.state = HostState::Disconnected {
                        cause: DisconnectCause::User,
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::HostConnect,
                        },
                        Action::Send(env),
                    ])
                }
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            HostState::Connected { ref session } => match event {
                HostEvent::HeartbeatDue => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        Some(&session.session_id),
                        SignalingBody::Heartbeat,
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::IncomingRequest {
                    controller_device_id,
                    session_id,
                    ..
                } => {
                    // Busy rejection keyed to the *incoming* request's session
                    // so the refused controller can correlate it (QA F10 —
                    // every busy Reject carries the requester's session id).
                    let env = self.envelopes.envelope(
                        &controller_device_id,
                        Some(&session_id),
                        SignalingBody::Reject {
                            reason: RejectReason::Busy,
                        },
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                HostEvent::IceCandidateReceived {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                    ..
                } => Ok(vec![Action::ForwardIce {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                }]),
                HostEvent::DisconnectReceived { .. } => {
                    self.state = HostState::Disconnected {
                        cause: DisconnectCause::Peer,
                    };
                    Ok(vec![
                        Action::StopStreaming,
                        Action::SessionEnded {
                            cause: DisconnectCause::Peer,
                        },
                    ])
                }
                HostEvent::TransportFailed { .. } => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Disconnect {
                            reason: SignalingDisconnectReason::TransportError,
                        },
                        now_ms,
                    );
                    self.state = HostState::Disconnected {
                        cause: DisconnectCause::TransportError,
                    };
                    Ok(vec![
                        Action::StopStreaming,
                        Action::Send(env),
                        Action::SessionEnded {
                            cause: DisconnectCause::TransportError,
                        },
                    ])
                }
                HostEvent::Stop => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Disconnect {
                            reason: SignalingDisconnectReason::User,
                        },
                        now_ms,
                    );
                    self.state = HostState::Disconnected {
                        cause: DisconnectCause::User,
                    };
                    Ok(vec![
                        Action::StopStreaming,
                        Action::Send(env),
                        Action::SessionEnded {
                            cause: DisconnectCause::User,
                        },
                    ])
                }
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            HostState::Disconnected { .. } => match event {
                HostEvent::Start { capabilities } => {
                    self.state = HostState::Registering;
                    Ok(vec![Action::Send(self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        None,
                        SignalingBody::Register { capabilities },
                        now_ms,
                    ))])
                }
                // Post-mortem tolerance: session traffic that raced our own
                // timeout/teardown arrives after we are done. Dropping it is
                // correct (dedupe already ran); erroring would turn every
                // timer race into a protocol violation. New requests are NOT
                // tolerated — the runtime must not deliver them while we are
                // not hosting.
                HostEvent::OfferReceived { .. }
                | HostEvent::CancelReceived { .. }
                | HostEvent::IceCandidateReceived { .. }
                | HostEvent::DisconnectReceived { .. } => Ok(Vec::new()),
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },
        }
    }

    /// Test-only state injection for the exhaustive illegal-transition table.
    #[cfg(test)]
    pub(crate) fn force_state(&mut self, state: HostState) {
        self.state = state;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> HostSession {
        HostSession::new("host-a".to_owned(), SessionConfig::default())
    }

    fn info() -> PendingRequest {
        PendingRequest {
            session_id: "ctrl-b-1".to_owned(),
            controller_device_id: "ctrl-b".to_owned(),
        }
    }

    fn session() -> HostSessionInfo {
        HostSessionInfo {
            session_id: "ctrl-b-1".to_owned(),
            peer_device_id: "ctrl-b".to_owned(),
            secret: Some(SessionSecret("s".to_owned())),
        }
    }

    fn state_samples() -> Vec<HostState> {
        vec![
            HostState::Idle,
            HostState::Registering,
            HostState::Online,
            HostState::ConsentPrompted { info: info() },
            HostState::Exchanging { session: session() },
            HostState::Connecting { session: session() },
            HostState::Connected { session: session() },
            HostState::Disconnected {
                cause: DisconnectCause::User,
            },
        ]
    }

    fn caps() -> Capabilities {
        use protocol::capabilities::{
            Capabilities, EncoderCapabilities, EncoderKind, FeatureFlags, MonitorInfo,
        };
        Capabilities {
            encoders: vec![EncoderCapabilities {
                kind: EncoderKind::Software,
                codec: protocol::capabilities::Codec::H264,
                max_width_px: 1920,
                max_height_px: 1080,
                max_fps: 30,
            }],
            monitors: vec![MonitorInfo {
                monitor_id: "\\\\.\\DISPLAY1".to_owned(),
                width_px: 1920,
                height_px: 1080,
                is_primary: true,
            }],
            max_bitrate_kbps: 5_000,
            features: FeatureFlags::empty(),
        }
    }

    fn event_samples() -> Vec<HostEvent> {
        vec![
            HostEvent::Start {
                capabilities: caps(),
            },
            HostEvent::Registered,
            HostEvent::RegistrationFailed {
                reason: "rate".to_owned(),
            },
            HostEvent::HeartbeatDue,
            HostEvent::IncomingRequest {
                message_id: "e1".to_owned(),
                controller_device_id: "ctrl-b".to_owned(),
                session_id: "ctrl-b-1".to_owned(),
            },
            HostEvent::ConsentAccepted {
                secret: SessionSecret("s".to_owned()),
            },
            HostEvent::ConsentRejected,
            HostEvent::ConsentTimeout,
            HostEvent::OfferReceived {
                message_id: "e2".to_owned(),
                sdp: "offer".to_owned(),
            },
            HostEvent::AnswerComposed {
                sdp: "answer".to_owned(),
            },
            HostEvent::CancelReceived {
                message_id: "e3".to_owned(),
                reason: CancelReason::User,
            },
            HostEvent::IceCandidateReceived {
                message_id: "e4".to_owned(),
                candidate: "candidate:1".to_owned(),
                sdp_mid: Some("0".to_owned()),
                sdp_mline_index: Some(0),
            },
            HostEvent::ConnectTimeout,
            HostEvent::DataChannelOpen,
            HostEvent::DisconnectReceived {
                message_id: "e5".to_owned(),
                reason: SignalingDisconnectReason::User,
            },
            HostEvent::TransportFailed {
                reason: "ice".to_owned(),
            },
            HostEvent::Stop,
        ]
    }

    /// The documented legal-transition table. Everything not listed here
    /// must be rejected with `IllegalTransition` and must not mutate state.
    fn legal_pairs() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Idle", "Start"),
            ("Registering", "Registered"),
            ("Registering", "RegistrationFailed"),
            ("Online", "HeartbeatDue"),
            ("Online", "IncomingRequest"),
            ("Online", "Stop"),
            ("Online", "CancelReceived"),
            ("ConsentPrompted", "HeartbeatDue"),
            ("ConsentPrompted", "IncomingRequest"),
            ("ConsentPrompted", "ConsentAccepted"),
            ("ConsentPrompted", "ConsentRejected"),
            ("ConsentPrompted", "ConsentTimeout"),
            ("ConsentPrompted", "CancelReceived"),
            ("ConsentPrompted", "DisconnectReceived"),
            ("ConsentPrompted", "Stop"),
            ("Exchanging", "HeartbeatDue"),
            ("Exchanging", "IncomingRequest"),
            ("Exchanging", "OfferReceived"),
            ("Exchanging", "AnswerComposed"),
            ("Exchanging", "CancelReceived"),
            ("Exchanging", "DisconnectReceived"),
            ("Exchanging", "ConnectTimeout"),
            ("Exchanging", "TransportFailed"),
            ("Exchanging", "IceCandidateReceived"),
            ("Exchanging", "Stop"),
            ("Connecting", "HeartbeatDue"),
            ("Connecting", "IncomingRequest"),
            ("Connecting", "DataChannelOpen"),
            ("Connecting", "ConnectTimeout"),
            ("Connecting", "CancelReceived"),
            ("Connecting", "DisconnectReceived"),
            ("Connecting", "TransportFailed"),
            ("Connecting", "IceCandidateReceived"),
            ("Connecting", "Stop"),
            ("Connected", "HeartbeatDue"),
            ("Connected", "IncomingRequest"),
            ("Connected", "DisconnectReceived"),
            ("Connected", "TransportFailed"),
            ("Connected", "IceCandidateReceived"),
            ("Connected", "Stop"),
            // Post-mortem tolerance: late session traffic in Disconnected.
            ("Disconnected", "Start"),
            ("Disconnected", "OfferReceived"),
            ("Disconnected", "CancelReceived"),
            ("Disconnected", "IceCandidateReceived"),
            ("Disconnected", "DisconnectReceived"),
        ]
    }

    #[test]
    fn every_illegal_transition_is_rejected_without_state_change() {
        let legal = legal_pairs();
        let mut illegal_count = 0;
        for state in state_samples() {
            for event in event_samples() {
                let mut m = machine();
                m.force_state(state.clone());
                let result = m.step(event.clone(), 1_000);
                let pair = (state.name(), event.name());
                if legal.contains(&pair) {
                    assert!(
                        result.is_ok(),
                        "pair {pair:?} must be legal, got {result:?}"
                    );
                } else {
                    illegal_count += 1;
                    let err = result.expect_err("must be illegal");
                    assert_eq!(err, IllegalTransition::new(state.name(), event.name()));
                    assert_eq!(m.state().name(), state.name(), "state must not change");
                }
            }
        }
        // Sanity: the table is not vacuous (136 combinations, 41 legal).
        assert!(
            illegal_count >= 80,
            "only {illegal_count} illegal pairs found"
        );
    }

    #[test]
    fn duplicate_connect_request_is_a_no_op() {
        let mut m = machine();
        m.force_state(HostState::Online);
        let first = m
            .step(
                HostEvent::IncomingRequest {
                    message_id: "dup-1".to_owned(),
                    controller_device_id: "ctrl-b".to_owned(),
                    session_id: "ctrl-b-1".to_owned(),
                },
                10,
            )
            .expect("legal");
        assert!(matches!(m.state(), HostState::ConsentPrompted { .. }));
        assert!(!first.is_empty());
        let dup = m
            .step(
                HostEvent::IncomingRequest {
                    message_id: "dup-1".to_owned(),
                    controller_device_id: "ctrl-b".to_owned(),
                    session_id: "ctrl-b-1".to_owned(),
                },
                11,
            )
            .expect("duplicates are Ok(empty), not errors");
        assert!(dup.is_empty());
        assert!(matches!(m.state(), HostState::ConsentPrompted { .. }));
    }

    #[test]
    fn second_request_while_prompting_is_rejected_busy() {
        let mut m = machine();
        m.force_state(HostState::Online);
        m.step(
            HostEvent::IncomingRequest {
                message_id: "r1".to_owned(),
                controller_device_id: "ctrl-b".to_owned(),
                session_id: "ctrl-b-1".to_owned(),
            },
            10,
        )
        .unwrap();
        let actions = m
            .step(
                HostEvent::IncomingRequest {
                    message_id: "r2".to_owned(),
                    controller_device_id: "ctrl-c".to_owned(),
                    session_id: "ctrl-c-1".to_owned(),
                },
                20,
            )
            .unwrap();
        match actions.as_slice() {
            [Action::Send(env)] => {
                assert_eq!(env.to_device_id, "ctrl-c");
                assert_eq!(
                    env.body,
                    SignalingBody::Reject {
                        reason: RejectReason::Busy
                    }
                );
                // QA F10: the busy reject is keyed to the *incoming*
                // request's session ("ctrl-c-1"), not the pending one.
                assert_eq!(env.session_id.as_deref(), Some("ctrl-c-1"));
            }
            other => panic!("expected one busy Reject, got {other:?}"),
        }
        assert!(matches!(m.state(), HostState::ConsentPrompted { .. }));
    }

    /// QA F10: busy rejections carry the requester's session id in *every*
    /// host state, so consumers can correlate them uniformly.
    #[test]
    fn busy_reject_session_id_is_consistent_across_host_states() {
        for state in [
            HostState::Exchanging { session: session() },
            HostState::Connecting { session: session() },
            HostState::Connected { session: session() },
        ] {
            let mut m = machine();
            m.force_state(state);
            let actions = m
                .step(
                    HostEvent::IncomingRequest {
                        message_id: "r9".to_owned(),
                        controller_device_id: "ctrl-c".to_owned(),
                        session_id: "ctrl-c-7".to_owned(),
                    },
                    20,
                )
                .unwrap();
            match actions.as_slice() {
                [Action::Send(env)] => {
                    assert_eq!(
                        env.session_id.as_deref(),
                        Some("ctrl-c-7"),
                        "busy reject must carry the requester's session id in {:?}",
                        m.state()
                    );
                }
                other => panic!("expected one busy Reject, got {other:?}"),
            }
        }
    }

    #[test]
    fn consent_timeout_auto_rejects_and_returns_online() {
        let mut m = machine();
        m.force_state(HostState::Online);
        m.step(
            HostEvent::IncomingRequest {
                message_id: "r1".to_owned(),
                controller_device_id: "ctrl-b".to_owned(),
                session_id: "ctrl-b-1".to_owned(),
            },
            10,
        )
        .unwrap();
        let actions = m.step(HostEvent::ConsentTimeout, 40_000).unwrap();
        match actions.as_slice() {
            [Action::Send(env)] => {
                assert_eq!(
                    env.body,
                    SignalingBody::Reject {
                        reason: RejectReason::Timeout
                    }
                );
            }
            other => panic!("expected timeout Reject, got {other:?}"),
        }
        assert_eq!(m.state().name(), "Online");
    }

    #[test]
    fn host_secret_never_debug_prints() {
        let mut m = machine();
        m.force_state(HostState::Online);
        m.step(
            HostEvent::IncomingRequest {
                message_id: "r1".to_owned(),
                controller_device_id: "ctrl-b".to_owned(),
                session_id: "ctrl-b-1".to_owned(),
            },
            10,
        )
        .unwrap();
        m.step(
            HostEvent::ConsentAccepted {
                secret: SessionSecret("top-secret-value".to_owned()),
            },
            20,
        )
        .unwrap();
        let debug = format!("{:?}", m.state());
        assert!(!debug.contains("top-secret-value"), "leaked via Debug");
    }
}
