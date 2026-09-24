//! Controller-side state machine (`Idle → Registering → Online → Requesting →
//! Offering → Connecting → Connected → Disconnected`).
//!
//! Deterministic, event-injected, clock-injected — mirrors
//! [`crate::host`]. The simultaneous-call collision rule lives here:
//! when our host side and our controller side both have a session toward the
//! same peer (request, offer, or ICE — the runtime raises
//! [`ControllerEvent::CollisionDetected`] in `Requesting`, `Offering`, and
//! `Connecting`), the **lexicographically smaller device id keeps the
//! controller role**; the losing controller cancels with
//! `Cancel{reason: "collision"}`. Both nodes apply the same rule from their
//! own view, so the outcome is deterministic without communication (see
//! `docs/protocol/state-machines.md`).

use protocol::capabilities::Capabilities;
use protocol::signaling::{
    CancelReason, DeviceId, DisconnectReason as SignalingDisconnectReason, MessageId, RejectReason,
    SIGNALING_SERVICE_ID, SessionId, SessionSecret, SignalingBody,
};

use crate::common::{
    Action, DedupeLog, DisconnectCause, EnvelopeBuilder, IdRole, IllegalTransition, SessionConfig,
    TimerId,
};

/// What the controller tracks about the session it is trying to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerSessionInfo {
    pub session_id: SessionId,
    pub peer_device_id: DeviceId,
    /// Received in `Accept`; used to authenticate the first direct-channel
    /// handshake (M2). Never logged (invariant 6).
    pub secret: Option<SessionSecret>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ControllerState {
    Idle,
    Registering,
    Online,
    /// `connect_request` sent; awaiting accept/reject.
    Requesting {
        session: ControllerSessionInfo,
    },
    /// Accepted; offer composed/sent; awaiting answer.
    Offering {
        session: ControllerSessionInfo,
    },
    /// Answer received; ICE/DTLS in progress.
    Connecting {
        session: ControllerSessionInfo,
    },
    Connected {
        session: ControllerSessionInfo,
    },
    /// Terminal until an explicit `Start` restarts the controller role.
    Disconnected {
        cause: DisconnectCause,
    },
}

impl ControllerState {
    pub fn name(&self) -> &'static str {
        match self {
            ControllerState::Idle => "Idle",
            ControllerState::Registering => "Registering",
            ControllerState::Online => "Online",
            ControllerState::Requesting { .. } => "Requesting",
            ControllerState::Offering { .. } => "Offering",
            ControllerState::Connecting { .. } => "Connecting",
            ControllerState::Connected { .. } => "Connected",
            ControllerState::Disconnected { .. } => "Disconnected",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ControllerEvent {
    /// User picked the controller role.
    Start {
        capabilities: Capabilities,
    },
    Registered,
    RegistrationFailed {
        reason: String,
    },
    HeartbeatDue,
    /// User asked to control `host_device_id`. Creates the session id
    /// deterministically (`"{device}-ctrl-{n}"`, role-namespaced — QA F1).
    Connect {
        host_device_id: DeviceId,
    },
    /// Host accepted; carries the one-time session secret.
    AcceptReceived {
        message_id: MessageId,
        session_secret: SessionSecret,
    },
    /// Host rejected.
    RejectReceived {
        message_id: MessageId,
        reason: RejectReason,
    },
    /// Runtime produced the SDP offer (from `Action::ComposeOffer`).
    OfferComposed {
        sdp: String,
    },
    /// Host's SDP answer arrived.
    AnswerReceived {
        message_id: MessageId,
        sdp: String,
    },
    /// Request timeout timer fired.
    RequestTimeout,
    /// Connect timeout timer fired (Offering/Connecting).
    ConnectTimeout,
    /// User withdrew the attempt.
    Cancel,
    /// Simultaneous-call collision: this device's host side and controller
    /// side both have a session toward the same peer (possible in
    /// `Requesting`, `Offering`, and `Connecting` — a peer request can
    /// arrive after our own was already accepted, via mailbox latency or
    /// redelivery). Tie-break on device ids. (QA F2: the whole window is
    /// covered, not just `Requesting`.)
    CollisionDetected {
        peer_device_id: DeviceId,
    },
    /// Trickle ICE candidate from the host (no state change). `sdp_mid` is
    /// the JSEP string mid (protocol version 1, QA F9).
    IceCandidateReceived {
        message_id: MessageId,
        candidate: String,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
    },
    DataChannelOpen,
    /// Host ended the session (`disconnect`).
    DisconnectReceived {
        message_id: MessageId,
        reason: SignalingDisconnectReason,
    },
    TransportFailed {
        reason: String,
    },
    /// User disconnected an established session.
    Disconnect,
}

impl ControllerEvent {
    pub fn name(&self) -> &'static str {
        match self {
            ControllerEvent::Start { .. } => "Start",
            ControllerEvent::Registered => "Registered",
            ControllerEvent::RegistrationFailed { .. } => "RegistrationFailed",
            ControllerEvent::HeartbeatDue => "HeartbeatDue",
            ControllerEvent::Connect { .. } => "Connect",
            ControllerEvent::AcceptReceived { .. } => "AcceptReceived",
            ControllerEvent::RejectReceived { .. } => "RejectReceived",
            ControllerEvent::OfferComposed { .. } => "OfferComposed",
            ControllerEvent::AnswerReceived { .. } => "AnswerReceived",
            ControllerEvent::RequestTimeout => "RequestTimeout",
            ControllerEvent::ConnectTimeout => "ConnectTimeout",
            ControllerEvent::Cancel => "Cancel",
            ControllerEvent::CollisionDetected { .. } => "CollisionDetected",
            ControllerEvent::IceCandidateReceived { .. } => "IceCandidateReceived",
            ControllerEvent::DataChannelOpen => "DataChannelOpen",
            ControllerEvent::DisconnectReceived { .. } => "DisconnectReceived",
            ControllerEvent::TransportFailed { .. } => "TransportFailed",
            ControllerEvent::Disconnect => "Disconnect",
        }
    }

    pub fn message_id(&self) -> Option<&str> {
        match self {
            ControllerEvent::AcceptReceived { message_id, .. }
            | ControllerEvent::RejectReceived { message_id, .. }
            | ControllerEvent::AnswerReceived { message_id, .. }
            | ControllerEvent::IceCandidateReceived { message_id, .. }
            | ControllerEvent::DisconnectReceived { message_id, .. } => Some(message_id),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct ControllerSession {
    state: ControllerState,
    cfg: SessionConfig,
    envelopes: EnvelopeBuilder,
    seen: DedupeLog,
    /// Capabilities registered on `Start`; re-sent in `connect_request`.
    capabilities: Option<Capabilities>,
}

impl ControllerSession {
    pub fn new(device_id: DeviceId, cfg: SessionConfig) -> Self {
        Self {
            state: ControllerState::Idle,
            seen: DedupeLog::new(cfg.dedupe_capacity),
            cfg,
            envelopes: EnvelopeBuilder::new(device_id, IdRole::Controller),
            capabilities: None,
        }
    }

    pub fn state(&self) -> &ControllerState {
        &self.state
    }

    pub fn step(
        &mut self,
        event: ControllerEvent,
        now_ms: u64,
    ) -> Result<Vec<Action>, IllegalTransition> {
        if let Some(id) = event.message_id() {
            if !self.seen.observe(id) {
                return Ok(Vec::new());
            }
        }
        let state_name = self.state.name();
        let event_name = event.name();
        match self.state {
            ControllerState::Idle => match event {
                ControllerEvent::Start { capabilities } => {
                    self.capabilities = Some(capabilities.clone());
                    self.state = ControllerState::Registering;
                    Ok(vec![Action::Send(self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        None,
                        SignalingBody::Register { capabilities },
                        now_ms,
                    ))])
                }
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            ControllerState::Registering => match event {
                ControllerEvent::Registered => {
                    self.state = ControllerState::Online;
                    Ok(Vec::new())
                }
                ControllerEvent::RegistrationFailed { .. } => {
                    self.state = ControllerState::Idle;
                    Ok(Vec::new())
                }
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            ControllerState::Online => match event {
                ControllerEvent::HeartbeatDue => {
                    let env = self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        None,
                        SignalingBody::Heartbeat,
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                ControllerEvent::Connect { host_device_id } => {
                    let Some(capabilities) = self.capabilities.clone() else {
                        // Unreachable: capabilities are set by `Start`, the
                        // only way into Registering → Online.
                        return Err(IllegalTransition::new(state_name, event_name));
                    };
                    let session = ControllerSessionInfo {
                        session_id: self.envelopes.next_local_id(),
                        peer_device_id: host_device_id.clone(),
                        secret: None,
                    };
                    let env = self.envelopes.envelope(
                        &host_device_id,
                        Some(&session.session_id),
                        SignalingBody::ConnectRequest { capabilities },
                        now_ms,
                    );
                    self.state = ControllerState::Requesting {
                        session: session.clone(),
                    };
                    Ok(vec![
                        Action::Send(env),
                        Action::ScheduleTimer {
                            id: TimerId::ControllerRequest,
                            fire_at_ms: now_ms + self.cfg.request_timeout_ms,
                        },
                    ])
                }
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            ControllerState::Requesting { ref session } => match event {
                ControllerEvent::HeartbeatDue => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        Some(&session.session_id),
                        SignalingBody::Heartbeat,
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                ControllerEvent::AcceptReceived { session_secret, .. } => {
                    let mut session = session.clone();
                    session.secret = Some(session_secret);
                    // Nothing is sent on accept: the controller immediately
                    // composes the SDP offer; the Offer message follows.
                    self.state = ControllerState::Offering {
                        session: session.clone(),
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::ControllerRequest,
                        },
                        Action::ComposeOffer,
                        Action::ScheduleTimer {
                            id: TimerId::ControllerConnect,
                            fire_at_ms: now_ms + self.cfg.connect_timeout_ms,
                        },
                    ])
                }
                ControllerEvent::RejectReceived { reason, .. } => {
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::Rejected(reason),
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::ControllerRequest,
                        },
                        Action::SessionEnded {
                            cause: DisconnectCause::Rejected(reason),
                        },
                    ])
                }
                ControllerEvent::RequestTimeout => {
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::Timeout,
                    };
                    // ReconnectPolicy placeholder: MVP never auto-retries
                    // (cfg.reconnect.max_attempts == 0); M5 replaces this
                    // comment with policy-driven actions.
                    Ok(vec![Action::SessionEnded {
                        cause: DisconnectCause::Timeout,
                    }])
                }
                ControllerEvent::Cancel => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Cancel {
                            reason: CancelReason::User,
                        },
                        now_ms,
                    );
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::Canceled,
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::ControllerRequest,
                        },
                        Action::Send(env),
                        Action::SessionEnded {
                            cause: DisconnectCause::Canceled,
                        },
                    ])
                }
                ControllerEvent::CollisionDetected { peer_device_id } => self.resolve_collision(
                    state_name,
                    event_name,
                    &peer_device_id,
                    TimerId::ControllerRequest,
                    now_ms,
                ),
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            ControllerState::Offering { ref session } => match event {
                ControllerEvent::HeartbeatDue => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        Some(&session.session_id),
                        SignalingBody::Heartbeat,
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                ControllerEvent::OfferComposed { sdp } => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Offer { sdp },
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                ControllerEvent::AnswerReceived { .. } => {
                    let session = session.clone();
                    self.state = ControllerState::Connecting {
                        session: session.clone(),
                    };
                    // The runtime applies the SDP answer to the transport;
                    // it already holds the event payload.
                    Ok(Vec::new())
                }
                ControllerEvent::RejectReceived { reason, .. } => {
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::Rejected(reason),
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::ControllerConnect,
                        },
                        Action::SessionEnded {
                            cause: DisconnectCause::Rejected(reason),
                        },
                    ])
                }
                ControllerEvent::ConnectTimeout => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Disconnect {
                            reason: SignalingDisconnectReason::Timeout,
                        },
                        now_ms,
                    );
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::Timeout,
                    };
                    Ok(vec![
                        Action::Send(env),
                        Action::SessionEnded {
                            cause: DisconnectCause::Timeout,
                        },
                    ])
                }
                ControllerEvent::Cancel => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Cancel {
                            reason: CancelReason::User,
                        },
                        now_ms,
                    );
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::Canceled,
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::ControllerConnect,
                        },
                        Action::Send(env),
                        Action::SessionEnded {
                            cause: DisconnectCause::Canceled,
                        },
                    ])
                }
                ControllerEvent::DisconnectReceived { .. } => {
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::Peer,
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::ControllerConnect,
                        },
                        Action::SessionEnded {
                            cause: DisconnectCause::Peer,
                        },
                    ])
                }
                ControllerEvent::IceCandidateReceived {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                    ..
                } => Ok(vec![Action::ForwardIce {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                }]),
                // QA F2: a peer's request can reach our host after our own
                // request was already accepted (mailbox latency/redelivery).
                // Same tie-break as in `Requesting`; the loser abandons its
                // accepted session in favor of its host role.
                ControllerEvent::CollisionDetected { peer_device_id } => self.resolve_collision(
                    state_name,
                    event_name,
                    &peer_device_id,
                    TimerId::ControllerConnect,
                    now_ms,
                ),
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            ControllerState::Connecting { ref session } => match event {
                ControllerEvent::HeartbeatDue => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        Some(&session.session_id),
                        SignalingBody::Heartbeat,
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                ControllerEvent::DataChannelOpen => {
                    let session = session.clone();
                    self.state = ControllerState::Connected {
                        session: session.clone(),
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::ControllerConnect,
                        },
                        Action::StartRendering,
                        Action::SessionEstablished {
                            session_id: session.session_id,
                        },
                    ])
                }
                ControllerEvent::ConnectTimeout => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Disconnect {
                            reason: SignalingDisconnectReason::Timeout,
                        },
                        now_ms,
                    );
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::Timeout,
                    };
                    Ok(vec![
                        Action::Send(env),
                        Action::SessionEnded {
                            cause: DisconnectCause::Timeout,
                        },
                    ])
                }
                ControllerEvent::Cancel => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Cancel {
                            reason: CancelReason::User,
                        },
                        now_ms,
                    );
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::Canceled,
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::ControllerConnect,
                        },
                        Action::Send(env),
                        Action::SessionEnded {
                            cause: DisconnectCause::Canceled,
                        },
                    ])
                }
                ControllerEvent::DisconnectReceived { .. } => {
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::Peer,
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::ControllerConnect,
                        },
                        Action::SessionEnded {
                            cause: DisconnectCause::Peer,
                        },
                    ])
                }
                ControllerEvent::TransportFailed { .. } => {
                    let session = session.clone();
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Disconnect {
                            reason: SignalingDisconnectReason::TransportError,
                        },
                        now_ms,
                    );
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::TransportError,
                    };
                    Ok(vec![
                        Action::CancelTimer {
                            id: TimerId::ControllerConnect,
                        },
                        Action::Send(env),
                        Action::SessionEnded {
                            cause: DisconnectCause::TransportError,
                        },
                    ])
                }
                ControllerEvent::IceCandidateReceived {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                    ..
                } => Ok(vec![Action::ForwardIce {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                }]),
                // QA F2: same tie-break as Requesting/Offering; the loser
                // cancels its in-flight connection attempt.
                ControllerEvent::CollisionDetected { peer_device_id } => self.resolve_collision(
                    state_name,
                    event_name,
                    &peer_device_id,
                    TimerId::ControllerConnect,
                    now_ms,
                ),
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            ControllerState::Connected { .. } => match event {
                ControllerEvent::HeartbeatDue => {
                    let session = self.session_info().cloned().expect("state matched");
                    let env = self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        Some(&session.session_id),
                        SignalingBody::Heartbeat,
                        now_ms,
                    );
                    Ok(vec![Action::Send(env)])
                }
                ControllerEvent::Disconnect => {
                    let session = self.session_info().cloned().expect("state matched");
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Disconnect {
                            reason: SignalingDisconnectReason::User,
                        },
                        now_ms,
                    );
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::User,
                    };
                    Ok(vec![
                        Action::StopRendering,
                        Action::Send(env),
                        Action::SessionEnded {
                            cause: DisconnectCause::User,
                        },
                    ])
                }
                ControllerEvent::DisconnectReceived { .. } => {
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::Peer,
                    };
                    Ok(vec![
                        Action::StopRendering,
                        Action::SessionEnded {
                            cause: DisconnectCause::Peer,
                        },
                    ])
                }
                ControllerEvent::TransportFailed { .. } => {
                    let session = self.session_info().cloned().expect("state matched");
                    let env = self.envelopes.envelope(
                        &session.peer_device_id,
                        Some(&session.session_id),
                        SignalingBody::Disconnect {
                            reason: SignalingDisconnectReason::TransportError,
                        },
                        now_ms,
                    );
                    self.state = ControllerState::Disconnected {
                        cause: DisconnectCause::TransportError,
                    };
                    Ok(vec![
                        Action::StopRendering,
                        Action::Send(env),
                        Action::SessionEnded {
                            cause: DisconnectCause::TransportError,
                        },
                    ])
                }
                ControllerEvent::IceCandidateReceived {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                    ..
                } => Ok(vec![Action::ForwardIce {
                    candidate,
                    sdp_mid,
                    sdp_mline_index,
                }]),
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },

            ControllerState::Disconnected { .. } => match event {
                ControllerEvent::Start { capabilities } => {
                    self.capabilities = Some(capabilities.clone());
                    self.state = ControllerState::Registering;
                    Ok(vec![Action::Send(self.envelopes.envelope(
                        SIGNALING_SERVICE_ID,
                        None,
                        SignalingBody::Register { capabilities },
                        now_ms,
                    ))])
                }
                // Post-mortem tolerance: session traffic that raced our own
                // timeout/teardown (a late reject, a late answer, a stale
                // disconnect) is dropped, not treated as a violation.
                ControllerEvent::AcceptReceived { .. }
                | ControllerEvent::RejectReceived { .. }
                | ControllerEvent::AnswerReceived { .. }
                | ControllerEvent::IceCandidateReceived { .. }
                | ControllerEvent::DisconnectReceived { .. } => Ok(Vec::new()),
                _ => Err(IllegalTransition::new(state_name, event_name)),
            },
        }
    }

    /// Simultaneous-call tie-break: the lexicographically smaller device id
    /// keeps the controller role. Legal in `Requesting`, `Offering`, and
    /// `Connecting`; `timer_to_cancel` is the timer active in that state.
    /// The loser cancels its outbound attempt/session with
    /// `reason: "collision"` and goes `Disconnected{Collision}` — abandoning
    /// its own controller side in favor of its host side. The winner does
    /// nothing and keeps its state (its host side will reject or prompt for
    /// the loser's request as usual; the loser's cancel cleans any prompt).
    fn resolve_collision(
        &mut self,
        state_name: &'static str,
        event_name: &'static str,
        peer_device_id: &str,
        timer_to_cancel: TimerId,
        now_ms: u64,
    ) -> Result<Vec<Action>, IllegalTransition> {
        let we_keep_controller_role = self.envelopes.device_id() < peer_device_id;
        if we_keep_controller_role {
            Ok(Vec::new())
        } else {
            let session = match self.session_info().cloned() {
                Some(session) => session,
                None => return Err(IllegalTransition::new(state_name, event_name)),
            };
            let env = self.envelopes.envelope(
                &session.peer_device_id,
                Some(&session.session_id),
                SignalingBody::Cancel {
                    reason: CancelReason::Collision,
                },
                now_ms,
            );
            self.state = ControllerState::Disconnected {
                cause: DisconnectCause::Collision,
            };
            Ok(vec![
                Action::CancelTimer {
                    id: timer_to_cancel,
                },
                Action::Send(env),
                Action::SessionEnded {
                    cause: DisconnectCause::Collision,
                },
            ])
        }
    }

    fn session_info(&self) -> Option<&ControllerSessionInfo> {
        match &self.state {
            ControllerState::Requesting { session }
            | ControllerState::Offering { session }
            | ControllerState::Connecting { session }
            | ControllerState::Connected { session } => Some(session),
            _ => None,
        }
    }

    /// Test-only state injection for the illegal-transition table.
    #[cfg(test)]
    pub(crate) fn force_state(&mut self, state: ControllerState) {
        self.state = state;
    }

    /// Test-only capability injection (normally set by `Start`).
    #[cfg(test)]
    pub(crate) fn force_capabilities(&mut self, capabilities: Capabilities) {
        self.capabilities = Some(capabilities);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine() -> ControllerSession {
        ControllerSession::new("ctrl-a".to_owned(), SessionConfig::default())
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

    fn session() -> ControllerSessionInfo {
        ControllerSessionInfo {
            session_id: "ctrl-a-1".to_owned(),
            peer_device_id: "host-b".to_owned(),
            secret: None,
        }
    }

    fn state_samples() -> Vec<ControllerState> {
        vec![
            ControllerState::Idle,
            ControllerState::Registering,
            ControllerState::Online,
            ControllerState::Requesting { session: session() },
            ControllerState::Offering { session: session() },
            ControllerState::Connecting { session: session() },
            ControllerState::Connected { session: session() },
            ControllerState::Disconnected {
                cause: DisconnectCause::User,
            },
        ]
    }

    fn event_samples() -> Vec<ControllerEvent> {
        vec![
            ControllerEvent::Start {
                capabilities: caps(),
            },
            ControllerEvent::Registered,
            ControllerEvent::RegistrationFailed {
                reason: "rate".to_owned(),
            },
            ControllerEvent::HeartbeatDue,
            ControllerEvent::Connect {
                host_device_id: "host-b".to_owned(),
            },
            ControllerEvent::AcceptReceived {
                message_id: "e1".to_owned(),
                session_secret: SessionSecret("s".to_owned()),
            },
            ControllerEvent::RejectReceived {
                message_id: "e2".to_owned(),
                reason: RejectReason::Declined,
            },
            ControllerEvent::OfferComposed {
                sdp: "offer".to_owned(),
            },
            ControllerEvent::AnswerReceived {
                message_id: "e3".to_owned(),
                sdp: "answer".to_owned(),
            },
            ControllerEvent::RequestTimeout,
            ControllerEvent::ConnectTimeout,
            ControllerEvent::Cancel,
            ControllerEvent::CollisionDetected {
                peer_device_id: "host-b".to_owned(),
            },
            ControllerEvent::IceCandidateReceived {
                message_id: "e4".to_owned(),
                candidate: "candidate:1".to_owned(),
                sdp_mid: Some("0".to_owned()),
                sdp_mline_index: Some(0),
            },
            ControllerEvent::DataChannelOpen,
            ControllerEvent::DisconnectReceived {
                message_id: "e5".to_owned(),
                reason: SignalingDisconnectReason::User,
            },
            ControllerEvent::TransportFailed {
                reason: "ice".to_owned(),
            },
            ControllerEvent::Disconnect,
        ]
    }

    /// Documented legal table. Note: `CollisionDetected` is legal in
    /// `Requesting`/`Offering`/`Connecting` but its outcome depends on the
    /// device-id tie-break, so the table test only asserts `is_ok()` for it.
    fn legal_pairs() -> Vec<(&'static str, &'static str)> {
        vec![
            ("Idle", "Start"),
            ("Registering", "Registered"),
            ("Registering", "RegistrationFailed"),
            ("Online", "HeartbeatDue"),
            ("Online", "Connect"),
            ("Requesting", "HeartbeatDue"),
            ("Requesting", "AcceptReceived"),
            ("Requesting", "RejectReceived"),
            ("Requesting", "RequestTimeout"),
            ("Requesting", "Cancel"),
            ("Requesting", "CollisionDetected"),
            ("Offering", "HeartbeatDue"),
            ("Offering", "OfferComposed"),
            ("Offering", "AnswerReceived"),
            ("Offering", "RejectReceived"),
            ("Offering", "ConnectTimeout"),
            ("Offering", "Cancel"),
            ("Offering", "DisconnectReceived"),
            ("Offering", "IceCandidateReceived"),
            ("Offering", "CollisionDetected"),
            ("Connecting", "HeartbeatDue"),
            ("Connecting", "DataChannelOpen"),
            ("Connecting", "ConnectTimeout"),
            ("Connecting", "Cancel"),
            ("Connecting", "DisconnectReceived"),
            ("Connecting", "TransportFailed"),
            ("Connecting", "IceCandidateReceived"),
            ("Connecting", "CollisionDetected"),
            ("Connected", "HeartbeatDue"),
            ("Connected", "Disconnect"),
            ("Connected", "DisconnectReceived"),
            ("Connected", "TransportFailed"),
            ("Connected", "IceCandidateReceived"),
            // Post-mortem tolerance: late session traffic in Disconnected.
            ("Disconnected", "Start"),
            ("Disconnected", "AcceptReceived"),
            ("Disconnected", "RejectReceived"),
            ("Disconnected", "AnswerReceived"),
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
                m.force_capabilities(caps());
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
        // Sanity: the table is not vacuous (136 combinations, 37 legal).
        assert!(
            illegal_count >= 80,
            "only {illegal_count} illegal pairs found"
        );
    }

    #[test]
    fn duplicate_accept_is_a_no_op() {
        let mut m = machine();
        m.force_state(ControllerState::Requesting { session: session() });
        let accept = ControllerEvent::AcceptReceived {
            message_id: "dup-1".to_owned(),
            session_secret: SessionSecret("s".to_owned()),
        };
        m.step(accept.clone(), 10).expect("legal");
        assert!(matches!(m.state(), ControllerState::Offering { .. }));
        let actions = m.step(accept, 11).expect("duplicates are Ok(empty)");
        assert!(actions.is_empty());
        assert!(matches!(m.state(), ControllerState::Offering { .. }));
    }

    #[test]
    fn collision_tie_break_is_deterministic_by_device_id() {
        // "ctrl-a" < "host-b": we keep the controller role, no action.
        let mut winner = ControllerSession::new("ctrl-a".to_owned(), SessionConfig::default());
        winner.force_state(ControllerState::Requesting { session: session() });
        let actions = winner
            .step(
                ControllerEvent::CollisionDetected {
                    peer_device_id: "host-b".to_owned(),
                },
                10,
            )
            .unwrap();
        assert!(actions.is_empty());
        assert_eq!(winner.state().name(), "Requesting");

        // "host-b" > "ctrl-a": we lose; cancel with reason "collision".
        let mut loser = ControllerSession::new("host-b".to_owned(), SessionConfig::default());
        loser.force_state(ControllerState::Requesting {
            session: ControllerSessionInfo {
                session_id: "host-b-1".to_owned(),
                peer_device_id: "ctrl-a".to_owned(),
                secret: None,
            },
        });
        let actions = loser
            .step(
                ControllerEvent::CollisionDetected {
                    peer_device_id: "ctrl-a".to_owned(),
                },
                10,
            )
            .unwrap();
        assert!(matches!(
            loser.state(),
            ControllerState::Disconnected {
                cause: DisconnectCause::Collision
            }
        ));
        assert!(
            actions.contains(&Action::Send(protocol::signaling::SignalingEnvelope {
                protocol_version: protocol::signaling::SIGNALING_PROTOCOL_VERSION,
                message_id: "host-b-ctrl-1".to_owned(),
                session_id: Some("host-b-1".to_owned()),
                from_device_id: "host-b".to_owned(),
                to_device_id: "ctrl-a".to_owned(),
                timestamp_ms: 10,
                body: SignalingBody::Cancel {
                    reason: CancelReason::Collision
                },
            }))
        );
    }

    /// QA F2: a peer's request arriving *after* our own request was accepted
    /// (states `Offering`/`Connecting`) must hit the same tie-break — loser
    /// cancels its accepted session, winner continues — never an
    /// `IllegalTransition` and never a second parallel session.
    #[test]
    fn collision_after_accept_hits_the_same_tie_break() {
        let make_offering = |s: ControllerSessionInfo| ControllerState::Offering { session: s };
        let make_connecting = |s: ControllerSessionInfo| ControllerState::Connecting { session: s };
        for make_state in [make_offering, make_connecting] {
            // Winner ("ctrl-a" < "host-b"): no action, state unchanged.
            let winner_session = ControllerSessionInfo {
                session_id: "s1".to_owned(),
                peer_device_id: "host-b".to_owned(),
                secret: None,
            };
            let mut winner = machine();
            winner.force_state(make_state(winner_session));
            let actions = winner
                .step(
                    ControllerEvent::CollisionDetected {
                        peer_device_id: "host-b".to_owned(),
                    },
                    10,
                )
                .unwrap();
            let winner_state = winner.state().name().to_owned();
            assert!(actions.is_empty(), "winner must not act in {winner_state}");
            assert_eq!(winner.state().name(), winner_state);

            // Loser ("host-b" > "ctrl-a"): cancel with reason "collision",
            // connect timer canceled, session ended.
            let loser_session = ControllerSessionInfo {
                session_id: "s2".to_owned(),
                peer_device_id: "ctrl-a".to_owned(),
                secret: None,
            };
            let mut loser = ControllerSession::new("host-b".to_owned(), SessionConfig::default());
            loser.force_state(make_state(loser_session));
            let actions = loser
                .step(
                    ControllerEvent::CollisionDetected {
                        peer_device_id: "ctrl-a".to_owned(),
                    },
                    10,
                )
                .unwrap();
            assert!(matches!(
                loser.state(),
                ControllerState::Disconnected {
                    cause: DisconnectCause::Collision
                }
            ));
            assert!(actions.contains(&Action::CancelTimer {
                id: TimerId::ControllerConnect
            }));
            assert!(actions.iter().any(|a| matches!(
                a,
                Action::Send(env)
                    if matches!(env.body, SignalingBody::Cancel { reason: CancelReason::Collision })
                        && env.to_device_id == "ctrl-a"
            )));
            assert!(actions.contains(&Action::SessionEnded {
                cause: DisconnectCause::Collision
            }));
        }
    }

    #[test]
    fn connect_creates_deterministic_session_id_and_request_timer() {
        let mut m = machine();
        m.step(
            ControllerEvent::Start {
                capabilities: caps(),
            },
            0,
        )
        .unwrap();
        m.step(ControllerEvent::Registered, 1).unwrap();
        let actions = m
            .step(
                ControllerEvent::Connect {
                    host_device_id: "host-b".to_owned(),
                },
                100,
            )
            .unwrap();
        let session_id = match m.state() {
            ControllerState::Requesting { session } => session.session_id.clone(),
            other => panic!("expected Requesting, got {other:?}"),
        };
        assert_eq!(
            session_id, "ctrl-a-ctrl-2",
            "session id reuses the id counter"
        );
        match actions.as_slice() {
            [Action::Send(env), Action::ScheduleTimer { id, fire_at_ms }] => {
                assert!(matches!(env.body, SignalingBody::ConnectRequest { .. }));
                assert_eq!(env.session_id.as_deref(), Some(session_id.as_str()));
                assert_eq!(*id, TimerId::ControllerRequest);
                assert_eq!(*fire_at_ms, 100 + 10_000);
            }
            other => panic!("unexpected actions {other:?}"),
        }
    }

    #[test]
    fn reject_ends_session_with_typed_cause() {
        let mut m = machine();
        m.force_state(ControllerState::Requesting { session: session() });
        m.step(
            ControllerEvent::RejectReceived {
                message_id: "r".to_owned(),
                reason: RejectReason::Declined,
            },
            10,
        )
        .unwrap();
        assert!(matches!(
            m.state(),
            ControllerState::Disconnected {
                cause: DisconnectCause::Rejected(RejectReason::Declined)
            }
        ));
    }
}
