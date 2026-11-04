// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Public session observations are independent of account writer access and registration state.

use crate::{AccountNetworkingReason, GatewaySessionTransportKind};
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NetworkingState {
    Live,
    NetworkingPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConnectionPhase {
    Connecting,
    Live,
    Backoff,
    Stopped,
}

#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct NetworkingSnapshot {
    pub state: NetworkingState,
    pub phase: ConnectionPhase,
    pub generation: u64,
    pub attempt: u64,
    #[serde(skip)]
    pub attempt_started: Option<Instant>,
    pub attempt_started_at_ms: Option<u64>,
    pub next_retry_at_ms: Option<u64>,
    pub retry_after_ms: Option<u64>,
    pub last_reason: Option<String>,
    pub cause: Option<AccountNetworkingReason>,
    pub active_transport_kind: Option<GatewaySessionTransportKind>,
    pub session_id: Option<String>,
}

impl NetworkingSnapshot {
    pub(super) fn pending(generation: u64) -> Self {
        Self {
            state: NetworkingState::NetworkingPending,
            phase: ConnectionPhase::Connecting,
            generation,
            attempt: 0,
            attempt_started: None,
            attempt_started_at_ms: None,
            next_retry_at_ms: None,
            retry_after_ms: None,
            last_reason: None,
            cause: None,
            active_transport_kind: None,
            session_id: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DisconnectReason {
    Drain,
    Close,
    UnexpectedReply,
    CallTimeout,
    CallerCancelled,
    Transport,
    Lock,
    Stop,
    Restart,
}

#[derive(Clone, Debug)]
pub(crate) enum ConnectionEvent {
    Connected { session_id: String, resumed: bool, generation: u64 },
    Disconnected { reason: DisconnectReason, generation: u64 },
    AttemptFailed { reason: String, retry_after_ms: Option<u64>, generation: u64 },
}
