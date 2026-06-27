// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use serde::{Deserialize, Serialize};

use crate::ClientEvent;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CursorState {
    Accepted,
    PendingMissingDependency,
    PendingUnknownEpoch,
    RejectedReplay,
    RejectedEpochRollback,
    RejectedInvalidSignature,
    QuarantinedRejectedInbox,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventOrderingState {
    Accepted,
    PendingMissingDependency,
    PendingUnknownEpoch,
    RejectedReplay,
    RejectedEpochRollback,
    RejectedInvalidSignature,
    ConflictPending,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupEpochState {
    Known,
    PendingUnknownEpoch,
    RejectedEpochRollback,
    ConflictPending,
    SupersededTransition,
    CanonicalProjection,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EventSortKey {
    pub lamport_time: u64,
    pub actor_device_id: String,
    pub event_id: String,
}

#[must_use]
pub fn event_sort_key<T>(event: &ClientEvent<T>) -> EventSortKey {
    EventSortKey {
        lamport_time: event.lamport_time,
        actor_device_id: event.actor_device_id.clone(),
        event_id: event.event_id.clone(),
    }
}
