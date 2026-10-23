// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed task carriers and account-owned task projections in encrypted conversations.
pub(crate) mod carrier;
mod projection;
use crate::SdkError;
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AcceptedEvent {
    pub carrier: carrier::Carrier,
    pub public_key: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub(crate) struct TaskHistory {
    pub events: Vec<AcceptedEvent>,
    pub created_at: i64,
    pub updated_at: i64,
}
pub(crate) fn key(kind: &str, id: &str) -> String {
    format!(
        "task/{kind}/{}",
        ramflux_protocol::hash_base64url("ramflux.task.storage.v1", id.as_bytes())
    )
}
pub(crate) fn invalid(message: impl Into<String>) -> SdkError {
    SdkError::LocalBus(message.into())
}
