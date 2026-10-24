// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Signed task carriers and account-owned task projections in encrypted conversations.
mod authority;
pub(crate) mod carrier;
pub(crate) mod certificate;
pub(crate) mod control;
pub(crate) mod decision;
mod intervention;
pub(crate) mod pending;
mod projection;
pub(crate) use authority::require_local_human;
pub(crate) mod own_history;
mod read;
use crate::SdkError;
pub(crate) use projection::Delivery;
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AcceptedEvent {
    pub carrier: carrier::Carrier,
    pub public_key: String,
    #[serde(default)]
    pub actor_kind_verified: bool,
    #[serde(default)]
    pub received_at: i64,
    #[serde(default)]
    pub decision_certificate: Option<certificate::Certificate>,
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

pub(crate) fn scoped(kind: &str, conversation: &str, id: &str) -> Result<String, SdkError> {
    Ok(key(kind, &serde_json::to_string(&(conversation, id))?))
}

pub(crate) fn timeline_id(carrier: &carrier::Carrier) -> Result<String, SdkError> {
    scoped(
        "timeline",
        &carrier.conversation_id,
        &serde_json::to_string(&(&carrier.principal_id, &carrier.message_id))?,
    )
}

#[cfg(test)]
mod tests;

/// Conservative budget for nested encrypted JSON frames, including bootstrap overhead.
pub(crate) const MAX_DELIVERY_BYTES: usize =
    (ramflux_transport::MAX_GATEWAY_FRAME_BYTES - 64 * 1024) / 32;
pub(crate) fn check_delivery_size(bytes: usize) -> Result<(), SdkError> {
    if bytes > MAX_DELIVERY_BYTES {
        return Err(SdkError::TaskDeliveryTooLarge { bytes, limit: MAX_DELIVERY_BYTES });
    }
    Ok(())
}
