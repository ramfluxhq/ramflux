// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Account-owned surfaces in authenticated conversation messages, independent of pair sessions.
mod authored;
mod backfill;
pub(crate) mod carrier;
mod control;
mod control_context;
mod decision;
mod group;
mod logical;
mod own_checkpoint;
mod own_history;
pub(crate) use control::{ControlKind, OwnContext, SurfaceControl};
pub(crate) use logical::SurfaceLogicalJob;
pub(crate) use own_checkpoint::OwnedSurfaceCheckpoint;
pub(crate) use own_history::{SurfaceExportMetadata, SurfaceHistoryExport};
mod delivery;
mod fallback;
mod origin;
mod pending;
mod persist;
mod projection;
mod read;
mod scope;
mod snapshot;
mod task_decision;
pub(crate) use carrier::{Carrier, Payload, PayloadKind, command_id, invalid};
pub(crate) use read::surface_metadata;
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub(crate) use snapshot::SnapshotProof;
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredSurface {
    pub surface_id: String,
    pub conversation_id: String,
    pub author_principal_id: String,
    pub author_device_id: String,
    pub checkpoint_base64: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Receipt {
    pub fingerprint: String,
    pub result: Outcome,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Outcome {
    pub accepted: bool,
    pub fallback_text: String,
    pub renderer_error: Option<Value>,
    #[serde(default)]
    pub retryable: bool,
    #[serde(default)]
    pub queued: bool,
}
impl Outcome {
    fn accepted(
        author: &str,
        state: &ramflux_protocol::SurfaceState,
    ) -> Result<Self, crate::SdkError> {
        let content = state.content().ok_or_else(|| invalid("surface content absent"))?;
        Ok(Self {
            accepted: true,
            fallback_text: fallback::render(author, &content.fallback_text),
            renderer_error: None,
            retryable: false,
            queued: false,
        })
    }

    fn protocol_rejected(error: &ramflux_protocol::SurfaceReject) -> Self {
        let retryable = matches!(error, ramflux_protocol::SurfaceReject::NotCreated)
            || matches!(error,ramflux_protocol::SurfaceReject::Version { expected, actual } if actual>expected);
        let mut outcome =
            Self::rejected(serde_json::json!({"code":"renderer_error","reject":error}));
        outcome.retryable = retryable;
        outcome
    }
    pub(crate) fn rejected(error: Value) -> Self {
        Self {
            accepted: false,
            fallback_text: "[Surface rejected]".into(),
            renderer_error: Some(error),
            retryable: false,
            queued: false,
        }
    }
}
pub(crate) fn key(prefix: &str, id: &str) -> String {
    format!(
        "surface/{prefix}/{}",
        ramflux_protocol::hash_base64url("ramflux.surface.storage_key.v1", id.as_bytes())
    )
}
pub(crate) fn scoped_key(prefix: &str, parts: &[&str]) -> Result<String, crate::SdkError> {
    Ok(key(prefix, &serde_json::to_string(parts)?))
}

#[cfg(test)]
mod tests;

#[derive(Clone, Copy)]
pub(crate) struct SurfaceSender<'a> {
    pub principal: &'a str,
    pub device: &'a str,
    pub envelope_id: &'a str,
    pub expires_at: Option<i64>,
    pub group_epoch: Option<u64>,
}

pub(super) fn receipt_key(carrier: &Carrier) -> Result<String, crate::SdkError> {
    scoped_key(
        "receipt_v2",
        &[&carrier.surface_reference()?, &carrier.sender_principal_id, &carrier.message_id],
    )
}
