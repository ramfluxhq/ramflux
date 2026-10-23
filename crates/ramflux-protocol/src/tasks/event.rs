// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Common signed event framing and verification against caller-pinned identities.
use super::{TaskEventBody, TaskReject};
use crate::{
    ActorType, Ext, ProtocolObject, SignedFields, canonical_json_bytes, domain, hash_base64url,
    signed_bytes, verify_signed_fields,
};
use serde::{Deserialize, Serialize};
pub const TASK_EVENT_SCHEMA: &str = "ramflux.task_event.v1";

/// One task event, including signed conversation context for every operation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskEvent {
    pub schema: String,
    pub version: u32,
    pub domain: String,
    #[serde(flatten)]
    pub ext: Ext,
    #[serde(flatten)]
    pub signed: SignedFields,
    pub conversation_id: String,
    pub event: TaskEventBody,
}

/// Caller-pinned key/identity/role, never taken from the untrusted event.
/// Callers must also authorize this participant's conversation membership and verify any
/// referenced grant/surface decision (including its target, outcome and single-use policy).
#[derive(Clone, Debug)]
pub struct TaskSigner<'a> {
    pub principal_id: &'a str,
    pub actor_type: ActorType,
    pub signing_key_id: &'a str,
    pub public_key_base64url: &'a str,
}
impl TaskEvent {
    #[must_use]
    pub fn new(conversation_id: String, event: TaskEventBody, signed: SignedFields) -> Self {
        Self {
            schema: TASK_EVENT_SCHEMA.to_owned(),
            version: 1,
            domain: domain::TASK_EVENT.to_owned(),
            ext: Ext::default(),
            signed,
            conversation_id,
            event,
        }
    }
    /// Canonical signing bytes using the existing domain-bearing protocol representation.
    /// # Errors
    /// Rejects invalid framing, limits, extensions or serialization.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TaskReject> {
        self.validate()?;
        Ok(signed_bytes(self)?)
    }
    /// Verifies the event with the caller's authenticated principal/key binding.
    /// # Errors
    /// Rejects invalid framing, limits, key ids, or Ed25519 signatures.
    pub fn verify(&self, signer: &TaskSigner<'_>) -> Result<(), TaskReject> {
        self.validate()?;
        if signer.principal_id.is_empty() || self.signed.signing_key_id != signer.signing_key_id {
            return Err(TaskReject::WrongSigner);
        }
        verify_signed_fields(self, &self.signed, signer.public_key_base64url)
            .map_err(|_| TaskReject::InvalidSignature)
    }
}
impl ProtocolObject for TaskEvent {
    fn domain(&self) -> &'static str {
        domain::TASK_EVENT
    }
    fn replay_key(&self) -> Option<String> {
        canonical_json_bytes(&(&self.conversation_id, self.event.task_id(), self.event.version()))
            .ok()
            .map(|bytes| hash_base64url(domain::TASK_EVENT, &bytes))
    }
}
