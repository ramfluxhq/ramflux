// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Opaque original-byte ingress and signing against caller-pinned identity/role bindings.
use super::{MAX_TASK_EVENT_BYTES, TaskEventBody, TaskReject};
use crate::{
    ActorType, Ext, ProtocolObject, SignedFields, canonical_json_bytes, domain, hash_base64url,
    signed_bytes, verify_signed_fields,
};
use serde::{Deserialize, Serialize};
pub const TASK_EVENT_SCHEMA: &str = "ramflux.task_event.v1";
/// Validated framing. Only original bytes enter through `from_wire_bytes`; builders are for
/// trusted local typed data. Signature/authority still require `verify`/`TaskState::apply`.
/// ```compile_fail
/// use ramflux_protocol::TaskEvent;
/// let value:serde_json::Value=serde_json::from_str(r#"{"x":1,"x":2}"#).unwrap();
/// let event=serde_json::from_value::<TaskEvent>(value).unwrap();
/// ```
/// ```compile_fail
/// use ramflux_protocol::TaskEvent;
/// let event=serde_json::from_slice::<TaskEvent>(b"{}").unwrap();
/// ```
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct TaskEvent(EventFields);
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct EventFields {
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
/// Trusted caller-owned mapping from the authenticated current device key to principal and
/// account role. Neither principal nor role may be inferred from untrusted event content.
/// The caller also verifies conversation membership and external decision binding/single use.
#[derive(Clone, Debug)]
pub struct TaskSigner<'a> {
    pub principal_id: &'a str,
    pub actor_type: ActorType,
    pub signing_key_id: &'a str,
    pub public_key_base64url: &'a str,
}
impl TaskEvent {
    /// Original UTF-8 JSON ingress, capped before parsing and checked by the shared I-JSON parser.
    /// # Errors
    /// Rejects oversized bytes, duplicate members, non-I-JSON content, framing or payload limits.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, TaskReject> {
        if bytes.len() > MAX_TASK_EVENT_BYTES {
            return Err(TaskReject::EventTooLarge);
        }
        let event = Self(crate::parse_i_json(bytes)?);
        event.validate()?;
        Ok(event)
    }
    /// Constructs a local event from trusted typed fields; use byte ingress for received data.
    /// # Errors
    /// Rejects invalid framing, I-JSON or payload limits.
    pub fn new(
        conversation_id: String,
        event: TaskEventBody,
        signed: SignedFields,
    ) -> Result<Self, TaskReject> {
        Self(EventFields {
            schema: TASK_EVENT_SCHEMA.into(),
            version: 1,
            domain: domain::TASK_EVENT.into(),
            ext: Ext::default(),
            signed,
            conversation_id,
            event,
        })
        .checked()
    }
    fn checked(self) -> Result<Self, TaskReject> {
        self.validate()?;
        let value = serde_json::to_value(&self).map_err(crate::ProtocolError::from)?;
        crate::validate_i_json_value(&value)?;
        Ok(self)
    }
    /// Adds locally constructed extensions without exposing mutable wire fields.
    /// # Errors
    /// Rejects non-I-JSON, critical extensions or size/field violations.
    pub fn with_extensions(mut self, ext: Ext) -> Result<Self, TaskReject> {
        self.0.ext = ext;
        self.checked()
    }
    /// Attaches a detached signature without changing the validated signed content.
    /// # Errors
    /// Rejects invalid text or an oversized complete event. Cryptographic verification is separate.
    pub fn with_signature(mut self, signature: String) -> Result<Self, TaskReject> {
        self.0.signed.signature = signature;
        self.checked()
    }
    #[must_use]
    pub fn conversation_id(&self) -> &str {
        &self.0.conversation_id
    }
    #[must_use]
    pub const fn event(&self) -> &TaskEventBody {
        &self.0.event
    }
    #[must_use]
    pub const fn signed(&self) -> &SignedFields {
        &self.0.signed
    }
    #[must_use]
    pub const fn extensions(&self) -> &Ext {
        &self.0.ext
    }
    pub(super) const fn fields(&self) -> &EventFields {
        &self.0
    }
    /// Canonical bytes for signing with the existing domain-bearing protocol representation.
    /// # Errors
    /// Rejects framing, limits, extensions or serialization.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TaskReject> {
        self.validate()?;
        Ok(signed_bytes(self)?)
    }
    /// Verifies against the caller's authenticated key/principal/role binding.
    /// # Errors
    /// Rejects framing, key ids or Ed25519 signatures.
    pub fn verify(&self, signer: &TaskSigner<'_>) -> Result<(), TaskReject> {
        self.validate()?;
        if signer.principal_id.is_empty() || self.0.signed.signing_key_id != signer.signing_key_id {
            return Err(TaskReject::WrongSigner);
        }
        verify_signed_fields(self, &self.0.signed, signer.public_key_base64url)
            .map_err(|_| TaskReject::InvalidSignature)
    }
}
impl ProtocolObject for TaskEvent {
    fn domain(&self) -> &'static str {
        domain::TASK_EVENT
    }
    fn replay_key(&self) -> Option<String> {
        canonical_json_bytes(&(
            self.conversation_id(),
            self.event().task_id(),
            self.event().kind(),
            &self.signed().signing_key_id,
            self.event(),
        ))
        .ok()
        .map(|bytes| hash_base64url(domain::TASK_EVENT, &bytes))
    }
}
