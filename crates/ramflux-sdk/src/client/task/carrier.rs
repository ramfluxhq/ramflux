// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact signed task wire bytes with signed conversation, sender and content bindings.
use super::invalid;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{TaskEvent, TaskSigner};
use serde::{Deserialize, Serialize};
pub(crate) const PREFIX: &[u8] = b"ramflux.task.v1\n";
const MAX_CARRIER: usize = 512 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Carrier {
    pub content_type: String,
    pub conversation_id: String,
    pub message_id: String,
    pub principal_id: String,
    pub device_id: String,
    pub wire_base64: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_proof_base64: Option<String>,
}
impl Carrier {
    fn signing_bytes(&self) -> Result<Vec<u8>, SdkError> {
        Ok(ramflux_protocol::canonical_json_bytes(&(
            "ramflux.task.carrier.v1",
            &self.content_type,
            &self.conversation_id,
            &self.message_id,
            &self.principal_id,
            &self.device_id,
            &self.wire_base64,
            &self.decision_proof_base64,
        ))?)
    }
    pub(crate) fn event(&self) -> Result<TaskEvent, SdkError> {
        let wire = ramflux_protocol::decode_base64url(&self.wire_base64)
            .map_err(|_| invalid("invalid task wire encoding"))?;
        if wire.len() > ramflux_protocol::MAX_TASK_EVENT_BYTES {
            return Err(invalid("task wire too large"));
        }
        // Parse the original authenticated bytes. Never accept an already-decoded map as ingress.
        let event = TaskEvent::from_wire_bytes(&wire).map_err(|e| invalid(e.to_string()))?;
        if self.principal_id.is_empty()
            || self.principal_id.len() > 256
            || self.device_id.is_empty()
            || self.device_id.len() > 256
            || event.signed().signing_key_id != format!("device:{}", self.device_id)
        {
            return Err(invalid("invalid task signer binding"));
        }
        if self.content_type != "task"
            || event.conversation_id() != self.conversation_id
            || self.message_id.is_empty()
            || self.message_id.len() > 256
        {
            return Err(invalid("invalid task carrier binding"));
        }
        Ok(event)
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, SdkError> {
        let mut bytes = PREFIX.to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        if bytes.len() > MAX_CARRIER {
            return Err(invalid("task carrier too large"));
        }
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Option<Self>, SdkError> {
        let Some(json) = bytes.strip_prefix(PREFIX) else { return Ok(None) };
        if bytes.len() > MAX_CARRIER {
            return Err(invalid("task carrier too large"));
        }
        Ok(Some(ramflux_protocol::parse_i_json(json)?))
    }
    pub(crate) fn signer<'a>(
        &'a self,
        public: &'a str,
        event: &'a TaskEvent,
    ) -> Result<TaskSigner<'a>, SdkError> {
        Ok(TaskSigner {
            principal_id: &self.principal_id,
            actor_type: super::authority::relation_role(event.event()),
            signing_key_id: &event.signed().signing_key_id,
            public_key_base64url: public,
        })
    }
    pub(crate) fn verify(&self, public: &str) -> Result<TaskEvent, SdkError> {
        ramflux_crypto::verify_canonical_signature(
            &self.signing_bytes()?,
            &self.signature,
            public,
        )?;
        let event = self.event()?;
        event.verify(&self.signer(public, &event)?).map_err(|error| invalid(error.to_string()))?;
        Ok(event)
    }
}
impl RamfluxClient {
    pub(crate) fn task_signer_key(
        &self,
        principal: &str,
        device: &str,
    ) -> Result<String, SdkError> {
        if let Some(local) = &self.device_branch
            && local.principal_id == principal
            && local.device_id == device
        {
            return Ok(ramflux_protocol::encode_base64url(
                local.signing_key.verifying_key().to_bytes(),
            ));
        }
        if self
            .account_db()?
            .load_actor_state::<bool>(&format!("device/revoked/{device}"))?
            .unwrap_or(false)
        {
            return Err(invalid("task signer device is revoked"));
        }
        let record = self
            .account_db()?
            .client_record("device", device)?
            .ok_or_else(|| invalid("task signer has no verified device"))?;
        if record["principal_id"] != principal {
            return Err(invalid("task signer principal mismatch"));
        }
        record["signing_public_key"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("task signer key missing"))
    }
    pub(crate) fn sign_task_event(
        &self,
        mut event: TaskEvent,
        message: String,
        decision_proof_base64: Option<String>,
    ) -> Result<Carrier, SdkError> {
        let device = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if event.signed().signing_key_id != format!("device:{}", device.device_id) {
            return Err(invalid("task signing key must be the local device"));
        }
        let signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &event.signing_bytes().map_err(|e| invalid(e.to_string()))?,
            device,
        );
        event = event.with_signature(signature).map_err(|e| invalid(e.to_string()))?;
        let mut carrier = Carrier {
            content_type: "task".into(),
            conversation_id: event.conversation_id().to_owned(),
            message_id: message,
            principal_id: device.principal_id.clone(),
            device_id: device.device_id.clone(),
            wire_base64: ramflux_protocol::encode_base64url(serde_json::to_vec(&event)?),
            signature: String::new(),
            decision_proof_base64,
        };
        carrier.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &carrier.signing_bytes()?,
            device,
        );
        carrier.event()?;
        Ok(carrier)
    }
}
