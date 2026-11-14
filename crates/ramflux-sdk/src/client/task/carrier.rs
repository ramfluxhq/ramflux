// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Exact signed task wire bytes with signed conversation, sender and content bindings.
use super::invalid;
use crate::client::identity_authority::HeadUse;
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::message as g;
use ramflux_protocol::{TaskEvent, TaskSigner};
use serde::{Deserialize, Serialize};
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
    pub(crate) fn to_generated(&self) -> Result<g::TaskCarrier, SdkError> {
        let event = RamfluxClient::encode_generated_task_event(&self.event()?)?;
        Ok(g::TaskCarrier {
            content_type: self.content_type.clone(),
            conversation_id: self.conversation_id.clone(),
            message_id: self.message_id.clone(),
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            event: Some(
                g::TaskEvent::decode(event.as_slice())
                    .map_err(|_| invalid("Task event encoding"))?,
            ),
            signature: self.signature.clone(),
            decision_proof: self
                .decision_proof_base64
                .as_ref()
                .map(|value| {
                    g::TaskCertificate::try_from(&super::certificate::Certificate::decode(value)?)
                })
                .transpose()?,
        })
    }
    pub(crate) fn from_generated(value: &g::TaskCarrier) -> Result<Self, SdkError> {
        let event = super::generated::native_task_event(
            value.event.as_ref().ok_or_else(|| invalid("Task event missing"))?,
        )?;
        let carrier = Self {
            content_type: value.content_type.clone(),
            conversation_id: value.conversation_id.clone(),
            message_id: value.message_id.clone(),
            principal_id: value.principal_id.clone(),
            device_id: value.device_id.clone(),
            wire_base64: ramflux_protocol::encode_base64url(
                ramflux_protocol::canonical_json_bytes(&event)?,
            ),
            signature: value.signature.clone(),
            decision_proof_base64: value
                .decision_proof
                .as_ref()
                .map(|value| super::generated::certificate::native_certificate(value)?.encoded())
                .transpose()?,
        };
        carrier.event()?;
        Ok(carrier)
    }
    fn signing_bytes(&self) -> Result<Vec<u8>, SdkError> {
        let mut unsigned = self.to_generated()?;
        unsigned.signature.clear();
        super::generated::typed_transcript("TaskCarrier", &unsigned.encode_to_vec())
    }
    pub(crate) fn event(&self) -> Result<TaskEvent, SdkError> {
        let wire = ramflux_protocol::decode_base64url(&self.wire_base64)
            .map_err(|_| invalid("invalid task wire encoding"))?;
        if wire.len() > ramflux_protocol::MAX_TASK_EVENT_BYTES {
            return Err(invalid("task wire too large"));
        }
        // Parse the original authenticated bytes. Never accept an already-decoded map as ingress.
        let event = TaskEvent::from_wire_bytes(&wire)
            .map_err(|error| crate::task_refusal::protocol(&error))?;
        if self.principal_id.is_empty()
            || self.principal_id.len() > 256
            || self.device_id.is_empty()
            || self.device_id.len() > 256
            || event.signed().signing_key_id != format!("device:{}", self.device_id)
        {
            return Err(invalid("invalid task signer binding"));
        }
        if let Some(proof) = &self.decision_proof_base64 {
            super::certificate::Certificate::decode(proof)?;
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
        let bytes = g::Task { payload: Some(g::task::Payload::Carrier(self.to_generated()?)) }
            .encode_to_vec();
        if bytes.len() > MAX_CARRIER {
            return Err(invalid("task carrier too large"));
        }
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Option<Self>, SdkError> {
        if bytes.len() > MAX_CARRIER {
            return Err(invalid("task carrier too large"));
        }
        if g::validation::scan_message("Task", bytes, g::registry::COMPILED_LAYER).is_err() {
            return Ok(None);
        }
        let value = g::Task::decode(bytes).map_err(|_| invalid("invalid typed Task carrier"))?;
        let Some(g::task::Payload::Carrier(carrier)) = value.payload else {
            return Ok(None);
        };
        Ok(Some(Self::from_generated(&carrier)?))
    }
    pub(crate) fn signer<'a>(&'a self, public: &'a str, event: &'a TaskEvent) -> TaskSigner<'a> {
        TaskSigner {
            principal_id: &self.principal_id,
            actor_type: super::authority::relation_role(event.event()),
            signing_key_id: &event.signed().signing_key_id,
            public_key_base64url: public,
        }
    }
    pub(crate) fn verify(&self, public: &str) -> Result<TaskEvent, SdkError> {
        ramflux_crypto::verify_canonical_signature(
            &self.signing_bytes()?,
            &self.signature,
            public,
        )?;
        let event = self.event()?;
        event
            .verify(&self.signer(public, &event))
            .map_err(|error| crate::task_refusal::protocol(&error))?;
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
        let identity = self.peer_device_identity(principal, device)?;
        self.require_cached_root_authority(HeadUse::NewAuthorization, &identity)?;
        let record = self
            .account_db()?
            .client_device_record(&identity)?
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
            &event.signing_bytes().map_err(|error| crate::task_refusal::protocol(&error))?,
            device,
        );
        event = event
            .with_signature(signature)
            .map_err(|error| crate::task_refusal::protocol(&error))?;
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
