// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Dormant typed carrier signing, independent of legacy transport encoders.
use super::{g, invalid};
use crate::{RamfluxClient, SdkError};
use prost::Message as _;
use ramflux_protocol::{TaskEvent, TaskSigner};

impl RamfluxClient {
    /// Sign a candidate generated carrier with the local device. The inner event
    /// retains its native signing domain. No transport or storage is invoked.
    /// # Errors
    /// Rejects wrong local keys, invalid events/bindings, or the delivery byte cap.
    pub fn encode_generated_task_carrier(
        &self,
        event: TaskEvent,
        message_id: String,
    ) -> Result<Vec<u8>, SdkError> {
        let device = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if event.signed().signing_key_id
            != crate::prelude::sdk_device_signed_fields(&device.device_id, "").signing_key_id
        {
            return Err(invalid("task signing key must be the local device"));
        }
        let signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &event.signing_bytes().map_err(|error| crate::task_refusal::protocol(&error))?,
            device,
        );
        let event = event
            .with_signature(signature)
            .map_err(|error| crate::task_refusal::protocol(&error))?;
        let event_bytes = Self::encode_generated_task_event(&event)?;
        let mut carrier = g::TaskCarrier {
            content_type: "task".into(),
            conversation_id: event.conversation_id().into(),
            message_id,
            principal_id: device.principal_id.clone(),
            device_id: device.device_id.clone(),
            event: Some(
                g::TaskEvent::decode(event_bytes.as_slice())
                    .map_err(|_| invalid("invalid generated task event"))?,
            ),
            signature: String::new(),
            decision_proof: None,
        };
        carrier.signature =
            ramflux_crypto::sign_canonical_bytes_with_device_branch(&transcript(&carrier)?, device);
        let bytes = g::Task { payload: Some(g::task::Payload::Carrier(carrier)) }.encode_to_vec();
        self.decode_generated_task_carrier(&bytes)?;
        Ok(bytes)
    }

    /// Verify a candidate carrier against the authenticated native device directory.
    /// This authenticates its content only; the caller still owns membership,
    /// `TaskState` transitions and external decision/certificate admission.
    /// # Errors
    /// Rejects noncanonical/unsupported bytes before hashing or signature checks,
    /// wrong bindings/keys, invalid native event signatures, and delivery caps.
    pub fn decode_generated_task_carrier(&self, bytes: &[u8]) -> Result<g::TaskCarrier, SdkError> {
        super::super::check_delivery_size(bytes.len())?;
        if g::validation::scan_message("Task", bytes, g::registry::COMPILED_LAYER)
            .map_err(|_| invalid("noncanonical generated task carrier"))?
            != g::validation::ScanOutcome::Supported
        {
            return Err(invalid("unsupported generated task carrier"));
        }
        let task = g::Task::decode(bytes).map_err(|_| invalid("invalid generated task carrier"))?;
        let Some(g::task::Payload::Carrier(carrier)) = task.payload else {
            return Err(invalid("generated task carrier required"));
        };
        // P17b replaces this temporary refusal with certificate verification and bindings.
        if carrier.decision_proof.is_some() {
            return Err(invalid("generated task decision proof verification unavailable"));
        }
        if carrier.content_type != "task"
            || carrier.message_id.is_empty()
            || carrier.principal_id.is_empty()
            || carrier.device_id.is_empty()
        {
            return Err(invalid("invalid generated task carrier binding"));
        }
        let event =
            carrier.event.as_ref().ok_or_else(|| invalid("generated task event missing"))?;
        if event.conversation_id != carrier.conversation_id {
            return Err(invalid("invalid generated task carrier binding"));
        }
        let expected = crate::prelude::sdk_device_signed_fields(&carrier.device_id, "");
        let public = self.task_signer_key(&carrier.principal_id, &carrier.device_id)?;
        let signer = TaskSigner {
            principal_id: &carrier.principal_id,
            actor_type: ramflux_protocol::ActorType::Human,
            signing_key_id: &expected.signing_key_id,
            public_key_base64url: &public,
        };
        Self::decode_generated_task_event(&event.encode_to_vec(), &signer)?;
        ramflux_crypto::verify_canonical_signature(
            &transcript(&carrier)?,
            &carrier.signature,
            &public,
        )?;
        Ok(carrier)
    }
}

fn transcript(carrier: &g::TaskCarrier) -> Result<Vec<u8>, SdkError> {
    let mut unsigned = carrier.clone();
    unsigned.signature.clear();
    super::typed_transcript("TaskCarrier", &unsigned.encode_to_vec())
}
