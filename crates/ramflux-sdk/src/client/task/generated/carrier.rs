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
        self.encode_generated_task_carrier_with_certificate(event, message_id, None)
    }

    /// Sign a candidate carrier with an optional already signed executor certificate.
    /// No Task decision is admitted and no state is changed.
    /// # Errors
    /// Rejects invalid carrier fields, signatures, certificate bindings or byte caps.
    pub fn encode_generated_task_carrier_with_certificate(
        &self,
        event: TaskEvent,
        message_id: String,
        decision_proof: Option<g::TaskCertificate>,
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
            decision_proof,
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
        for field in [&carrier.message_id, &carrier.principal_id, &carrier.device_id] {
            if field.is_empty()
                || field.len() > 256
                || !ramflux_protocol::text_safety::single_line_is_safe(field)
            {
                return Err(invalid("invalid generated task carrier identifier"));
            }
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
        if let Some(certificate) = &carrier.decision_proof {
            self.decode_generated_task_certificate(&certificate.encode_to_vec())?;
            check_resolution(&carrier, certificate)?;
        }
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

pub(super) fn check_resolution(
    carrier: &g::TaskCarrier,
    certificate: &g::TaskCertificate,
) -> Result<(), SdkError> {
    let resolution = match carrier
        .event
        .as_ref()
        .and_then(|event| event.event.as_ref())
        .and_then(|event| event.value.as_ref())
    {
        Some(g::task_event_body::Value::Resolve(value)) => value.value.as_ref(),
        _ => None,
    }
    .ok_or_else(|| invalid("task certificate requires a resolution carrier"))?;
    if certificate.conversation_id != carrier.conversation_id
        || certificate.resolution.as_ref() != Some(resolution)
    {
        return Err(invalid("task certificate resolution binding mismatch"));
    }
    Ok(())
}

pub(super) fn carrier_hash(carrier: &g::TaskCarrier) -> String {
    ramflux_protocol::hash_base64url(
        "ramflux.message.typed.TaskCarrier.v1",
        &carrier.encode_to_vec(),
    )
}
