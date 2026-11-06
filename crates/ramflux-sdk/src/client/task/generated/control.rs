// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate control authentication without importing manifests or committing decisions.
use super::{carrier, g, invalid, typed_transcript};
use crate::{RamfluxClient, SdkError};
use prost::Message as _;

impl RamfluxClient {
    /// Encode an intent or sign an acknowledgement with the local executor.
    /// Embedded certificates and original carriers must already be signed.
    /// # Errors
    /// Rejects invalid fields, source bindings, manifest authority, signatures or caps.
    pub fn encode_generated_task_control(
        &self,
        mut control: g::TaskControl,
    ) -> Result<Vec<u8>, SdkError> {
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let conversation = match control.value.as_mut() {
            Some(g::task_control::Value::Intent(intent)) => {
                let carrier = intent
                    .carrier
                    .as_ref()
                    .ok_or_else(|| invalid("task intent carrier missing"))?;
                carrier.conversation_id.clone()
            }
            Some(g::task_control::Value::Ack(value)) => {
                let ack =
                    value.value.as_mut().ok_or_else(|| invalid("task acknowledgement missing"))?;
                if ack.signer_principal != local.principal_id
                    || ack.signer_device != local.device_id
                {
                    return Err(invalid("task acknowledgement signer differs from local executor"));
                }
                ack.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
                    &ack_transcript(ack)?,
                    local,
                );
                ack.carrier
                    .as_ref()
                    .ok_or_else(|| invalid("task acknowledgement carrier missing"))?
                    .conversation_id
                    .clone()
            }
            None => return Err(invalid("task control choice missing")),
        };
        let bytes = control.encode_to_vec();
        self.decode_generated_task_control(
            &bytes,
            &conversation,
            &local.principal_id,
            &local.device_id,
        )?;
        Ok(bytes)
    }

    /// Authenticate a candidate control against caller-supplied authenticated source
    /// and conversation bindings. Does not import keys, admit membership, consume a
    /// grant, acknowledge delivery or persist a decision.
    /// # Errors
    /// Rejects unsupported/noncanonical bytes before hashing, source/certificate
    /// mismatches, invalid native manifests, signatures or delivery caps.
    pub fn decode_generated_task_control(
        &self,
        bytes: &[u8],
        conversation: &str,
        source_principal: &str,
        source_device: &str,
    ) -> Result<g::TaskControl, SdkError> {
        super::super::check_delivery_size(bytes.len())?;
        if g::validation::scan_message("TaskControl", bytes, g::registry::COMPILED_LAYER)
            .map_err(|_| invalid("noncanonical generated task control"))?
            != g::validation::ScanOutcome::Supported
        {
            return Err(invalid("unsupported generated task control"));
        }
        let control =
            g::TaskControl::decode(bytes).map_err(|_| invalid("invalid generated task control"))?;
        match control.value.as_ref() {
            Some(g::task_control::Value::Intent(intent)) => {
                let carrier = intent
                    .carrier
                    .as_ref()
                    .ok_or_else(|| invalid("task intent carrier missing"))?;
                if carrier.conversation_id != conversation
                    || carrier.principal_id != source_principal
                    || carrier.device_id != source_device
                {
                    return Err(invalid("task intent source or context mismatch"));
                }
                self.check_generated_control_carrier(carrier)?;
                if !matches!(
                    carrier
                        .event
                        .as_ref()
                        .and_then(|event| event.event.as_ref())
                        .and_then(|event| event.value.as_ref()),
                    Some(g::task_event_body::Value::Resolve(_))
                ) {
                    return Err(invalid("task intent requires a resolution carrier"));
                }
            }
            Some(g::task_control::Value::Ack(value)) => {
                let ack =
                    value.value.as_ref().ok_or_else(|| invalid("task acknowledgement missing"))?;
                self.check_generated_task_ack(ack, conversation, source_principal, source_device)?;
            }
            None => return Err(invalid("task control choice missing")),
        }
        Ok(control)
    }

    fn check_generated_control_carrier(&self, carrier: &g::TaskCarrier) -> Result<(), SdkError> {
        let bytes =
            g::Task { payload: Some(g::task::Payload::Carrier(carrier.clone())) }.encode_to_vec();
        self.decode_generated_task_carrier(&bytes)?;
        Ok(())
    }

    fn check_generated_task_ack(
        &self,
        ack: &g::TaskAck,
        conversation: &str,
        source_principal: &str,
        source_device: &str,
    ) -> Result<(), SdkError> {
        let original =
            ack.carrier.as_ref().ok_or_else(|| invalid("task acknowledgement carrier missing"))?;
        let certificate = ack
            .certificate
            .as_ref()
            .ok_or_else(|| invalid("task acknowledgement certificate missing"))?;
        if ack.signer_principal != source_principal
            || ack.signer_device != source_device
            || certificate.assignee != ack.signer_principal
            || certificate.issuer_device != ack.signer_device
            || original.conversation_id != conversation
        {
            return Err(invalid("task acknowledgement source or context mismatch"));
        }
        if ack.manifests.len() > 1 {
            return Err(invalid("task acknowledgement manifest count exceeded"));
        }
        if !matches!(
            certificate.phase.as_ref().and_then(|phase| phase.value.as_ref()),
            Some(g::task_certificate_phase::Value::Committed(_))
        ) || certificate.carrier_hash.as_deref()
            != Some(carrier::carrier_hash(original).as_str())
        {
            return Err(invalid("task acknowledgement committed carrier binding mismatch"));
        }
        carrier::check_resolution(original, certificate)?;
        self.decode_generated_task_certificate(&certificate.encode_to_vec())?;
        self.check_generated_control_carrier(original)?;
        for manifest in &ack.manifests {
            self.check_generated_task_manifest(manifest, &original.principal_id)?;
        }
        let public = self.task_signer_key(&ack.signer_principal, &ack.signer_device)?;
        ramflux_crypto::verify_canonical_signature(&ack_transcript(ack)?, &ack.signature, &public)?;
        Ok(())
    }
}

fn ack_transcript(ack: &g::TaskAck) -> Result<Vec<u8>, SdkError> {
    let mut unsigned = ack.clone();
    unsigned.signature.clear();
    typed_transcript("TaskAck", &unsigned.encode_to_vec())
}
