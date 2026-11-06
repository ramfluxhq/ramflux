// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate certificates use the approved typed executor signing transcript.
use super::super::certificate::{Certificate, Phase};
use super::{g, invalid};
use crate::{RamfluxClient, SdkError};
use prost::Message as _;

impl RamfluxClient {
    /// Sign a candidate certificate with the local executor using the typed transcript.
    /// This checks content and signature only; it does not admit a decision or write state.
    /// # Errors
    /// Rejects invalid fields, phase bindings, wrong local executor or delivery limits.
    pub fn encode_generated_task_certificate(
        &self,
        certificate: &g::TaskCertificate,
    ) -> Result<Vec<u8>, SdkError> {
        native_certificate(certificate)?;
        let device = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if device.principal_id != certificate.assignee
            || device.device_id != certificate.issuer_device
        {
            return Err(invalid("task certificate must be signed by its executor"));
        }
        let mut certificate = certificate.clone();
        certificate.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
            &transcript(&certificate)?,
            device,
        );
        let bytes = certificate.encode_to_vec();
        self.decode_generated_task_certificate(&bytes)?;
        Ok(bytes)
    }

    /// Decode canonical certificate bytes and verify the typed executor signature
    /// against the pinned executor device. Membership and revision admission remain
    /// with the Task owner; successful authentication has no persistent effect.
    /// # Errors
    /// Rejects unsupported/noncanonical bytes before hashing, invalid native fields,
    /// inconsistent phase fields, unknown executor keys or invalid signatures.
    pub fn decode_generated_task_certificate(
        &self,
        bytes: &[u8],
    ) -> Result<g::TaskCertificate, SdkError> {
        super::super::check_delivery_size(bytes.len())?;
        if g::validation::scan_message("TaskCertificate", bytes, g::registry::COMPILED_LAYER)
            .map_err(|_| invalid("noncanonical generated task certificate"))?
            != g::validation::ScanOutcome::Supported
        {
            return Err(invalid("unsupported generated task certificate"));
        }
        let generated = g::TaskCertificate::decode(bytes)
            .map_err(|_| invalid("invalid generated task certificate"))?;
        native_certificate(&generated)?;
        let public = self.task_signer_key(&generated.assignee, &generated.issuer_device)?;
        ramflux_crypto::verify_canonical_signature(
            &transcript(&generated)?,
            &generated.signature,
            &public,
        )?;
        Ok(generated)
    }
}

pub(super) fn native_certificate(value: &g::TaskCertificate) -> Result<Certificate, SdkError> {
    let resolution =
        value.resolution.as_ref().ok_or_else(|| invalid("task certificate resolution missing"))?;
    let target = match resolution.target.as_ref().and_then(|target| target.value.as_ref()) {
        Some(g::needs_me::Value::Approval(value)) => {
            ramflux_protocol::NeedsMe::Approval { grant_id: value.grant_id.clone() }
        }
        Some(g::needs_me::Value::Choice(value)) => {
            ramflux_protocol::NeedsMe::Choice { surface_id: value.surface_id.clone() }
        }
        Some(g::needs_me::Value::Input(value)) => {
            ramflux_protocol::NeedsMe::Input { surface_id: value.surface_id.clone() }
        }
        None => return Err(invalid("task certificate resolution target missing")),
    };
    let decision = match resolution.decision.as_ref().and_then(|decision| decision.value.as_ref()) {
        Some(g::task_decision::Value::Resume(_)) => ramflux_protocol::TaskDecision::Resume,
        Some(g::task_decision::Value::Deny(_)) => ramflux_protocol::TaskDecision::Deny,
        None => return Err(invalid("task certificate resolution decision missing")),
    };
    let resolution = ramflux_protocol::TaskResolve {
        task_id: resolution.task_id.clone(),
        base_revision: resolution.base_revision,
        step_id: resolution.step_id.clone(),
        target,
        decision_id: resolution.decision_id.clone(),
        decision,
    };
    // Reuse native scalar/revision/target validation without creating a signature
    // or performing a state transition.
    ramflux_protocol::TaskEvent::new(
        value.conversation_id.clone(),
        ramflux_protocol::TaskEventBody::Resolve(resolution.clone()),
        ramflux_protocol::SignedFields {
            signing_key_id: "certificate-validation".into(),
            signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
            signature: String::new(),
        },
    )
    .map_err(|error| crate::task_refusal::protocol(&error))?;
    let phase = match value.phase.as_ref().and_then(|phase| phase.value.as_ref()) {
        Some(g::task_certificate_phase::Value::Reserved(_)) => Phase::Reserved,
        Some(g::task_certificate_phase::Value::Committed(_)) => Phase::Committed,
        None => return Err(invalid("task certificate phase missing")),
    };
    for field in [&value.assignee, &value.issuer_device, &value.decision_key, &value.evidence_hash]
    {
        if field.trim().is_empty()
            || field.chars().count() > 256
            || !ramflux_protocol::text_safety::single_line_is_safe(field)
        {
            return Err(invalid("invalid task certificate identifier"));
        }
    }
    let valid_commit = match phase {
        Phase::Reserved => value.committed_version.is_none() && value.carrier_hash.is_none(),
        Phase::Committed => {
            value.committed_version.is_some_and(|version| {
                version > resolution.base_revision && version <= ramflux_protocol::MAX_TASK_VERSION
            }) && value.carrier_hash.as_ref().is_some_and(|hash| {
                !hash.trim().is_empty()
                    && hash.chars().count() <= 256
                    && ramflux_protocol::text_safety::single_line_is_safe(hash)
            })
        }
    };
    if !valid_commit {
        return Err(invalid("task certificate phase fields mismatch"));
    }
    Ok(Certificate {
        conversation_id: value.conversation_id.clone(),
        resolution,
        assignee: value.assignee.clone(),
        issuer_device: value.issuer_device.clone(),
        issued_at: value.issued_at,
        phase,
        committed_version: value.committed_version,
        carrier_hash: value.carrier_hash.clone(),
        decision_key: value.decision_key.clone(),
        evidence_hash: value.evidence_hash.clone(),
        signature: value.signature.clone(),
    })
}

fn transcript(certificate: &g::TaskCertificate) -> Result<Vec<u8>, SdkError> {
    let mut unsigned = certificate.clone();
    unsigned.signature.clear();
    super::typed_transcript("TaskCertificate", &unsigned.encode_to_vec())
}
