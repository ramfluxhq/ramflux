// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Candidate approval verification preserves the native grant signing body.
use super::{g, invalid, typed_transcript, value_json};
use crate::{
    LocalMcpApprovalRecord, LocalMcpGrantSigningBody, RamfluxClient, SdkError, TaskApprovalBinding,
};
use prost::Message as _;
use serde::de::DeserializeOwned;

impl RamfluxClient {
    /// Sign a candidate approval wrapper using the local device. Approved decisions
    /// must already carry the requester's native grant signature. No state is written.
    /// # Errors
    /// Rejects invalid request bindings, grants, signer endpoints, expiry or size.
    pub fn encode_generated_task_approval(
        &self,
        mut packet: g::TaskApprovalPacket,
    ) -> Result<Vec<u8>, SdkError> {
        let device = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if packet.principal != device.principal_id || packet.device != device.device_id {
            return Err(invalid("generated task approval signer differs from local device"));
        }
        self.check_generated_approval(&packet, false)?;
        packet.signature =
            ramflux_crypto::sign_canonical_bytes_with_device_branch(&transcript(&packet)?, device);
        let bytes = g::Task { payload: Some(g::task::Payload::Approval(packet)) }.encode_to_vec();
        self.decode_generated_task_approval(&bytes)?;
        Ok(bytes)
    }
    /// Verify generated approval bytes and the embedded native grant signature.
    /// Membership, open-intervention state and single-use consumption remain with
    /// the task owner; this candidate method neither persists nor grants capability.
    /// # Errors
    /// Rejects noncanonical bytes before hashing, invalid request/grant bindings,
    /// expired requests, wrong device signatures or the delivery cap.
    pub fn decode_generated_task_approval(
        &self,
        bytes: &[u8],
    ) -> Result<g::TaskApprovalPacket, SdkError> {
        super::super::check_delivery_size(bytes.len())?;
        if g::validation::scan_message("Task", bytes, g::registry::COMPILED_LAYER)
            .map_err(|_| invalid("noncanonical generated task approval"))?
            != g::validation::ScanOutcome::Supported
        {
            return Err(invalid("unsupported generated task approval"));
        }
        let task =
            g::Task::decode(bytes).map_err(|_| invalid("invalid generated task approval"))?;
        let Some(g::task::Payload::Approval(packet)) = task.payload else {
            return Err(invalid("generated task approval required"));
        };
        self.check_generated_approval(&packet, true)?;
        Ok(packet)
    }
    fn check_generated_approval(
        &self,
        packet: &g::TaskApprovalPacket,
        verify_outer: bool,
    ) -> Result<(), SdkError> {
        let payload = packet
            .payload
            .as_ref()
            .and_then(|value| value.value.as_ref())
            .ok_or_else(|| invalid("task approval payload missing"))?;
        let (request, decision) = match payload {
            g::task_approval_payload::Value::Request(value) => (value.request.as_ref(), None),
            g::task_approval_payload::Value::Decision(value) => {
                (value.request.as_ref(), Some((value.approved, value.grant_signature.as_deref())))
            }
        };
        let request = request.ok_or_else(|| invalid("task approval request missing"))?;
        let request = native_request(request)?;
        super::super::approval::validate_display(&request)?;
        let b = &request.binding;
        let grant = &request.grant_body;
        let displayed = &request.approval;
        for value in [
            &b.conversation_id,
            &b.task_id,
            &b.step_id,
            &b.requester,
            &b.assignee,
            &b.executor_device_id,
            &grant.grant_id,
            &grant.registry_hash,
            &grant.tool_manifest_set_hash,
            &packet.principal,
            &packet.device,
        ] {
            if value.is_empty()
                || value.len() > 256
                || !ramflux_protocol::text_safety::single_line_is_safe(value)
            {
                return Err(invalid("invalid generated task approval identifier"));
            }
        }
        if !(1..=ramflux_protocol::MAX_TASK_VERSION).contains(&b.opening_revision)
            || grant.task_binding.as_ref() != Some(b)
            || grant.approval_id != displayed.approval_id
            || grant.server_id != displayed.server_id
            || grant.tool_name != displayed.tool_name
            || grant.tool_scope != displayed.tool_scope
            || grant.capability != displayed.capability
            || displayed.details["arguments_hash"].as_str() != grant.arguments_hash.as_deref()
            || !grant.single_use
            || grant.full_delegation
            || grant.arguments_hash.as_deref().is_none_or(str::is_empty)
            || grant.expires_at <= crate::time::now_unix_timestamp()
            || grant.expires_at != displayed.expires_at
            || displayed.status != "pending"
            || displayed.risk_level < displayed.capability.default_risk()
        {
            return Err(invalid("task approval binding or single-use constraints mismatch"));
        }
        let expected = if decision.is_some() { &b.requester } else { &b.assignee };
        if packet.principal != *expected
            || (decision.is_none() && packet.device != b.executor_device_id)
        {
            return Err(invalid("task approval sender is not a task endpoint"));
        }
        let public = self.task_signer_key(&packet.principal, &packet.device)?;
        if verify_outer {
            ramflux_crypto::verify_canonical_signature(
                &transcript(packet)?,
                &packet.signature,
                &public,
            )?;
        }
        if let Some((approved, signature)) = decision {
            match (approved, signature) {
                (true, Some(signature)) => {
                    ramflux_crypto::verify_device_branch_signature(&public, grant, signature)
                        .map_err(|error| {
                            SdkError::SignatureVerificationFailed(error.to_string())
                        })?;
                }
                (false, None) => (),
                _ => return Err(invalid("task approval decision signature missing")),
            }
        }
        Ok(())
    }
}

fn transcript(packet: &g::TaskApprovalPacket) -> Result<Vec<u8>, SdkError> {
    let mut unsigned = packet.clone();
    unsigned.signature.clear();
    typed_transcript("TaskApprovalPacket", &unsigned.encode_to_vec())
}
fn choice<T: DeserializeOwned>(value: &impl serde::Serialize) -> Result<T, SdkError> {
    let value = serde_json::to_value(value)?;
    let object = value.as_object().ok_or_else(|| invalid("task approval enum missing"))?;
    if object.len() != 1 {
        return Err(invalid("task approval enum missing"));
    }
    let name = object.keys().next().ok_or_else(|| invalid("task approval enum missing"))?;
    Ok(serde_json::from_value(serde_json::Value::String(super::snake(name)))?)
}
fn binding(value: &g::TaskApprovalBinding) -> TaskApprovalBinding {
    TaskApprovalBinding {
        conversation_id: value.conversation_id.clone(),
        task_id: value.task_id.clone(),
        step_id: value.step_id.clone(),
        opening_revision: value.opening_revision,
        requester: value.requester.clone(),
        assignee: value.assignee.clone(),
        executor_device_id: value.executor_device_id.clone(),
    }
}
pub(super) fn native_request(
    value: &g::TaskApprovalRequest,
) -> Result<super::super::approval::Request, SdkError> {
    let record = value.approval.as_ref().ok_or_else(|| invalid("task approval record missing"))?;
    let grant = value.grant_body.as_ref().ok_or_else(|| invalid("task approval grant missing"))?;
    Ok(super::super::approval::Request {
        binding: binding(
            value.binding.as_ref().ok_or_else(|| invalid("task approval binding missing"))?,
        ),
        approval: LocalMcpApprovalRecord {
            approval_id: record.approval_id.clone(),
            server_id: record.server_id.clone(),
            tool_name: record.tool_name.clone(),
            capability: choice(
                record
                    .capability
                    .as_ref()
                    .ok_or_else(|| invalid("task approval capability missing"))?,
            )?,
            risk_level: choice(
                record.risk_level.as_ref().ok_or_else(|| invalid("task approval risk missing"))?,
            )?,
            tool_scope: record.tool_scope.clone(),
            confirmation_mode: record.confirmation_mode.clone(),
            expires_at: record.expires_at,
            status: record.status.clone(),
            details: value_json(
                record.details.as_ref().ok_or_else(|| invalid("task approval details missing"))?,
            )?,
        },
        grant_body: LocalMcpGrantSigningBody {
            task_binding: grant.task_binding.as_ref().map(binding),
            approval_id: grant.approval_id.clone(),
            grant_id: grant.grant_id.clone(),
            server_id: grant.server_id.clone(),
            tool_name: grant.tool_name.clone(),
            tool_scope: grant.tool_scope.clone(),
            capability: choice(
                grant
                    .capability
                    .as_ref()
                    .ok_or_else(|| invalid("task grant capability missing"))?,
            )?,
            registry_hash: grant.registry_hash.clone(),
            tool_manifest_set_hash: grant.tool_manifest_set_hash.clone(),
            full_delegation: grant.full_delegation,
            single_use: grant.single_use,
            arguments_hash: grant.arguments_hash.clone(),
            expires_at: grant.expires_at,
        },
    })
}
