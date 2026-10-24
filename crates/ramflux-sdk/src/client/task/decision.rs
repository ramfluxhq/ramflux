// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Verified external decisions: an assignee witness is a receipt and never a tool capability.
use super::{carrier::Carrier, invalid, key};
use crate::{LocalMcpApprovalRecord, LocalMcpGrantRecord, RamfluxClient, SdkError};
use ramflux_protocol::{NeedsMe, Task, TaskDecision, TaskResolve};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Evidence {
    Grant { record: Box<LocalMcpGrantRecord> },
    Surface { receipt_base64: String },
    Denied { record: Box<LocalMcpApprovalRecord> },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecisionProof {
    pub conversation_id: String,
    pub resolution: TaskResolve,
    pub assignee: String,
    pub issuer_device: String,
    pub issued_at: i64,
    pub evidence: Evidence,
    pub signature: String,
}
impl DecisionProof {
    fn signing_bytes(&self) -> Result<Vec<u8>, SdkError> {
        Ok(ramflux_protocol::canonical_json_bytes(&(
            "ramflux.task.external_decision.v1",
            &self.conversation_id,
            &self.resolution,
            &self.assignee,
            &self.issuer_device,
            self.issued_at,
            &self.evidence,
        ))?)
    }
    pub(crate) fn encoded(&self) -> Result<String, SdkError> {
        Ok(ramflux_protocol::encode_base64url(serde_json::to_vec(self)?))
    }
    pub(crate) fn decode(encoded: &str) -> Result<Self, SdkError> {
        if encoded.len() > 256 * 1024 {
            return Err(invalid("task decision proof exceeds byte budget"));
        }
        let bytes = ramflux_protocol::decode_base64url(encoded)
            .map_err(|_| invalid("invalid task decision proof encoding"))?;
        Ok(ramflux_protocol::parse_i_json(&bytes)?)
    }
}
impl RamfluxClient {
    pub(crate) fn witness_task_decision(
        &self,
        conversation: &str,
        resolution: TaskResolve,
        evidence: Evidence,
    ) -> Result<DecisionProof, SdkError> {
        let history = self.task_history(conversation, &resolution.task_id)?;
        let (executor, opened) =
            history.intervention_source(&resolution.step_id, &resolution.target)?;
        let state = history.state()?;
        let task = state.task().ok_or_else(|| invalid("task not found"))?;
        let device = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if task.assignee != device.principal_id
            || device.device_id != executor
            || resolution.base_revision < opened
            || resolution.base_revision > task.version
        {
            return Err(invalid("only task assignee can attest an external decision"));
        }
        let mut proof = DecisionProof {
            conversation_id: conversation.into(),
            resolution,
            assignee: task.assignee.clone(),
            issuer_device: device.device_id.clone(),
            issued_at: crate::time::now_unix_timestamp(),
            evidence,
            signature: String::new(),
        };
        self.account_db()?.write_transaction(|| {
            let decision_key = self.verify_task_evidence(&proof, task, true)?;
            let reservation = key("decision_reserved", &decision_key);
            if self.account_db()?.load_actor_state::<serde_json::Value>(&decision_key)?.is_some() {
                return Err(invalid("task external decision already consumed"));
            }
            if let Some(previous) =
                self.account_db()?.load_actor_state::<DecisionProof>(&reservation)?
            {
                if previous.conversation_id != proof.conversation_id
                    || previous.resolution != proof.resolution
                    || previous.issuer_device != proof.issuer_device
                {
                    return Err(invalid(
                        "external decision already reserved for another task intervention",
                    ));
                }
                return Ok(previous);
            }
            proof.signature = ramflux_crypto::sign_canonical_bytes_with_device_branch(
                &proof.signing_bytes()?,
                device,
            );
            self.account_db()?.persist_actor_state(&reservation, &proof)?;
            Ok(proof)
        })
    }

    pub(super) fn verify_task_decision(
        &self,
        carrier: &Carrier,
        task: &Task,
        resolution: &TaskResolve,
    ) -> Result<String, SdkError> {
        let proof =
            DecisionProof::decode(carrier.decision_proof_base64.as_deref().ok_or_else(|| {
                invalid("task resolution requires verified external decision proof")
            })?)?;
        if &proof.resolution != resolution
            || proof.conversation_id != task.conversation_id
            || proof.assignee != task.assignee
            || task.requester.as_deref() != Some(carrier.principal_id.as_str())
        {
            return Err(invalid("task decision proof context mismatch"));
        }
        let history = self.task_history(&task.conversation_id, &task.task_id)?;
        let (executor, opened) =
            history.intervention_source(&resolution.step_id, &resolution.target)?;
        if proof.issuer_device != executor || resolution.base_revision < opened {
            return Err(invalid("task decision is not from the intervention's executor"));
        }
        self.require_task_member(
            &task.conversation_id,
            &proof.assignee,
            Some(&proof.issuer_device),
        )?;
        let public = self.task_signer_key(&proof.assignee, &proof.issuer_device)?;
        ramflux_crypto::verify_canonical_signature(
            &proof.signing_bytes()?,
            &proof.signature,
            &public,
        )?;
        self.verify_task_evidence(&proof, task, false)
    }
    fn verify_task_evidence(
        &self,
        proof: &DecisionProof,
        task: &Task,
        require_stored: bool,
    ) -> Result<String, SdkError> {
        let resolution = &proof.resolution;
        let requester =
            task.requester.as_deref().ok_or_else(|| invalid("task requester missing"))?;
        if proof.issued_at > crate::time::now_unix_timestamp().saturating_add(60)
            || proof.issued_at <= 0
        {
            return Err(invalid("task decision witness timestamp invalid"));
        }
        let step = task
            .steps
            .iter()
            .find(|s| s.id == resolution.step_id && s.needs_me.as_ref() == Some(&resolution.target))
            .ok_or_else(|| invalid("task intervention is not open"))?;
        if step.needs_me.is_none() {
            return Err(invalid("task intervention closed"));
        }
        match (&resolution.target, &proof.evidence) {
            (NeedsMe::Approval { grant_id }, Evidence::Grant { record }) => {
                let body = &record.signing_body;
                if resolution.decision != TaskDecision::Resume
                    || body.grant_id != *grant_id
                    || record.grant_id != *grant_id
                    || resolution.decision_id != body.approval_id
                    || !body.single_use
                    || body.full_delegation
                    || body.arguments_hash.as_deref().is_none_or(str::is_empty)
                    || body.expires_at < proof.issued_at
                    || record.state.revoked
                {
                    return Err(invalid(
                        "task approval requires a live single-use bound grant decision",
                    ));
                }
                let key = self.task_signer_key(requester, &record.signed_by_device_id)?;
                if key != record.signer_public_key {
                    return Err(invalid("task grant signer is not the requester device"));
                }
                ramflux_crypto::verify_device_branch_signature(&key, body, &record.signature)?;
                if require_stored {
                    let stored = self
                        .account_db()?
                        .load_mcp_grant::<LocalMcpGrantRecord>(grant_id)?
                        .ok_or_else(|| {
                            invalid("task grant was not accepted by the existing MCP flow")
                        })?;
                    if serde_json::to_vec(&stored)? != serde_json::to_vec(record)? {
                        return Err(invalid("task grant differs from the stored MCP decision"));
                    }
                }
                Ok(key_for_decision("grant", &(&task.assignee, grant_id))?)
            }
            (NeedsMe::Approval { grant_id }, Evidence::Denied { record }) => {
                let requested = record.details["requested_grant_id"]
                    .as_str()
                    .map_or_else(|| format!("grant_{}", record.approval_id), str::to_owned);
                if resolution.decision != TaskDecision::Deny
                    || record.status != "denied"
                    || record.approval_id != resolution.decision_id
                    || requested != *grant_id
                    || record.details["single_use"] != true
                {
                    return Err(invalid("task denial is not the matching existing MCP decision"));
                }
                if require_stored {
                    let stored = self
                        .account_db()?
                        .load_actor_state::<LocalMcpApprovalRecord>(&format!(
                            "mcp/denied/{}",
                            record.approval_id
                        ))?
                        .ok_or_else(|| {
                            invalid("task MCP denial has not completed the existing flow")
                        })?;
                    if serde_json::to_vec(&stored)? != serde_json::to_vec(record)? {
                        return Err(invalid("task MCP denial differs from the stored decision"));
                    }
                }
                key_for_decision("grant", &(&task.assignee, grant_id))
            }
            (
                NeedsMe::Choice { surface_id } | NeedsMe::Input { surface_id },
                Evidence::Surface { receipt_base64 },
            ) => {
                let identity = self.verify_task_surface_decision(
                    &task.conversation_id,
                    surface_id,
                    &task.assignee,
                    requester,
                    resolution,
                    receipt_base64,
                    require_stored,
                )?;
                Ok(key("decision_used", &identity))
            }
            _ => Err(invalid("task decision evidence does not match needs_me target")),
        }
    }
}
fn key_for_decision(kind: &str, value: &impl Serialize) -> Result<String, SdkError> {
    Ok(key("decision_used", &serde_json::to_string(&(kind, value))?))
}
