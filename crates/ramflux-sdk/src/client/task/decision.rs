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
    #[serde(default)]
    pub certificate: Option<super::certificate::Certificate>,
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
        self.certificate
            .as_ref()
            .ok_or_else(|| invalid("task decision certificate missing"))?
            .encoded()
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
            certificate: None,
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
                    || !same_decision(&previous.resolution, &proof.resolution)
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
            proof.certificate =
                Some(self.sign_task_certificate(super::certificate::Certificate {
                    conversation_id: proof.conversation_id.clone(),
                    resolution: proof.resolution.clone(),
                    assignee: proof.assignee.clone(),
                    issuer_device: proof.issuer_device.clone(),
                    issued_at: proof.issued_at,
                    phase: super::certificate::Phase::Reserved,
                    committed_version: None,
                    carrier_hash: None,
                    decision_key: decision_key.clone(),
                    evidence_hash: ramflux_protocol::hash_base64url(
                        "ramflux.task.private_evidence.v1",
                        &ramflux_protocol::canonical_json_bytes(&proof.evidence)?,
                    ),
                    signature: String::new(),
                })?);
            self.account_db()?.persist_actor_state(&reservation, &proof)?;
            Ok(proof)
        })
    }

    pub(super) fn verify_task_decision(
        &self,
        c: &Carrier,
        task: &Task,
        resolution: &TaskResolve,
    ) -> Result<(String, super::certificate::Certificate), SdkError> {
        use super::certificate::{Certificate, Phase, carrier_hash, committed_key};
        let history = self.task_history(&task.conversation_id, &task.task_id)?;
        let (executor, _) = history.intervention_source(&resolution.step_id, &resolution.target)?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let certificate = if local.principal_id == task.assignee && local.device_id == executor {
            let evidence =
                self.task_external_evidence(&task.conversation_id, &task.assignee, resolution)?;
            let witness =
                self.witness_task_decision(&task.conversation_id, resolution.clone(), evidence)?;
            let mut certificate =
                witness.certificate.ok_or_else(|| invalid("executor certificate missing"))?;
            certificate.resolution = resolution.clone();
            certificate.phase = Phase::Committed;
            certificate.committed_version = task.version.checked_add(1);
            certificate.carrier_hash = Some(carrier_hash(c)?);
            self.sign_task_certificate(certificate)?
        } else {
            let attached =
                c.decision_proof_base64.as_deref().map(Certificate::decode).transpose()?;
            if let Some(certificate) = attached.filter(|p| p.phase == Phase::Committed) {
                certificate
            } else {
                self.account_db()?
                    .load_actor_state(&committed_key(c, &task.assignee, &executor)?)?
                    .ok_or_else(|| {
                        SdkError::InboundPending(
                            "task decision awaits executor confirmation".into(),
                        )
                    })?
            }
        };
        self.check_committed_task_certificate(c, task, resolution, &certificate)?;
        Ok((certificate.decision_key.clone(), certificate))
    }
    pub(super) fn task_decision_is_waiting(
        &self,
        c: &Carrier,
        task: &Task,
        resolution: &TaskResolve,
    ) -> Result<bool, SdkError> {
        let history = self.task_history(&task.conversation_id, &task.task_id)?;
        let (executor, _) = history.intervention_source(&resolution.step_id, &resolution.target)?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if local.principal_id == task.assignee && local.device_id == executor {
            return match self.task_external_evidence(
                &task.conversation_id,
                &task.assignee,
                resolution,
            ) {
                Ok(_) => Ok(false),
                Err(SdkError::InboundPending(_)) => Ok(true),
                Err(other) => Err(other),
            };
        }
        let certificate = self.account_db()?.load_actor_state::<super::certificate::Certificate>(
            &super::certificate::committed_key(c, &task.assignee, &executor)?,
        )?;
        let attached = c
            .decision_proof_base64
            .as_deref()
            .map(super::certificate::Certificate::decode)
            .transpose()?
            .filter(|p| p.phase == super::certificate::Phase::Committed);
        Ok(certificate.or(attached).is_none_or(|p| {
            p.committed_version.is_none_or(|version| version > task.version.saturating_add(1))
        }))
    }
    pub(crate) fn task_external_evidence(
        &self,
        conversation: &str,
        assignee: &str,
        resolution: &TaskResolve,
    ) -> Result<Evidence, SdkError> {
        let pending =
            || SdkError::InboundPending("task decision awaits the existing approval flow".into());
        match &resolution.target {
            NeedsMe::Approval { grant_id } if resolution.decision == TaskDecision::Resume => {
                Ok(Evidence::Grant {
                    record: Box::new(
                        self.account_db()?.load_mcp_grant(grant_id)?.ok_or_else(pending)?,
                    ),
                })
            }
            NeedsMe::Approval { .. } => Ok(Evidence::Denied {
                record: Box::new(
                    self.account_db()?
                        .load_actor_state(&format!("mcp/denied/{}", resolution.decision_id))?
                        .ok_or_else(pending)?,
                ),
            }),
            NeedsMe::Choice { surface_id } | NeedsMe::Input { surface_id } => {
                Ok(Evidence::Surface {
                    receipt_base64: self.task_surface_receipt(
                        conversation,
                        surface_id,
                        assignee,
                        &resolution.decision_id,
                    )?,
                })
            }
        }
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
                let grant_reference = record.details["requested_grant_id"]
                    .as_str()
                    .map_or_else(|| format!("grant_{}", record.approval_id), str::to_owned);
                if resolution.decision != TaskDecision::Deny
                    || record.status != "denied"
                    || record.approval_id != resolution.decision_id
                    || grant_reference != *grant_id
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
pub(super) fn key_for_decision(kind: &str, value: &impl Serialize) -> Result<String, SdkError> {
    Ok(key("decision_used", &serde_json::to_string(&(kind, value))?))
}

pub(super) fn same_decision(a: &TaskResolve, b: &TaskResolve) -> bool {
    a.task_id == b.task_id
        && a.step_id == b.step_id
        && a.target == b.target
        && a.decision_id == b.decision_id
        && a.decision == b.decision
}
