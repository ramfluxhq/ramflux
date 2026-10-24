// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Private, signed task approval requests and decisions, durable before transport acknowledgement.
use super::{invalid, key};
use crate::{
    GatewayInboxEntry, LocalMcpApprovalRecord, LocalMcpGrantSigningBody, RamfluxClient, SdkError,
    TaskApprovalBinding,
};
use ramflux_protocol::NeedsMe;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub(crate) const PREFIX: &[u8] = b"ramflux.task.approval.v1\n";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub binding: TaskApprovalBinding,
    pub approval: LocalMcpApprovalRecord,
    pub grant_body: LocalMcpGrantSigningBody,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Payload {
    Request { request: Box<Request> },
    Decision { request: Box<Request>, approved: bool, grant_signature: Option<String> },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Packet {
    pub payload: Payload,
    pub principal: String,
    pub device: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_expires_at: Option<i64>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Job {
    pub packet: Packet,
    pub attempts: u32,
    pub next_at: i64,
}
impl Packet {
    pub(crate) fn request(&self) -> &Request {
        match &self.payload {
            Payload::Request { request } | Payload::Decision { request, .. } => request,
        }
    }
    fn signing_bytes(&self) -> Result<Vec<u8>, SdkError> {
        Ok(ramflux_protocol::canonical_json_bytes(&(
            "ramflux.task.approval.v1",
            &self.principal,
            &self.device,
            &self.payload,
        ))?)
    }
    pub(crate) fn bytes(&self) -> Result<Vec<u8>, SdkError> {
        let mut bytes = PREFIX.to_vec();
        let mut wire = self.clone();
        wire.local_expires_at = None;
        bytes.extend(serde_json::to_vec(&wire)?);
        super::check_delivery_size(bytes.len())?;
        Ok(bytes)
    }
    pub(crate) fn id(&self) -> Result<String, SdkError> {
        Ok(ramflux_protocol::hash_base64url(
            "ramflux.task.approval.request.v1",
            &ramflux_protocol::canonical_json_bytes(self.request())?,
        ))
    }
    pub(crate) fn deadline(&self) -> i64 {
        self.local_expires_at.unwrap_or_else(|| {
            self.request().approval.expires_at.min(
                crate::time::now_unix_timestamp().saturating_add(super::approval_retention::TTL),
            )
        })
    }
    pub(crate) fn received(&self) -> Self {
        let mut packet = self.clone();
        packet.local_expires_at =
            Some(self.request().approval.expires_at.min(
                crate::time::now_unix_timestamp().saturating_add(super::approval_retention::TTL),
            ));
        packet
    }
    pub(crate) fn recipient(&self) -> &str {
        match self.payload {
            Payload::Request { .. } => &self.request().binding.requester,
            Payload::Decision { .. } => &self.request().binding.assignee,
        }
    }
}
impl RamfluxClient {
    pub(crate) fn task_approval_binding(
        &self,
        conversation: &str,
        task: &str,
        step: &str,
        target: &NeedsMe,
    ) -> Result<TaskApprovalBinding, SdkError> {
        let history = self.task_history(conversation, task)?;
        let state = history.state()?;
        let row = state.task().ok_or_else(|| invalid("task approval has no task"))?;
        let (executor, revision) = history.intervention_source(step, target)?;
        if !row.steps.iter().any(|s| s.id == step && s.needs_me.as_ref() == Some(target)) {
            return Err(invalid("task approval intervention is closed"));
        }
        Ok(TaskApprovalBinding {
            conversation_id: conversation.into(),
            task_id: task.into(),
            step_id: step.into(),
            opening_revision: revision,
            requester: row
                .requester
                .clone()
                .ok_or_else(|| invalid("task approval requires requester"))?,
            assignee: row.assignee.clone(),
            executor_device_id: executor,
        })
    }
    pub(crate) fn sign_task_approval(&self, payload: Payload) -> Result<Packet, SdkError> {
        let d = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let mut packet = Packet {
            payload,
            principal: d.principal_id.clone(),
            device: d.device_id.clone(),
            signature: String::new(),
            local_expires_at: None,
        };
        packet.signature =
            ramflux_crypto::sign_canonical_bytes_with_device_branch(&packet.signing_bytes()?, d);
        packet.bytes()?;
        Ok(packet)
    }
    pub(crate) fn queue_task_approval(&self, packet: &Packet) -> Result<(), SdkError> {
        let id = packet.id()?;
        let namespace = if matches!(packet.payload, Payload::Request { .. }) {
            "approval_out"
        } else {
            "approval_decision_out"
        };
        let key = key(namespace, &id);
        if self.account_db()?.actor_state_exists(&key)? {
            return Ok(());
        }
        let mut packet = packet.clone();
        packet.local_expires_at = Some(packet.deadline());
        self.store_task_approval_row(
            &key,
            &Job { packet: packet.clone(), attempts: 0, next_at: 0 },
            &packet,
        )
    }
    pub(crate) fn receive_task_approval(
        &self,
        entry: &GatewayInboxEntry,
        conversation: &str,
        bytes: &[u8],
    ) -> Result<bool, SdkError> {
        let Some(body) = bytes.strip_prefix(PREFIX) else { return Ok(false) };
        super::check_delivery_size(bytes.len())?;
        let packet: Packet = ramflux_protocol::parse_i_json(body)?;
        if packet.principal != entry.envelope.source_principal_id
            || packet.device != entry.envelope.source_device_id
            || packet.request().binding.conversation_id != conversation
        {
            return Err(invalid("task approval authenticated source mismatch"));
        }
        self.accept_task_approval(&packet)?;
        Ok(true)
    }
    pub(crate) fn accept_task_approval(&self, packet: &Packet) -> Result<(), SdkError> {
        let mut received = packet.received();
        if self.device_branch.as_ref().is_some_and(|local| local.device_id == packet.device) {
            received.local_expires_at = Some(packet.deadline());
        }
        let packet = received;
        let request = packet.request();
        let b = &request.binding;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if matches!(packet.payload, Payload::Decision { .. }) && local.principal_id == b.assignee {
            if let Some(receipt) = self.task_approval_receipt(&packet.id()?)? {
                let fingerprint = ramflux_protocol::hash_base64url(
                    "ramflux.task.approval.decision.v1",
                    &ramflux_protocol::canonical_json_bytes(&packet.payload)?,
                );
                if receipt.fingerprint != fingerprint {
                    return Err(crate::task_refusal::refused(
                        crate::TaskRefusalCode::DecisionConsumed,
                        "task approval already decided",
                    ));
                }
                return Ok(());
            }
            let original = self
                .account_db()?
                .load_actor_state::<Packet>(&key("approval_source", &packet.id()?))?
                .ok_or_else(|| invalid("task approval decision has no local source"))?;
            if ramflux_protocol::canonical_json_bytes(request)?
                != ramflux_protocol::canonical_json_bytes(original.request())?
            {
                return Err(invalid("task decision differs from original MCP approval"));
            }
        }
        let target = NeedsMe::Approval { grant_id: request.grant_body.grant_id.clone() };
        validate_display(request)?;
        let view = self.task_get(Some(&b.conversation_id), &b.task_id)?;
        if view.is_null() || view["version"].as_u64().is_some_and(|v| v < b.opening_revision) {
            return Err(SdkError::InboundPending("task approval awaits its task revision".into()));
        }
        if request.grant_body.server_id != request.approval.server_id
            || request.grant_body.tool_name != request.approval.tool_name
            || request.grant_body.tool_scope != request.approval.tool_scope
            || request.grant_body.capability != request.approval.capability
            || request.approval.details["arguments_hash"].as_str()
                != request.grant_body.arguments_hash.as_deref()
        {
            return Err(invalid("task approval display differs from signed capability"));
        }
        if self.task_approval_binding(&b.conversation_id, &b.task_id, &b.step_id, &target)? != *b
            || request.grant_body.task_binding.as_ref() != Some(b)
            || request.grant_body.approval_id != request.approval.approval_id
            || !request.grant_body.single_use
            || request.grant_body.full_delegation
            || request.grant_body.arguments_hash.as_deref().is_none_or(str::is_empty)
            || request.grant_body.expires_at <= crate::time::now_unix_timestamp()
            || request.grant_body.expires_at != request.approval.expires_at
            || request.approval.status != "pending"
            || request.approval.risk_level < request.approval.capability.default_risk()
        {
            return Err(invalid("task approval binding or single-use constraints mismatch"));
        }
        self.require_task_member(&b.conversation_id, &packet.principal, Some(&packet.device))?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let expected = if matches!(packet.payload, Payload::Request { .. }) {
            &b.assignee
        } else {
            &b.requester
        };
        if packet.principal != *expected
            || (!matches!(packet.payload, Payload::Decision { .. })
                && packet.device != b.executor_device_id)
            || (local.principal_id != *packet.recipient() && local.principal_id != packet.principal)
        {
            return Err(invalid("task approval sender or recipient is not a task endpoint"));
        }
        let public = self.task_signer_key(&packet.principal, &packet.device)?;
        ramflux_crypto::verify_canonical_signature(
            &packet.signing_bytes()?,
            &packet.signature,
            &public,
        )?;
        if let Payload::Decision { approved, grant_signature, .. } = &packet.payload {
            match (approved, grant_signature) {
                (true, Some(signature)) => ramflux_crypto::verify_device_branch_signature(
                    &public,
                    &request.grant_body,
                    signature,
                )
                .map_err(|e| SdkError::SignatureVerificationFailed(e.to_string()))?,
                (false, None) => (),
                _ => return Err(invalid("task approval decision signature missing")),
            }
        }
        let phase =
            if matches!(packet.payload, Payload::Request { .. }) { "in" } else { "decision_in" };
        let id = packet.id()?;
        let storage = key(&format!("approval_{phase}"), &id);
        self.persist_task_approval(&packet, &id, phase, &storage)
    }
    fn persist_task_approval(
        &self,
        packet: &Packet,
        id: &str,
        phase: &str,
        storage: &str,
    ) -> Result<(), SdkError> {
        let b = &packet.request().binding;
        let db = self.account_db()?;
        db.write_transaction(|| {
            if let Some(receipt)=self.task_approval_receipt(id)? {
                let fingerprint=ramflux_protocol::hash_base64url("ramflux.task.approval.decision.v1",&ramflux_protocol::canonical_json_bytes(&packet.payload)?);
                if matches!(packet.payload,Payload::Decision {..}) && receipt.fingerprint!=fingerprint {return Err(crate::task_refusal::refused(crate::TaskRefusalCode::DecisionConsumed,"task approval already decided"));}
                return Ok(());
            }
            if let Some(old)=db.load_actor_state::<Packet>(storage)? {
                if ramflux_protocol::canonical_json_bytes(&old.payload)?!=ramflux_protocol::canonical_json_bytes(&packet.payload)? {return Err(crate::task_refusal::refused(crate::TaskRefusalCode::DecisionConsumed,"task approval already decided"));}
                return Ok(());
            }
            self.store_task_approval_row(storage,packet,packet)?;
            if phase=="decision_in" {
                db.delete_task_state(&key("approval_in",id))?;
                let local=self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
                if local.principal_id==b.requester {
                    let state=if packet.device==local.device_id {super::approval_retention::DeliveryState::Pending}else{super::approval_retention::DeliveryState::Submitted};
                    self.retire_task_approval(packet,state,None)?;
                }
            }
            db.append_journal(&format!("task-approval:{phase}:{id}"),match &packet.payload {Payload::Request {..}=>"mcp.approval.request",Payload::Decision {approved:true,..}=>"mcp.approval.granted",Payload::Decision {approved:false,..}=>"mcp.approval.denied"},&json!({"approval_id":format!("task_approval_{id}"),"task_id":b.task_id,"conversation_id":b.conversation_id}),crate::time::now_unix_timestamp(),None)?;
            Ok(())
        })
    }

    pub(crate) fn task_remote_approvals(&self) -> Result<Vec<Value>, SdkError> {
        let db = self.account_db()?;
        let local = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        let rows = db.task_record_page::<Packet>("task/approval_in/", "task/approval_in/", 129)?;
        let mut result = Vec::new();
        for (_, packet) in rows {
            let id = packet.id()?;
            let request = packet.request();
            if request.binding.requester != local.principal_id
                || packet.deadline() <= crate::time::now_unix_timestamp()
                || db.actor_state_exists(&key("approval_decision_in", &id))?
            {
                continue;
            }
            let target = NeedsMe::Approval { grant_id: request.grant_body.grant_id.clone() };
            if self
                .task_approval_binding(
                    &request.binding.conversation_id,
                    &request.binding.task_id,
                    &request.binding.step_id,
                    &target,
                )
                .ok()
                .as_ref()
                != Some(&request.binding)
            {
                continue;
            }
            let mut value = serde_json::to_value(&request.approval)?;
            value["confirmation_mode"] = json!("task_requester");
            value["risk_level"] =
                serde_json::to_value(request.grant_body.capability.default_risk())?;
            value["expires_at"] = json!(packet.deadline());
            value["details"] = json!({"arguments":request.approval.details["arguments"],"arguments_hash":request.grant_body.arguments_hash,"single_use":request.grant_body.single_use,"full_delegation":request.grant_body.full_delegation,"task_binding":request.binding});
            value["approval_id"] = json!(format!("task_approval_{id}"));
            value["decision_id"] = json!(request.approval.approval_id);
            value["task_binding"] = serde_json::to_value(&request.binding)?;
            value["grant_id"] = json!(request.grant_body.grant_id);
            value["details"]["requested_grant_id"] = json!(request.grant_body.grant_id);
            result.push(value);
        }
        Ok(result)
    }
    pub(crate) fn canonical_task_approval_decision(
        &self,
        id: &str,
        conversation: &str,
        task: &str,
        step: &str,
    ) -> Result<String, SdkError> {
        let Some(scoped) = id.strip_prefix("task_approval_") else { return Ok(id.into()) };
        if let Some(receipt) = self.task_approval_receipt(scoped)? {
            if receipt.binding.conversation_id != conversation
                || receipt.binding.task_id != task
                || receipt.binding.step_id != step
            {
                return Err(crate::task_refusal::refused(
                    crate::TaskRefusalCode::DecisionMismatch,
                    "approval belongs to another task intervention",
                ));
            }
            return Ok(receipt.approval_id);
        }
        let packet = self
            .account_db()?
            .load_actor_state::<Packet>(&key("approval_in", scoped))?
            .or(self
                .account_db()?
                .load_actor_state::<Packet>(&key("approval_decision_in", scoped))?)
            .ok_or_else(|| invalid("task approval not found"))?;
        let b = &packet.request().binding;
        if b.conversation_id != conversation || b.task_id != task || b.step_id != step {
            return Err(crate::task_refusal::refused(
                crate::TaskRefusalCode::DecisionMismatch,
                "approval belongs to another task intervention",
            ));
        }
        Ok(packet.request().approval.approval_id.clone())
    }
}

fn validate_display(request: &Request) -> Result<(), SdkError> {
    let arguments = request
        .approval
        .details
        .get("arguments")
        .ok_or_else(|| invalid("task approval arguments missing"))?;
    let arguments_hash = ramflux_protocol::hash_base64url(
        ramflux_protocol::domain::MCP_GRANT,
        &ramflux_protocol::canonical_json_bytes(arguments)?,
    );
    if request.grant_body.arguments_hash.as_deref() != Some(arguments_hash.as_str()) {
        return Err(invalid("task approval arguments differ from signed hash"));
    }
    for text in
        [&request.approval.server_id, &request.approval.tool_name, &request.approval.approval_id]
    {
        if text.is_empty()
            || text.chars().count() > 256
            || !ramflux_protocol::text_safety::single_line_is_safe(text)
        {
            return Err(invalid("unsafe task approval label"));
        }
    }

    Ok(())
}
