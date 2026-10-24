// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Device-authenticated task relations; peer principal kinds await signed identity metadata.
use super::{carrier::Carrier, invalid};
use crate::{LocalBusClientMode, RamfluxClient, SdkError};
use ramflux_protocol::{ActorType, Task, TaskEventBody};

/// Temporary role adapter: role class never authenticates a peer's principal kind.
/// Every operation must pass `authorize_task_relations` before protocol reduction.
pub(super) const fn relation_role(event: &TaskEventBody) -> ActorType {
    match event {
        TaskEventBody::Proposal(_) | TaskEventBody::Update(_) => ActorType::Bot,
        _ => ActorType::Human,
    }
}
pub(crate) fn require_local_human(
    mode: &LocalBusClientMode,
    kind: Option<&str>,
) -> Result<(), SdkError> {
    if *mode != LocalBusClientMode::AttendedCli || kind != Some("human") {
        return Err(invalid("task human decision requires attended human account"));
    }
    Ok(())
}
impl RamfluxClient {
    pub(super) fn require_task_member(
        &self,
        conversation: &str,
        principal: &str,
        device: Option<&str>,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let thread = db
            .client_record("conversation", conversation)?
            .ok_or_else(|| invalid("task requires a known conversation"))?;
        if let Some(group) = thread["group_id"].as_str() {
            let state = self.group_state(group)?;
            for member in &state.members {
                let record = db.client_record("device", member)?;
                let owner = record.as_ref().and_then(|v| v["principal_id"].as_str());
                let local = self.device_branch.as_ref().filter(|d| d.device_id == *member);
                if (owner == Some(principal) || local.is_some_and(|d| d.principal_id == principal))
                    && device.is_none_or(|id| id == member)
                {
                    if local.is_some_and(|d| d.principal_id == principal) {
                        self.pin_local_group_member(group)?;
                    } else {
                        self.require_group_sender_pin(group, principal, member)?;
                    }
                    return Ok(());
                }
            }
            return Err(invalid("task actor is not a current pinned group member"));
        }
        if thread["kind"] != "direct"
            || !thread["participants"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(principal)))
        {
            return Err(invalid("task actor is not a conversation participant"));
        }
        if self.friend_rejection_reason(principal)?.is_some() {
            return Err(invalid("task actor contact is blocked or revoked"));
        }
        Ok(())
    }
    pub(super) fn authorize_task_relations(
        &self,
        carrier: &Carrier,
        current: Option<&Task>,
    ) -> Result<(), SdkError> {
        self.require_task_member(
            &carrier.conversation_id,
            &carrier.principal_id,
            Some(&carrier.device_id),
        )?;
        let event = carrier.event()?;
        match event.event() {
            TaskEventBody::Start(start) => {
                if start.requester != carrier.principal_id {
                    return Err(invalid("task start requester differs from authenticated actor"));
                }
                self.require_task_member(&carrier.conversation_id, &start.assignee, None)?;
                let local =
                    &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id;
                if local != &start.requester && local != &start.assignee {
                    return Err(invalid("local account has no role in this task"));
                }
            }
            TaskEventBody::Proposal(proposal) => {
                if proposal.proposer != carrier.principal_id {
                    return Err(invalid("task proposer differs from authenticated actor"));
                }
                self.require_task_member(&carrier.conversation_id, &proposal.assignee, None)?;
            }
            action => {
                let task = current.ok_or_else(|| invalid("task not found"))?;
                if !matches!(action, TaskEventBody::Cancel(_)) {
                    self.require_task_member(&carrier.conversation_id, &task.assignee, None)?;
                }
                let allowed = match action {
                    TaskEventBody::Accept(_) | TaskEventBody::Decline(_) => {
                        task.proposer.as_deref() != Some(carrier.principal_id.as_str())
                            && task.assignee != carrier.principal_id
                    }
                    TaskEventBody::Update(_) => task.assignee == carrier.principal_id,
                    TaskEventBody::Cancel(_) | TaskEventBody::Resolve(_) => {
                        task.requester.as_deref() == Some(carrier.principal_id.as_str())
                    }
                    _ => false,
                };
                if !allowed {
                    return Err(invalid("task actor lacks the required verified relation"));
                }
            }
        }
        Ok(())
    }
}
