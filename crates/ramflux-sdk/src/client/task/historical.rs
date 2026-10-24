// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Same-root committed history uses its witnessed membership position, never today's contact state.
use super::{AcceptedEvent, Delivery, carrier::Carrier, invalid, projection::Applied};
use crate::client::surface::OwnContext;
use crate::{RamfluxClient, SdkError};
use ramflux_protocol::{Task, TaskEventBody};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Membership {
    conversation: String,
    group: Option<String>,
    epoch: Option<u64>,
    at: i64,
    members: Vec<String>,
}
impl RamfluxClient {
    pub(super) fn task_membership_witness(
        &self,
        c: &Carrier,
        task: &Task,
        at: i64,
    ) -> Result<Membership, SdkError> {
        let thread = self
            .account_db()?
            .client_record("conversation", &c.conversation_id)?
            .ok_or_else(|| invalid("task conversation missing"))?;
        let group = thread["group_id"].as_str().map(str::to_owned);
        let epoch = group
            .as_deref()
            .map(|g| {
                let state = self.group_state(g)?;
                Ok::<_, SdkError>(state.group_epoch)
            })
            .transpose()?;
        Ok(Membership {
            conversation: c.conversation_id.clone(),
            group,
            epoch,
            at,
            members: vec![c.principal_id.clone(), task.assignee.clone()],
        })
    }
    pub(super) fn project_historical_task_event(
        &self,
        accepted: &AcceptedEvent,
        context: &OwnContext,
    ) -> Result<String, SdkError> {
        let c = &accepted.carrier;
        if self.task_signer_key(&c.principal_id, &c.device_id)? != accepted.public_key {
            return Err(invalid("historical task key differs from verified device"));
        }
        let event = c.verify(&accepted.public_key)?;
        let history = self.task_history(&c.conversation_id, event.event().task_id())?;
        let mut state = history.state()?;
        let previous = state.task().cloned();
        state
            .apply(&event, &c.signer(&accepted.public_key, &event))
            .map_err(|error| crate::task_refusal::protocol(&error))?;
        let task = state.task().cloned().ok_or_else(|| invalid("historical task is absent"))?;
        self.check_task_historical_membership(accepted, context, &task)?;
        self.check_task_capacity(c, &history)?;
        let (decision_key, certificate) = if let TaskEventBody::Resolve(resolution) = event.event()
        {
            let cert = accepted
                .decision_certificate
                .as_ref()
                .ok_or_else(|| invalid("historical resolve has no committed certificate"))?;
            self.check_historical_task_certificate(
                c,
                previous.as_ref().ok_or_else(|| invalid("historical intervention absent"))?,
                resolution,
                cert,
            )?;
            if let Some(used) =
                self.account_db()?.load_actor_state::<serde_json::Value>(&cert.decision_key)?
                && (used["task_id"] != task.task_id
                    || used["conversation_id"] != task.conversation_id
                    || used["version"] != task.version)
            {
                return Err(invalid("historical external decision was consumed by another task"));
            }
            (Some(cert.decision_key.clone()), Some(cert.clone()))
        } else {
            if accepted.decision_certificate.is_some() {
                return Err(invalid("unexpected historical certificate"));
            }
            (None, None)
        };
        let outcome = self.record_task_applied(
            &Delivery {
                conversation: &c.conversation_id,
                message: &super::timeline_id(c)?,
                principal: &c.principal_id,
                device: &c.device_id,
                at: accepted.received_at,
            },
            c.clone(),
            Applied {
                history,
                event,
                public: accepted.public_key.clone(),
                task,
                decision_key,
                decision_proof: certificate,
                membership: accepted.membership.clone(),
            },
            false,
        )?;
        Ok(outcome.fallback_text)
    }
    fn check_task_historical_membership(
        &self,
        accepted: &AcceptedEvent,
        context: &OwnContext,
        task: &Task,
    ) -> Result<(), SdkError> {
        let c = &accepted.carrier;
        if let Some(witness) = &accepted.membership {
            let group = context.group.as_ref();
            if witness.conversation != c.conversation_id
                || witness.at != accepted.received_at
                || witness.group.as_deref() != group.map(|g| g.group_id.as_str())
                || witness.epoch.is_some() != group.is_some()
                || witness.epoch.is_some_and(|epoch| group.is_none_or(|g| epoch > g.group_epoch))
                || !witness.members.contains(&c.principal_id)
                || !witness.members.contains(&task.assignee)
            {
                return Err(invalid("historical task membership witness mismatch"));
            }
            if let (Some(group), Some(epoch)) = (group, witness.epoch) {
                self.check_verified_task_roster(c, &group.group_id, epoch, &task.assignee)?;
            }
            if group.is_none()
                && (!context.participants.contains(&c.principal_id)
                    || !context.participants.contains(&task.assignee))
            {
                return Err(invalid("historical direct participant mismatch"));
            }
            return Ok(());
        }
        // Older direct histories carry the same-root committed participant set. Group
        // histories without a position witness cannot prove a departed member's epoch.
        if context.group.is_some()
            || !context.participants.contains(&c.principal_id)
            || !context.participants.contains(&task.assignee)
        {
            return Err(invalid("historical task membership witness unavailable"));
        }
        Ok(())
    }
}
