// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Attended decisions are first-wins; retry changes delivery state without resigning authority.
use super::{
    approval::{Job, Packet, Payload},
    approval_retention::{DeliveryState, Receipt},
    invalid, key,
};
use crate::{RamfluxClient, SdkError, TaskRefusalCode};
use serde_json::Value;
impl RamfluxClient {
    pub(crate) fn decide_task_approval(
        &self,
        scoped: &str,
        approved: bool,
    ) -> Result<Value, SdkError> {
        let id = scoped
            .strip_prefix("task_approval_")
            .ok_or_else(|| invalid("invalid task approval id"))?;
        let db = self.account_db()?;
        if let Some(receipt) = self.task_approval_receipt(id)? {
            return self.retry_task_approval(id, approved, receipt);
        }
        let packet = db
            .load_actor_state::<Packet>(&key("approval_in", id))?
            .or(db.load_actor_state::<Packet>(&key("approval_decision_in", id))?)
            .ok_or_else(|| invalid("task approval not found"))?;
        if packet.deadline() <= crate::time::now_unix_timestamp() {
            return Err(invalid("task approval expired"));
        }
        let request = packet.request().clone();
        let device = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if device.principal_id != request.binding.requester {
            return Err(invalid("only task requester may decide approval"));
        }
        let signature = if approved {
            Some(ramflux_crypto::sign_with_device_branch(device, &request.grant_body)?)
        } else {
            None
        };
        let mut decision = self.sign_task_approval(Payload::Decision {
            request: Box::new(request),
            approved,
            grant_signature: signature,
        })?;
        decision.local_expires_at = Some(packet.deadline());
        db.write_transaction(|| {
            self.accept_task_approval(&decision)?;
            self.queue_task_approval(&decision)?;
            let receipt =
                self.record_task_approval_delivery(&decision, DeliveryState::Pending, None)?;
            Ok(receipt.row(id))
        })
    }
    fn retry_task_approval(
        &self,
        id: &str,
        approved: bool,
        receipt: Receipt,
    ) -> Result<Value, SdkError> {
        let device = self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
        if device.principal_id != receipt.binding.requester {
            return Err(invalid("only task requester may retry approval"));
        }
        if receipt.approved != approved {
            return Err(crate::task_refusal::refused(
                TaskRefusalCode::DecisionConsumed,
                "task approval already decided",
            ));
        }
        if receipt.delivery_state != DeliveryState::Failed {
            return Ok(receipt.row(id));
        }
        let db = self.account_db()?;
        let storage = key("approval_decision_out", id);
        let mut job = db
            .load_actor_state::<Job>(&storage)?
            .ok_or_else(|| invalid("task approval delivery is no longer retryable"))?;
        if job.packet.deadline() <= crate::time::now_unix_timestamp() {
            return Err(invalid("task approval expired"));
        }
        job.attempts = 0;
        job.next_at = crate::time::now_unix_timestamp();
        db.write_transaction(|| {
            db.persist_actor_state(&storage, &job)?;
            Ok(self
                .record_task_approval_delivery(&job.packet, DeliveryState::Pending, None)?
                .row(id))
        })
    }
}
