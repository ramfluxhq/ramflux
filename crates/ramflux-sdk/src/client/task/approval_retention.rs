// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receiver-owned approval lifetimes, fair courier capacity, and compact replay/delivery receipts.
use super::{
    approval::{Packet, Payload},
    invalid, key,
};
use crate::{RamfluxClient, SdkError, TaskApprovalBinding, TaskRefusalCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub(crate) const TTL: i64 = crate::bus::dispatch::grant_mcp::MCP_GRANT_TTL_SECONDS;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeliveryState {
    Pending,
    Submitted,
    Applied,
    Rejected,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeliveryReason {
    RetryExhausted,
    TransportUnavailable,
    InterventionClosed,
    InvalidDecision,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Receipt {
    pub request_id: String,
    pub peer: String,
    pub binding: TaskApprovalBinding,
    pub approval_id: String,
    pub grant_id: String,
    pub approved: bool,
    pub fingerprint: String,
    pub expires_at: i64,
    pub updated_at: i64,
    pub revision: u64,
    pub delivery_state: DeliveryState,
    pub reason_code: Option<DeliveryReason>,
}
impl Receipt {
    pub(crate) fn row(&self, id: &str) -> Value {
        json!({"approval_id":format!("task_approval_{id}"),"decision_id":self.approval_id,"grant_id":self.grant_id,"task_binding":self.binding,"status":if self.approved {"approved"}else{"denied"},"delivery_state":self.delivery_state,"reason_code":self.reason_code,"expires_at":self.expires_at})
    }
}
impl RamfluxClient {
    pub(crate) fn task_approval_peer(&self, packet: &Packet) -> Result<String, SdkError> {
        let local = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id;
        let b = &packet.request().binding;
        Ok(if *local == b.requester { b.assignee.clone() } else { b.requester.clone() })
    }
    pub(crate) fn store_task_approval_row(
        &self,
        storage: &str,
        value: &impl Serialize,
        packet: &Packet,
    ) -> Result<(), SdkError> {
        let (namespace, _) =
            storage.rsplit_once('/').ok_or_else(|| invalid("approval namespace missing"))?;
        let prefix = namespace.to_owned() + "/";
        let db = self.account_db()?;
        let rows = db.task_record_page::<Value>(&prefix, &prefix, 101)?;
        let peer = self.task_approval_peer(packet)?;
        let local = &self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?.principal_id;
        let mut count = 0usize;
        let mut bytes = 0usize;
        let mut peer_count = 0usize;
        let mut peer_bytes = 0usize;
        for (key, row) in rows {
            if key == storage {
                continue;
            }
            let length = serde_json::to_vec(&row)?.len();
            count += 1;
            bytes = bytes.saturating_add(length);
            let p = row.get("packet").unwrap_or(&row);
            let b = &p["payload"]["request"]["binding"];
            let other = if b["requester"] == *local { &b["assignee"] } else { &b["requester"] };
            if other.as_str() == Some(&peer) {
                peer_count += 1;
                peer_bytes = peer_bytes.saturating_add(length);
            }
        }
        let incoming_request = namespace == "task/approval_in";
        let byte_limit = if incoming_request { 384 * 1024 } else { 2 * 1024 * 1024 };
        let peer_limit = if incoming_request { 96 * 1024 } else { 512 * 1024 };
        let size = serde_json::to_vec(value)?.len();
        if count >= 64 || bytes.saturating_add(size) > byte_limit {
            return Err(crate::task_refusal::refused(
                TaskRefusalCode::AccountQuotaExhausted,
                "task approval account capacity reached",
            ));
        }
        if peer_count >= 16 || peer_bytes.saturating_add(size) > peer_limit {
            return Err(crate::task_refusal::refused(
                TaskRefusalCode::PeerQuotaExhausted,
                "task approval peer capacity reached",
            ));
        }
        db.persist_actor_state(storage, value)?;
        Ok(())
    }
    pub(crate) fn remember_task_approval_source(&self, packet: &Packet) -> Result<(), SdkError> {
        let packet = packet.received();
        self.store_task_approval_row(&key("approval_source", &packet.id()?), &packet, &packet)
    }
    pub(crate) fn task_approval_receipt(&self, id: &str) -> Result<Option<Receipt>, SdkError> {
        Ok(self
            .account_db()?
            .load_actor_state::<Receipt>(&key("approval_receipt", id))?
            .filter(|r| r.expires_at > crate::time::now_unix_timestamp()))
    }
    pub(crate) fn record_task_approval_delivery(
        &self,
        packet: &Packet,
        state: DeliveryState,
        reason: Option<DeliveryReason>,
    ) -> Result<Receipt, SdkError> {
        let Payload::Decision { approved, .. } = packet.payload else {
            return Err(invalid("decision receipt requires a decision"));
        };
        let id = packet.id()?;
        let db = self.account_db()?;
        let now = crate::time::now_unix_timestamp();
        let fingerprint = ramflux_protocol::hash_base64url(
            "ramflux.task.approval.decision.v1",
            &ramflux_protocol::canonical_json_bytes(&packet.payload)?,
        );
        let old = self.task_approval_receipt(&id)?;
        if old.as_ref().is_some_and(|r| r.fingerprint != fingerprint) {
            return Err(crate::task_refusal::refused(
                TaskRefusalCode::DecisionConsumed,
                "task approval already decided",
            ));
        }
        let changed =
            old.as_ref().is_none_or(|r| r.delivery_state != state || r.reason_code != reason);
        let row = Receipt {
            request_id: id.clone(),
            peer: self.task_approval_peer(packet)?,
            binding: packet.request().binding.clone(),
            approval_id: packet.request().approval.approval_id.clone(),
            grant_id: packet.request().grant_body.grant_id.clone(),
            approved,
            fingerprint,
            expires_at: old
                .as_ref()
                .map_or(packet.deadline(), |r| r.expires_at.min(packet.deadline())),
            updated_at: if changed { now } else { old.as_ref().map_or(now, |r| r.updated_at) },
            revision: old.as_ref().map_or(1, |r| r.revision.saturating_add(u64::from(changed))),
            delivery_state: state,
            reason_code: reason,
        };
        db.persist_actor_state(&key("approval_receipt", &id), &row)?;
        self.prune_task_approval_receipts()?;
        if changed {
            db.append_journal(&format!("task-approval-delivery:{id}:{}",row.revision),"task.changed",&json!({"kind":ramflux_protocol::TaskChangeKind::Updated,"conversation_id":row.binding.conversation_id,"task_id":row.binding.task_id,"step_id":row.binding.step_id,"approval_id":format!("task_approval_{id}"),"delivery_state":state,"reason_code":reason}),now,None)?;
        }
        Ok(row)
    }
    pub(crate) fn retire_task_approval(
        &self,
        packet: &Packet,
        state: DeliveryState,
        reason: Option<DeliveryReason>,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let id = packet.id()?;
        db.write_transaction(|| {
            self.record_task_approval_delivery(packet, state, reason)?;
            for namespace in ["approval_in", "approval_decision_in"] {
                db.delete_task_state(&key(namespace, &id))?;
            }
            if self
                .device_branch
                .as_ref()
                .is_some_and(|d| d.principal_id == packet.request().binding.assignee)
            {
                for namespace in ["approval_source", "approval_out"] {
                    db.delete_task_state(&key(namespace, &id))?;
                }
            }
            if state == DeliveryState::Submitted {
                db.delete_task_state(&key("approval_decision_out", &id))?;
            }
            Ok(())
        })
    }
    pub(crate) fn task_approval_decision_rows(&self) -> Result<Vec<Value>, SdkError> {
        let now = crate::time::now_unix_timestamp();
        Ok(self
            .approval_receipt_rows()?
            .into_iter()
            .filter(|(_, r)| r.expires_at > now)
            .map(|(_, r)| r.row(&r.request_id))
            .collect())
    }
    fn approval_receipt_rows(&self) -> Result<Vec<(String, Receipt)>, SdkError> {
        let prefix = "task/approval_receipt/";
        let mut after = prefix.to_owned();
        let mut result = Vec::new();
        for _ in 0..6 {
            let page = self.account_db()?.task_record_page::<Receipt>(prefix, &after, 101)?;
            let done = page.len() < 101;
            if let Some((last, _)) = page.last() {
                after.clone_from(last);
            }
            result.extend(page);
            if done {
                break;
            }
        }
        Ok(result)
    }
    pub(crate) fn prune_task_approval_receipts(&self) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let now = crate::time::now_unix_timestamp();
        let mut rows = self.approval_receipt_rows()?;
        let prefix = "task/approval_decision_out/";
        let outgoing = db
            .task_record_page::<Value>(prefix, prefix, 101)?
            .into_iter()
            .map(|(key, _)| key)
            .collect::<std::collections::BTreeSet<_>>();
        let protected = |r: &Receipt| {
            matches!(r.delivery_state, DeliveryState::Pending | DeliveryState::Failed)
                && outgoing.contains(&key("approval_decision_out", &r.request_id))
        };
        rows.sort_by_key(|(key, r)| (protected(r), r.updated_at, key.clone()));
        let mut kept = std::collections::BTreeMap::new();
        for (key, row) in rows.iter().rev() {
            let count = kept.entry(row.peer.clone()).or_insert(0usize);
            if !protected(row) && (row.expires_at <= now || *count >= 64) {
                db.delete_task_state(key)?;
            } else {
                *count += 1;
            }
        }
        rows = self.approval_receipt_rows()?;
        while rows.len() > 512 {
            let victim = rows
                .iter()
                .enumerate()
                .filter(|(_, (_, r))| !protected(r))
                .min_by_key(|(_, (key, r))| {
                    (
                        std::cmp::Reverse(kept.get(&r.peer).copied().unwrap_or_default()),
                        r.updated_at,
                        key.clone(),
                    )
                })
                .map(|(index, _)| index);
            let Some(victim) = victim else { break };
            let largest = rows[victim].1.peer.clone();
            let (key, _) = rows.remove(victim);
            db.delete_task_state(&key)?;
            if let Some(count) = kept.get_mut(&largest) {
                *count = count.saturating_sub(1);
            }
        }
        Ok(())
    }
}
