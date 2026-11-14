// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Roster retry expiry and restore/home-bound local success receipts.
use super::{
    Deserialize, Intent, OPERATION_HASH_DOMAIN, Operation, OperationResult, Queue, RamfluxClient,
    Reason, SdkError, Serialize, custody, grant, key, pending,
};
use ramflux_protocol::contact_reach::Applied;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RepairContext {
    pub home_head_hash: String,
    pub local_incarnation: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RosterSuccess {
    pub grant_hash: String,
    pub group_epoch: u64,
    pub context: RepairContext,
    pub outcome: Applied,
}
impl RosterSuccess {
    pub(super) fn valid(&self, grant: &str, epoch: u64, home: &str, incarnation: &str) -> bool {
        self.grant_hash == grant
            && self.group_epoch >= epoch
            && self.context.home_head_hash == home
            && self.context.local_incarnation == incarnation
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RosterRefusal {
    pub reason: Reason,
    pub grant_hash: String,
    pub group_epoch: u64,
    pub context: RepairContext,
    pub authority_hash: String,
}
impl RosterRefusal {
    pub(super) fn stale_for(&self, grant: &str, epoch: u64, home: &str, incarnation: &str) -> bool {
        self.reason == Reason::GroupEpochStale
            && self.grant_hash == grant
            && self.group_epoch >= epoch
            && self.context.home_head_hash == home
            && self.context.local_incarnation == incarnation
    }
}

impl RamfluxClient {
    pub(super) fn settle_reach_group_roster_remote_error(
        &self,
        group: &str,
        operation: &Operation,
        error: &SdkError,
    ) -> Result<(), SdkError> {
        if let SdkError::ReachRemote { reason, retry_after_ms, current_revision } = error {
            self.settle_reach_group_roster_refusal(
                group,
                operation,
                &OperationResult::Error {
                    reason: *reason,
                    retry_after_ms: *retry_after_ms,
                    current_revision: *current_revision,
                },
            )?;
        }
        Ok(())
    }

    pub(super) fn settle_reach_group_roster_refusal(
        &self,
        group: &str,
        operation: &Operation,
        result: &OperationResult,
    ) -> Result<(), SdkError> {
        operation.validate_result(result)?;
        let OperationResult::Error { reason, .. } = result else {
            return Err(pending());
        };
        if *reason == Reason::ReachCommandExpired {
            return self.expire_reach_group_roster(group, operation, result);
        }
        if !matches!(reason, Reason::GroupEpochStale | Reason::CustodyRefused) {
            // In particular, uncertain storage retains the exact operation bytes and id.
            return Ok(());
        }
        let db = self.account_db()?;
        db.write_transaction(|| {
            let mut queue: Queue = db.load_actor_state(&key(group))?.ok_or_else(pending)?;
            let intent = queue.active.as_ref().ok_or_else(pending)?;
            if intent.operation.as_ref() != Some(operation) {
                return Err(pending());
            }
            let mirror = self.group_reach_mirror()?.ok_or_else(pending)?;
            queue.refusal = intent.context.clone().map(|context| RosterRefusal {
                reason: *reason,
                grant_hash: queue.grant_hash.clone(),
                group_epoch: intent.epoch,
                context,
                authority_hash: mirror.authority_head_hash,
            });
            if *reason == Reason::GroupEpochStale {
                queue.active = queue.next.take();
            }
            db.persist_actor_state(&key(group), &queue)?;
            Ok(())
        })
    }

    pub(super) fn refresh_reach_roster_intent(
        &self,
        group: &str,
        now: u64,
    ) -> Result<u64, SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let floor = db.client_record("reach", "roster-clock")?
                .map(serde_json::from_value::<u64>).transpose()?.unwrap_or(0);
            let now = now.max(floor);
            if now > ramflux_protocol::MAX_SAFE_JSON_INTEGER {
                return Err(pending());
            }
            db.persist_client_record("reach", "roster-clock", &serde_json::json!(now))?;
            let mut queue: Queue = db.load_actor_state(&key(group))?.ok_or_else(pending)?;
            let expired = queue.active.as_ref().and_then(|intent| intent.operation.as_ref())
                .is_some_and(|operation| matches!(operation, Operation::GroupRoster { roster, .. }
                    if roster.header.body.issued_at.checked_add(300).is_none_or(|until| now >= until)));
            if expired {
                self.replace_expired_roster(group, &mut queue)?;
                db.persist_actor_state(&key(group), &queue)?;
            }
            Ok(now)
        })
    }

    fn replace_expired_roster(&self, group: &str, queue: &mut Queue) -> Result<(), SdkError> {
        let mirror = self.group_reach_mirror()?.ok_or_else(pending)?;
        let state = self.account_db()?.shared_group_state(group)?.ok_or_else(pending)?;
        if mirror.conflict
            || queue.pending_fork
            || custody::framed_hash(OPERATION_HASH_DOMAIN, grant(&mirror.records, &state)?)?
                != queue.grant_hash
        {
            return Err(pending());
        }
        queue.active = Some(Intent {
            operation_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            epoch: state.view().epoch,
            hash: state.snapshot().state_hash.clone(),
            operation: None,
            context: None,
        });
        queue.next = None;
        Ok(())
    }

    /// Retire an exact expired operation without changing the live grant or retained floors.
    /// # Errors
    /// Refuses unrelated operations or a changed/forked grant/head. Other errors preserve retries.
    pub fn expire_reach_group_roster(
        &self,
        group: &str,
        operation: &Operation,
        result: &OperationResult,
    ) -> Result<(), SdkError> {
        if !matches!(
            result,
            OperationResult::Error {
                reason: Reason::ReachCommandExpired,
                retry_after_ms: None,
                current_revision: None,
            }
        ) {
            return Err(pending());
        }
        let db = self.account_db()?;
        db.write_transaction(|| {
            let mut queue: Queue = db.load_actor_state(&key(group))?.ok_or_else(pending)?;
            if queue.active.as_ref().and_then(|intent| intent.operation.as_ref()) != Some(operation)
            {
                return Err(pending());
            }
            self.replace_expired_roster(group, &mut queue)?;
            db.persist_actor_state(&key(group), &queue)?;
            Ok(())
        })
    }
}
