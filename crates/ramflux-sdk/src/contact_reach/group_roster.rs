// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Adopted-head roster intents retain an in-flight operation while coalescing its successor.
mod membership;
mod recovery;
mod repair;
#[cfg(test)]
mod tests;
use super::refused;
use crate::{RamfluxClient, SdkError, custody::PrimaryVault};
use ramflux_crypto::{GroupStateRelation, VerifiedGroupState};
use ramflux_protocol::{
    contact_reach::{
        Admission, GROUP_ROSTER_MEMBERS_DOMAIN, GroupRoster, GroupRosterHeader,
        OPERATION_HASH_DOMAIN, Operation, OperationResult, Reason, StateRecord, Subject,
    },
    custody::{self, Envelope as Signed},
};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "reach-group-roster/";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    operation_id: String,
    epoch: u64,
    hash: String,
    operation: Option<Operation>,
    #[serde(default)]
    context: Option<recovery::RepairContext>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Queue {
    grant_hash: String,
    checkpoint: Option<GroupRoster>,
    active: Option<Intent>,
    next: Option<Intent>,
    pending_fork: bool,
    #[serde(default)]
    success: Option<recovery::RosterSuccess>,
    #[serde(default)]
    refusal: Option<recovery::RosterRefusal>,
}
fn key(group: &str) -> String {
    format!("{PREFIX}{}", ramflux_protocol::encode_base64url(group))
}
fn pending() -> SdkError {
    SdkError::InboundPending("group roster requires adopted membership history".into())
}
fn grant<'a>(
    records: &'a [StateRecord],
    state: &VerifiedGroupState,
) -> Result<&'a Signed<Admission>, SdkError> {
    let update = records
        .iter()
        .find_map(|record| match record {
            StateRecord::Grant { subject: Subject::Group { group_id, .. }, update, .. }
                if group_id == &state.view().group_id =>
            {
                Some(update)
            }
            _ => None,
        })
        .ok_or_else(pending)?;
    let Subject::Group { conversation_id, genesis_hash, .. } = &update.body.subject else {
        return Err(pending());
    };
    if conversation_id != &state.view().conversation_id || genesis_hash != &state.genesis_hash()? {
        return Err(pending());
    }
    Ok(update)
}
impl RamfluxClient {
    pub(super) fn require_reach_group_roster_unforked(&self, group: &str) -> Result<(), SdkError> {
        if self
            .account_db()?
            .load_actor_state::<Queue>(&key(group))?
            .is_some_and(|queue| queue.pending_fork)
        {
            return Err(SdkError::InboundPending("group roster is pending_fork".into()));
        }
        Ok(())
    }
    pub(crate) fn pause_reach_group_roster(&self, group: &str) -> Result<(), SdkError> {
        let Some(mirror) = self.group_reach_mirror()? else {
            return Ok(());
        };
        if !mirror.records.iter().any(|record| matches!(record,
            StateRecord::Grant { subject: Subject::Group { group_id, .. }, .. } if group_id == group)) {
            return Ok(());
        }
        let db = self.account_db()?;
        db.write_transaction(|| {
            let id = key(group);
            let mut queue: Queue = db.load_actor_state(&id)?.unwrap_or_default();
            queue.pending_fork = true;
            db.persist_actor_state(&id, &queue)?;
            Ok(())
        })
    }
    pub(super) fn stage_reach_group_roster(
        &self,
        adopted: &VerifiedGroupState,
        previous: &VerifiedGroupState,
    ) -> Result<(), SdkError> {
        if !matches!(
            adopted.relation_to(previous)?,
            GroupStateRelation::Extension | GroupStateRelation::IncomingPreferred
        ) {
            return Ok(());
        }
        self.enqueue_reach_group_roster(adopted)
    }

    fn enqueue_reach_group_roster(&self, state: &VerifiedGroupState) -> Result<(), SdkError> {
        let Some(mirror) = self.group_reach_mirror()? else {
            return Ok(());
        };
        if mirror.conflict || mirror.root != self.owned_device_identity()?.root_commitment() {
            return Err(pending());
        }
        if !state.view().members.iter().any(|member| member.identity.root_commitment == mirror.root)
        {
            return Ok(());
        }
        let update = match grant(&mirror.records, state) {
            Ok(update) => update,
            Err(SdkError::InboundPending(_)) => return Ok(()),
            Err(error) => return Err(error),
        };
        let hash = custody::framed_hash(OPERATION_HASH_DOMAIN, update)?;
        let db = self.account_db()?;
        let id = key(&state.view().group_id);
        let mut queue: Queue = db.load_actor_state(&id)?.unwrap_or_default();
        if queue.grant_hash != hash {
            queue =
                Queue { grant_hash: hash, pending_fork: queue.pending_fork, ..Queue::default() };
        }
        let incarnation = db.reach_local_incarnation()?;
        if queue.success.as_ref().is_some_and(|success| {
            success.valid(
                &queue.grant_hash,
                state.view().epoch,
                &mirror.home_head_hash,
                &incarnation,
            )
        }) || queue.refusal.as_ref().is_some_and(|refusal| {
            refusal.stale_for(
                &queue.grant_hash,
                state.view().epoch,
                &mirror.home_head_hash,
                &incarnation,
            )
        }) || queue.active.iter().chain(queue.next.iter()).any(|intent| {
            intent.epoch == state.view().epoch && intent.hash == state.snapshot().state_hash
        }) {
            return Ok(());
        }
        if !db.actor_state_exists(&id)? && db.actor_state_usage(PREFIX)?.0 >= 1024 {
            return Err(refused(Reason::ForeignCapacity));
        }
        let intent = Intent {
            operation_id: ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?),
            epoch: state.view().epoch,
            hash: state.snapshot().state_hash.clone(),
            operation: None,
            context: None,
        };
        if queue.active.as_ref().is_none_or(|active| active.operation.is_none()) {
            queue.active = Some(intent);
        } else {
            queue.next = Some(intent);
        }
        db.persist_actor_state(&id, &queue)?;
        Ok(())
    }

    /// Repair only derived bookkeeping from a current adopted head and a verified live grant.
    /// This never signs or stages an allow, including after restart or restore.
    /// # Errors
    /// Refuses missing signed state, restrictive fork or exhausted bounded local intent storage.
    pub fn stage_reach_group_roster_repair(&self, group: &str) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let state = db.shared_group_state(group)?.ok_or_else(pending)?;
            self.enqueue_reach_group_kick(&state)?;
            self.enqueue_reach_group_roster(&state)
        })
    }

    /// Sign a committed derived roster intent after the account writer has closed.
    /// # Errors
    /// Keeps missing history pending; refuses changed grant/head, unavailable primary and races.
    pub fn prepare_reach_group_roster(
        &self,
        vault: &dyn PrimaryVault,
        group: &str,
        now: u64,
    ) -> Result<Operation, SdkError> {
        let now = self.refresh_reach_roster_intent(group, now)?;
        let db = self.account_db()?;
        let mut queue: Queue = db.load_actor_state(&key(group))?.ok_or_else(pending)?;
        if queue.pending_fork {
            return Err(pending());
        }
        let intent = queue.active.as_ref().ok_or_else(pending)?;
        let mirror = self.group_reach_mirror()?.ok_or_else(pending)?;
        let current = db.shared_group_state(group)?.ok_or_else(pending)?;
        if queue.refusal.as_ref().is_some_and(|refusal| {
            refusal.reason == Reason::CustodyRefused
                && refusal.authority_hash == mirror.authority_head_hash
        }) {
            return Err(pending());
        }
        if mirror.conflict
            || !current
                .view()
                .members
                .iter()
                .any(|member| member.identity.root_commitment == mirror.root)
        {
            return Err(pending());
        }
        if let Some(operation) = &intent.operation {
            return Ok(operation.clone());
        }
        let state = db.shared_group_state_at_epoch(group, intent.epoch)?.ok_or_else(pending)?;
        if !state.contains_head(intent.epoch, &intent.hash) {
            return Err(pending());
        }
        let update = grant(&mirror.records, &state)?;
        if custody::framed_hash(OPERATION_HASH_DOMAIN, update)? != queue.grant_hash {
            return Err(pending());
        }
        let account = self.born_v3_account.as_ref().ok_or_else(pending)?;
        let authority = self.current_custody_authority(&mirror.root, now)?.ok_or_else(pending)?;
        ramflux_crypto::contact_reach::verify_retained_admission(update, &authority, now)?;
        if let Some(checkpoint) = &queue.checkpoint {
            ramflux_crypto::contact_reach::verify_group_roster(
                checkpoint, update, &authority, now,
            )?;
        }
        let members = membership::derive(db, update, &state, queue.checkpoint.as_ref())?;
        let header = GroupRosterHeader {
            authority_head_hash: custody::object_hash(authority.envelope())?,
            master_certificate_hash: custody::object_hash(
                &authority.envelope().body.master_certificate,
            )?,
            version: 1,
            recipient_root: mirror.root,
            group_id: group.into(),
            conversation_id: state.view().conversation_id.clone(),
            grant_hash: queue.grant_hash.clone(),
            group_epoch: intent.epoch,
            membership_hash: intent.hash.clone(),
            members_hash: custody::framed_hash(GROUP_ROSTER_MEMBERS_DOMAIN, &members)?,
            member_count: u64::try_from(members.len()).map_err(|_| pending())?,
            issued_at: now,
        };
        let roster = GroupRoster {
            header: account
                .group_primary(vault)?
                .sign_group_roster_header(header, &authority, now)?,
            members,
        };
        roster.validate(update)?;
        let operation = Operation::GroupRoster {
            operation_id: intent.operation_id.clone(),
            roster: Box::new(roster),
        };
        let old = ramflux_protocol::canonical_json_bytes(&queue)?;
        let active = queue.active.as_mut().ok_or_else(pending)?;
        active.operation = Some(operation.clone());
        active.context = Some(recovery::RepairContext {
            home_head_hash: mirror.home_head_hash.clone(),
            local_incarnation: db.reach_local_incarnation()?,
        });
        db.write_transaction(|| {
            let current: Queue = db.load_actor_state(&key(group))?.ok_or_else(pending)?;
            let latest = self.group_reach_mirror()?.ok_or_else(pending)?;
            let latest_head = db.shared_group_state(group)?.ok_or_else(pending)?;
            if ramflux_protocol::canonical_json_bytes(&current)? != old
                || latest.conflict
                || latest.state_hash != mirror.state_hash
                || latest_head.snapshot().state_hash != state.snapshot().state_hash
            {
                return Err(pending());
            }
            self.retain_reach_intent_signer(&operation, now)?;
            db.persist_actor_state(&key(group), &queue)?;
            Ok::<_, SdkError>(())
        })?;
        Ok(operation)
    }

    /// Settle a correlated applied/duplicate roster result and promote its committed successor.
    /// # Errors
    /// Refuses mismatched operations/results; uncertainty keeps the exact operation in flight.
    pub fn apply_reach_group_roster_result(
        &self,
        group: &str,
        operation: &Operation,
        result: &OperationResult,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        db.write_transaction(|| {
            let mut queue: Queue = db.load_actor_state(&key(group))?.ok_or_else(pending)?;
            if queue.active.as_ref().and_then(|intent| intent.operation.as_ref()) != Some(operation)
                || !matches!(result, OperationResult::GroupRoster { .. })
            {
                return Err(pending());
            }
            operation.validate_result(result)?;
            let Operation::GroupRoster { roster, .. } = operation else {
                return Err(pending());
            };
            let OperationResult::GroupRoster { group_epoch, outcome } = result else {
                return Err(pending());
            };
            queue.success =
                queue.active.as_ref().and_then(|intent| intent.context.clone()).map(|context| {
                    recovery::RosterSuccess {
                        grant_hash: queue.grant_hash.clone(),
                        group_epoch: *group_epoch,
                        context,
                        outcome: *outcome,
                    }
                });
            queue.refusal = None;
            queue.checkpoint = Some(roster.as_ref().clone());
            queue.active = queue.next.take();
            db.persist_actor_state(&key(group), &queue)?;
            Ok(())
        })
    }

    /// Submit the exact prepared bookkeeping on the authenticated home session after commit.
    /// # Errors
    /// Preserves the in-flight operation through primary/history, transport and home refusals.
    pub async fn send_reach_group_roster<S>(
        &self,
        connection: &mut crate::custody::CustodyConnection<S>,
        vault: &dyn PrimaryVault,
        group: &str,
        now: u64,
    ) -> Result<OperationResult, SdkError>
    where
        S: ramflux_transport::GatewaySessionTransport + Send,
    {
        let operation = self.prepare_reach_group_roster(vault, group, now)?;
        let result = match connection.reach_operation(operation.clone()).await {
            Ok(result) => result,
            Err(error) => {
                self.settle_reach_group_roster_remote_error(group, &operation, &error)?;
                return Err(error);
            }
        };
        self.apply_reach_group_roster_result(group, &operation, &result)?;
        Ok(result)
    }
}
