// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deterministic fork repair re-signs only this device's durable local mutations.
use super::{
    GroupStateChange, RamfluxClient, SdkError, StorageError, VerifiedGroupState,
    advance_group_state, json, now_unix_timestamp,
};
use ramflux_crypto::GroupStateRelation;
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
struct LocalWrite {
    epoch: u64,
    head: String,
    change: GroupStateChange,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConflictReason {
    UnrelatedHistory,
    LocalWriteUnauthorized,
    StaleDelegation,
}
fn writes_key(group: &str) -> String {
    format!("group-state/local-writes/{}", ramflux_protocol::encode_base64url(group))
}
impl RamfluxClient {
    pub(super) fn record_group_write(
        &self,
        state: &VerifiedGroupState,
        change: GroupStateChange,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let key = writes_key(&state.view().group_id);
        let mut writes: Vec<LocalWrite> = db.load_actor_state(&key)?.unwrap_or_default();
        writes.push(LocalWrite {
            epoch: state.view().epoch,
            head: state.view().head_hash.clone(),
            change,
        });
        // Forks older than the retained signed ancestry window produce an explicit conflict.
        let floor = state.view().epoch.saturating_sub(96);
        writes
            .retain(|write| write.epoch >= floor && state.contains_head(write.epoch, &write.head));
        db.persist_actor_state(&key, &writes)?;
        Ok(())
    }
    fn journal_group_conflict(
        &self,
        incoming: &VerifiedGroupState,
        reason: ConflictReason,
    ) -> Result<(), SdkError> {
        let event = format!("group-conflict/{}", incoming.snapshot().state_hash);
        self.account_db()?.append_journal(
            &event,
            "group.state.conflict",
            &json!({
            "group_id": incoming.view().group_id, "epoch": incoming.view().epoch,
            "state_hash": incoming.snapshot().state_hash, "reason": reason }),
            now_unix_timestamp(),
            None,
        )?;
        Ok(())
    }
    pub(super) fn reconcile_group_state(
        &self,
        incoming: &VerifiedGroupState,
        target: &str,
    ) -> Result<Option<VerifiedGroupState>, SdkError> {
        let Some(previous) = self.account_db()?.shared_group_state(&incoming.view().group_id)?
        else {
            return Ok(Some(incoming.clone()));
        };
        let authority_epoch = |state: &VerifiedGroupState| {
            state
                .snapshot()
                .checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.authority.as_ref())
                .map_or(0, |authority| authority.epoch)
        };
        let relation = incoming.relation_to(&previous)?;
        let local = self.owned_device_identity()?;
        let creator_repair = relation == GroupStateRelation::IncomingPreferred
            && incoming.snapshot().checkpoint.as_ref().is_some_and(|checkpoint| {
                checkpoint.genesis.actor.identity.root_commitment == local.root_commitment()
            })
            && previous.view().effective_role(local.root_commitment(), local.device_id())
                == Some(ramflux_protocol::SharedGroupRole::Owner);
        if !creator_repair
            && incoming.snapshot().checkpoint.as_ref().is_some_and(|checkpoint| {
                checkpoint.owner.identity.root_commitment
                    != checkpoint.genesis.actor.identity.root_commitment
            })
            && authority_epoch(incoming) < authority_epoch(&previous)
        {
            self.journal_group_conflict(incoming, ConflictReason::StaleDelegation)?;
            return Ok(None);
        }
        match relation {
            GroupStateRelation::Same | GroupStateRelation::Extension => Ok(Some(incoming.clone())),
            GroupStateRelation::Unrelated => {
                self.journal_group_conflict(incoming, ConflictReason::UnrelatedHistory)?;
                Ok(None)
            }
            GroupStateRelation::Ancestor | GroupStateRelation::ExistingPreferred => {
                // A verified stale/forked peer is a detected gap, not an idle recovery timer.
                crate::bus::enqueue_shared_group(self, &previous, None)?;
                Ok(None)
            }
            GroupStateRelation::IncomingPreferred => {
                self.rebase_group_writes(incoming, &previous, target)
            }
        }
    }
    fn rebase_group_writes(
        &self,
        incoming: &VerifiedGroupState,
        previous: &VerifiedGroupState,
        target: &str,
    ) -> Result<Option<VerifiedGroupState>, SdkError> {
        let common = incoming.common_epoch(previous).ok_or(StorageError::GroupPermissionDenied)?;
        let db = self.account_db()?;
        let writes: Vec<LocalWrite> =
            db.load_actor_state(&writes_key(&incoming.view().group_id))?.unwrap_or_default();
        let actor = self.owned_group_actor(target)?;
        let mut repaired = incoming.clone();
        let mut replayed = Vec::new();
        for write in writes.iter().filter(|write| {
            write.epoch > common && previous.contains_head(write.epoch, &write.head)
        }) {
            if already_applied(repaired.view(), &write.change) {
                continue;
            }
            let next = advance_group_state(
                self.identity_root.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                self.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?,
                &actor,
                &repaired,
                write.change.clone(),
            );
            if let Ok(next) = next {
                replayed.push((next.clone(), write.change.clone()));
                repaired = next;
            } else {
                // Adopt current authority while retaining un-rebased local intents for resolution.
                db.persist_actor_state(
                    &format!(
                        "group-state/unapplied-local-writes/{}",
                        ramflux_protocol::encode_base64url(&incoming.view().group_id)
                    ),
                    &writes,
                )?;
                self.journal_group_conflict(incoming, ConflictReason::LocalWriteUnauthorized)?;
                return Ok(Some(incoming.clone()));
            }
        }
        // The receive transaction publishes only the final repaired state, never the transient winner.
        for (state, change) in replayed {
            self.record_group_write(&state, change)?;
        }
        Ok(Some(repaired))
    }
}
fn already_applied(
    state: &ramflux_protocol::group_state::SharedGroupState,
    change: &GroupStateChange,
) -> bool {
    match change {
        GroupStateChange::Remove { root_commitment, device_id } => {
            state.effective_role(root_commitment, device_id).is_none()
        }
        GroupStateChange::SetName { name } => state.name.as_ref() == Some(name),
        GroupStateChange::Add { member, role } => {
            state.members.iter().any(|present| present.identity == *member && present.role == *role)
        }
        GroupStateChange::SetRole { root_commitment, device_id, role } => {
            state.effective_role(root_commitment, device_id) == Some(*role)
        }
        GroupStateChange::Create { .. } => false,
    }
}
