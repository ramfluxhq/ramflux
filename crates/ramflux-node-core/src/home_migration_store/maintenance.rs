// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live admission accounting, bounded recovery scans and terminal-state reclamation.
use super::{
    Action, BACKLOG, BUDGETS, BUSINESS, CLOCK, COURIER, EXPIRES, FENCE_EXPIRES, FENCES, GUARDS,
    HEADS, HomeRecord, InboxRoute, MigrationOperation, NodeCoreError, OPS, Phase, ReadableDatabase,
    ReadableTable, RecordEvidence, Refusal, RouterRedbStore, TARGETS, business_key, clock, decode,
    read, refusal, storage, write,
};
fn count(tx: &redb::WriteTransaction, key: &str) -> Result<u64, NodeCoreError> {
    Ok(tx.open_table(BUDGETS).map_err(storage)?.get(key).map_err(storage)?.map_or(0, |v| v.value()))
}
fn set(tx: &redb::WriteTransaction, key: &str, value: u64) -> Result<(), NodeCoreError> {
    tx.open_table(BUDGETS).map_err(storage)?.insert(key, value).map_err(storage)?;
    Ok(())
}
pub(super) fn unsealed_budget(
    tx: &redb::WriteTransaction,
    anchor: &str,
    add: bool,
) -> Result<(), NodeCoreError> {
    let old = count(tx, "unsealed")?;
    let root_key = format!("unsealed/{anchor}");
    let root = count(tx, &root_key)?;
    if add && (old >= 1024 || root >= 1) {
        return Err(refusal(Refusal::CapacityRefused));
    }
    set(
        tx,
        &root_key,
        if add {
            root + 1
        } else {
            root.checked_sub(1)
                .ok_or_else(|| storage("migration root unsealed budget underflow"))?
        },
    )?;
    set(
        tx,
        "unsealed",
        if add {
            old + 1
        } else {
            old.checked_sub(1).ok_or_else(|| storage("migration unsealed budget underflow"))?
        },
    )
}
pub(super) fn reserve_budget(
    tx: &redb::WriteTransaction,
    anchor: &str,
    unsealed: bool,
) -> Result<(), NodeCoreError> {
    let root = count(tx, anchor)?;
    let global = count(tx, "live")?;
    if root >= 256 || global >= 16384 {
        return Err(refusal(Refusal::CapacityRefused));
    }
    set(tx, anchor, root + 1)?;
    set(tx, "live", global + 1)?;
    if unsealed {
        unsealed_budget(tx, anchor, true)?;
    }
    Ok(())
}
pub(super) fn release_budget(
    tx: &redb::WriteTransaction,
    anchor: &str,
    unsealed: bool,
) -> Result<(), NodeCoreError> {
    for key in [anchor, "live"] {
        set(
            tx,
            key,
            count(tx, key)?
                .checked_sub(1)
                .ok_or_else(|| storage("migration live budget underflow"))?,
        )?;
    }
    if unsealed {
        unsealed_budget(tx, anchor, false)?;
    }
    Ok(())
}
pub(super) fn require_no_live_window(
    tx: &redb::WriteTransaction,
    anchor: &str,
    exclude: Option<&str>,
) -> Result<(), NodeCoreError> {
    if let Some(guard) = tx.open_table(GUARDS).map_err(storage)?.get(anchor).map_err(storage)?
        && Some(guard.value()) != exclude
    {
        return Err(refusal(Refusal::MigrationInProgress));
    }
    if let Some(head) = read::<RecordEvidence>(tx, HEADS, anchor)?
        && let HomeRecord::Committed { commit_proof, .. } = head.record
    {
        let now = tx
            .open_table(CLOCK)
            .map_err(storage)?
            .get("floor")
            .map_err(storage)?
            .map_or(0, |v| v.value());
        if now < commit_proof.body.forward_until {
            return Err(refusal(Refusal::PreviousWindowActive));
        }
    }
    Ok(())
}
pub(super) fn due_key(now: u64, anchor: &str, id: &str) -> String {
    format!("{now:020}/{anchor}/{id}")
}
pub(super) fn expiry_key(expiry: u64, key: &str) -> String {
    format!("{expiry:020}/{key}")
}
pub(super) fn index_expiry(
    tx: &redb::WriteTransaction,
    key: &str,
    expiry: u64,
) -> Result<(), NodeCoreError> {
    write(tx, EXPIRES, &expiry_key(expiry, key), &key)
}
impl RouterRedbStore {
    /// Terminal cleanup is bounded; permanent heads/proofs are never pruned.
    /// # Errors
    /// Propagates durable errors; local time never moves below its persisted floor.
    pub fn cleanup_home_migrations(&self, now: u64) -> Result<usize, NodeCoreError> {
        let tx = self.migration_db().begin_write().map_err(storage)?;
        let now = clock(&tx, now)?;
        let upper = format!("{now:020}/");
        let expired = tx
            .open_table(EXPIRES)
            .map_err(storage)?
            .range(..upper.as_str())
            .map_err(storage)?
            .take(128)
            .map(|row| {
                let (k, v) = row.map_err(storage)?;
                Ok((k.value().to_owned(), decode::<String>(v.value())?))
            })
            .collect::<Result<Vec<_>, NodeCoreError>>()?;
        let mut removed = 0;
        for (index, key) in expired {
            tx.open_table(EXPIRES).map_err(storage)?.remove(index.as_str()).map_err(storage)?;
            let Some(op) = read::<MigrationOperation>(&tx, OPS, &key)? else {
                continue;
            };
            if now <= op.expires_at
                || !matches!(
                    op.phase,
                    Phase::Prepared
                        | Phase::Expired
                        | Phase::Aborted
                        | Phase::Active
                        | Phase::Committed
                )
            {
                continue;
            }
            if op.phase == Phase::Committed && op.live_budget {
                // A forwarding-window deadline never discards held drain obligations.
                index_expiry(&tx, &key, now.saturating_add(60))?;
                continue;
            }
            if op.live_budget {
                release_budget(&tx, &op.prepare.body.account_anchor, op.phase == Phase::Prepared)?;
            }
            remove_courier(&tx, &op)?;
            for target in &op.delivery_map {
                let cursor_key = serde_json::to_string(&(
                    &op.prepare.body.account_anchor,
                    &op.prepare.body.migration_id,
                    &target.target_delivery_id,
                ))
                .map_err(storage)?;
                tx.open_table(BACKLOG)
                    .map_err(storage)?
                    .remove(cursor_key.as_str())
                    .map_err(storage)?;
            }
            tx.open_table(OPS).map_err(storage)?.remove(key.as_str()).map_err(storage)?;
            for action in
                [Action::Prepare, Action::Seal, Action::Commit, Action::Activate, Action::Abort]
            {
                tx.open_table(BUSINESS)
                    .map_err(storage)?
                    .remove(
                        business_key(
                            &op.prepare.body.account_anchor,
                            &op.prepare.body.migration_id,
                            action,
                        )?
                        .as_str(),
                    )
                    .map_err(storage)?;
            }
            removed += 1;
        }
        let fences = tx
            .open_table(FENCE_EXPIRES)
            .map_err(storage)?
            .range(..upper.as_str())
            .map_err(storage)?
            .take(128)
            .map(|row| {
                let (k, v) = row.map_err(storage)?;
                Ok((k.value().to_owned(), decode::<String>(v.value())?))
            })
            .collect::<Result<Vec<_>, NodeCoreError>>()?;
        for (index, key) in fences {
            tx.open_table(FENCE_EXPIRES)
                .map_err(storage)?
                .remove(index.as_str())
                .map_err(storage)?;
            tx.open_table(FENCES).map_err(storage)?.remove(key.as_str()).map_err(storage)?;
        }
        super::authority_evidence::cleanup(&tx, now)?;
        tx.commit().map_err(storage)?;
        Ok(removed)
    }
    /// A higher custody range cannot race a pending/activating migration.
    /// # Errors
    /// Propagates durable read failures.
    pub fn home_migration_blocks_recovery(&self, anchor: &str) -> Result<bool, NodeCoreError> {
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = match tx.open_table(GUARDS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(storage(e)),
        };
        Ok(table.get(anchor).map_err(storage)?.is_some())
    }
    /// Dormant mapped routes cannot return delivery ACKs before proof activation.
    /// # Errors
    /// Propagates durable read/decode failures.
    pub fn home_migration_target_active(&self, target: &str) -> Result<bool, NodeCoreError> {
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = match tx.open_table(TARGETS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(true),
            Err(e) => return Err(storage(e)),
        };
        Ok(table
            .get(target)
            .map_err(storage)?
            .map(|v| decode::<InboxRoute>(v.value()))
            .transpose()?
            .is_none_or(|route| route.active))
    }
}

pub(super) fn remove_courier(
    tx: &redb::WriteTransaction,
    op: &MigrationOperation,
) -> Result<(), NodeCoreError> {
    let key = due_key(op.next_due, &op.prepare.body.account_anchor, &op.prepare.body.migration_id);
    tx.open_table(COURIER).map_err(storage)?.remove(key.as_str()).map_err(storage)?;
    Ok(())
}
impl RouterRedbStore {
    /// Release a source reservation once every durable drain obligation is terminal.
    /// # Errors
    /// Rejects an unknown/noncommitted operation or outstanding delivery obligations.
    pub fn finish_home_migration_backlog(
        &self,
        anchor: &str,
        migration_id: &str,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        let tx = self.migration_db().begin_write().map_err(storage)?;
        clock(&tx, now)?;
        let key = super::op_key(anchor, migration_id, super::MigrationRole::Source)?;
        let mut op: MigrationOperation =
            read(&tx, OPS, &key)?.ok_or_else(|| refusal(Refusal::EvidenceRequired))?;
        if op.phase != Phase::Committed {
            return Err(refusal(Refusal::BaseMismatch));
        }
        for target in &op.delivery_map {
            let cursor_key =
                serde_json::to_string(&(anchor, migration_id, &target.target_delivery_id))
                    .map_err(storage)?;
            let cursor: super::MigrationBacklogCursor = read(&tx, BACKLOG, &cursor_key)?
                .ok_or_else(|| storage("migration backlog cursor missing"))?;
            if cursor.progress.remaining != 0 {
                return Err(refusal(Refusal::MigrationInProgress));
            }
        }
        if op.live_budget {
            release_budget(&tx, anchor, false)?;
            op.live_budget = false;
            op.state_version += 1;
            write(&tx, OPS, &key, &op)?;
        }
        super::commit_transition(self, tx)
    }
}
