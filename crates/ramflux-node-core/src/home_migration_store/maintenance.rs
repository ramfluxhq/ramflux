// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Live admission accounting, bounded recovery scans and terminal-state reclamation.
use super::{
    Action, BUDGETS, BUSINESS, CLOCK, EXPIRES, GUARDS, HEADS, HomeRecord, InboxRoute,
    MigrationOperation, NodeCoreError, OPS, Phase, ReadableDatabase, ReadableTable, RecordEvidence,
    Refusal, RouterRedbStore, TARGETS, business_key, clock, decode, read, refusal, storage, write,
};
fn count(tx: &redb::WriteTransaction, key: &str) -> Result<u64, NodeCoreError> {
    Ok(tx.open_table(BUDGETS).map_err(storage)?.get(key).map_err(storage)?.map_or(0, |v| v.value()))
}
fn set(tx: &redb::WriteTransaction, key: &str, value: u64) -> Result<(), NodeCoreError> {
    tx.open_table(BUDGETS).map_err(storage)?.insert(key, value).map_err(storage)?;
    Ok(())
}
pub(super) fn unsealed_budget(tx: &redb::WriteTransaction, add: bool) -> Result<(), NodeCoreError> {
    let old = count(tx, "unsealed")?;
    if add && old >= 1024 {
        return Err(refusal(Refusal::CapacityRefused));
    }
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
        unsealed_budget(tx, true)?;
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
        unsealed_budget(tx, false)?;
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
    /// Propagates all durable errors and refuses clock rollback.
    pub fn cleanup_home_migrations(&self, now: u64) -> Result<usize, NodeCoreError> {
        let tx = self.migration_db().begin_write().map_err(storage)?;
        clock(&tx, now)?;
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
                || !matches!(op.phase, Phase::Prepared | Phase::Expired | Phase::Aborted)
            {
                continue;
            }
            if op.phase == Phase::Prepared {
                release_budget(&tx, &op.prepare.body.account_anchor, true)?;
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
