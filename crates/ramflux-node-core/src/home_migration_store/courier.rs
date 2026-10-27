// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable fair claims keep sealed retry work across lost replies and process exits.
use super::{
    COURIER, MigrationOperation, MigrationRole, NodeCoreError, OPS, Phase, ReadableTable,
    RouterRedbStore, clock, commit_transition, decode, maintenance, op_key, read, storage, write,
};
pub(crate) struct MigrationCourierClaim {
    pub(crate) peer: String,
    key: String,
    next_due: u64,
    state_version: u64,
}
impl RouterRedbStore {
    pub(crate) fn claim_migration_courier(
        &self,
        now: u64,
        limit: usize,
    ) -> Result<Vec<MigrationCourierClaim>, NodeCoreError> {
        let now = self.migration_clock_floor(now)?;
        let due = {
            use redb::ReadableDatabase;
            let tx = self.migration_db().begin_read().map_err(storage)?;
            let table = match tx.open_table(COURIER) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
                Err(error) => return Err(storage(error)),
            };
            let upper = format!("{now:020}/~");
            table
                .range(..upper.as_str())
                .map_err(storage)?
                .take(limit.min(128))
                .map(|row| {
                    let (key, value) = row.map_err(storage)?;
                    Ok((key.value().to_owned(), decode::<String>(value.value())?))
                })
                .collect::<Result<Vec<_>, NodeCoreError>>()?
        };
        let mut claimed = Vec::new();
        for (index, key) in due {
            // Each claim has its own short write transaction. Never retain 128 full
            // admission bundles or hold a node-wide writer over the whole bounded page.
            let tx = self.migration_db().begin_write().map_err(storage)?;
            let now = clock(&tx, now)?;
            if tx
                .open_table(COURIER)
                .map_err(storage)?
                .get(index.as_str())
                .map_err(storage)?
                .is_none()
            {
                continue;
            }
            tx.open_table(COURIER).map_err(storage)?.remove(index.as_str()).map_err(storage)?;
            let Some(mut op) = read::<MigrationOperation>(&tx, OPS, &key)? else {
                commit_transition(self, tx)?;
                continue;
            };
            if !pending(op.phase) {
                commit_transition(self, tx)?;
                continue;
            }
            op.next_due = now.checked_add(30).ok_or_else(|| storage("courier time overflow"))?;
            write(&tx, OPS, &key, &op)?;
            write(
                &tx,
                COURIER,
                &maintenance::due_key(
                    op.next_due,
                    &op.prepare.body.account_anchor,
                    &op.prepare.body.migration_id,
                ),
                &key,
            )?;
            claimed.push(MigrationCourierClaim {
                peer: op.base.record.home().0.to_owned(),
                key,
                next_due: op.next_due,
                state_version: op.state_version,
            });
            commit_transition(self, tx)?;
        }
        Ok(claimed)
    }
    pub(crate) fn claimed_migration_courier(
        &self,
        claim: &MigrationCourierClaim,
    ) -> Result<Option<MigrationOperation>, NodeCoreError> {
        use redb::ReadableDatabase;
        let tx = self.migration_db().begin_read().map_err(storage)?;
        let table = tx.open_table(OPS).map_err(storage)?;
        let op = table
            .get(claim.key.as_str())
            .map_err(storage)?
            .map(|value| decode::<MigrationOperation>(value.value()))
            .transpose()?;
        Ok(op.filter(|op| {
            pending(op.phase)
                && op.next_due == claim.next_due
                && op.state_version == claim.state_version
        }))
    }
    pub(crate) fn retry_migration_courier(
        &self,
        claimed: &MigrationOperation,
        outcome_unknown: bool,
        now: u64,
    ) -> Result<(), NodeCoreError> {
        let tx = self.migration_db().begin_write().map_err(storage)?;
        let now = clock(&tx, now)?;
        let p = &claimed.prepare.body;
        let key = op_key(&p.account_anchor, &p.migration_id, MigrationRole::Destination)?;
        let Some(mut op) = read::<MigrationOperation>(&tx, OPS, &key)? else {
            return Ok(());
        };
        if !pending(op.phase)
            || op.state_version != claimed.state_version
            || op.next_due != claimed.next_due
        {
            return Ok(());
        }
        maintenance::remove_courier(&tx, &op)?;
        op.phase = if outcome_unknown { Phase::CommitOutcomeUnknown } else { Phase::CommitPending };
        let delay = (1_u64 << op.state_version.saturating_sub(2).min(6)).min(60);
        op.state_version =
            op.state_version.checked_add(1).ok_or_else(|| storage("courier version overflow"))?;
        op.next_due = now.checked_add(delay).ok_or_else(|| storage("courier time overflow"))?;
        write(&tx, OPS, &key, &op)?;
        write(
            &tx,
            COURIER,
            &maintenance::due_key(op.next_due, &p.account_anchor, &p.migration_id),
            &key,
        )?;
        commit_transition(self, tx)
    }
}
fn pending(phase: Phase) -> bool {
    matches!(phase, Phase::Sealed | Phase::CommitPending | Phase::CommitOutcomeUnknown)
}
