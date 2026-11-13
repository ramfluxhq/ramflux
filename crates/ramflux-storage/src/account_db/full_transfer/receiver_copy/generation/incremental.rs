// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Update retained G1 by local row differences instead of another physical database copy.
use super::{FullPreparedReceiverDatabase, FullTransferStage, StorageError, wrong};
use crate::BackupDatabase;
use rusqlite::params;
use std::collections::BTreeSet;

impl FullPreparedReceiverDatabase {
    /// Rebase the last optimistic attempt under the caller's bounded all-writer fence.
    /// A's retained ledger is unchanged; only B's local row differences are applied.
    /// # Errors
    /// Refuses replaced/locked writers, key changes, corrupt G1, unsafe input or the deadline.
    pub fn rebase_current_target(
        &mut self,
        stage: &FullTransferStage<'_>,
        now: u64,
    ) -> Result<crate::FullUnionEncoding, StorageError> {
        self.0.live()?;
        self.1.lock().map_err(|_| wrong())?.require(&self.0.path)?;
        stage.db.verify_key(&self.0.key)?;
        self.0.copy.rebase_current_target(stage)?;
        self.0.copy.retain_for_installation(stage, now)?;
        let current = self.0.copy.union.as_ref().ok_or_else(wrong)?;
        let union = crate::FullUnionEncoding {
            generation_nonce: current.generation_nonce,
            records: current.records,
            total_bytes: current.total_bytes,
            chunks_root: current.chunks_root,
        };
        self.0.adoption.full_initial_union_root =
            Some(ramflux_protocol::encode_base64url(union.chunks_root));
        let mut target = BackupDatabase::open_full_receiver_copy(&self.0.path, &self.0.key)?;
        super::super::sql_delta::attach(
            &mut target.db,
            &self.0.copy.scratch.path.join("private.db"),
            &self.0.copy.key,
        )?;
        target.db.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let tables: BTreeSet<_> = super::super::super::full_transfer_catalog()
                .iter()
                .filter_map(|rule| match rule.selector {
                    super::super::super::FamilySelector::Table(table)
                        if table != "account_key_check" =>
                    {
                        Some(table)
                    }
                    _ => None,
                })
                .collect();
            for table in tables {
                stage.require_io()?;
                super::super::sql_delta::table(&target.db, table)?;
            }
            super::super::sql_delta::sequences(&target.db)?;
            let row = &self.0.adoption;
            target.db.execute("INSERT INTO pairing_adoption(account_id,operation_id,record_hash,local_ref,local_role,branch_vault_ref,data_vault_ref,primary_vault_ref,full_generation_nonce,full_initial_union_root) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) ON CONFLICT(account_id) DO UPDATE SET operation_id=excluded.operation_id,record_hash=excluded.record_hash,local_ref=excluded.local_ref,local_role=excluded.local_role,branch_vault_ref=excluded.branch_vault_ref,data_vault_ref=excluded.data_vault_ref,primary_vault_ref=excluded.primary_vault_ref,full_generation_nonce=excluded.full_generation_nonce,full_initial_union_root=excluded.full_initial_union_root",params![row.account_id,row.operation_id,row.record_hash,row.local_ref,row.local_role,row.branch_vault_ref,row.data_vault_ref,row.primary_vault_ref,row.full_generation_nonce,row.full_initial_union_root])?;
            target.db.execute(
                "DELETE FROM pairing_full_tail_dependency WHERE operation_id=?1",
                params![row.operation_id],
            )?;
            target.db.execute(
                "DELETE FROM pairing_full_tail_apply WHERE operation_id=?1",
                params![row.operation_id],
            )?;
            super::tail::seed(&target.db, &self.0.copy, row, || self.0.live())?;
            stage.require_io()?;
            target.db.execute_batch("COMMIT")?;
            Ok::<_, StorageError>(())
        })();
        if result.is_err() {
            let _ = target.db.execute_batch("ROLLBACK");
        }
        result?;
        drop(target);
        super::super::super::stage::open_regular(&self.0.path, false)?.sync_all()?;
        let sealed = self.0.verify_prepared(stage)?;
        *self.1.lock().map_err(|_| wrong())? = sealed;
        Ok(union)
    }
}
