// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Search restore admission belongs to the local index owner, outside every account archive.
use super::AccountIndex;
use crate::{StorageError, local_search::SearchActivation};
use rusqlite::{OptionalExtension as _, params};
impl AccountIndex {
    pub(crate) fn search_owner_admitted(&self, id: &str) -> Result<bool, StorageError> {
        let restored: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM account_backup_generation WHERE local_account_id=?1)",
            params![id],
            |r| r.get(0),
        )?;
        if !restored {
            return Ok(true);
        }
        let exists:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='account_local_search_admission')",[],|r|r.get(0))?;
        if !exists {
            return Ok(false);
        }
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM account_local_search_admission a JOIN local_account l USING(local_account_id) WHERE a.local_account_id=?1 AND a.db_relative_path=l.db_relative_path AND a.principal_commitment=l.principal_commitment)",params![id],|r|r.get(0))?)
    }
    /// Records a trusted restore-owner decision AFTER visibility/floor validation.
    /// This API is never called from archive decoding or exposed as an archive-controlled field.
    /// A new generation needs a new decision; an archive cannot grant itself search permission.
    /// # Errors
    /// Refuses missing/removed accounts and a selection changed during admission.
    pub fn admit_local_search_after_floor_validation(
        &self,
        _activation: &SearchActivation,
        id: &str,
    ) -> Result<(), StorageError> {
        let _writer = self.acquire_account_writer(id)?;
        crate::account_erase::refuse_removed(&self.account(id)?)?;
        let tx = self.connection.immediate_transaction()?;
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS account_local_search_admission(local_account_id TEXT PRIMARY KEY,db_relative_path TEXT NOT NULL,principal_commitment TEXT NOT NULL);")?;
        let selection:Option<(String,String)>=self.connection.query_row("SELECT db_relative_path,principal_commitment FROM local_account WHERE local_account_id=?1",params![id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (path, principal) =
            selection.ok_or_else(|| StorageError::AccountNotFound(id.into()))?;
        self.connection.execute("INSERT INTO account_local_search_admission VALUES(?1,?2,?3) ON CONFLICT(local_account_id) DO UPDATE SET db_relative_path=excluded.db_relative_path,principal_commitment=excluded.principal_commitment",params![id,path,principal])?;
        tx.commit()?;
        Ok(())
    }
}
