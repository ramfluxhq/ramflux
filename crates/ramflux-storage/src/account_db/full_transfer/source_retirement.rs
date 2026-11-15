// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Source role handback releases only its installed head, retaining its one tail opportunity.
use crate::{AccountDb, AdoptionRow, StorageError};
fn wrong() -> StorageError {
    StorageError::PairingField("PublicationPending")
}
impl AccountDb {
    /// Caller has durably installed the independently verified secondary role/refs.
    /// No stage, source data, branch/data key or tail marker is deleted by this operation.
    /// # Errors
    /// Refuses wrong source/role/candidate, missing J6/tail link or an unrelated live head.
    pub fn retire_full_source_install_head(
        &self,
        adoption: &AdoptionRow,
    ) -> Result<(), StorageError> {
        self.require_full_stage_unlock()?;
        if adoption.account_id != self.local_account_id
            || adoption.local_role != "secondary"
            || adoption.primary_vault_ref.is_some()
        {
            return Err(wrong());
        }
        let transaction = self.connection.immediate_transaction()?;
        if self.pairing_adoption()?.as_ref() != Some(adoption) {
            return Err(wrong());
        }
        if let Some(head) = self.pairing_head()? {
            let live = self
                .pairing_live_rows()?
                .into_iter()
                .find(|row| row.operation_id == adoption.operation_id)
                .ok_or_else(wrong)?;
            let reference = live.full_stage_reference()?.ok_or_else(wrong)?;
            let tail:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM pairing_full_tail WHERE account_id=?1 AND operation_id=?2 AND stage_id=?3 AND record_hash=?4)",rusqlite::params![adoption.account_id,adoption.operation_id,reference.stage_id,adoption.record_hash],|row|row.get(0))?;
            if head.operation_id != adoption.operation_id
                || head.state != "acknowledged"
                || head.kind != "transfer"
                || head.candidate_hash != adoption.record_hash
                || head.publisher_ref != adoption.local_ref
                || head.recipient_ref.as_deref() == Some(adoption.local_ref.as_slice())
                || live.role != "initiator"
                || live.phase != "locally_installed"
                || live.generation != head.generation
                || !tail
            {
                return Err(wrong());
            }
            if self.connection.execute("DELETE FROM pairing_head WHERE account_id=?1 AND operation_id=?2 AND candidate_hash=?3 AND state='acknowledged'",rusqlite::params![adoption.account_id,adoption.operation_id,adoption.record_hash])?!=1{return Err(wrong());}
        }
        transaction.commit()?;
        Ok(())
    }
}
