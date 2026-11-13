// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! B's completed G3 releases its head-writer slot while retaining the data/tail reference.
use crate::{AccountDb, AdoptionRow, StorageError};
fn wrong() -> StorageError {
    StorageError::PairingField("PublicationPending")
}
impl AccountDb {
    /// Retire only the installed full recipient's exact acknowledged local head.
    /// Caller must finish native files and G3 first. This grants no native authority,
    /// erases no key/stage and leaves the full live reference for tail/terminal cleanup.
    /// # Errors
    /// Refuses another account/role/candidate, nonselected DB or incomplete adoption.
    pub fn retire_full_recipient_install_head(
        &self,
        adoption: &AdoptionRow,
    ) -> Result<(), StorageError> {
        self.require_full_stage_unlock()?;
        if adoption.account_id != self.local_account_id
            || adoption.local_role != "primary"
            || adoption.full_generation_nonce.is_none()
            || adoption.full_initial_union_root.is_none()
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
            if head.operation_id != adoption.operation_id
                || head.state != "acknowledged"
                || head.kind != "transfer"
                || head.candidate_hash != adoption.record_hash
                || head.recipient_ref.as_deref() != Some(adoption.local_ref.as_slice())
                || head.publisher_ref == adoption.local_ref
                || live.role != "responder"
                || live.phase != "locally_installed"
                || live.generation != head.generation
                || live.full_stage_reference()?.is_none()
            {
                return Err(wrong());
            }
            if self.connection.execute("DELETE FROM pairing_head WHERE account_id=?1 AND operation_id=?2 AND candidate_hash=?3 AND state='acknowledged'",rusqlite::params![adoption.account_id,adoption.operation_id,adoption.record_hash])?!=1{return Err(wrong());}
        }
        transaction.commit()?;
        Ok(())
    }
}
