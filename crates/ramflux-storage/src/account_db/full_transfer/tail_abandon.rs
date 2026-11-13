// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit local data abandonment leaves installation and independent cleanup evidence intact.
use crate::{AccountDb, StorageError};
use ramflux_crypto::custody::pairing::PairingRole;
use rusqlite::params;
fn wrong() -> StorageError {
    StorageError::PairingField("WrongContext")
}
impl AccountDb {
    /// Explicitly abandon only a retained installed tail, including after lease expiry.
    /// This does not revoke native authority, erase portable data or reclaim any key/file.
    /// The caller must cancel and drain that operation's local jobs before calling it.
    /// # Errors
    /// Refuses another generation, incomplete installation/J6, foreign local scope or busy stage.
    pub fn abandon_full_tail(
        &self,
        operation: &str,
        generation: u64,
        now: u64,
    ) -> Result<(), StorageError> {
        self.require_full_stage_unlock()?;
        let live = self
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or_else(wrong)?;
        if live.generation != generation || self.pairing_head()?.is_some() {
            return Err(wrong());
        }
        let stage = match live.role.as_str() {
            "initiator" => {
                let reference = live.full_stage_reference()?.ok_or_else(wrong)?;
                let stage = self.open_full_stage_reference_inner(
                    reference,
                    PairingRole::Initiator,
                    now,
                    true,
                )?;
                let hash: String = self.connection.query_row(
                    "SELECT record_hash FROM pairing_full_tail WHERE account_id=?1 AND operation_id=?2 AND stage_id=?3",
                    params![self.local_account_id, operation, stage.reference().stage_id], |row| row.get(0),
                )?;
                self.full_source_retirement_owner(operation, &hash, now)?;
                let adoption = self.pairing_adoption()?.ok_or_else(wrong)?;
                if adoption.local_ref
                    != ramflux_protocol::canonical_json_bytes(
                        &stage.resume_record()?.grant.source_ref,
                    )?
                {
                    return Err(wrong());
                }
                stage
            }
            "responder" => self.installed_tail_stage(operation, generation, now)?,
            _ => return Err(wrong()),
        };
        let merged: bool = if live.role == "initiator" {
            self.connection.query_row("SELECT tail_status='merged' FROM pairing_full_tail WHERE account_id=?1 AND operation_id=?2 AND stage_id=?3", params![self.local_account_id, operation, stage.reference().stage_id], |row| row.get(0))?
        } else {
            self.connection.query_row("SELECT tail_status='merged' FROM pairing_full_tail_apply WHERE operation_id=?1 AND stage_digest=?2", params![operation, stage.resume_record()?.stage_digest()?.as_slice()], |row| row.get(0))?
        };
        if merged {
            return Ok(());
        }
        stage.connection.execute(
            "INSERT INTO data_terminal VALUES(1,'cancelled') ON CONFLICT(singleton) DO NOTHING",
            [],
        )?;
        super::stage::sync_stage(&stage.directory)?;
        let account = self.local_account_id.clone();
        let operation = operation.to_owned();
        self.connection.call(move |raw| {
            let tx = raw.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute("UPDATE pairing_full_tail SET tail_status='abandoned' WHERE account_id=?1 AND operation_id=?2 AND tail_status='pending'", params![account, operation])?;
            tx.execute("UPDATE pairing_full_tail_apply SET tail_status='abandoned' WHERE operation_id=?1 AND tail_status='pending'", params![operation])?;
            tx.commit()
        })?;
        Ok(())
    }
}
