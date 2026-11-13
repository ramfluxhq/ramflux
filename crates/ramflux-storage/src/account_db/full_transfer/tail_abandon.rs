// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Explicit local data abandonment leaves installation and independent cleanup evidence intact.
use crate::{AccountDb, StorageError};
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
        if live.role != "responder" {
            return Err(wrong());
        }
        if let Some(completion) = self.full_completion(operation, generation, "responder", now)? {
            return if completion.outcome() == "abandoned" { Ok(()) } else { Err(wrong()) };
        }
        let stage = self.installed_tail_stage(operation, generation, now)?;
        let merged: bool = self.connection.query_row("SELECT tail_status='merged' FROM pairing_full_tail_apply WHERE operation_id=?1 AND stage_digest=?2", params![operation, stage.resume_record()?.stage_digest()?.as_slice()], |row| row.get(0))?;
        if merged {
            return Err(wrong());
        }
        stage.connection.execute(
            "INSERT INTO data_terminal VALUES(1,'cancelled') ON CONFLICT(singleton) DO NOTHING",
            [],
        )?;
        super::stage::sync_stage(&stage.directory)?;
        let completion =
            super::completion::Completion::from_stage(&stage, operation, "abandoned", None)?;
        self.write_transaction(|| {
            self.connection.execute("UPDATE pairing_full_tail SET tail_status='abandoned' WHERE account_id=?1 AND operation_id=?2 AND tail_status='pending'", params![self.local_account_id, operation])?;
            self.connection.execute("UPDATE pairing_full_tail_apply SET tail_status='abandoned' WHERE operation_id=?1 AND tail_status='pending'", params![operation])?;
            self.retain_full_completion(&completion, now)
        })?;
        Ok(())
    }
}
