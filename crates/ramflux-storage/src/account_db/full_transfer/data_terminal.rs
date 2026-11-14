// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable endpoint data cancellation survives installation and process restart.
use crate::{AccountDb, StorageError};
use ramflux_crypto::custody::pairing::PairingRole;
pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS data_terminal(singleton INTEGER PRIMARY KEY CHECK(singleton=1),reason TEXT NOT NULL CHECK(reason IN ('cancelled','expired','rejected')));";
impl AccountDb {
    /// Close only this endpoint's data opportunity while retaining exact publication/install work.
    /// Installation may subsequently finish; it cannot clear this terminal data barrier.
    /// # Errors
    /// Refuses wrong role/link/reason, unavailable unlock or an active stage owner.
    pub fn mark_full_transfer_data_terminal(
        &self,
        operation: &str,
        role: PairingRole,
        reason: &str,
        now: u64,
    ) -> Result<(), StorageError> {
        if !matches!(reason, "cancelled" | "expired" | "rejected") {
            return Err(StorageError::PairingField("phase"));
        }
        let live = self
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or(StorageError::PairingField("WrongContext"))?;
        if live.role != role.as_str() {
            return Err(StorageError::PairingField("WrongContext"));
        }
        let reference =
            live.full_stage_reference()?.ok_or(StorageError::PairingField("WrongContext"))?;
        let stage = self.open_full_stage_reference_inner(reference, role, now, true)?;
        stage.connection.execute(
            "INSERT INTO data_terminal VALUES(1,?1) ON CONFLICT(singleton) DO NOTHING",
            rusqlite::params![reason],
        )?;
        super::stage::sync_stage(&stage.directory)
    }
    /// Reclaim only an unprepared terminal DATA stage after its async owners are drained.
    /// A durable head, local adoption or selected generation retains all reconciliation data.
    /// # Errors
    /// Refuses an active stage owner, wrong terminal scope, unsafe paths or I/O failure.
    pub fn reclaim_unprepared_full_stage(
        &self,
        operation: &str,
        role: PairingRole,
        now: u64,
    ) -> Result<bool, StorageError> {
        self.require_full_stage_unlock()?;
        let live = self
            .pairing_live_rows()?
            .into_iter()
            .find(|row| row.operation_id == operation)
            .ok_or(StorageError::PairingField("WrongContext"))?;
        if live.role != role.as_str()
            || !matches!(live.phase.as_str(), "cancelled" | "expired" | "rejected")
        {
            return Err(StorageError::PairingField("WrongContext"));
        }
        if self.pairing_head()?.is_some()
            || self.pairing_adoption()?.is_some_and(|row| row.operation_id == operation)
        {
            return Ok(false);
        }
        let reference =
            live.full_stage_reference()?.ok_or(StorageError::PairingField("WrongContext"))?;
        let directory = match super::stage::stage_directory(self, &reference.stage_id, false) {
            Ok(path) => path,
            Err(StorageError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(true);
            }
            Err(error) => return Err(error),
        };
        let stage = self.open_full_stage_reference_inner(reference, role, now, true)?;
        super::receiver_copy::rebase::require_before_selection(&stage)?;
        let terminal: bool = stage.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM data_terminal)",
            [],
            |row| row.get(0),
        )?;
        if !terminal {
            return Err(StorageError::PairingField("WrongContext"));
        }
        // Keep the exclusive lock after SQLite and the private stage key have closed.
        let lock = stage.lock.clone();
        drop(stage);
        let parent = directory.parent().ok_or(StorageError::PairingField("WrongContext"))?;
        std::fs::remove_dir_all(&directory)?;
        crate::sync_path::sync_path(parent)?;
        drop(lock);
        Ok(true)
    }
}
