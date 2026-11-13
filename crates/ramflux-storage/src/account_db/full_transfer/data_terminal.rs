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
}
