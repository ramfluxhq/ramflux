// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Optimistic target-copy observation, never a generation lease or native approval.
use super::super::backup::FullTransferCut;
use crate::{
    AccountDb, LocalAccountRecord, StorageError,
    database::{Connection, WeakConnection},
};

#[derive(PartialEq, Eq)]
struct Version {
    own_changes: u64,
    other_changes: u64,
    privacy_epoch: u64,
}
fn version(connection: &Connection) -> Result<Version, StorageError> {
    Ok(connection.query_row(
        "SELECT total_changes(),(SELECT data_version FROM pragma_data_version),(SELECT generation FROM account_erasure_generation WHERE singleton=1)",
        [],|row|Ok(Version {own_changes:row.get(0)?,other_changes:row.get(1)?,privacy_epoch:row.get(2)?}),
    )?)
}
fn busy() -> StorageError {
    StorageError::PairingField("Busy")
}

/// Opaque data-copy observation of the actual original unlocked target worker.
/// It retains no connection, key, approval or publication capability. It cannot be
/// deserialized after restart; the target must rebase against its new current owner.
pub struct FullTargetObservation {
    account: LocalAccountRecord,
    root: std::path::PathBuf,
    worker: WeakConnection,
    version: Version,
}
impl FullTargetObservation {
    #[must_use]
    pub fn local_account_id(&self) -> &str {
        &self.account.local_account_id
    }
    #[must_use]
    pub fn prior_db_relative_path(&self) -> &str {
        &self.account.db_relative_path
    }
    #[must_use]
    pub fn prior_object_relative_path(&self) -> &str {
        &self.account.object_dir_relative_path
    }
    #[must_use]
    pub const fn privacy_epoch(&self) -> u64 {
        self.version.privacy_epoch
    }

    /// Recheck under the actual generation/writer owner immediately before selection.
    /// ALL target writes matter, including B-local session/device state not in the
    /// portable root. Progress should be staged separately; no network runs in that fence.
    /// Success is an observation only; it cannot reserve a future mutation-free interval.
    /// # Errors
    /// Refuses a different/reopened/locked worker, changed selected paths or target writes.
    pub fn require_current(&self, db: &AccountDb) -> Result<(), StorageError> {
        db.require_selected_transfer_source()?;
        let original =
            self.worker.upgrade_account_writer().ok_or(StorageError::AuthorizationRejected)?;
        if !original.same_worker(&db.connection)
            || self.root != db.account_index.root()
            || self.account.local_account_id != db.local_account_id
            || self.account != db.account_index.account(&db.local_account_id)?
        {
            return Err(busy());
        }
        if self.version != version(&db.connection)? {
            return Err(busy());
        }
        db.require_selected_transfer_source()?;
        Ok(())
    }
}

impl AccountDb {
    /// Pin B's immutable target view and its optimistic change observation together.
    /// Release the caller's writer fence after this returns, then perform the bulk copy
    /// using the existing bounded snapshot owner. Before selecting a prepared union,
    /// reacquire the real generation/writer fence and call `require_current`.
    /// # Errors
    /// Refuses stale/read-only/locked owners or a write/selection change during pinning.
    pub fn pin_full_transfer_target(
        &self,
    ) -> Result<(FullTransferCut, FullTargetObservation), StorageError> {
        self.require_selected_transfer_source()?;
        let worker = self.connection.downgrade();
        if worker.upgrade_account_writer().is_none() {
            return Err(StorageError::AuthorizationRejected);
        }
        let account = self.account_index.account(&self.local_account_id)?;
        let observed = version(&self.connection)?;
        let cut = self.pin_full_transfer_cut()?;
        let observation = FullTargetObservation {
            account,
            root: self.account_index.root().to_owned(),
            worker,
            version: observed,
        };
        observation.require_current(self)?;
        Ok((cut, observation))
    }
}

#[cfg(test)]
mod tests;
