// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Optimistic target-copy observation, never a generation lease or native approval.
use super::super::backup::FullTransferCut;
use crate::{
    AccountDb, LocalAccountRecord, StorageError,
    database::{Connection, WeakConnection},
};

#[derive(Clone, PartialEq, Eq)]
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
    pub(super) fn refresh_current(&self, db: &AccountDb) -> Result<Self, StorageError> {
        db.require_selected_transfer_source()?;
        let original =
            self.worker.upgrade_account_writer().ok_or(StorageError::AuthorizationRejected)?;
        let account = db.account_index.account(&db.local_account_id)?;
        if !original.same_worker(&db.connection)
            || self.root != db.account_index.root()
            || account != self.account
        {
            return Err(busy());
        }
        let observed = Self {
            account,
            root: self.root.clone(),
            // Keep the original weak owner, not this short fence's expiring permit.
            worker: self.worker.clone(),
            version: version(&db.connection)?,
        };
        observed.require_current(db)?;
        Ok(observed)
    }
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

    /// Commit a locally prepared G2 index selection under the shared account writer fence.
    /// This low-level data primitive does not verify prepared bytes, publication, adoption
    /// or installed files. Its caller must own those proofs and keep ordinary admission
    /// closed through G3. Existing readers retain their old generation until drained.
    ///
    /// Successful selection retires every existing account writer, including queued jobs;
    /// the caller must reopen the exact selected generation. No network runs in this fence.
    /// # Errors
    /// Refuses changed B (all writes, paths, privacy and wrapping), concurrent ownership,
    /// unsafe paths or SQL/I/O errors. Unknown index outcomes retire writers fail-closed.
    pub fn commit_prepared_generation(
        &self,
        db: &AccountDb,
        install: &crate::BackupIndexInstall<'_>,
    ) -> Result<(), StorageError> {
        self.require_current(db)?;
        if install.account_id != self.account.local_account_id
            || install.principal_commitment != self.account.principal_commitment
            || install.db_relative_path == self.account.db_relative_path
            || install.object_relative_path == self.account.object_dir_relative_path
        {
            return Err(StorageError::AuthorizationRejected);
        }
        let index = db.account_index.clone();
        let prior = self.account.clone();
        let version = self.version.clone();
        let wrapped = index
            .load_wrapped_db_key(&prior.local_account_id)?
            .ok_or(StorageError::AuthorizationRejected)?;
        // Retain B's current wrapping, never an incoming source credential.
        if install.wrapped_key != &wrapped {
            return Err(StorageError::AuthorizationRejected);
        }
        let db_path = install.db_relative_path.to_owned();
        let object_path = install.object_relative_path.to_owned();
        let manifest = install.manifest_json.to_vec();
        let account = prior.local_account_id.clone();
        db.connection.call_generation(move |raw| {
            let outcome = (|| -> Result<(), StorageError> {
                let tx = raw.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let actual = tx.query_row(
                    "SELECT total_changes(),(SELECT data_version FROM pragma_data_version),(SELECT generation FROM account_erasure_generation WHERE singleton=1)",
                    [], |r| Ok(Version {own_changes:r.get(0)?,other_changes:r.get(1)?,privacy_epoch:r.get(2)?}))?;
                if actual != version { return Err(busy()); }
                index.install_generation_under_fence(&crate::BackupIndexInstall {
                    account_id: &account, principal_commitment: &prior.principal_commitment,
                    db_relative_path: &db_path, object_relative_path: &object_path,
                    manifest_json: &manifest, wrapped_key: &wrapped,
                }, Some((&prior, &wrapped)))?;
                // No mutation of old B is necessary. The index owns the G2 commit.
                tx.rollback()?;
                Ok(())
            })();
            let selected = index.account_generation_selection(&account);
            match selected {
                Ok(selected) if selected.account.db_relative_path == db_path
                    && selected.account.object_dir_relative_path == object_path
                    && selected.manifest_json.as_deref() == Some(manifest.as_slice()) =>
                    (Ok(Ok(())), true),
                Ok(selected) if selected.account == prior => (Ok(outcome), false),
                // A changed/unknown pointer is never permission to keep an old writer alive.
                _ => (Ok(Err(StorageError::PairingField("InstallPending"))), true),
            }
        }).map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy) { busy() } else { error.into() }
        })?
    }

    pub(super) fn require_current_off_loan(&self) -> Result<(), StorageError> {
        let worker =
            self.worker.upgrade_account_writer().ok_or(StorageError::AuthorizationRejected)?;
        let index = crate::AccountIndex::open(&self.root)?;
        if index.account(&self.account.local_account_id)? != self.account
            || version(&worker)? != self.version
        {
            return Err(busy());
        }
        Ok(())
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
