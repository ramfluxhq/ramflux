// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Persistent receive-ledger activation discriminator in existing checkpoint metadata.
//! Default-off: production never first-activates. Restore strips the discriminator.

use super::migrate::{ReceiveMigrate, ReceiveMigrateResult};
use crate::{AccountDb, ProjectionStore, StorageError};

/// Checkpoint name in existing `projection_checkpoint` receive metadata.
pub const ACTIVATION_KEY: &str = "gateway_receive_activation";
const ACTIVATED: &str = "activated";

/// Exact error when a legacy receive writer meets an activated account DB.
pub const LEGACY_RECEIVE_ACTIVATED: &str = "receive ledger activated";
/// Exact error when the discriminator is present but not a known state.
pub const UNKNOWN_ACTIVATION: &str = "receive activation unknown";
/// Exact error when Activated metadata has no epoch for the requested target.
pub const MISSING_EPOCH: &str = "receive activation missing epoch";

/// First-activation switch. Off until P25; already-activated accounts stay on the ledger.
pub const FIRST_ACTIVATION_DEFAULT: bool = false;

/// Whether this account DB has committed ledger activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum ReceiveActivation {
    Inactive,
    Activated,
}

impl AccountDb {
    /// Reads the durable discriminator. Absence is Inactive (including a stripped restore).
    ///
    /// # Errors
    /// Returns SQLite errors. An unknown discriminator value fails closed.
    pub fn receive_activation(&self) -> Result<ReceiveActivation, StorageError> {
        match self.projection_checkpoint(ACTIVATION_KEY)?.as_deref() {
            Some(ACTIVATED) => Ok(ReceiveActivation::Activated),
            None => Ok(ReceiveActivation::Inactive),
            Some(_) => Err(StorageError::Integrity(UNKNOWN_ACTIVATION)),
        }
    }

    /// Legacy receive writers must call this before writing C or ACK state.
    ///
    /// # Errors
    /// Returns [`LEGACY_RECEIVE_ACTIVATED`] when the discriminator is Activated, or
    /// [`UNKNOWN_ACTIVATION`] when the stored value is not a known state.
    pub fn refuse_legacy_receive(&self) -> Result<(), StorageError> {
        match self.receive_activation()? {
            ReceiveActivation::Activated => Err(StorageError::Integrity(LEGACY_RECEIVE_ACTIVATED)),
            ReceiveActivation::Inactive => Ok(()),
        }
    }

    /// Writes a legacy checkpoint only after re-reading the discriminator in this writer.
    ///
    /// # Errors
    /// Returns [`LEGACY_RECEIVE_ACTIVATED`] or [`UNKNOWN_ACTIVATION`] instead of writing.
    pub fn persist_legacy_checkpoint_if_inactive(
        &self,
        projection_name: &str,
        last_event_id: &str,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            self.refuse_legacy_receive()?;
            self.set_projection_checkpoint(projection_name, last_event_id)
        })
    }

    /// Advances legacy receive C only after re-reading the discriminator in this writer.
    ///
    /// # Errors
    /// Returns [`LEGACY_RECEIVE_ACTIVATED`] or [`UNKNOWN_ACTIVATION`] instead of writing.
    pub fn persist_receive_cursor_if_inactive(
        &self,
        target: &str,
        inbox_seq: u64,
    ) -> Result<(), StorageError> {
        self.write_transaction(|| {
            self.refuse_legacy_receive()?;
            let next = inbox_seq.max(self.receive_cursor(target)?);
            self.set_projection_checkpoint(
                &format!("gateway_receive_cursor:{target}"),
                &next.to_string(),
            )
        })
    }

    /// Dormant first-activation. Production stays off; tests call [`Self::activate_receive_ledger`].
    ///
    /// # Errors
    /// Returns writer or migration errors when the default is on.
    pub fn first_activate_if_default(
        &self,
        input: ReceiveMigrate<'_>,
    ) -> Result<Option<ReceiveMigrateResult>, StorageError> {
        if !FIRST_ACTIVATION_DEFAULT {
            return Ok(None);
        }
        self.activate_receive_ledger(input).map(Some)
    }

    /// Atomically commits schema/migration/import and the discriminator in one outer transaction.
    ///
    /// # Errors
    /// Requires a writable account DB. A crash before COMMIT leaves Inactive; after COMMIT, Activated.
    pub fn activate_receive_ledger(
        &self,
        input: ReceiveMigrate<'_>,
    ) -> Result<ReceiveMigrateResult, StorageError> {
        self.write_transaction(|| self.activate_receive_ledger_in(input))
    }

    /// Same as [`Self::activate_receive_ledger`] inside the caller's writer.
    ///
    /// # Errors
    /// Refuses autocommit. Migration and discriminator share this transaction.
    pub fn activate_receive_ledger_in(
        &self,
        input: ReceiveMigrate<'_>,
    ) -> Result<ReceiveMigrateResult, StorageError> {
        if self.connection.is_autocommit()? {
            return Err(StorageError::AuthorizationRejected);
        }
        if self.receive_activation()? == ReceiveActivation::Activated {
            if !self.epoch_exists_for(input.target)? {
                return Err(StorageError::Integrity(MISSING_EPOCH));
            }
            return Ok(ReceiveMigrateResult::Existing);
        }
        let result = self.migrate_direct(input)?;
        self.set_projection_checkpoint(ACTIVATION_KEY, ACTIVATED)?;
        before_activation_commit()?;
        Ok(result)
    }

    fn epoch_exists_for(&self, target: &str) -> Result<bool, StorageError> {
        let table: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='gateway_receive_epoch')",
            [],
            |row| row.get(0),
        )?;
        if table == 0 {
            return Ok(false);
        }
        let exists: i64 = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway_receive_epoch WHERE target_delivery_id=?1)",
            rusqlite::params![target],
            |row| row.get(0),
        )?;
        Ok(exists != 0)
    }
}

fn before_activation_commit() -> Result<(), StorageError> {
    if current_fault() == Fault::BeforeCommit {
        return Err(StorageError::Integrity("receive activation before-commit"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Fault {
    None,
    BeforeCommit,
}

fn current_fault() -> Fault {
    #[cfg(test)]
    {
        FAULT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        Fault::None
    }
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
}

#[cfg(test)]
pub(crate) fn run<T>(fault: FaultKind, write: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULT.with(|slot| slot.set(Fault::None));
        }
    }
    let mapped = match fault {
        FaultKind::BeforeCommit => Fault::BeforeCommit,
    };
    FAULT.with(|slot| slot.set(mapped));
    let _reset = Reset;
    write()
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FaultKind {
    BeforeCommit,
}
