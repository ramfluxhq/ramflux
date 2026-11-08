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
    /// Returns SQLite errors.
    pub fn receive_activation(&self) -> Result<ReceiveActivation, StorageError> {
        Ok(match self.projection_checkpoint(ACTIVATION_KEY)?.as_deref() {
            Some(ACTIVATED) => ReceiveActivation::Activated,
            _ => ReceiveActivation::Inactive,
        })
    }

    /// Legacy receive writers must call this before writing C or ACK state.
    ///
    /// # Errors
    /// Returns [`LEGACY_RECEIVE_ACTIVATED`] when the discriminator is Activated.
    pub fn refuse_legacy_receive(&self) -> Result<(), StorageError> {
        match self.receive_activation()? {
            ReceiveActivation::Activated => Err(StorageError::Integrity(LEGACY_RECEIVE_ACTIVATED)),
            ReceiveActivation::Inactive => Ok(()),
        }
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
            return Ok(ReceiveMigrateResult::Existing);
        }
        let result = self.migrate_direct(input)?;
        self.set_projection_checkpoint(ACTIVATION_KEY, ACTIVATED)?;
        before_activation_commit()?;
        Ok(result)
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
