// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT W1 adapter for own-copy receive (S6b P14). No production caller reaches it: the
//! live `apply_own_receive` path is unchanged. The expectation values come from the caller;
//! P20 (the actor contract) supplies them.
//!
//! Contract: W0 (`stage`) precedes the own-copy effect; replay marker, control, pair slot,
//! receipt, erased/backup-safe (T,E,s) locator and late bind run inside one generation,
//! incarnation, cursor and erase-fenced receive transaction. Recovery's durable reset work
//! is the same W1 cut. Never persist plaintext to make a step resumable.
#![allow(dead_code)]

use super::receipts::OwnCopyAckBinding;
use crate::{RamfluxClient, SdkError};
use ramflux_storage::{
    AccountDb, ReceiveBind, ReceiveExpectation, ReceiveStage, ReceiveStageResult,
    ReceiveTransaction, StorageError,
};
use serde::{Deserialize, Serialize};

/// Message-linked locator prefix. Backup native/merge already exclude `own-device/%`.
pub(crate) const LOCATORS: &str = "own-device/sequence-locator/";

/// Erased- and backup-safe (target, incarnation, sequence) locator. No body or content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SequenceLocator {
    pub target: String,
    pub incarnation: String,
    pub sequence: u64,
    /// Set only by WA on a terminal router result. Expiry never sets this.
    #[serde(default)]
    pub acknowledged: bool,
    /// Keys of the existing replay marker and receipt that WA marks in the settlement
    /// transaction. Stored at W1 so the marking never needs the inbox entry.
    #[serde(default)]
    pub ack: Option<OwnCopyAckBinding>,
}

/// Locator actor key bound to `message` so erase visits it.
#[must_use]
pub(crate) fn locator_key(message: &str) -> String {
    format!("{LOCATORS}{message}")
}

pub(crate) struct OwnCopyW1<'a> {
    pub expected: ReceiveExpectation<'a>,
    /// The caller actor's current generation (the fence compares it with `expected.generation`).
    pub generation: u64,
}

impl OwnCopyW1<'_> {
    /// W0: reserves receipt, work and terminal-intent capacity before any own-copy effect.
    pub(crate) fn stage(
        &self,
        db: &AccountDb,
        input: ReceiveStage<'_>,
    ) -> Result<ReceiveStageResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.stage(input))?)
    }

    /// Runs the own-copy durable writes, then registers the (T,E,s) locator (carrying the
    /// `ack` binding of the replay marker and receipt the effect committed) and binds the
    /// staged input to `message`, all inside one receive transaction.
    ///
    /// Error contract: any error from `effect` rolls back every write it made, and that error
    /// is returned unchanged. A `PairRecoveryRequired` therefore leaves no reset work behind
    /// here. P20 must route that exact error to `recover`, which runs the reset as its own
    /// W1 cut. Nothing in this path retries the reset implicitly.
    pub(crate) fn effect<T>(
        &self,
        db: &AccountDb,
        sequence: u64,
        message: &str,
        ack: Option<OwnCopyAckBinding>,
        effect: impl FnOnce() -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        join_own_copy(db, self.expected, self.generation, "own-copy effect failed", |tx| {
            self.effect_in(tx, sequence, message, ack, effect)
        })
    }

    /// Same cut as [`Self::effect`], joining an already-open receive transaction.
    pub(crate) fn effect_in<T>(
        &self,
        tx: &ReceiveTransaction<'_>,
        sequence: u64,
        message: &str,
        ack: Option<OwnCopyAckBinding>,
        effect: impl FnOnce() -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        tx.require_open_input(sequence)?;
        let value = effect()?;
        register_sequence_locator(tx.account(), message, self.expected, sequence, ack)?;
        match tx.bind_logical_message(sequence, message)? {
            ReceiveBind::Bound | ReceiveBind::Erased => {}
        }
        before_commit_fault()?;
        Ok(value)
    }

    /// Recovery W1 cut: durable reset work runs inside the same fenced transaction.
    pub(crate) fn recover<T>(
        &self,
        db: &AccountDb,
        sequence: u64,
        effect: impl FnOnce() -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        join_own_copy(db, self.expected, self.generation, "own-copy recovery failed", |tx| {
            self.recover_in(tx, sequence, effect)
        })
    }

    /// Same cut as [`Self::recover`], joining an already-open receive transaction.
    #[allow(clippy::unused_self)]
    pub(crate) fn recover_in<T>(
        &self,
        tx: &ReceiveTransaction<'_>,
        sequence: u64,
        effect: impl FnOnce() -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        tx.require_open_input(sequence)?;
        let value = effect()?;
        before_commit_fault()?;
        Ok(value)
    }
}

fn join_own_copy<T>(
    db: &AccountDb,
    expected: ReceiveExpectation<'_>,
    generation: u64,
    failed: &'static str,
    write: impl FnOnce(&ReceiveTransaction<'_>) -> Result<T, SdkError>,
) -> Result<T, SdkError> {
    let mut outcome = None;
    let fenced = db.receive_transaction(expected, generation, |tx| match write(tx) {
        Ok(value) => {
            outcome = Some(Ok(value));
            Ok(())
        }
        Err(error) => {
            outcome = Some(Err(error));
            Err(StorageError::Integrity(failed))
        }
    });
    match (fenced, outcome) {
        (_, Some(Err(error))) => Err(error),
        (Err(error), _) => Err(error.into()),
        (Ok(()), Some(Ok(value))) => Ok(value),
        (Ok(()), None) => Err(SdkError::LocalBus("own-copy write did not run".into())),
    }
}

fn register_sequence_locator(
    db: &AccountDb,
    message: &str,
    expected: ReceiveExpectation<'_>,
    sequence: u64,
    ack: Option<OwnCopyAckBinding>,
) -> Result<(), StorageError> {
    let locator = SequenceLocator {
        target: expected.target.to_owned(),
        incarnation: expected.incarnation.to_owned(),
        sequence,
        acknowledged: false,
        ack,
    };
    let key = locator_key(message);
    if omit_locator_registration() {
        // Negative: actor row without a message footprint. Erase will not visit it.
        return db.persist_actor_state(&key, &locator);
    }
    db.persist_message_actor_state(message, &key, &locator)
}

fn before_commit_fault() -> Result<(), StorageError> {
    if matches!(current_fault(), Fault::BeforeCommit) {
        return Err(StorageError::Integrity("own-copy w1 before-commit"));
    }
    Ok(())
}

fn omit_locator_registration() -> bool {
    #[cfg(test)]
    {
        OMIT_LOCATOR.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
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

/// In-transaction fault injected by tests. Production always uses `None`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fault {
    None,
    BeforeCommit,
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) };
    static OMIT_LOCATOR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn run<T>(fault: Fault, f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULT.with(|cell| cell.set(Fault::None));
        }
    }
    FAULT.with(|cell| cell.set(fault));
    let _reset = Reset;
    f()
}

#[cfg(test)]
pub(crate) fn with_omit_locator<T>(f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            OMIT_LOCATOR.with(|cell| cell.set(false));
        }
    }
    OMIT_LOCATOR.with(|cell| cell.set(true));
    let _reset = Reset;
    f()
}

impl RamfluxClient {
    /// Decrypts an own-copy packet and commits through the dormant W1 adapter.
    pub(crate) fn apply_own_copy_w1(
        &self,
        entry: &crate::GatewayInboxEntry,
        manifest: &crate::SdkDeviceManifestResponse,
        expected: ReceiveExpectation<'_>,
        sequence: u64,
        message: &str,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let generation = expected.generation;
        let gate = OwnCopyW1 { expected, generation };
        let ack = self.own_copy_ack_binding(entry)?;
        gate.effect(db, sequence, message, ack, || self.commit_own_copy_from_entry(entry, manifest))
    }

    /// Same cut as [`Self::apply_own_copy_w1`], joining an already-open receive transaction.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_own_copy_w1_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        entry: &crate::GatewayInboxEntry,
        manifest: &crate::SdkDeviceManifestResponse,
        expected: ReceiveExpectation<'_>,
        sequence: u64,
        message: &str,
    ) -> Result<bool, SdkError> {
        let generation = expected.generation;
        let gate = OwnCopyW1 { expected, generation };
        let ack = self.own_copy_ack_binding(entry)?;
        gate.effect_in(tx, sequence, message, ack, || {
            self.commit_own_copy_from_entry(entry, manifest)
        })
    }

    /// Recovery W1 cut for the pair-reset durable writes.
    pub(crate) fn recover_own_copy_w1(
        &self,
        entry: &crate::GatewayInboxEntry,
        expected: ReceiveExpectation<'_>,
        sequence: u64,
        now: i64,
    ) -> Result<bool, SdkError> {
        let db = self.account_db()?;
        let generation = expected.generation;
        let gate = OwnCopyW1 { expected, generation };
        let local = self.owned_device_identity()?;
        let remote = self.authenticated_device_identity(
            crate::client::identity_authority::HeadUse::NewAuthorization,
            entry,
        )?;
        gate.recover(db, sequence, || self.begin_pair_recovery(&local, &remote, now))
    }

    /// Same recovery cut as [`Self::recover_own_copy_w1`], joining an already-open receive
    /// transaction under `lifecycle_fence`.
    pub(crate) fn recover_own_copy_w1_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        entry: &crate::GatewayInboxEntry,
        expected: ReceiveExpectation<'_>,
        sequence: u64,
        now: i64,
    ) -> Result<bool, SdkError> {
        let generation = expected.generation;
        let gate = OwnCopyW1 { expected, generation };
        let local = self.owned_device_identity()?;
        let remote = self.authenticated_device_identity(
            crate::client::identity_authority::HeadUse::NewAuthorization,
            entry,
        )?;
        gate.recover_in(tx, sequence, || self.begin_pair_recovery(&local, &remote, now))
    }
}

#[cfg(test)]
mod tests {
    use super::{LOCATORS, locator_key};

    #[test]
    fn sequence_locator_key_is_own_device_prefixed() {
        let key = locator_key("message-id");
        assert!(key.starts_with(LOCATORS), "{key}");
        assert!(key.starts_with("own-device/"), "{key}");
    }
}
