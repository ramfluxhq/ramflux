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

use crate::{RamfluxClient, SdkError};
use ramflux_storage::{
    AccountDb, ReceiveBind, ReceiveExpectation, ReceiveStage, ReceiveStageResult, StorageError,
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

    /// Runs the own-copy durable writes, then registers the (T,E,s) locator and binds the
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
        effect: impl FnOnce() -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        let mut outcome = None;
        let expected = self.expected;
        let fenced = db.receive_transaction(expected, self.generation, |tx| {
            tx.require_open_input(sequence)?;
            let result = effect();
            let failed = result.is_err();
            outcome = Some(result);
            if failed {
                return Err(StorageError::Integrity("own-copy effect failed"));
            }
            register_sequence_locator(db, message, expected, sequence)?;
            match tx.bind_logical_message(sequence, message)? {
                ReceiveBind::Bound | ReceiveBind::Erased => {}
            }
            before_commit_fault()?;
            Ok(())
        });
        match (fenced, outcome) {
            (_, Some(Err(error))) => Err(error),
            (Err(error), _) => Err(error.into()),
            (Ok(()), Some(Ok(value))) => Ok(value),
            (Ok(()), None) => Err(SdkError::LocalBus("own-copy effect did not run".into())),
        }
    }

    /// Recovery W1 cut: durable reset work runs inside the same fenced transaction.
    pub(crate) fn recover<T>(
        &self,
        db: &AccountDb,
        sequence: u64,
        effect: impl FnOnce() -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        let mut outcome = None;
        let fenced = db.receive_transaction(self.expected, self.generation, |tx| {
            tx.require_open_input(sequence)?;
            let result = effect();
            let failed = result.is_err();
            outcome = Some(result);
            if failed {
                return Err(StorageError::Integrity("own-copy recovery failed"));
            }
            before_commit_fault()?;
            Ok(())
        });
        match (fenced, outcome) {
            (_, Some(Err(error))) => Err(error),
            (Err(error), _) => Err(error.into()),
            (Ok(()), Some(Ok(value))) => Ok(value),
            (Ok(()), None) => Err(SdkError::LocalBus("own-copy recovery did not run".into())),
        }
    }
}

fn register_sequence_locator(
    db: &AccountDb,
    message: &str,
    expected: ReceiveExpectation<'_>,
    sequence: u64,
) -> Result<(), StorageError> {
    let locator = SequenceLocator {
        target: expected.target.to_owned(),
        incarnation: expected.incarnation.to_owned(),
        sequence,
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
    /// Test-only: decrypts an own-copy packet and commits through the dormant W1 adapter.
    #[cfg(test)]
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
        gate.effect(db, sequence, message, || self.commit_own_copy_from_entry(entry, manifest))
    }

    /// Test-only: recovery W1 cut for the pair-reset durable writes.
    #[cfg(test)]
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
