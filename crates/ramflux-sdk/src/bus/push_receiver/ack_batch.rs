// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT WA executor (S6b P21). Live `Writer::apply` / per-entry ACK is unchanged
//! until P24/P25. P20e/P20g wire the actor flush. One sorted positive max-64 batch
//! with an exact result set; uncertainty retains. On a terminal router result the
//! settlement transaction also marks the existing own-copy replay marker and receipt
//! (through the W1 locator's stored binding) and the locator flag.
#![allow(dead_code)]

use crate::SdkError;
use crate::client::own_device_copy::receipts::mark_own_copy_acknowledged;
use crate::client::own_device_copy::w1::{LOCATORS, SequenceLocator};
use ramflux_storage::{
    AccountDb, ReceiveAckApply, ReceiveAckApplyResult, ReceiveAckOutcome, ReceiveExpectation,
    ReceiveTransaction, StorageError,
};

pub(crate) struct SourceWa<'a> {
    pub expected: ReceiveExpectation<'a>,
    pub generation: u64,
}

impl SourceWa<'_> {
    /// Select a due batch inside an open receive transaction.
    ///
    /// # Errors
    /// Returns storage refusals from [`ReceiveTransaction::select_ack_batch`].
    pub(crate) fn select_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        now: i64,
        force: bool,
    ) -> Result<Vec<u64>, StorageError> {
        let _ = self;
        tx.select_ack_batch(now, force)
    }

    /// Apply an exact result set inside `tx`. Terminal outcomes also mark the own-copy
    /// replay marker, receipt and locator in the same transaction; the fault hook runs after
    /// those marks, right before COMMIT.
    ///
    /// # Errors
    /// Returns storage refusals from [`ReceiveTransaction::apply_ack_results_with`].
    pub(crate) fn apply_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        input: ReceiveAckApply<'_>,
    ) -> Result<ReceiveAckApplyResult, StorageError> {
        let _ = self;
        tx.apply_ack_results_with(input, |tx| {
            for row in input.results {
                if marks_locator(row.outcome) {
                    mark_locator(
                        tx.account(),
                        input.incarnation,
                        self.expected.target,
                        row.sequence,
                    )?;
                }
            }
            before_commit()
        })
    }

    /// Select due intents (16 / 1s / force).
    ///
    /// # Errors
    /// Returns the fenced select refusal.
    pub(crate) fn select(
        &self,
        db: &AccountDb,
        now: i64,
        force: bool,
    ) -> Result<Vec<u64>, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| {
            self.select_in(tx, now, force)
        })?)
    }

    /// Apply WA results and mark locators in one transaction.
    ///
    /// # Errors
    /// Returns the fenced apply refusal.
    pub(crate) fn apply(
        &self,
        db: &AccountDb,
        input: ReceiveAckApply<'_>,
    ) -> Result<ReceiveAckApplyResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| self.apply_in(tx, input))?)
    }
}

fn marks_locator(outcome: ReceiveAckOutcome) -> bool {
    matches!(
        outcome,
        ReceiveAckOutcome::Acked | ReceiveAckOutcome::AlreadySettled | ReceiveAckOutcome::NotFound
    )
}

fn mark_locator(
    db: &AccountDb,
    incarnation: &str,
    target: &str,
    sequence: u64,
) -> Result<(), StorageError> {
    for key in db.actor_state_keys(LOCATORS)? {
        let Some(mut locator) = db.load_actor_state::<SequenceLocator>(&key)? else {
            continue;
        };
        if locator.target == target
            && locator.incarnation == incarnation
            && locator.sequence == sequence
            && !locator.acknowledged
        {
            if let Some(binding) = &locator.ack {
                mark_own_copy_acknowledged(db, binding)?;
            }
            locator.acknowledged = true;
            let message = key.strip_prefix(LOCATORS).unwrap_or("");
            db.persist_message_actor_state(message, &key, &locator)?;
        }
    }
    Ok(())
}

fn before_commit() -> Result<(), StorageError> {
    if fault_armed() {
        return Err(StorageError::Integrity("wa settlement before-commit"));
    }
    Ok(())
}

fn fault_armed() -> bool {
    #[cfg(test)]
    {
        FAULT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Runs `write` with the WA before-commit fault armed (after the last own-copy mark).
#[cfg(test)]
pub(crate) fn run<T>(write: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAULT.with(|slot| slot.set(false));
        }
    }
    FAULT.with(|slot| slot.set(true));
    let _reset = Reset;
    write()
}
