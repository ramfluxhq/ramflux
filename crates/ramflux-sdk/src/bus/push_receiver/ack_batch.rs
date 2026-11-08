// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT WA executor (S6b P21). Live `Writer::apply` / per-entry ACK is unchanged
//! until P24/P25. P20e/P20g wire the actor flush. One sorted positive max-64 batch
//! with an exact result set; uncertainty retains; own-copy locators are marked only
//! on a terminal router result.
#![allow(dead_code)]

use crate::SdkError;
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

    /// Apply an exact result set inside `tx` and mark locators for terminal outcomes.
    ///
    /// # Errors
    /// Returns storage refusals from [`ReceiveTransaction::apply_ack_results`].
    pub(crate) fn apply_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        input: ReceiveAckApply<'_>,
    ) -> Result<ReceiveAckApplyResult, StorageError> {
        let _ = self;
        let result = tx.apply_ack_results(input)?;
        if matches!(result, ReceiveAckApplyResult::Applied { .. }) {
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
        }
        Ok(result)
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
            locator.acknowledged = true;
            let message = key.strip_prefix(LOCATORS).unwrap_or("");
            db.persist_message_actor_state(message, &key, &locator)?;
        }
    }
    Ok(())
}
