// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT W0 adapter for source preparation (S6b P12). No production caller reaches it: the
//! live `Writer::apply` path is unchanged. The expectation values (target, incarnation, cursor,
//! generation, erasure generation) come from the caller; P20 (the actor contract) supplies them.
//!
//! Contract: W0 (`stage`) precedes every preparation effect; each effect runs inside one
//! generation, incarnation, cursor and erase-fenced receive transaction and only while the
//! coordinate's recovery input (receipt plus work) is retained; a late W1 bind erases or binds.
#![allow(dead_code)]

use crate::{RamfluxClient, SdkError};
use ramflux_storage::{
    AccountDb, ReceiveBind, ReceiveExpectation, ReceiveStage, ReceiveStageResult, StorageError,
};

pub(crate) struct SourceW0<'a> {
    pub expected: ReceiveExpectation<'a>,
    /// The caller actor's current generation (the fence compares it with `expected.generation`).
    pub generation: u64,
}

impl SourceW0<'_> {
    /// W0: reserves receipt, work and terminal-intent capacity before any preparation effect.
    pub(crate) fn stage(
        &self,
        db: &AccountDb,
        input: ReceiveStage<'_>,
    ) -> Result<ReceiveStageResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.stage(input))?)
    }

    /// Runs one preparation effect inside the fenced transaction. A stale generation,
    /// incarnation, cursor or erasure generation, or a missing recovery input, refuses before
    /// the effect; a failing effect rolls the whole transaction back.
    pub(crate) fn effect<T>(
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
                return Err(StorageError::Integrity("source effect failed"));
            }
            Ok(())
        });
        match (fenced, outcome) {
            (_, Some(Err(error))) => Err(error),
            (Err(error), _) => Err(error.into()),
            (Ok(()), Some(Ok(value))) => Ok(value),
            (Ok(()), None) => Err(SdkError::LocalBus("source effect did not run".into())),
        }
    }

    /// The same gate for an effect that needs `&mut RamfluxClient` and therefore cannot run
    /// inside the receive transaction (the client owns the database handle). The fence is a
    /// pre-check and a post-check only: a concurrent erase or retirement is reported instead of
    /// looking like success. The post-check cannot undo a write the effect already committed.
    /// P20 runs `prepare_own_history_receive` inside the receive transaction.
    pub(crate) fn effect_mut<T>(
        &self,
        client: &mut RamfluxClient,
        sequence: u64,
        effect: impl FnOnce(&mut RamfluxClient) -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        self.require_open(client.account_db()?, sequence)?;
        let value = effect(client)?;
        self.require_open(client.account_db()?, sequence)?;
        Ok(value)
    }

    fn require_open(&self, db: &AccountDb, sequence: u64) -> Result<(), SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| {
            tx.require_open_input(sequence)
        })?)
    }

    /// Late W1: binds the staged input to `message`, or erases it when that message is deleted.
    pub(crate) fn bind(
        &self,
        db: &AccountDb,
        sequence: u64,
        message: &str,
    ) -> Result<ReceiveBind, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| {
            tx.bind_logical_message(sequence, message)
        })?)
    }
}
