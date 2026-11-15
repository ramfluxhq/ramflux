// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Receive transaction fence shared by the live source-hold path and historical unit adapters.
//! The generic gate stages and joins storage effects without interpreting application bytes.
//!
//! Contract: W0 (`stage`) precedes the irreversible effect; ratchet, content/rejection/receipt
//! and the authenticated dedup marker run inside one generation, incarnation, cursor and
//! erase-fenced receive transaction. Cursor and ACK are not embedded (ledger WA). Attachment
//! and auth reads stay outside the transaction. Group holds remain held. Never persist
//! plaintext to make a step resumable.
#![allow(dead_code)]

use crate::prelude::*;
use ramflux_storage::{
    AccountDb, ReceiveBind, ReceiveExpectation, ReceiveStage, ReceiveStageResult,
    ReceiveTransaction, StorageError,
};

pub(crate) struct LegacyW1<'a> {
    pub expected: ReceiveExpectation<'a>,
    /// The caller actor's current generation (the fence compares it with `expected.generation`).
    pub generation: u64,
}

impl LegacyW1<'_> {
    pub(crate) fn stage(
        &self,
        db: &AccountDb,
        input: ReceiveStage<'_>,
    ) -> Result<ReceiveStageResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.stage(input))?)
    }

    /// Runs the irreversible effect and optional logical-message bind inside one receive
    /// transaction. A missing recovery input refuses before the effect.
    pub(crate) fn effect<T>(
        &self,
        db: &AccountDb,
        sequence: u64,
        message: Option<&str>,
        effect: impl FnOnce() -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        let mut outcome = None;
        let fenced = db.receive_transaction(self.expected, self.generation, |tx| {
            match self.effect_in(tx, sequence, message, effect) {
                Ok(value) => {
                    outcome = Some(Ok(value));
                    Ok(())
                }
                Err(error) => {
                    outcome = Some(Err(error));
                    Err(StorageError::Integrity("legacy effect failed"))
                }
            }
        });
        match (fenced, outcome) {
            (_, Some(Err(error))) => Err(error),
            (Err(error), _) => Err(error.into()),
            (Ok(()), Some(Ok(value))) => Ok(value),
            (Ok(()), None) => Err(SdkError::LocalBus("legacy effect did not run".into())),
        }
    }

    /// Same cut as [`Self::effect`], joining an already-open receive transaction.
    #[allow(clippy::unused_self)]
    pub(crate) fn effect_in<T>(
        &self,
        tx: &ReceiveTransaction<'_>,
        sequence: u64,
        message: Option<&str>,
        effect: impl FnOnce() -> Result<T, SdkError>,
    ) -> Result<T, SdkError> {
        tx.require_open_input(sequence)?;
        let value = effect()?;
        if let Some(message) = message {
            match tx.bind_logical_message(sequence, message)? {
                ReceiveBind::Bound | ReceiveBind::Erased => {}
            }
        }
        before_commit_fault()?;
        Ok(value)
    }
}

fn before_commit_fault() -> Result<(), StorageError> {
    if matches!(current_fault(), Fault::BeforeCommit) {
        return Err(StorageError::Integrity("legacy w1 before-commit"));
    }
    Ok(())
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
pub(crate) fn set_fault(fault: Fault) {
    FAULT.with(|cell| cell.set(fault));
}

impl RamfluxClient {
    /// Wired by P20. Group local apply that cannot complete stays held; no terminal marker.
    pub(crate) fn apply_legacy_group_hold_w1(
        &self,
        entry: &GatewayInboxEntry,
        expected: ReceiveExpectation<'_>,
        generation: u64,
    ) -> Result<(), SdkError> {
        let db = self.account_db()?;
        let gate = LegacyW1 { expected, generation };
        let sequence = entry.inbox_seq;
        gate.effect(db, sequence, None, || Self::commit_legacy_group_hold(db, entry))
    }

    /// Same cut as [`Self::apply_legacy_group_hold_w1`], joining an already-open receive transaction.
    #[allow(clippy::unused_self)]
    pub(crate) fn apply_legacy_group_hold_w1_in(
        &self,
        tx: &ReceiveTransaction<'_>,
        entry: &GatewayInboxEntry,
        expected: ReceiveExpectation<'_>,
        generation: u64,
    ) -> Result<(), SdkError> {
        let gate = LegacyW1 { expected, generation };
        let sequence = entry.inbox_seq;
        gate.effect_in(tx, sequence, None, || Self::commit_legacy_group_hold(tx.account(), entry))
    }

    fn commit_legacy_group_hold(db: &AccountDb, entry: &GatewayInboxEntry) -> Result<(), SdkError> {
        db.hold_unrouted(
            &entry.envelope.envelope_id,
            entry.inbox_seq,
            &serde_json::to_vec(entry)?,
            now_unix_timestamp(),
        )?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "legacy_w1_tests.rs"]
mod tests;
