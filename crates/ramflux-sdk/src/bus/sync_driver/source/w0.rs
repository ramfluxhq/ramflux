// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT W0 adapter for source preparation (S6b P12 / P20b). No production caller reaches
//! the live `Writer::apply` path: that body is unchanged until P24/P25. The actor
//! `PrepareReceive` arm supplies `ReceiveExpectation` via [`SourceW0::from_actor`].
//!
//! Contract: W0 (`stage`) precedes every preparation effect; each effect runs inside one
//! generation, incarnation, cursor and erase-fenced receive transaction and only while the
//! coordinate's recovery input (receipt plus work) is retained; a late W1 bind erases or binds.
//! `prepare_own_history_receive` runs through [`SourceW0::effect`] so its writes join the
//! receive transaction (nested `write_transaction` is a SAVEPOINT).
#![allow(dead_code)]

use crate::bus::connection_manager::{ReceivePlan, ReceiveTurn};
use crate::bus::state::LocalBusAccountState;
use crate::gateway::session_push::SessionMode;
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
    /// Actor-owned coordinates become the W0 fence. `handle_generation` is S2's current
    /// generation; a mismatch with `turn.generation` refuses at commit.
    #[must_use]
    pub(crate) fn from_actor(turn: &ReceiveTurn, handle_generation: u64) -> SourceW0<'_> {
        SourceW0 { expected: turn.expected(), generation: handle_generation }
    }

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
    /// the effect; a failing effect rolls the whole transaction back. Own-history preparation
    /// (`prepare_own_history_receive`) uses this path so manifest accept and history import
    /// commit with the fence or not at all.
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
            before_commit_fault()?;
            Ok(())
        });
        match (fenced, outcome) {
            (_, Some(Err(error))) => Err(error),
            (Err(error), _) => Err(error.into()),
            (Ok(()), Some(Ok(value))) => Ok(value),
            (Ok(()), None) => Err(SdkError::LocalBus("source effect did not run".into())),
        }
    }

    /// Gate for an effect that needs `&mut RamfluxClient` (the client owns the database
    /// handle). Cipher import still uses this seam; own-history *preparation* uses [`Self::effect`].
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

/// Refuse the legacy receive path on an activated ledger.
///
/// `actor_turn` is `Some` only for a Push session: that is the ledger actor path
/// an activated account must use, so it is not refused here. `None` is the
/// legacy PrepareReceive/ApplyPage branch and is refused first.
pub(crate) fn refuse_legacy_receive_unless_ledger_turn(
    account: &LocalBusAccountState,
    generation: u64,
) -> Result<(), SdkError> {
    if actor_turn(account, generation)?.is_some() {
        return Ok(());
    }
    Ok(account.client.account_db()?.refuse_legacy_receive()?)
}

/// Actor `PrepareReceive` entry. Constructs [`SourceW0`] from the actor's generation and,
/// when the session is Push, its incarnation. The live cursor plan is unchanged until P24.
pub(crate) fn prepare_receive_turn(
    account: &LocalBusAccountState,
    generation: u64,
) -> Result<ReceivePlan, SdkError> {
    refuse_legacy_receive_unless_ledger_turn(account, generation)?;
    if let Some(turn) = actor_turn(account, generation)? {
        let source = SourceW0::from_actor(&turn, generation);
        debug_assert_eq!(source.generation, generation);
        debug_assert_eq!(source.expected.generation, turn.generation);
    }
    crate::bus::sync_driver::prepare_receive(account, generation)
}

fn actor_turn(
    account: &LocalBusAccountState,
    generation: u64,
) -> Result<Option<ReceiveTurn>, SdkError> {
    let Some(engine) = account.engine.as_ref() else {
        return Ok(None);
    };
    let SessionMode::Push { incarnation } = &engine.mode else {
        return Ok(None);
    };
    let target = account.target_delivery_id.clone();
    let cursor = account.client.gateway_receive_cursor(&target)?;
    let erasure_generation = account.client.account_db()?.privacy_erasure_generation()?;
    Ok(Some(ReceiveTurn {
        target,
        incarnation: incarnation.as_str().to_owned(),
        cursor,
        generation,
        erasure_generation,
    }))
}

fn before_commit_fault() -> Result<(), StorageError> {
    if matches!(current_fault(), Fault::BeforeCommit) {
        return Err(StorageError::Integrity("source w0 before-commit"));
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
