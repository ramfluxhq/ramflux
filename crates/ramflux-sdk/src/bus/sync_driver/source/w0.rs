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

use crate::bus::connection_manager::{ReceiveEntry, ReceivePlan, ReceiveTurn};
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

    /// Resume open W0/W1 work from disk under this fence. RAM held pages are ignored.
    #[allow(clippy::redundant_closure_for_method_calls)]
    pub(crate) fn recover_from_disk(
        &self,
        db: &AccountDb,
    ) -> Result<Vec<ramflux_storage::RecoveryInput>, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.recovery_inputs())?)
    }
}

/// Refuse the legacy receive path on an activated ledger.
///
/// `turn` is `Some` only for a Push session: that is the ledger actor path
/// an activated account must use, so it is not refused here. `None` is the
/// legacy PrepareReceive/ApplyPage branch and is refused first.
pub(crate) fn refuse_legacy_receive_unless_ledger_turn(
    account: &LocalBusAccountState,
    turn: Option<&ReceiveTurn>,
) -> Result<(), SdkError> {
    if turn.is_some() {
        return Ok(());
    }
    Ok(account.client.account_db()?.refuse_legacy_receive()?)
}

/// Actor `PrepareReceive` entry. The legacy guard and its activation/epoch/cursor/erase
/// reads run before the live cursor plan, so their errors fail `PrepareReceive`. `actor_turn`
/// is computed once and reused for the guard and Connected recovery. When the ledger is
/// activated and this is the Connected pass, [`SourceW0::from_actor`] builds the fence
/// (`turn.generation` vs S2 `handle_generation`) and the open W0/W1 rows read from disk
/// inside that fence feed `plan.retries`. An activated fence refusal or epoch read error
/// is a typed `PrepareReceive` failure. Inactive accounts skip recovery and keep the live plan.
pub(crate) fn prepare_receive_turn(
    account: &LocalBusAccountState,
    turn_generation: u64,
    handle_generation: u64,
    trigger: crate::bus::connection_manager::ReceiveTrigger,
) -> Result<ReceivePlan, SdkError> {
    let turn = actor_turn(account, turn_generation)?;
    refuse_legacy_receive_unless_ledger_turn(account, turn.as_ref())?;
    let mut plan = crate::bus::sync_driver::prepare_receive(account, turn_generation)?;
    // Only the Connected pass recovers: Tick/Resync never pay the writer lock for a read.
    if trigger != crate::bus::connection_manager::ReceiveTrigger::Connected {
        return Ok(plan);
    }
    let Some(turn) = turn else {
        return Ok(plan);
    };
    let recovered = account
        .client
        .account_db()
        .and_then(|db| SourceW0::from_actor(&turn, handle_generation).recover_from_disk(db))?;
    merge_recovered(&mut plan, &recovered);
    Ok(plan)
}

/// Adds each recovered staged/held entry to the plan unless the plan already carries it.
fn merge_recovered(plan: &mut ReceivePlan, inputs: &[ramflux_storage::RecoveryInput]) {
    merge_retry_inputs(&mut plan.retries, inputs);
}

fn merge_retry_inputs(retries: &mut Vec<ReceiveEntry>, inputs: &[ramflux_storage::RecoveryInput]) {
    for input in inputs {
        let entry = match serde_json::from_slice::<crate::GatewayInboxEntry>(&input.entry_json) {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!(%error, sequence = input.sequence,
                    "recovered receive entry is not decodable; left on disk");
                continue;
            }
        };
        let known = retries.iter().any(|prepared| {
            prepared.entry.inbox_seq == entry.inbox_seq
                && prepared.entry.envelope.envelope_id == entry.envelope.envelope_id
        });
        if !known {
            retries.push(ReceiveEntry { entry, retry_key: None, replay: false, turn: None });
        }
    }
}

/// Leftover W0/W1 rows for standalone catch-up. Activated standalone has no Push
/// engine, so [`prepare_receive_turn`] would refuse as a legacy path.
pub(crate) fn recover_standalone_retries(
    account: &LocalBusAccountState,
    turn: &ReceiveTurn,
    handle_generation: u64,
) -> Result<Vec<ReceiveEntry>, SdkError> {
    let recovered = account
        .client
        .account_db()
        .and_then(|db| SourceW0::from_actor(turn, handle_generation).recover_from_disk(db))?;
    let mut retries = Vec::new();
    merge_retry_inputs(&mut retries, &recovered);
    Ok(retries)
}

/// Push-session coordinates from S2's engine plus disk cursor/erase. `None` when the
/// ledger is Inactive or the session is not Push. Activated without an epoch is
/// [`ramflux_storage::MISSING_EPOCH`]. Extra DB reads stay behind the discriminator
/// so live `PrepareReceive` cannot fail on them for inactive accounts.
pub(crate) fn actor_turn(
    account: &LocalBusAccountState,
    generation: u64,
) -> Result<Option<ReceiveTurn>, SdkError> {
    let db = account.client.account_db()?;
    match db.receive_activation()? {
        ramflux_storage::ReceiveActivation::Inactive => return Ok(None),
        ramflux_storage::ReceiveActivation::Activated => {
            if db.receive_epoch(&account.target_delivery_id)?.is_none() {
                return Err(ramflux_storage::StorageError::Integrity(
                    ramflux_storage::MISSING_EPOCH,
                )
                .into());
            }
        }
    }
    let Some(engine) = account.engine.as_ref() else {
        return Ok(None);
    };
    let SessionMode::Push { incarnation } = &engine.mode else {
        return Ok(None);
    };
    let target = account.target_delivery_id.clone();
    let cursor = account.client.gateway_receive_cursor(&target)?;
    Ok(Some(ReceiveTurn {
        target,
        incarnation: incarnation.as_str().to_owned(),
        cursor,
        generation,
        erasure_generation: db.privacy_erasure_generation()?,
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
