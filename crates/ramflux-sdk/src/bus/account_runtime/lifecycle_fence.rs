// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Commit-time generation / E / erase / expected-state fence for receive actor turns.
//!
//! Live unactivated accounts have no epoch row and keep today's prepare/apply/ack
//! bodies. Activated accounts persist `gateway_receive_activation` in receive metadata;
//! first activation is default-on. Legacy receive-C writers refuse once
//! Activated. After lock/unlock or restart the actor recovers solely from disk
//! (W0/W1/work rows): `PrepareReceive` on a Connected pass feeds the open rows into the
//! receive plan (`source::w0::prepare_receive_turn`). Shared-ledger routing is P24b2.
#![allow(dead_code)]

use ramflux_storage::{
    AccountDb, ReceiveExpectation, ReceiveTransaction, RecoveryInput, StorageError,
};

use crate::SdkError;
use crate::bus::connection_manager::ReceiveTurn;

/// Open recovery inputs loaded from disk under the actor fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DiskRecovery {
    pub inputs: Vec<RecoveryInput>,
}

/// Actor commit. `handle_generation` is S2's current generation; `expected.generation`
/// is the generation captured when the turn was prepared. A mismatch, wrong E, stale
/// cursor, or erasure generation refuses before `write`.
pub(crate) fn commit<T>(
    db: &AccountDb,
    handle_generation: u64,
    expected: ReceiveExpectation<'_>,
    write: impl FnOnce(&ReceiveTransaction<'_>) -> Result<T, StorageError>,
) -> Result<T, StorageError> {
    db.receive_transaction(expected, handle_generation, write)
}

/// Outcome of one ACK decision or record. Never writes C.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AckRecord {
    /// Terminal W2/WS intent at or below C; cursor succeeded.
    Recorded,
    /// Pre-send decision: the intent exists, `seq <= C` and the fence holds.
    Permitted,
    /// No intent (held / quarantined). Never acknowledged.
    Held,
    /// Sequence is above the captured cursor.
    AboveCursor,
    /// Cursor failed; C stays at the captured value.
    CursorFailed,
}

/// Intent exists and `seq <= C`, evaluated inside the commit fence.
fn decide(
    tx: &ReceiveTransaction<'_>,
    turn: &ReceiveTurn,
    sequence: u64,
) -> Result<Option<AckRecord>, StorageError> {
    tx.require_writer()?;
    if sequence > turn.cursor {
        return Ok(Some(AckRecord::AboveCursor));
    }
    if !tx.has_ack_intent(sequence)? {
        return Ok(Some(AckRecord::Held));
    }
    Ok(None)
}

/// Decide before the gateway ACK is transmitted. Only `Permitted` may be sent; a
/// stale generation, E, or erase is refused with a storage error. C is unchanged.
pub(crate) fn ack_permit(
    db: &AccountDb,
    handle_generation: u64,
    turn: &ReceiveTurn,
    sequence: u64,
) -> Result<AckRecord, SdkError> {
    commit(db, handle_generation, turn.expected(), |tx| {
        Ok(decide(tx, turn, sequence)?.unwrap_or(AckRecord::Permitted))
    })
    .map_err(SdkError::from)
}

/// Record one ACK outcome under the commit fence. C is unchanged.
pub(crate) fn ack_results(
    db: &AccountDb,
    handle_generation: u64,
    turn: &ReceiveTurn,
    sequence: u64,
    cursor_ok: bool,
) -> Result<AckRecord, SdkError> {
    commit(db, handle_generation, turn.expected(), |tx| {
        if let Some(refused) = decide(tx, turn, sequence)? {
            return Ok(refused);
        }
        if cursor_ok { Ok(AckRecord::Recorded) } else { Ok(AckRecord::CursorFailed) }
    })
    .map_err(SdkError::from)
}
/// Resume open W0/W1 work from disk under the commit fence. RAM held pages are ignored.
pub(crate) fn recover_from_disk(
    db: &AccountDb,
    handle_generation: u64,
    expected: ReceiveExpectation<'_>,
) -> Result<DiskRecovery, StorageError> {
    commit(db, handle_generation, expected, |tx| Ok(DiskRecovery { inputs: tx.recovery_inputs()? }))
}
