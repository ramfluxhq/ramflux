// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Commit-time generation / E / erase / expected-state fence for receive actor turns.
//!
//! Live unactivated accounts have no epoch row and keep today's prepare/apply/ack
//! bodies. Activated (test-seeded) turns fail late inputs inside `receive_transaction`
//! before any write or ACK. Activation remains P24/P25.
#![allow(dead_code)]

use ramflux_storage::{AccountDb, ReceiveExpectation, ReceiveTransaction, StorageError};

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

/// Outcome of one `AckResults` record. Never writes C.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AckRecord {
    /// Terminal W2/WS intent at or below C; cursor succeeded.
    Recorded,
    /// No intent (held / quarantined). Never acknowledged.
    Held,
    /// Sequence is above the captured cursor.
    AboveCursor,
    /// Cursor failed; C stays at the captured value.
    CursorFailed,
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
        tx.require_writer()?;
        if sequence > turn.cursor {
            return Ok(AckRecord::AboveCursor);
        }
        if !tx.has_ack_intent(sequence)? {
            return Ok(AckRecord::Held);
        }
        if cursor_ok { Ok(AckRecord::Recorded) } else { Ok(AckRecord::CursorFailed) }
    })
    .map_err(SdkError::from)
}
