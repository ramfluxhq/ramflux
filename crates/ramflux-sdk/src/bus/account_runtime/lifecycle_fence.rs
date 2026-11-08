// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Commit-time generation / E / erase / expected-state fence for receive actor turns.
//!
//! Live unactivated accounts have no epoch row and keep today's prepare/apply/ack
//! bodies. Activated (test-seeded) turns fail late inputs inside `receive_transaction`
//! before any write or ACK. Activation remains P24/P25.
#![allow(dead_code)]

use ramflux_storage::{AccountDb, ReceiveExpectation, ReceiveTransaction, StorageError};

use crate::SdkError;
use crate::bus::connection_manager::ReceiveTurn;

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

/// Settle one retained sequence under the commit fence. No network.
pub(crate) fn settle_retained(
    db: &AccountDb,
    handle_generation: u64,
    turn: &ReceiveTurn,
    sequence: u64,
) -> Result<(), SdkError> {
    commit(db, handle_generation, turn.expected(), |tx| {
        tx.require_writer()?;
        let _ = sequence;
        Ok(())
    })
    .map_err(SdkError::from)
}
