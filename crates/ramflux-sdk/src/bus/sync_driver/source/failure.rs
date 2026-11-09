// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT failure-policy adapter (S6b P08). No production caller reaches it: the live
//! `Writer::apply` path is unchanged. P20 supplies the expectation and wires admission.
//!
//! Contract: one receive transaction joins verified policy, retry or dead-letter marker,
//! and held/terminal receipt disposition. Storage errors propagate with W0 retained and
//! no ACK. Group/contact expiry uses the same W2/WS transition.
#![allow(dead_code)]

use ramflux_storage::{
    AccountDb, ReceiveExpectation, ReceiveFailure, ReceiveFailureReason, ReceiveFailureResult,
    ReceiveTransaction, StorageError,
};

use crate::SdkError;

pub(crate) struct SourceFailure<'a> {
    pub expected: ReceiveExpectation<'a>,
    pub generation: u64,
}

impl SourceFailure<'_> {
    /// Failure-policy/retry admission on the caller's open W1 receive transaction.
    pub(crate) fn admit_in(
        tx: &ReceiveTransaction<'_>,
        input: ReceiveFailure<'_>,
    ) -> Result<ReceiveFailureResult, StorageError> {
        let result = tx.admit_failure(input)?;
        before_commit_fault()?;
        Ok(result)
    }

    /// Failure-policy/retry admission inside the caller's expected generation.
    /// Callers set `input.policy` from `crate::client::inbox_failure::verified_failure_policy`.
    pub(crate) fn admit(
        &self,
        db: &AccountDb,
        input: ReceiveFailure<'_>,
    ) -> Result<ReceiveFailureResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| Self::admit_in(tx, input))?)
    }

    /// Local hold expiry on the caller's open receive transaction.
    pub(crate) fn expire_holds_in(
        tx: &ReceiveTransaction<'_>,
        at: i64,
    ) -> Result<Vec<u64>, StorageError> {
        let settled = tx.expire_holds_keyed(at)?;
        for (_, key) in &settled {
            crate::client::reply_outbox::ReplyOutbox::prune_marker_in(tx, key)?;
        }
        before_commit_fault()?;
        Ok(settled.into_iter().map(|(sequence, _)| sequence).collect())
    }

    /// Local hold expiry (policy `expires_at` or the class 7-day max from `first_seen`) through WS/W2.
    pub(crate) fn expire_holds(&self, db: &AccountDb, at: i64) -> Result<Vec<u64>, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| {
            Self::expire_holds_in(tx, at)
        })?)
    }

    /// Shared terminal reason vocabulary used by `group_quarantine` and contact expiry.
    pub(crate) const fn expired() -> ReceiveFailureReason {
        ReceiveFailureReason::HeldExpired
    }
}

fn before_commit_fault() -> Result<(), StorageError> {
    if matches!(current_fault(), Fault::BeforeCommit) {
        return Err(StorageError::Integrity("source failure before-commit"));
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
pub(crate) fn set_fault(fault: Fault) {
    FAULT.with(|cell| cell.set(fault));
}
