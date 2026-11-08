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
};

use crate::SdkError;

pub(crate) struct SourceFailure<'a> {
    pub expected: ReceiveExpectation<'a>,
    pub generation: u64,
}

impl SourceFailure<'_> {
    /// Failure-policy/retry admission inside the caller's expected generation.
    pub(crate) fn admit(
        &self,
        db: &AccountDb,
        input: ReceiveFailure<'_>,
    ) -> Result<ReceiveFailureResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.admit_failure(input))?)
    }

    /// Local hold expiry (policy, `retain_until`, or contact) through WS/W2.
    pub(crate) fn expire_holds(&self, db: &AccountDb, at: i64) -> Result<Vec<u64>, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.expire_holds(at))?)
    }

    /// Shared terminal reason vocabulary used by `group_quarantine` and contact expiry.
    pub(crate) const fn expired() -> ReceiveFailureReason {
        ReceiveFailureReason::HeldExpired
    }
}
