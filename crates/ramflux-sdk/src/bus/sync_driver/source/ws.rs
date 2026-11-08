// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT WS adapter for below-C local redrive (S6b P06). No production caller reaches it:
//! the live `Writer::apply` path is unchanged. P20 (the actor contract) supplies the
//! expectation values and wires `SettleRetained`.
//!
//! Contract: WS is indexed local redrive below C. A terminal event, intent and cleanup share
//! one transaction, or the hold is preserved; C never moves. Above-C settlement delegates to
//! ordered W2 (`cover`). A retired incarnation is local cleanup of any sequence (no ACK
//! intent). Cover and stage refuse a retired E; source gate and bind redrive
//! retained work. Compat U stays live.
#![allow(dead_code)]

use ramflux_storage::{AccountDb, ReceiveExpectation, ReceiveSettle, ReceiveSettleResult};

use crate::SdkError;

pub(crate) struct SourceWs<'a> {
    pub expected: ReceiveExpectation<'a>,
    pub generation: u64,
}

impl SourceWs<'_> {
    /// WS: settle one retained sequence, or delegate s>C to ordered cover.
    pub(crate) fn settle(
        &self,
        db: &AccountDb,
        input: ReceiveSettle,
    ) -> Result<ReceiveSettleResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.settle(input))?)
    }

    /// Sequences at or below C that still have held/quarantined/staged work.
    pub(crate) fn due_retained(&self, db: &AccountDb, limit: u32) -> Result<Vec<u64>, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.due_retained(limit))?)
    }
}
