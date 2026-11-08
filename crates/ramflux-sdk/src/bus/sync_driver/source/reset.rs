// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! DORMANT reset/migration adapter (S6b P10). No production caller reaches it:
//! the live `Writer::apply` path is unchanged. P20/P24 supply the expectation
//! and first-page S. Cover and stage keep refusing a retired E; source gate and
//! bind redrive already-retained work.
#![allow(dead_code)]

use ramflux_storage::{
    AccountDb, ReceiveExpectation, ReceiveIssued, ReceiveMigrate, ReceiveMigrateResult,
    ReceiveReset, ReceiveResetResult,
};

use crate::SdkError;

pub(crate) struct SourceReset<'a> {
    pub expected: ReceiveExpectation<'a>,
    pub generation: u64,
}

impl SourceReset<'_> {
    /// WJ: publish unpublished old-E loss events before reset.
    pub(crate) fn publish_pending_loss(&self, db: &AccountDb, at: i64) -> Result<u32, SdkError> {
        Ok(db.publish_pending_receive_loss(self.expected.target, self.expected.incarnation, at)?)
    }

    /// Direct pre-ledger bind. Requires the caller's open writer.
    pub(crate) fn migrate_direct(
        &self,
        db: &AccountDb,
        input: ReceiveMigrate<'_>,
    ) -> Result<ReceiveMigrateResult, SdkError> {
        if input.target != self.expected.target || input.incarnation != self.expected.incarnation {
            return Err(ramflux_storage::StorageError::Integrity(
                "receive migrate identity missing",
            )
            .into());
        }
        Ok(db.migrate_direct(input)?)
    }

    /// Atomic expected-E reset onto first-page S.
    pub(crate) fn reset(
        &self,
        db: &AccountDb,
        input: ReceiveReset<'_>,
    ) -> Result<ReceiveResetResult, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.reset(input))?)
    }

    /// Same-E issued<C freeze.
    pub(crate) fn observe_issued(
        &self,
        db: &AccountDb,
        issued: u64,
    ) -> Result<ReceiveIssued, SdkError> {
        Ok(db.receive_transaction(self.expected, self.generation, |tx| tx.observe_issued(issued))?)
    }

    /// Retired-fence pause diagnostic, read by recovery.
    pub(crate) fn pause_reason(&self, db: &AccountDb) -> Result<Option<String>, SdkError> {
        Ok(db.receive_pause(self.expected.target)?)
    }

    /// Recovery clears the retired-fence pause.
    pub(crate) fn clear_pause(&self, db: &AccountDb) -> Result<(), SdkError> {
        Ok(db.write_transaction(|| db.clear_receive_pause(self.expected.target))?)
    }
}
