// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-way local I/O cancellation, with no key, connection or cleanup/publication authority.
use super::FullTransferStage;
use crate::StorageError;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone)]
pub struct FullStageIoCancel(Arc<AtomicBool>);
impl FullStageIoCancel {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
impl FullTransferStage<'_> {
    #[must_use]
    pub fn io_cancel_handle(&self) -> FullStageIoCancel {
        FullStageIoCancel(self.source_cancelled.clone())
    }
    /// Bind each fresh short stage loan to its actual ceremony's one-way cancellation.
    /// Detached copy/encoding jobs inherit this SAME flag; no key or approval is restored.
    /// # Errors
    /// Refuses an already cancelled stage/owner or lost original unlock; cannot revive I/O.
    pub fn bind_local_io_cancellation(
        &mut self,
        owner: &FullStageIoCancel,
    ) -> Result<(), StorageError> {
        self.require_io()?;
        if owner.is_cancelled() {
            return Err(StorageError::PairingField("Cancelled"));
        }
        self.source_cancelled = owner.0.clone();
        self.require_io()
    }
    pub(super) fn require_io(&self) -> Result<(), StorageError> {
        if self.source_cancelled.load(Ordering::Acquire) {
            return Err(StorageError::PairingField("Cancelled"));
        }
        self.db.require_full_stage_unlock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pairing_full_short_loan_and_detached_work_share_cancellation_without_rearming()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, db) = crate::tests::test_db("full-shared-loan-cancel")?;
        let (record, _, _) = super::super::stage_tests::fixture()?;
        let mut stage = db.create_full_stage_for_test(record, 604_900)?;
        let owner = FullStageIoCancel(Arc::new(AtomicBool::new(false)));
        stage.bind_local_io_cancellation(&owner)?;
        let detached = stage.io_cancel_handle();
        owner.cancel();
        assert!(detached.is_cancelled(), "fresh loan detached cancellation from the root owner");
        assert!(stage.require_io().is_err());
        let fresh = FullStageIoCancel(Arc::new(AtomicBool::new(false)));
        assert!(stage.bind_local_io_cancellation(&fresh).is_err(), "cancelled stage was rearmed");
        assert!(stage.io_cancel_handle().is_cancelled());
        drop(stage);
        drop(db);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
