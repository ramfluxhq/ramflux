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
    pub(super) fn require_io(&self) -> Result<(), StorageError> {
        if self.source_cancelled.load(Ordering::Acquire) {
            return Err(StorageError::PairingField("Cancelled"));
        }
        self.db.require_full_stage_unlock()
    }
}
