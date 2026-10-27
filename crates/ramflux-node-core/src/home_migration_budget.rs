// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A shared node admission ceiling bounds concurrent owner and peer verification/exchanges.
use crate::{MigrationNode, NodeCoreError};
use std::sync::atomic::{AtomicUsize, Ordering};
pub(crate) struct VerificationPermit<'a>(&'a AtomicUsize);
impl Drop for VerificationPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
impl MigrationNode {
    pub(crate) fn acquire_migration_verification(
        &self,
    ) -> Result<VerificationPermit<'_>, NodeCoreError> {
        self.verification_jobs
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < 16).then_some(current + 1)
            })
            .map_err(|_| {
                NodeCoreError::HomeMigration(
                    ramflux_protocol::home_migration::Refusal::CapacityRefused,
                )
            })?;
        Ok(VerificationPermit(&self.verification_jobs))
    }
}
