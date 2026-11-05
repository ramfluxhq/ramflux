// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Direct transactions preserve caller-side rollback refusals, but a failed
//! begin/commit or an unwind in a held transaction fail-stops the process.
use crate::{NodeCoreError, fatal_durability};
use std::ops::{Deref, DerefMut};
use std::path::Path;

struct PanicGuard;
impl Drop for PanicGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            fatal_durability::fence(false);
        }
    }
}
pub(super) struct DirectWrite<'a> {
    // Signal before redb transaction teardown during unwind.
    _panic: PanicGuard,
    txn: redb::WriteTransaction,
    path: &'a Path,
}
impl Deref for DirectWrite<'_> {
    type Target = redb::WriteTransaction;
    fn deref(&self) -> &Self::Target {
        &self.txn
    }
}
impl DerefMut for DirectWrite<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.txn
    }
}
impl DirectWrite<'_> {
    pub(super) fn commit(self) -> Result<(), NodeCoreError> {
        let guard = fatal_durability::WriteGuard::new(false)?;
        crate::durability_io::boundary(self.path, "direct_commit", || {
            self.txn.commit().map_err(std::io::Error::other)
        })
        .map_err(super::incarnation::error)?;
        guard.complete()
    }
    pub(super) fn abort(self) -> Result<(), NodeCoreError> {
        self.txn.abort().map_err(super::incarnation::error)
    }
}
impl super::RouterRedbStore {
    pub(super) fn begin_write(&self) -> Result<DirectWrite<'_>, NodeCoreError> {
        let guard = fatal_durability::WriteGuard::new(false)?;
        let txn = crate::durability_io::boundary(&self.path, "direct_begin", || {
            self.db.begin_write().map_err(std::io::Error::other)
        })
        .map_err(super::incarnation::error)?;
        guard.complete()?;
        Ok(DirectWrite { txn, path: &self.path, _panic: PanicGuard })
    }
}
