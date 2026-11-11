// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Opt-in test instrumentation for all statements on the account writer connection.
use crate::{AccountDb, StorageError};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

struct ProgressReset<'a>(&'a AccountDb);
impl Drop for ProgressReset<'_> {
    fn drop(&mut self) {
        let _ = self.0.connection.call(|connection| {
            connection.progress_handler(0, None::<fn() -> bool>)?;
            Ok(())
        });
    }
}

impl AccountDb {
    /// Counts SQLite VM instructions, including triggers, executed by a synchronous test operation.
    /// Enabled only by `test-instrumentation`; use a dedicated account with no concurrent writers.
    /// The handler is removed even if the operation returns an error or unwinds.
    /// # Errors
    /// Returns an error if installing instrumentation on the writer fails.
    pub fn measure_sqlite_vm_steps<T>(
        &self,
        operation: impl FnOnce() -> T,
    ) -> Result<(T, u64), StorageError> {
        let steps = Arc::new(AtomicU64::new(0));
        let counter = steps.clone();
        self.connection.call(move |connection| {
            connection.progress_handler(
                1,
                Some(move || {
                    counter.fetch_add(1, Ordering::Relaxed);
                    false
                }),
            )?;
            Ok(())
        })?;
        let reset = ProgressReset(self);
        let result = operation();
        drop(reset);
        Ok((result, steps.load(Ordering::Relaxed)))
    }
}

struct CommitReset<'a>(&'a AccountDb);
impl Drop for CommitReset<'_> {
    fn drop(&mut self) {
        let _ = self.0.connection.call(|connection| {
            connection.commit_hook(None::<fn() -> bool>)?;
            Ok(())
        });
    }
}
impl AccountDb {
    /// Reject the first real SQLite commit in a synchronous test operation.
    /// Available only with test instrumentation; use a dedicated account writer.
    /// The commit hook is removed on success, failure and unwind.
    /// # Errors
    /// Returns hook installation errors. The callback's result is returned unchanged.
    pub fn reject_next_sqlite_commit<T>(
        &self,
        operation: impl FnOnce() -> T,
    ) -> Result<(T, u64), StorageError> {
        let commits = Arc::new(AtomicU64::new(0));
        let counter = commits.clone();
        self.connection.call(move |connection| {
            connection.commit_hook(Some(move || counter.fetch_add(1, Ordering::Relaxed) == 0))?;
            Ok(())
        })?;
        let reset = CommitReset(self);
        let result = operation();
        drop(reset);
        Ok((result, commits.load(Ordering::Relaxed)))
    }
}
