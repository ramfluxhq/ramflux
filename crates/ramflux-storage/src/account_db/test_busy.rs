// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Test support: a competing writer connection that fails fast instead of waiting.
use crate::{AccountDb, StorageError};

#[cfg(any(test, feature = "test-instrumentation"))]
impl AccountDb {
    /// Test support: this connection's busy handler gives up immediately, so a competing write
    /// reports the exact busy error instead of waiting out the default timeout.
    ///
    /// # Errors
    /// Returns storage errors.
    pub fn fail_fast_busy_for_test(&self) -> Result<(), StorageError> {
        self.connection.call(|raw| raw.busy_timeout(std::time::Duration::ZERO))?;
        Ok(())
    }
}
