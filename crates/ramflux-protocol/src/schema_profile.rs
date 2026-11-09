// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable application-profile generations, independent of SQL migration versions.

/// Profile used by existing stores. PR1 does not activate the candidate schema.
pub const ACTIVE_STORAGE_GENERATION: i64 = 0;
/// Reserved generation for the coordinated message-schema v1 activation.
pub const MESSAGE_SCHEMA_V1_GENERATION: i64 = 1;
/// Authenticated backup context key. Absence denotes the existing generation zero.
pub const ARCHIVE_GENERATION_KEY: &str = "schema_generation";

/// True only after PR24/P25 flips the live generation to message schema v1.
#[must_use]
pub fn schema_v1_live() -> bool {
    if FORCE_SCHEMA_V1_LIVE.with(std::cell::Cell::get) {
        return true;
    }
    ACTIVE_STORAGE_GENERATION == MESSAGE_SCHEMA_V1_GENERATION
}

thread_local! {
    static FORCE_SCHEMA_V1_LIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test-only: force the v1 profile on for this thread until dropped.
#[doc(hidden)]
pub struct SchemaV1LiveGuard {
    previous: bool,
}

impl SchemaV1LiveGuard {
    /// Enable the v1 profile for the current thread.
    #[must_use]
    pub fn enter() -> Self {
        let previous = FORCE_SCHEMA_V1_LIVE.with(std::cell::Cell::get);
        FORCE_SCHEMA_V1_LIVE.with(|flag| flag.set(true));
        Self { previous }
    }
}

impl Drop for SchemaV1LiveGuard {
    fn drop(&mut self) {
        FORCE_SCHEMA_V1_LIVE.with(|flag| flag.set(self.previous));
    }
}
