// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable application-profile generations, independent of SQL migration versions.

/// Active application profile. Other development store generations require an explicit reset.
pub const ACTIVE_STORAGE_GENERATION: i64 = 1;
/// Reserved generation for the coordinated message-schema v1 activation.
pub const MESSAGE_SCHEMA_V1_GENERATION: i64 = 1;
/// Authenticated backup context key. Absence denotes the existing generation zero.
pub const ARCHIVE_GENERATION_KEY: &str = "schema_generation";

/// True only after PR24/P25 flips the live generation to message schema v1.
#[must_use]
pub fn schema_v1_live() -> bool {
    true
}

/// Test fixture marker retained for callers of the active v1 profile.
#[doc(hidden)]
pub struct SchemaV1LiveGuard;
impl SchemaV1LiveGuard {
    /// The profile is always active; no override is installed.
    #[must_use]
    pub fn enter() -> Self {
        Self
    }
}
