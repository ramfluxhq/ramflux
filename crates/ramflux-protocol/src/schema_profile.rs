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
pub const fn schema_v1_live() -> bool {
    ACTIVE_STORAGE_GENERATION == MESSAGE_SCHEMA_V1_GENERATION
}
