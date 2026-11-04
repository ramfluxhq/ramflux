// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Release interlock shared by service startup and capability discovery.
pub const HOME_MIGRATION_RELEASE_GATE: bool = true;

/// Validates the opt-in before any service startup mutation.
/// # Errors
/// Rejects invalid opt-in configuration.
pub fn home_migration_enabled() -> Result<bool, crate::NodeCoreError> {
    match crate::environment::var("RAMFLUX_HOME_MIGRATION_ENABLED").ok().as_deref() {
        None | Some("0") => Ok(false),
        Some("1") => Ok(true),
        _ => Err(crate::NodeCoreError::Unauthorized(
            "RAMFLUX_HOME_MIGRATION_ENABLED must be 0 or 1".into(),
        )),
    }
}
