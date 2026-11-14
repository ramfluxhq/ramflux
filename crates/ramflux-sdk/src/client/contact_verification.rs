// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One-time legacy safety baselining and read-only current-authority verification.
use crate::SdkError;
use ramflux_storage::AccountDb;

pub(crate) const MIGRATION_MARKER: &str = ramflux_storage::LEGACY_SAFETY_VERIFICATION_MARKER;

/// Baselines only eligible legacy rows present when the account first opens after upgrade.
pub(crate) fn migrate_legacy_contact_verifications(db: &AccountDb) -> Result<(), SdkError> {
    if db.load_actor_state::<bool>(MIGRATION_MARKER)? == Some(true) {
        return Ok(());
    }
    Ok(db.migrate_legacy_contact_verifications()?)
}
